import asyncio
from fastapi import APIRouter, UploadFile, File, HTTPException

from services.email_parser import parse_eml
from services.domain_analyzer import analyze_domain
from services.phishing_detector import analyze_phishing
from services.ip_analyzer import analyze_ips
from services.lookalike_detector import analyze_email_domains
from services.html_body_analyzer import analyze_html_body
from integrations.urlhaus import lookup_url as urlhaus_url
from integrations.virustotal import lookup_url as vt_url, lookup_file as vt_file
from integrations.threatfox import lookup_domain as tf_domain, lookup_ip as tf_ip, lookup_hash as tf_hash
from integrations.whois_lookup import lookup_domain as whois_domain
from config import settings

router = APIRouter(prefix="/api/email", tags=["email"])

MAX_BYTES = settings.max_file_size_mb * 1024 * 1024

# Max URLs/IPs/attachments to enrich (API rate limit protection)
MAX_URLS_ENRICH   = 10
MAX_IPS_ENRICH    = 10
MAX_ATTACH_ENRICH = 5


@router.post("/analyze")
async def analyze_email(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are accepted")

    data = await file.read()
    if len(data) > MAX_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds {settings.max_file_size_mb}MB limit")
    if len(data) == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    parsed = parse_eml(data)
    summary = parsed["summary"]
    auth_headers = parsed["authentication_headers"]

    # --- Local analysis (no I/O) ---
    domain_info = analyze_domain(summary["from"], auth_headers.get("dkim_signature", ""))
    lookalike   = analyze_email_domains(summary)
    html_body   = analyze_html_body(parsed.get("body_html", ""))

    # Collect all attachment flags for phishing scoring
    all_attachment_flags = [
        flag
        for att in parsed["attachments"]
        for flag in att.get("flags", [])
    ]

    # --- External async lookups (parallel) ---
    sender_domain = domain_info.get("domain", "")

    # URL enrichment: URLhaus + VirusTotal (first N URLs)
    urls_to_enrich = parsed["urls"][:MAX_URLS_ENRICH]
    url_tasks_urlhaus = [urlhaus_url(u) for u in urls_to_enrich]
    url_tasks_vt      = [vt_url(u)      for u in urls_to_enrich]

    # IP reputation
    ips_to_check = parsed["all_ips"][:MAX_IPS_ENRICH]
    ip_task      = analyze_ips(ips_to_check) if ips_to_check else asyncio.sleep(0, result={})
    tf_ip_tasks  = [tf_ip(ip) for ip in ips_to_check]

    # WHOIS for sender domain
    whois_task = whois_domain(sender_domain) if sender_domain else asyncio.sleep(0, result={})

    # ThreatFox domain check for sender
    tf_domain_task = tf_domain(sender_domain) if sender_domain else asyncio.sleep(0, result={})

    # Attachment hash lookups (VT + ThreatFox)
    attachments_with_payloads = [a for a in parsed["attachments"] if a.get("sha256")][:MAX_ATTACH_ENRICH]
    att_vt_tasks = [vt_file(a["sha256"]) for a in attachments_with_payloads]
    att_tf_tasks = [tf_hash(a["sha256"]) for a in attachments_with_payloads]

    # Gather everything
    all_tasks = [
        ip_task,
        whois_task,
        tf_domain_task,
        *url_tasks_urlhaus,
        *url_tasks_vt,
        *tf_ip_tasks,
        *att_vt_tasks,
        *att_tf_tasks,
    ]
    results = await asyncio.gather(*all_tasks, return_exceptions=True)

    # Unpack results
    idx = 0
    ip_reputation = results[idx] if not isinstance(results[idx], Exception) else {}; idx += 1
    whois_info    = results[idx] if not isinstance(results[idx], Exception) else {}; idx += 1
    tf_domain_result = results[idx] if not isinstance(results[idx], Exception) else {}; idx += 1

    urlhaus_results = []
    for i, url in enumerate(urls_to_enrich):
        r = results[idx + i]
        urlhaus_results.append(r if isinstance(r, dict) else {})
    idx += len(urls_to_enrich)

    vt_url_results = []
    for i, url in enumerate(urls_to_enrich):
        r = results[idx + i]
        vt_url_results.append(r if isinstance(r, dict) else {})
    idx += len(urls_to_enrich)

    tf_ip_results = []
    for i in range(len(ips_to_check)):
        r = results[idx + i]
        tf_ip_results.append(r if isinstance(r, dict) else {})
    idx += len(ips_to_check)

    att_vt_results = []
    for i in range(len(attachments_with_payloads)):
        r = results[idx + i]
        att_vt_results.append(r if isinstance(r, dict) else {})
    idx += len(attachments_with_payloads)

    att_tf_results = []
    for i in range(len(attachments_with_payloads)):
        r = results[idx + i]
        att_tf_results.append(r if isinstance(r, dict) else {})

    # Enrich IP reputation with ThreatFox
    if isinstance(ip_reputation, dict):
        for i, ip in enumerate(ips_to_check):
            if ip in ip_reputation and i < len(tf_ip_results):
                ip_reputation[ip]["threatfox"] = tf_ip_results[i]

    # Build URL results list
    url_results = []
    for i, url in enumerate(urls_to_enrich):
        entry: dict = {"url": url}
        if urlhaus_results[i]:
            entry["urlhaus"] = urlhaus_results[i]
        if vt_url_results[i]:
            entry["virustotal"] = vt_url_results[i]
        url_results.append(entry)
    for url in parsed["urls"][MAX_URLS_ENRICH:50]:
        url_results.append({"url": url})

    # Enrich attachment records with VT/ThreatFox
    attachments_enriched = list(parsed["attachments"])
    for i, att in enumerate(attachments_with_payloads):
        # Find matching attachment by sha256
        for j, orig in enumerate(attachments_enriched):
            if orig.get("sha256") == att["sha256"]:
                if i < len(att_vt_results) and att_vt_results[i]:
                    attachments_enriched[j]["virustotal"] = att_vt_results[i]
                if i < len(att_tf_results) and att_tf_results[i]:
                    attachments_enriched[j]["threatfox"] = att_tf_results[i]
                break

    # --- Phishing scoring (now with WHOIS + HTML) ---
    phishing = analyze_phishing(
        summary=summary,
        urls=parsed["urls"],
        domain_info=domain_info,
        body_text=parsed["body_text"],
        whois_info=whois_info if isinstance(whois_info, dict) else None,
        html_analysis=html_body,
        attachment_flags=all_attachment_flags,
    )

    # Boost phishing score with lookalike findings
    if lookalike:
        for field, result in lookalike.items():
            for finding in result.get("findings", []):
                if finding["severity"] == "CRITICAL":
                    phishing["score"] = min(phishing["score"] + 40, 200)
                    phishing["indicators"].insert(0, f"LOOKALIKE DOMAIN [{field}]: {finding['detail']}")
                elif finding["severity"] == "HIGH":
                    phishing["score"] = min(phishing["score"] + 25, 200)
                    phishing["indicators"].insert(0, f"Lookalike domain [{field}]: {finding['detail']}")
        s = phishing["score"]
        phishing["level"] = "CRITICAL" if s >= 70 else "HIGH" if s >= 45 else "MEDIUM" if s >= 20 else "LOW"

    # Boost if sender domain found in ThreatFox
    if isinstance(tf_domain_result, dict) and tf_domain_result.get("found"):
        phishing["score"] = min(phishing["score"] + 50, 200)
        malware = tf_domain_result.get("malware", "unknown")
        phishing["indicators"].insert(0, f"THREATFOX: Sender domain known IOC — malware: {malware}")
        phishing["level"] = "CRITICAL"

    return {
        "status": "success",
        "filename": file.filename,
        "summary": summary,
        "routing_hops": parsed["routing_hops"],
        "header_anomalies": parsed.get("header_anomalies", []),
        "all_ips": parsed["all_ips"],
        "ip_reputation": ip_reputation,
        "authentication": {
            "headers": auth_headers,
            "dns": domain_info,
        },
        "whois": whois_info if isinstance(whois_info, dict) else {},
        "sender_domain_threatfox": tf_domain_result if isinstance(tf_domain_result, dict) else {},
        "lookalike_domains": lookalike,
        "phishing": phishing,
        "urls": url_results,
        "html_body_analysis": html_body,
        "attachments": attachments_enriched,
        "body_preview": parsed["body_text"][:1000],
        "raw_headers": parsed["raw_headers"],
    }
