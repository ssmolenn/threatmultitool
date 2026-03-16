import asyncio
from fastapi import APIRouter, UploadFile, File, HTTPException

from services.email_parser import parse_eml
from services.domain_analyzer import analyze_domain
from services.phishing_detector import analyze_phishing
from services.ip_analyzer import analyze_ips
from services.lookalike_detector import analyze_email_domains
from integrations.urlhaus import lookup_url as urlhaus_url
from config import settings

router = APIRouter(prefix="/api/email", tags=["email"])

MAX_BYTES = settings.max_file_size_mb * 1024 * 1024


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

    # Domain analysis (DNS lookups)
    domain_info = analyze_domain(summary["from"], auth_headers.get("dkim_signature", ""))

    # Lookalike domain detection
    lookalike = analyze_email_domains(summary)

    # Phishing heuristics
    phishing = analyze_phishing(
        summary=summary,
        urls=parsed["urls"],
        domain_info=domain_info,
        body_text=parsed["body_text"],
    )

    # Boost phishing score if lookalike domains detected
    if lookalike:
        for field, result in lookalike.items():
            for finding in result.get("findings", []):
                if finding["severity"] == "CRITICAL":
                    phishing["score"] = min(phishing["score"] + 40, 200)
                    phishing["indicators"].insert(0, f"LOOKALIKE DOMAIN [{field}]: {finding['detail']}")
                elif finding["severity"] == "HIGH":
                    phishing["score"] = min(phishing["score"] + 25, 200)
                    phishing["indicators"].insert(0, f"Lookalike domain [{field}]: {finding['detail']}")
        # Recalculate level
        s = phishing["score"]
        phishing["level"] = "CRITICAL" if s >= 70 else "HIGH" if s >= 45 else "MEDIUM" if s >= 20 else "LOW"

    # Parallel async tasks: IP reputation + URLhaus URL checks
    url_tasks = [urlhaus_url(u) for u in parsed["urls"][:10]]  # cap to 10 URLs
    ip_task = analyze_ips(parsed["all_ips"][:10]) if parsed["all_ips"] else asyncio.sleep(0)

    results = await asyncio.gather(ip_task, *url_tasks, return_exceptions=True)

    ip_reputation = results[0] if not isinstance(results[0], Exception) else {}
    url_results = []
    for i, url in enumerate(parsed["urls"][:10]):
        raw = results[i + 1]
        entry = {"url": url}
        if isinstance(raw, dict):
            entry["urlhaus"] = raw
        url_results.append(entry)

    # Append remaining URLs without lookup
    for url in parsed["urls"][10:50]:
        url_results.append({"url": url, "urlhaus": None})

    return {
        "status": "success",
        "filename": file.filename,
        "summary": summary,
        "routing_hops": parsed["routing_hops"],
        "all_ips": parsed["all_ips"],
        "ip_reputation": ip_reputation,
        "authentication": {
            "headers": auth_headers,
            "dns": domain_info,
        },
        "lookalike_domains": lookalike,
        "phishing": phishing,
        "urls": url_results,
        "attachments": parsed["attachments"],
        "body_preview": parsed["body_text"][:1000],
        "raw_headers": parsed["raw_headers"],
    }
