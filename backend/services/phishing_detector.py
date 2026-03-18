import re
from typing import Any


URGENCY_KEYWORDS = [
    "urgent", "immediately", "action required", "verify", "suspended",
    "limited", "expire", "unauthorized", "compromised", "confirm",
    "update your", "click here", "reset password", "account locked",
    "unusual activity", "security alert", "account will be", "verify your",
    "unusual sign-in", "suspicious activity", "your account has been",
    "invoice attached", "payment required", "overdue", "final notice",
    "last reminder", "your package", "track your shipment", "prize",
    "winner", "congratulations", "claim your",
]

BRAND_SPOOF_DOMAINS = {
    "paypal": "paypal.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
    "netflix": "netflix.com",
    "instagram": "instagram.com",
    "dropbox": "dropbox.com",
    "linkedin": "linkedin.com",
    "bankofamerica": "bankofamerica.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "irs": "irs.gov",
    "fedex": "fedex.com",
    "dhl": "dhl.com",
    "ups": "ups.com",
    "docusign": "docusign.com",
    "adobe": "adobe.com",
    "zoom": "zoom.us",
    "office365": "office.com",
    "coinbase": "coinbase.com",
    "binance": "binance.com",
    "stripe": "stripe.com",
    "salesforce": "salesforce.com",
    "intuit": "intuit.com",
    "turbotax": "turbotax.intuit.com",
    "citibank": "citibank.com",
    "hsbc": "hsbc.com",
    "barclays": "barclays.com",
    "halifax": "halifax.co.uk",
    "lloyds": "lloyds.com",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "short.link", "rebrand.ly", "tiny.cc",
    "cutt.ly", "shorturl.at", "rb.gy", "bl.ink",
}

# High-risk TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".gq", ".ml", ".cf", ".ga", ".tk",
    ".buzz", ".work", ".live", ".online", ".site", ".tech", ".fun",
    ".store", ".space", ".website", ".uno", ".rest", ".vip", ".host",
    ".pw", ".cc", ".su", ".ru",
}

# Suspicious sending infrastructure patterns
FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "mail.com", "yandex.com", "tutanota.com",
    "guerrillamail.com", "tempmail.com", "throwam.com", "mailinator.com",
    "sharklasers.com", "guerrillamailblock.com", "grr.la", "guerrillamail.info",
    "spam4.me", "trashmail.com", "dispostable.com",
}

DISPOSABLE_EMAIL_DOMAINS = {
    "guerrillamail.com", "tempmail.com", "throwam.com", "mailinator.com",
    "sharklasers.com", "guerrillamailblock.com", "grr.la", "guerrillamail.info",
    "spam4.me", "trashmail.com", "dispostable.com", "yopmail.com",
    "fakeinbox.com", "maildrop.cc", "getairmail.com",
}


def _extract_domain_from_email(address: str) -> str:
    match = re.search(r"@([\w.\-]+)", address)
    return match.group(1).lower() if match else ""


def _extract_display_name(address: str) -> str:
    match = re.match(r'^"?([^"<]+)"?\s*<', address)
    return match.group(1).strip().lower() if match else ""


def _extract_url_domain(url: str) -> str:
    match = re.match(r"https?://([^/?\s]+)", url, re.IGNORECASE)
    return match.group(1).lower() if match else ""


def _get_tld(domain: str) -> str:
    parts = domain.rsplit(".", 1)
    return "." + parts[-1] if len(parts) > 1 else ""


def analyze_phishing(
    summary: dict[str, Any],
    urls: list[str],
    domain_info: dict[str, Any],
    body_text: str,
    whois_info: dict | None = None,
    html_analysis: dict | None = None,
    attachment_flags: list[str] | None = None,
) -> dict:
    indicators = []
    score = 0

    from_addr   = summary.get("from", "")
    reply_to    = summary.get("reply_to", "")
    subject     = summary.get("subject", "").lower()
    return_path = summary.get("return_path", "")

    from_domain    = _extract_domain_from_email(from_addr)
    reply_to_domain = _extract_domain_from_email(reply_to)
    return_path_domain = _extract_domain_from_email(return_path)
    display_name   = _extract_display_name(from_addr)

    # --- Reply-To mismatch ---
    if reply_to and reply_to_domain and reply_to_domain != from_domain:
        indicators.append(f"Reply-To domain ({reply_to_domain}) differs from From domain ({from_domain})")
        score += 30

    # --- Return-Path / From mismatch ---
    if return_path and return_path_domain and return_path_domain != from_domain:
        indicators.append(f"Return-Path domain ({return_path_domain}) ≠ From domain ({from_domain})")
        score += 25

    # --- Brand spoofing in display name ---
    for brand, real_domain in BRAND_SPOOF_DOMAINS.items():
        if brand in display_name and from_domain != real_domain and brand not in from_domain:
            indicators.append(
                f"Display name contains '{brand}' but sender domain is '{from_domain}' (not {real_domain})"
            )
            score += 35
            break

    # --- Brand keyword in subject ---
    subject_raw = summary.get("subject", "")
    for brand in BRAND_SPOOF_DOMAINS:
        if brand in subject_raw.lower() and from_domain not in BRAND_SPOOF_DOMAINS.get(brand, ""):
            indicators.append(f"Subject references brand '{brand}' but sender is not from {BRAND_SPOOF_DOMAINS[brand]}")
            score += 20
            break

    # --- Urgency keywords in subject ---
    urgency_hits = [kw for kw in URGENCY_KEYWORDS if kw in subject]
    if urgency_hits:
        indicators.append(f"Urgency keywords in subject: {', '.join(urgency_hits[:3])}")
        score += min(len(urgency_hits) * 8, 25)

    # --- Urgency keywords in body ---
    body_lower = body_text.lower()
    body_urgency = [kw for kw in URGENCY_KEYWORDS if kw in body_lower]
    if len(body_urgency) >= 3:
        indicators.append(f"Multiple urgency keywords in body ({len(body_urgency)} found)")
        score += 15

    # --- URL shorteners ---
    shortener_urls = [u for u in urls if any(s in _extract_url_domain(u) for s in URL_SHORTENERS)]
    if shortener_urls:
        indicators.append(f"URL shortener(s): {len(shortener_urls)} link(s)")
        score += 20

    # --- Foreign domain URLs ---
    foreign_urls = []
    for url in urls:
        url_domain = _extract_url_domain(url)
        if url_domain and from_domain and from_domain not in url_domain:
            foreign_urls.append(url_domain)
    if len(foreign_urls) > 2:
        indicators.append(f"Links point to {len(set(foreign_urls))} domain(s) different from sender")
        score += 15

    # --- Direct IP URLs ---
    ip_urls = [u for u in urls if re.match(r"https?://\d+\.\d+\.\d+\.\d+", u)]
    if ip_urls:
        indicators.append(f"Direct IP-address URL(s): {len(ip_urls)}")
        score += 25

    # --- Punycode / IDN domains in URLs ---
    punycode_urls = [u for u in urls if "xn--" in u.lower()]
    if punycode_urls:
        indicators.append(f"Punycode (IDN) URL(s) — possible homograph attack: {punycode_urls[0][:80]}")
        score += 30

    # --- Suspicious TLD on sender domain ---
    sender_tld = _get_tld(from_domain)
    if sender_tld in SUSPICIOUS_TLDS:
        indicators.append(f"Sender domain uses high-risk TLD: {sender_tld}")
        score += 20

    # --- Disposable / free email provider ---
    if from_domain in DISPOSABLE_EMAIL_DOMAINS:
        indicators.append(f"Sender uses disposable email service: {from_domain}")
        score += 40
    elif from_domain in FREE_EMAIL_DOMAINS:
        indicators.append(f"Sender uses free email provider: {from_domain} (unusual for legitimate business)")
        score += 10

    # --- SPF checks ---
    spf = domain_info.get("spf", {})
    if spf.get("policy") in ("error", "none") or not spf.get("found"):
        indicators.append("No SPF record found for sender domain")
        score += 15
    elif spf.get("policy") == "allow_all (DANGEROUS)":
        indicators.append("SPF record allows ALL senders (+all) — highly suspicious")
        score += 30

    # --- DMARC checks ---
    dmarc = domain_info.get("dmarc", {})
    if not dmarc.get("found"):
        indicators.append("No DMARC record for sender domain")
        score += 10
    elif dmarc.get("policy") == "none":
        indicators.append("DMARC policy = 'none' (monitoring only, no enforcement)")
        score += 5
    if dmarc.get("pct") is not None and dmarc.get("pct", 100) < 100:
        pct = dmarc["pct"]
        indicators.append(f"DMARC applies to only {pct}% of emails (partial enforcement)")
        score += 5

    # --- DKIM missing ---
    dkim = domain_info.get("dkim", {})
    if not dkim.get("found"):
        indicators.append("DKIM signature not found or could not be verified")
        score += 10

    # --- Missing MX records (domain not set up for legitimate mail) ---
    if not domain_info.get("mx"):
        indicators.append("No MX records for sender domain — domain may not be used for legitimate email")
        score += 15

    # --- BIMI present (positive signal — reduce score slightly) ---
    bimi = domain_info.get("bimi", {})
    if bimi and bimi.get("found"):
        score = max(0, score - 10)  # BIMI = legitimate sender signal

    # --- WHOIS domain age ---
    if whois_info and not whois_info.get("error"):
        age_days = whois_info.get("age_days")
        if age_days is not None:
            if age_days < 7:
                indicators.append(f"Domain registered {age_days} day(s) ago — extremely new, very high phishing risk")
                score += 50
            elif age_days < 30:
                indicators.append(f"Domain registered {age_days} days ago — very new domain")
                score += 35
            elif age_days < 90:
                indicators.append(f"Domain registered {age_days} days ago — recently registered")
                score += 20
            elif age_days < 180:
                indicators.append(f"Domain registered {age_days} days ago — relatively new")
                score += 10

    # --- HTML body analysis ---
    if html_analysis and html_analysis.get("found"):
        html_score = html_analysis.get("risk_score", 0)
        if html_score >= 30:
            score += min(html_score // 2, 40)
        for ind in html_analysis.get("indicators", []):
            indicators.append(f"HTML: {ind}")

    # --- Dangerous attachments ---
    if attachment_flags:
        for flag in attachment_flags:
            if "executable" in flag.lower() or "dangerous" in flag.lower() or "PE" in flag:
                indicators.append(f"Attachment: {flag}")
                score += 20
                break

    # --- X-Originating-IP header (informational) ---
    x_orig_ip = summary.get("x_originating_ip", "")
    if x_orig_ip:
        pass  # informational only

    # --- Mismatched subject encoding (filter evasion) ---
    raw_subject = summary.get("subject", "")
    if re.search(r"=\?[a-zA-Z0-9\-]+\?[BbQq]\?", raw_subject):
        if len([c for c in raw_subject if ord(c) > 127]) > 5:
            indicators.append("Subject uses unusual encoding (possible filter evasion)")
            score += 10

    # --- Determine risk level ---
    if score >= 70:
        level = "CRITICAL"
    elif score >= 45:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": min(score, 200),
        "level": level,
        "indicators": indicators,
    }
