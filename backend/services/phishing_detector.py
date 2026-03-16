import re
from typing import Any


URGENCY_KEYWORDS = [
    "urgent", "immediately", "action required", "verify", "suspended",
    "limited", "expire", "unauthorized", "compromised", "confirm",
    "update your", "click here", "reset password", "account locked",
    "unusual activity", "security alert",
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
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "short.link", "rebrand.ly",
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


def analyze_phishing(
    summary: dict[str, Any],
    urls: list[str],
    domain_info: dict[str, Any],
    body_text: str,
) -> dict:
    indicators = []
    score = 0

    from_addr = summary.get("from", "")
    reply_to = summary.get("reply_to", "")
    subject = summary.get("subject", "").lower()

    from_domain = _extract_domain_from_email(from_addr)
    reply_to_domain = _extract_domain_from_email(reply_to)
    display_name = _extract_display_name(from_addr)

    # Reply-To mismatch
    if reply_to and reply_to_domain and reply_to_domain != from_domain:
        indicators.append(f"Reply-To domain ({reply_to_domain}) differs from From domain ({from_domain})")
        score += 30

    # Brand spoofing in display name
    for brand, real_domain in BRAND_SPOOF_DOMAINS.items():
        if brand in display_name and from_domain != real_domain and brand not in from_domain:
            indicators.append(f"Display name contains '{brand}' but sender domain is '{from_domain}' (not {real_domain})")
            score += 35
            break

    # Urgency keywords in subject
    urgency_hits = [kw for kw in URGENCY_KEYWORDS if kw in subject]
    if urgency_hits:
        indicators.append(f"Urgency keywords in subject: {', '.join(urgency_hits[:3])}")
        score += min(len(urgency_hits) * 8, 25)

    # Urgency keywords in body
    body_lower = body_text.lower()
    body_urgency = [kw for kw in URGENCY_KEYWORDS if kw in body_lower]
    if len(body_urgency) >= 3:
        indicators.append(f"Multiple urgency keywords in body ({len(body_urgency)} found)")
        score += 15

    # URL shorteners
    shortener_urls = [u for u in urls if any(s in _extract_url_domain(u) for s in URL_SHORTENERS)]
    if shortener_urls:
        indicators.append(f"URL shortener(s) detected: {len(shortener_urls)} link(s)")
        score += 20

    # URLs from different domains than sender
    foreign_urls = []
    for url in urls:
        url_domain = _extract_url_domain(url)
        if url_domain and from_domain and from_domain not in url_domain:
            foreign_urls.append(url_domain)
    if len(foreign_urls) > 2:
        indicators.append(f"Links point to {len(set(foreign_urls))} different domains than sender")
        score += 15

    # IP-based URLs (no domain name)
    ip_urls = [u for u in urls if re.match(r"https?://\d+\.\d+\.\d+\.\d+", u)]
    if ip_urls:
        indicators.append(f"Direct IP-address URL(s) detected: {len(ip_urls)}")
        score += 25

    # SPF failure
    spf = domain_info.get("spf", {})
    if spf.get("policy") in ("error", "none") or not spf.get("found"):
        indicators.append("No SPF record found for sender domain")
        score += 15
    elif spf.get("policy") == "allow_all (DANGEROUS)":
        indicators.append("SPF record allows ALL senders (+all) — highly suspicious")
        score += 30

    # DMARC missing
    dmarc = domain_info.get("dmarc", {})
    if not dmarc.get("found"):
        indicators.append("No DMARC record found for sender domain")
        score += 10
    elif dmarc.get("policy") == "none":
        indicators.append("DMARC policy is 'none' (monitoring only, no enforcement)")
        score += 5

    # Mismatched from domain vs X-Originating-IP
    x_orig_ip = summary.get("x_originating_ip", "")
    if x_orig_ip and from_domain:
        indicators_extra = f"X-Originating-IP header present: {x_orig_ip}"
        # just informational, no score addition

    # Determine risk level
    if score >= 70:
        level = "CRITICAL"
    elif score >= 45:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
        "indicators": indicators,
    }
