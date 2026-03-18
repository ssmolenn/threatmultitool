"""
Email HTML body threat analysis.
Detects hidden content, credential harvesting, obfuscation, and exfiltration vectors.
"""
import re
from bs4 import BeautifulSoup


SUSPICIOUS_META_TAGS = {"refresh", "http-equiv"}

CREDENTIAL_INPUT_TYPES = {"password", "text", "email", "tel", "number"}

EXFIL_DOMAINS_RE = re.compile(
    r"(bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly|short\.link|rebrand\.ly)",
    re.IGNORECASE,
)


def analyze_html_body(html: str) -> dict:
    if not html or len(html.strip()) < 10:
        return {"found": False}

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return {"found": True, "parse_error": True, "indicators": [], "risk_score": 0}

    indicators: list[str] = []
    risk_score = 0

    # --- Forms and credential harvesting ---
    forms = soup.find_all("form")
    external_form_actions = []
    for form in forms:
        action = form.get("action", "")
        if action and re.match(r"https?://", action, re.IGNORECASE):
            external_form_actions.append(action[:150])
            risk_score += 35
    if external_form_actions:
        indicators.append(
            f"Form(s) submit to external domain: {external_form_actions[0]}"
            + (f" (+{len(external_form_actions)-1} more)" if len(external_form_actions) > 1 else "")
        )

    # Password / credential input fields in email body
    password_inputs = soup.find_all("input", {"type": re.compile(r"password", re.IGNORECASE)})
    text_inputs = soup.find_all("input", {"type": re.compile(r"text|email|tel", re.IGNORECASE)})
    if password_inputs:
        indicators.append(f"Password input field(s) in email body: {len(password_inputs)} (credential harvesting)")
        risk_score += 50
    elif text_inputs and forms:
        indicators.append(f"Input form with {len(text_inputs)} text field(s) — potential credential harvesting")
        risk_score += 20

    # --- Hidden content (filter evasion) ---
    hidden_display = soup.find_all(style=re.compile(r"display\s*:\s*none", re.IGNORECASE))
    hidden_visibility = soup.find_all(style=re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE))
    hidden_opacity = soup.find_all(style=re.compile(r"opacity\s*:\s*0(?:\.0+)?[;\s]", re.IGNORECASE))
    total_hidden = len(hidden_display) + len(hidden_visibility) + len(hidden_opacity)
    if total_hidden > 0:
        indicators.append(f"Hidden elements (CSS): {total_hidden} — common spam filter evasion")
        risk_score += 15

    # Zero/tiny font size
    tiny_font = soup.find_all(style=re.compile(r"font-size\s*:\s*0|font-size\s*:\s*[01]px", re.IGNORECASE))
    if tiny_font:
        indicators.append(f"Zero/1px font-size elements: {len(tiny_font)} (filter evasion)")
        risk_score += 20

    # White text on white background
    white_text = soup.find_all(style=re.compile(r"color\s*:\s*(white|#fff(?:fff)?)\b", re.IGNORECASE))
    if white_text:
        indicators.append(f"White-on-white text: {len(white_text)} element(s) (invisible content)")
        risk_score += 15

    # --- iframes ---
    iframes = soup.find_all("iframe")
    for iframe in iframes:
        src = iframe.get("src", "")
        risk_score += 25
        indicators.append(f"Iframe in email body: {src[:100] if src else '(no src)'}")

    # --- Scripts ---
    scripts = soup.find_all("script")
    for script in scripts:
        src = script.get("src", "")
        content = script.string or ""
        if src:
            indicators.append(f"External script: {src[:100]}")
            risk_score += 35
        if re.search(r"eval\s*\(|unescape\s*\(|String\.fromCharCode", content, re.IGNORECASE):
            indicators.append("Obfuscated JavaScript in email body (eval/unescape/fromCharCode)")
            risk_score += 45

    # --- data: URIs ---
    data_uris = re.findall(r"data:[^;\"'\s]+;base64,[A-Za-z0-9+/=]{20,}", html)
    if data_uris:
        indicators.append(f"data: URI(s) with base64 payload: {len(data_uris)}")
        risk_score += 25

    # --- Meta refresh redirect ---
    meta_refresh = soup.find_all("meta", {"http-equiv": re.compile(r"refresh", re.IGNORECASE)})
    for meta in meta_refresh:
        content = meta.get("content", "")
        url_m = re.search(r"url=(.+)", content, re.IGNORECASE)
        if url_m:
            indicators.append(f"Meta refresh redirect: {url_m.group(1)[:100]}")
            risk_score += 30

    # --- Unicode control characters ---
    rtl_override = "\u202e"
    zero_width = ["\u200b", "\u200c", "\u200d", "\ufeff", "\u00ad"]
    if rtl_override in html:
        indicators.append("RTL override character (U+202E) — filename/extension spoofing trick")
        risk_score += 30
    zwc_count = sum(html.count(c) for c in zero_width)
    if zwc_count > 5:
        indicators.append(f"Zero-width/soft-hyphen characters: {zwc_count} (text obfuscation)")
        risk_score += 20

    # --- Tracking pixels ---
    imgs = soup.find_all("img")
    tracking_pixels = []
    for img in imgs:
        w = img.get("width", "")
        h = img.get("height", "")
        src = img.get("src", "")
        if (str(w) in ("1", "0") or str(h) in ("1", "0")) and re.match(r"https?://", src):
            tracking_pixels.append(src[:100])
    if tracking_pixels:
        indicators.append(f"Tracking pixel(s): {len(tracking_pixels)} (read receipt / IP tracking)")
        risk_score += 10

    # --- External links analysis ---
    links = soup.find_all("a", href=True)
    external_hrefs = []
    shortener_links = []
    ip_links = []
    punycode_links = []
    for a in links:
        href = a.get("href", "")
        if re.match(r"https?://", href, re.IGNORECASE):
            external_hrefs.append(href)
            if EXFIL_DOMAINS_RE.search(href):
                shortener_links.append(href[:100])
            if re.match(r"https?://\d+\.\d+\.\d+\.\d+", href):
                ip_links.append(href[:100])
            if "xn--" in href:
                punycode_links.append(href[:100])

    if shortener_links:
        indicators.append(f"URL shortener link(s): {len(shortener_links)}")
        risk_score += 20
    if ip_links:
        indicators.append(f"Direct IP address URL(s) in body: {', '.join(ip_links[:2])}")
        risk_score += 30
    if punycode_links:
        indicators.append(f"Punycode (IDN) URL(s): {punycode_links[0][:80]} — possible homograph attack")
        risk_score += 25

    # Mismatch between link text and href (e.g. shows paypal.com but links to evil.com)
    spoof_links = []
    for a in links:
        href = a.get("href", "")
        text = a.get_text(strip=True)
        if (
            re.match(r"https?://", href, re.IGNORECASE)
            and re.match(r"https?://", text, re.IGNORECASE)
        ):
            href_domain = re.match(r"https?://([^/\s]+)", href)
            text_domain = re.match(r"https?://([^/\s]+)", text)
            if href_domain and text_domain and href_domain.group(1) != text_domain.group(1):
                spoof_links.append(f"Shown: {text_domain.group(1)} → Actual: {href_domain.group(1)}")
    if spoof_links:
        indicators.append(f"Deceptive link text/URL mismatch: {spoof_links[0]}")
        risk_score += 40

    # --- Embedded objects ---
    objects = soup.find_all(["object", "embed", "applet"])
    if objects:
        indicators.append(f"Embedded object/applet in HTML: {len(objects)} (potential code execution)")
        risk_score += 40

    return {
        "found": True,
        "external_link_count": len(external_hrefs),
        "external_links": [h[:150] for h in external_hrefs[:30]],
        "form_count": len(forms),
        "script_count": len(scripts),
        "iframe_count": len(iframes),
        "tracking_pixels": tracking_pixels[:5],
        "indicators": indicators,
        "risk_score": min(risk_score, 100),
    }
