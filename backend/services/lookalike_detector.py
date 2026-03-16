"""
Lookalike domain detection for email analysis.
Detects typosquatting, IDN homograph attacks, and brand impersonation.
"""
import re
import unicodedata


PROTECTED_DOMAINS = [
    "paypal.com", "apple.com", "microsoft.com", "google.com", "amazon.com",
    "facebook.com", "netflix.com", "instagram.com", "dropbox.com", "linkedin.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "citibank.com",
    "irs.gov", "gov.uk", "fedex.com", "dhl.com", "ups.com",
    "ebay.com", "twitter.com", "x.com", "github.com", "gitlab.com",
    "zoom.us", "office.com", "live.com", "outlook.com", "hotmail.com",
    "icloud.com", "me.com", "yahoo.com", "gmail.com",
    "coinbase.com", "binance.com", "kraken.com",
    "stripe.com", "square.com", "intuit.com",
    "docusign.com", "adobe.com", "salesforce.com",
]

# Homoglyph map — common character substitutions used in IDN attacks
HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["а", "á", "à", "â", "ä", "ã", "å", "ā", "ă", "ą", "@"],
    "b": ["ƅ", "ḃ", "ɓ"],
    "c": ["с", "ċ", "ć", "č"],
    "d": ["ď", "đ", "ḋ"],
    "e": ["е", "é", "è", "ê", "ë", "ē", "ĕ", "ę", "ě", "3"],
    "f": ["ƒ"],
    "g": ["ġ", "ĝ", "ğ", "ģ", "9"],
    "h": ["ĥ", "ħ"],
    "i": ["і", "ı", "í", "ì", "î", "ï", "ī", "ĭ", "į", "ĩ", "1", "l"],
    "j": ["ĵ"],
    "k": ["ķ"],
    "l": ["ĺ", "ļ", "ľ", "ŀ", "ł", "1", "i"],
    "m": ["ṁ", "ḿ"],
    "n": ["ń", "ņ", "ň", "ŋ"],
    "o": ["о", "ο", "ö", "ó", "ò", "ô", "õ", "ø", "ō", "ŏ", "ő", "0"],
    "p": ["р", "ƥ"],
    "q": ["ԛ"],
    "r": ["ŕ", "ŗ", "ř"],
    "s": ["ѕ", "ś", "ŝ", "ş", "š", "5"],
    "t": ["ţ", "ť", "ŧ"],
    "u": ["υ", "ú", "ù", "û", "ü", "ū", "ŭ", "ů", "ű", "ų"],
    "v": ["ν", "ṽ"],
    "w": ["ŵ", "ẁ", "ẃ", "ẅ"],
    "x": ["×"],
    "y": ["у", "ý", "ÿ", "ŷ"],
    "z": ["ź", "ż", "ž", "2"],
}

# Reverse map: unicode char → ascii equivalent
_REVERSE_HOMOGLYPHS: dict[str, str] = {}
for ascii_char, variants in HOMOGLYPHS.items():
    for v in variants:
        _REVERSE_HOMOGLYPHS[v] = ascii_char


def normalize_domain(domain: str) -> str:
    """Convert a domain with homoglyphs to its ASCII equivalent."""
    result = []
    for char in domain.lower():
        result.append(_REVERSE_HOMOGLYPHS.get(char, char))
    return "".join(result)


def levenshtein(s1: str, s2: str) -> int:
    """Compute edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def check_lookalike(domain: str) -> dict:
    """Check if a domain is a lookalike of a protected brand domain."""
    domain = domain.lower().strip()
    findings = []

    # Normalize homoglyphs
    normalized = normalize_domain(domain)
    if normalized != domain:
        findings.append({
            "type": "homoglyph",
            "detail": f"IDN homoglyph attack: '{domain}' normalizes to '{normalized}'",
            "severity": "CRITICAL",
        })
        domain = normalized  # use normalized for further checks

    # Strip subdomains for comparison (keep last 2 parts)
    parts = domain.split(".")
    domain_root = ".".join(parts[-2:]) if len(parts) >= 2 else domain

    for protected in PROTECTED_DOMAINS:
        protected_root = ".".join(protected.split(".")[-2:])

        if domain_root == protected_root:
            continue  # exact match = legitimate

        protected_name = protected_root.split(".")[0]
        domain_name = domain_root.split(".")[0]

        # 1. Levenshtein distance on domain name (without TLD)
        dist = levenshtein(domain_name, protected_name)
        if 0 < dist <= 2 and len(protected_name) > 3:
            findings.append({
                "type": "typosquatting",
                "detail": f"'{domain}' is {dist} edit(s) away from '{protected}' (typosquatting)",
                "severity": "HIGH" if dist == 1 else "MEDIUM",
                "target": protected,
            })

        # 2. Protected name is substring of suspicious domain (e.g. paypal-secure.com)
        if protected_name in domain_name and domain_name != protected_name:
            findings.append({
                "type": "brand_in_domain",
                "detail": f"'{domain}' contains brand name '{protected_name}' from '{protected}'",
                "severity": "HIGH",
                "target": protected,
            })

        # 3. Domain contains protected name with extra chars (paypa1.com)
        if len(domain_name) == len(protected_name):
            diffs = sum(1 for a, b in zip(domain_name, protected_name) if a != b)
            if diffs == 1:
                findings.append({
                    "type": "character_substitution",
                    "detail": f"'{domain}' has 1 character substitution vs '{protected}' — character swap attack",
                    "severity": "CRITICAL",
                    "target": protected,
                })

    # Deduplicate by type+target
    seen = set()
    unique = []
    for f in findings:
        key = (f["type"], f.get("target", ""), f["detail"][:40])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return {
        "domain": domain,
        "is_suspicious": bool(unique),
        "findings": unique[:10],
    }


def analyze_email_domains(summary: dict) -> dict:
    """Run lookalike checks on all domains in an email."""
    results = {}
    to_check = {}

    for field in ("from", "reply_to", "x_originating_ip"):
        value = summary.get(field, "")
        if value:
            m = re.search(r"@([\w.\-]+)", value)
            if m:
                to_check[field] = m.group(1).lower()

    for field, domain in to_check.items():
        result = check_lookalike(domain)
        if result["is_suspicious"]:
            results[field] = result

    return results
