"""
RTF (Rich Text Format) threat analysis.
RTF is widely used to deliver OLE-embedded exploits (Equation Editor, DDE, NTLM leaks).
"""
import re


RTF_MAGIC = (b"{\\rtf", b"{\\ rtf")

# (pattern, description, score)
RTF_THREAT_PATTERNS: list[tuple[bytes, str, int]] = [
    (rb"equation\.3", "Equation Editor 3.0 object — CVE-2017-11882 / CVE-2018-0802 (CRITICAL RCE)", 90),
    (rb"\\objocx", "OCX/ActiveX object in RTF — code execution risk", 55),
    (rb"\\objautlink", "Auto-link OLE object", 40),
    (rb"\\object\\s*\\objauto", "Auto-executing OLE object", 65),
    (rb"\\\*\\template\s+https?://", "Remote template injection (HTTP)", 80),
    (rb"\\\*\\template\s+\\\\", "UNC template injection — NTLM credential leak / SMB relay", 80),
    (rb"\\field.*\\fldinst.*DDE", "DDE field instruction — Dynamic Data Exchange code execution", 75),
    (rb"\\field.*\\fldinst.*INCLUDE", "INCLUDE field — external file inclusion", 45),
    (rb"\\field.*\\fldinst.*EMBED", "EMBED field — OLE object embedding", 35),
    (rb"\\objdata", "OLE object raw data in RTF", 30),
    (rb"\\objclass", "OLE class name — possible exploit class", 35),
    (rb"\\object\\s*\\objemb", "Embedded OLE object (\\objemb)", 30),
    (rb"\\object\\s*\\objhtml", "HTML OLE object — script execution risk", 50),
    (rb"/JavaScript|/JS\b", "JavaScript reference inside RTF", 60),
    (rb"shellcode|NOP sled|\x90{10,}", "Shellcode pattern in RTF body", 70),
    (rb"\\bin[0-9]+", "\\bin keyword — binary data blob in RTF (common exploit payload delivery)", 40),
    (rb"CVE-\d{4}-\d{4,}", "Explicit CVE reference embedded in file", 25),
]

# Obfuscation indicators
HEAVY_HEX_THRESHOLD = 500     # number of \\' hex escapes considered obfuscation
UNICODE_ESC_THRESHOLD = 200   # number of \\u Unicode escapes


def analyze_rtf(data: bytes) -> dict:
    result: dict = {
        "is_rtf": False,
        "version": "",
        "ole_object_count": 0,
        "exploit_families": [],
        "embedded_urls": [],
        "indicators": [],
        "risk_score": 0,
    }

    # Validate RTF magic
    if not (data[:5] in RTF_MAGIC or data[:4] == b"{\\rt"):
        return result

    result["is_rtf"] = True

    # Version
    v_match = re.search(rb"\\rtf(\d+)", data[:30])
    result["version"] = v_match.group(1).decode() if v_match else "unknown"

    indicators: list[str] = []
    risk_score = 0
    data_lower = data.lower()

    # Threat patterns
    for pattern, description, score in RTF_THREAT_PATTERNS:
        if re.search(pattern, data_lower, re.IGNORECASE | re.DOTALL):
            indicators.append(description)
            risk_score += score
            if b"equation" in pattern:
                if "Equation Editor RCE" not in result["exploit_families"]:
                    result["exploit_families"].append("Equation Editor RCE (CVE-2017-11882 / CVE-2018-0802)")
            elif b"dde" in pattern:
                if "DDE code execution" not in result["exploit_families"]:
                    result["exploit_families"].append("DDE code execution")
            elif b"template" in pattern:
                if "Remote template injection" not in result["exploit_families"]:
                    result["exploit_families"].append("Remote template injection / NTLM relay")

    # Count OLE objects
    ole_count = len(re.findall(rb"\\object", data_lower))
    result["ole_object_count"] = ole_count

    # Obfuscation: heavy hex escaping (\' sequences)
    hex_escape_count = len(re.findall(rb"\\'[0-9a-fA-F]{2}", data))
    if hex_escape_count > HEAVY_HEX_THRESHOLD:
        indicators.append(
            f"Heavy hex-encoding obfuscation: {hex_escape_count} \\' escape sequences "
            "(common in exploit document delivery)"
        )
        risk_score += 35

    # Obfuscation: Unicode escapes
    unicode_esc_count = len(re.findall(rb"\\u-?\d{3,5}", data))
    if unicode_esc_count > UNICODE_ESC_THRESHOLD:
        indicators.append(
            f"Heavy Unicode escape obfuscation: {unicode_esc_count} \\u sequences"
        )
        risk_score += 25

    # Null-byte padding / space insertion (anti-parser tricks)
    null_sequences = len(re.findall(rb"\x00{4,}", data))
    if null_sequences > 10:
        indicators.append(f"Null-byte padding sequences ({null_sequences}) — anti-parser evasion")
        risk_score += 15

    # Embedded URLs
    url_re = re.compile(rb"https?://[^\s\"'\\\x00\r\n\)>]{10,}", re.IGNORECASE)
    urls = list({u.decode("latin-1", errors="replace") for u in url_re.findall(data)})
    result["embedded_urls"] = urls[:20]
    if urls:
        ip_urls = [u for u in urls if re.match(r"https?://\d+\.\d+\.\d+\.\d+", u)]
        if ip_urls:
            indicators.append(f"Direct IP URL in RTF: {ip_urls[0][:80]}")
            risk_score += 30

    # \\pntext / \\listtext obfuscation (hiding content in list/paragraph formatting)
    list_obfus = re.findall(rb"\\pntext\s*\{[^}]{1,300}\}", data)
    if len(list_obfus) > 5:
        indicators.append(f"List/paragraph text obfuscation: {len(list_obfus)} \\pntext blocks")
        risk_score += 20

    result["indicators"] = indicators
    result["risk_score"] = min(risk_score, 100)
    return result
