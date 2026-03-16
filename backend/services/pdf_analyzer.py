"""
PDF-specific threat analysis.
Inspects structure, JavaScript, actions, embedded files, and obfuscation
without executing the file.
"""
import re
import zlib
import struct
from typing import Any


# --- Regex patterns for PDF object parsing ---
OBJ_RE       = re.compile(rb"\d+\s+\d+\s+obj")
JS_RE        = re.compile(rb"/JS\s*[(<]|/JavaScript", re.IGNORECASE)
ACTION_RE    = re.compile(rb"/(OpenAction|AA|AcroForm|Names)\s*[<\[/]", re.IGNORECASE)
LAUNCH_RE    = re.compile(rb"/Launch\s*<<", re.IGNORECASE)
URI_RE       = re.compile(rb"/URI\s*\(([^)]{4,})\)", re.IGNORECASE)
EMBED_RE     = re.compile(rb"/EmbeddedFile|/Filespec|/EmbeddedFiles", re.IGNORECASE)
STREAM_RE    = re.compile(rb"stream\r?\n(.*?)endstream", re.DOTALL)
FILTER_RE    = re.compile(rb"/Filter\s*(/\w+|\[.*?\])", re.IGNORECASE)
ENCRYPT_RE   = re.compile(rb"/Encrypt\s+\d+\s+\d+\s+R", re.IGNORECASE)
ACROFORM_RE  = re.compile(rb"/AcroForm", re.IGNORECASE)
SUBMITFORM_RE= re.compile(rb"/SubmitForm", re.IGNORECASE)
URL_IN_JS_RE = re.compile(rb"https?://[^\s\"'\\)>]{8,}", re.IGNORECASE)
OBJ_STREAM_RE= re.compile(rb"/ObjStm", re.IGNORECASE)  # object streams hide objects
XREF_STREAM_RE = re.compile(rb"/XRef", re.IGNORECASE)

# Suspicious JavaScript patterns inside PDFs
JS_THREAT_PATTERNS = [
    (rb"eval\s*\(", "eval() — dynamic code execution"),
    (rb"unescape\s*\(", "unescape() — string deobfuscation"),
    (rb"String\.fromCharCode", "fromCharCode — character code obfuscation"),
    (rb"app\.launchURL\s*\(", "app.launchURL() — can open/execute external resource"),
    (rb"this\.submitForm\s*\(", "submitForm() — data exfiltration via form submission"),
    (rb"util\.printf\s*\(", "util.printf() — used in format-string heap spray exploits"),
    (rb"getAnnots\s*\(|getPageNthWord", "annotation/word enumeration — CVE heap spray pattern"),
    (rb"Collab\.collectEmailInfo\s*\(", "Collab.collectEmailInfo() — info leak exploit (CVE-2007-0044)"),
    (rb"media\.newPlayer\s*\(", "media.newPlayer() — media exploit"),
    (rb"spell\.customDictionaryOpen\s*\(", "spell.customDictionaryOpen() — path traversal exploit"),
    (rb"app\.openDoc\s*\(", "app.openDoc() — can open external documents"),
    (rb"shellcode|NOP sled|\x90{10,}", "Shellcode NOP sled pattern"),
    (rb"CVE-\d{4}-\d{4,}", "Explicit CVE reference found in PDF"),
    (rb"\\u00[0-9a-fA-F]{2}", "Unicode escape sequences — obfuscation"),
    (rb"(%[0-9a-fA-F]{2}){10,}", "Percent-encoded obfuscation (10+ consecutive)"),
]

SUSPICIOUS_KEYWORDS = [
    b"/JavaScript", b"/JS", b"/OpenAction", b"/Launch", b"/EmbeddedFile",
    b"/RichMedia", b"/XFA", b"/Encrypt", b"/ObjStm", b"/JBIG2Decode",
    b"/Colors", b"/AcroForm", b"/URI", b"/SubmitForm", b"/ImportData",
    b"/GoToR", b"/GoToE", b"/Sound", b"/Movie",
]


def analyze_pdf(data: bytes) -> dict:
    if not data.startswith(b"%PDF"):
        return {"error": "Not a valid PDF file"}

    result: dict[str, Any] = {
        "version": _extract_version(data),
        "object_count": len(OBJ_RE.findall(data)),
        "is_encrypted": bool(ENCRYPT_RE.search(data)),
        "has_acroform": bool(ACROFORM_RE.search(data)),
        "has_object_streams": bool(OBJ_STREAM_RE.search(data)),
        "javascript": _analyze_javascript(data),
        "actions": _analyze_actions(data),
        "embedded_files": _analyze_embedded_files(data),
        "uris": _extract_uris(data),
        "streams": _analyze_streams(data),
        "keyword_hits": _count_keywords(data),
        "indicators": [],
        "risk_score": 0,
    }

    result["indicators"], result["risk_score"] = _build_indicators(result)
    return result


def _extract_version(data: bytes) -> str:
    m = re.match(rb"%PDF-(\d+\.\d+)", data[:20])
    return m.group(1).decode() if m else "unknown"


def _analyze_javascript(data: bytes) -> dict:
    js_blocks = []
    threat_hits = []
    urls_in_js = []

    # Find all /JS or /JavaScript occurrences and grab surrounding context
    for m in re.finditer(rb"(?:/JS|/JavaScript)\s*[(<]", data, re.IGNORECASE):
        start = m.start()
        chunk = data[start:start + 2000]
        js_blocks.append(chunk)

    # Decode streams that might contain JS
    decoded_streams = _decode_streams(data)
    all_js_data = b" ".join(js_blocks) + b" ".join(decoded_streams)

    for pattern, description in JS_THREAT_PATTERNS:
        if re.search(pattern, all_js_data, re.IGNORECASE):
            threat_hits.append(description)

    for u in URL_IN_JS_RE.findall(all_js_data):
        try:
            urls_in_js.append(u.decode("utf-8", errors="replace"))
        except Exception:
            pass

    return {
        "found": bool(JS_RE.search(data)),
        "block_count": len(js_blocks),
        "threat_patterns": threat_hits,
        "urls_in_js": list(set(urls_in_js))[:20],
    }


def _analyze_actions(data: bytes) -> dict:
    return {
        "open_action": bool(re.search(rb"/OpenAction", data, re.IGNORECASE)),
        "additional_actions": bool(re.search(rb"\b/AA\b", data, re.IGNORECASE)),
        "launch_action": bool(LAUNCH_RE.search(data)),
        "submit_form": bool(SUBMITFORM_RE.search(data)),
        "goto_remote": bool(re.search(rb"/GoToR", data, re.IGNORECASE)),
        "goto_embedded": bool(re.search(rb"/GoToE", data, re.IGNORECASE)),
        "import_data": bool(re.search(rb"/ImportData", data, re.IGNORECASE)),
        "rich_media": bool(re.search(rb"/RichMedia", data, re.IGNORECASE)),
        "xfa_forms": bool(re.search(rb"/XFA", data, re.IGNORECASE)),
    }


def _analyze_embedded_files(data: bytes) -> dict:
    has_embedded = bool(EMBED_RE.search(data))
    filenames = []
    for m in re.finditer(rb"/F\s*\(([^)]{1,200})\)", data):
        try:
            filenames.append(m.group(1).decode("utf-8", errors="replace"))
        except Exception:
            pass
    return {
        "found": has_embedded,
        "filenames": list(set(filenames))[:20],
        "count": len(filenames),
    }


def _extract_uris(data: bytes) -> list[str]:
    uris = []
    for m in URI_RE.finditer(data):
        try:
            uris.append(m.group(1).decode("utf-8", errors="replace"))
        except Exception:
            pass
    return list(set(uris))[:30]


def _analyze_streams(data: bytes) -> dict:
    total = 0
    suspicious_filters = []
    decoded_content_hits = []

    filter_counts: dict[str, int] = {}

    for m in FILTER_RE.finditer(data):
        total += 1
        raw = m.group(1).decode("utf-8", errors="replace").strip()
        # Extract filter names
        names = re.findall(r"/(\w+)", raw)
        for name in names:
            filter_counts[name] = filter_counts.get(name, 0) + 1
            # Chained obfuscation filters
            if name in ("ASCIIHexDecode", "ASCII85Decode", "LZWDecode",
                        "JBIG2Decode", "CCITTFaxDecode"):
                suspicious_filters.append(name)

    # Check decoded stream content for threats
    for stream_data in _decode_streams(data):
        for pattern, desc in JS_THREAT_PATTERNS:
            if re.search(pattern, stream_data, re.IGNORECASE):
                decoded_content_hits.append(f"In decoded stream: {desc}")

    return {
        "total": total,
        "filter_counts": filter_counts,
        "suspicious_filters": list(set(suspicious_filters)),
        "decoded_threats": list(set(decoded_content_hits))[:10],
    }


def _decode_streams(data: bytes) -> list[bytes]:
    """Attempt to zlib-decompress FlateDecode streams for deeper inspection."""
    decoded = []
    for m in STREAM_RE.finditer(data):
        raw = m.group(1)
        # Try zlib decompress (FlateDecode)
        try:
            decompressed = zlib.decompress(raw)
            decoded.append(decompressed)
        except Exception:
            pass
        # Try wbits=-15 (raw deflate)
        try:
            decompressed = zlib.decompress(raw, -15)
            decoded.append(decompressed)
        except Exception:
            pass
    return decoded[:20]  # cap to avoid excessive processing


def _count_keywords(data: bytes) -> dict[str, int]:
    counts = {}
    for kw in SUSPICIOUS_KEYWORDS:
        count = data.count(kw) + data.count(kw.lower()) + data.count(kw.upper())
        if count > 0:
            counts[kw.decode("utf-8", errors="replace")] = count
    return counts


def _build_indicators(result: dict) -> tuple[list[str], int]:
    indicators = []
    score = 0

    js = result["javascript"]
    actions = result["actions"]
    embedded = result["embedded_files"]
    streams = result["streams"]

    # JavaScript presence
    if js["found"]:
        score += 20
        indicators.append(f"Embedded JavaScript detected ({js['block_count']} block(s))")

    # JS threat patterns
    for threat in js["threat_patterns"]:
        score += 25
        indicators.append(f"Malicious JS pattern: {threat}")

    # URLs inside JavaScript
    if js["urls_in_js"]:
        score += 15
        indicators.append(f"URLs inside JavaScript: {', '.join(js['urls_in_js'][:3])}")

    # Auto-execute actions
    if actions["open_action"] and js["found"]:
        score += 35
        indicators.append("/OpenAction + JavaScript = auto-executes on open (exploit delivery)")
    elif actions["open_action"]:
        score += 15
        indicators.append("/OpenAction present — PDF executes something on open")

    if actions["launch_action"]:
        score += 50
        indicators.append("/Launch action — can execute external programs or shell commands")

    if actions["goto_remote"]:
        score += 20
        indicators.append("/GoToR — opens remote file; can trigger execution or NTLM leak")

    if actions["import_data"]:
        score += 25
        indicators.append("/ImportData action — imports data from external source")

    if actions["submit_form"]:
        score += 20
        indicators.append("/SubmitForm — can exfiltrate data to external server")

    if actions["xfa_forms"]:
        score += 20
        indicators.append("/XFA forms — XML Forms Architecture, used in some exploits")

    if actions["rich_media"]:
        score += 15
        indicators.append("/RichMedia — embedded rich media, potential exploit vector")

    # Embedded files
    if embedded["found"]:
        score += 25
        filenames = embedded["filenames"]
        indicators.append(
            f"Embedded file(s) detected: {', '.join(filenames[:3]) if filenames else 'unnamed'}"
        )
        # Check if embedded files have dangerous extensions
        dangerous = {"exe","dll","bat","ps1","vbs","js","hta","cmd","scr"}
        for fname in filenames:
            ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
            if ext in dangerous:
                score += 40
                indicators.append(f"Dangerous embedded file: {fname}")

    # Obfuscation filters
    if streams["suspicious_filters"]:
        score += 15 * len(set(streams["suspicious_filters"]))
        indicators.append(f"Obfuscation stream filters: {', '.join(set(streams['suspicious_filters']))}")

    # Object streams (hide objects from simple parsers)
    if result["has_object_streams"]:
        score += 10
        indicators.append("/ObjStm — object streams can hide objects from simple scanners")

    # Threats found in decoded streams
    for threat in streams["decoded_threats"]:
        score += 20
        indicators.append(threat)

    # URIs to suspicious destinations
    uris = result["uris"]
    if uris:
        ip_uris = [u for u in uris if re.match(r"https?://\d+\.\d+\.\d+\.\d+", u)]
        if ip_uris:
            score += 25
            indicators.append(f"Direct IP URI(s): {', '.join(ip_uris[:2])}")

    # JBIG2Decode — used in famous exploit (CVE-2009-0658)
    if "JBIG2Decode" in (streams["filter_counts"] or {}):
        score += 30
        indicators.append("JBIG2Decode filter — associated with CVE-2009-0658 and similar exploits")

    return indicators, min(score, 100)
