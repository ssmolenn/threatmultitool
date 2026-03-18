"""
Windows LNK (shortcut) file analysis.
LNK files are a primary initial-access vector in phishing campaigns.
Parses the binary structure and extracts target, arguments, and threat indicators.
"""
import struct
import re


LNK_MAGIC = 0x0000004C
LNK_GUID  = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"

# LinkFlags (DWORD at offset 20)
HAS_LINK_TARGET_IDLIST = 0x00000001
HAS_LINK_INFO         = 0x00000002
HAS_NAME              = 0x00000004
HAS_RELATIVE_PATH     = 0x00000008
HAS_WORKING_DIR       = 0x00000010
HAS_ARGUMENTS         = 0x00000020
HAS_ICON_LOCATION     = 0x00000040


def _read_counted_string(data: bytes, offset: int, is_unicode: bool = False) -> tuple[str, int]:
    """Read a CountedString (2-byte length prefix) from LNK data."""
    try:
        count = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        if is_unicode:
            end = offset + count * 2
            s = data[offset:end].decode("utf-16-le", errors="replace")
            return s, end
        else:
            end = offset + count
            s = data[offset:end].decode("ascii", errors="replace")
            return s, end
    except Exception:
        return "", offset


def analyze_lnk(data: bytes) -> dict:
    result: dict = {
        "is_lnk": False,
        "target_path": "",
        "arguments": "",
        "working_dir": "",
        "description": "",
        "icon_location": "",
        "show_command": "",
        "indicators": [],
        "embedded_urls": [],
        "unc_paths": [],
        "risk_score": 0,
    }

    if len(data) < 76:
        return result

    # Validate header
    try:
        file_id = struct.unpack_from("<I", data, 0)[0]
    except Exception:
        return result

    if file_id != LNK_MAGIC:
        return result

    result["is_lnk"] = True

    indicators: list[str] = []
    risk_score = 0

    # Parse show command (hidden window = suspicious)
    try:
        show_cmd = struct.unpack_from("<I", data, 0x3C)[0]
        show_map = {1: "Normal", 2: "Minimized", 3: "Maximized", 7: "Minimized (hidden)"}
        result["show_command"] = show_map.get(show_cmd, f"0x{show_cmd:08x}")
        if show_cmd in (7,):
            indicators.append(f"Show command = Minimized (hidden window) — evasion")
            risk_score += 20
    except Exception:
        pass

    # Parse flags
    try:
        link_flags = struct.unpack_from("<I", data, 20)[0]
        is_unicode = bool(link_flags & 0x00000080)  # IsUnicode flag
    except Exception:
        is_unicode = True

    # Try to extract string data block (after Shell Item ID List and Link Info if present)
    # We'll use a simpler approach: scan for readable strings
    text = data.decode("latin-1", errors="replace")
    text_utf16 = ""
    try:
        text_utf16 = data.decode("utf-16-le", errors="replace")
    except Exception:
        pass

    combined_text = text + " " + text_utf16

    # Extract PowerShell patterns
    ps_re = re.compile(r"powershell(?:\.exe)?[^\x00\r\n]{0,500}", re.IGNORECASE)
    ps_matches = ps_re.findall(combined_text)
    if ps_matches:
        sample = ps_matches[0][:250]
        indicators.append(f"PowerShell execution: {sample}")
        risk_score += 50
        if re.search(r"-[Ee]nc(odedcommand)?", sample, re.IGNORECASE):
            indicators.append("PowerShell encoded command in LNK (strong obfuscation)")
            risk_score += 30
        if re.search(r"DownloadString|DownloadFile|WebClient|IWR|Invoke-WebRequest", sample, re.IGNORECASE):
            indicators.append("PowerShell web download capability in LNK")
            risk_score += 25
        if re.search(r"Set-MpPreference|Add-MpPreference", sample, re.IGNORECASE):
            indicators.append("Defender modification in LNK target")
            risk_score += 40

    # CMD patterns
    cmd_re = re.compile(r"cmd(?:\.exe)?[^\x00\r\n]{0,300}", re.IGNORECASE)
    cmd_matches = cmd_re.findall(combined_text)
    if cmd_matches:
        indicators.append(f"CMD execution: {cmd_matches[0][:200]}")
        risk_score += 35

    # WScript/CScript/MSHTA
    for binary in ["wscript", "cscript", "mshta", "regsvr32", "rundll32", "msiexec"]:
        pattern = re.compile(rf"{binary}(?:\.exe)?[^\x00\r\n]{{0,200}}", re.IGNORECASE)
        m = pattern.search(combined_text)
        if m:
            indicators.append(f"{binary.upper()} execution: {m.group()[:150]}")
            risk_score += 40

    # Embedded URLs
    url_re = re.compile(r"https?://[^\x00\s\r\n\"']{10,}", re.IGNORECASE)
    urls = list(set(url_re.findall(combined_text)))[:10]
    result["embedded_urls"] = urls
    if urls:
        indicators.append(f"URL(s) in LNK target/arguments: {len(urls)} found")
        risk_score += 25

    # UNC paths (possible NTLM credential theft via responder)
    unc_re = re.compile(r"\\\\[a-zA-Z0-9.\-]{3,}\\[^\x00\s]{3,}", re.IGNORECASE)
    unc_paths = list(set(unc_re.findall(combined_text)))[:5]
    result["unc_paths"] = unc_paths
    if unc_paths:
        indicators.append(f"UNC path(s) in LNK: {unc_paths[0][:100]} — NTLM credential theft risk")
        risk_score += 45

    # Double extension masking (e.g., invoice.pdf.lnk shown as invoice.pdf)
    dbl_ext_re = re.compile(
        r"\w+\.(pdf|doc|docx|xls|xlsx|txt|jpg|jpeg|png|mp4|zip)\.lnk",
        re.IGNORECASE
    )
    dbl_matches = dbl_ext_re.findall(text)
    if dbl_matches:
        indicators.append(f"Double extension masking: file disguised as .{dbl_matches[0]}")
        risk_score += 35

    # Excessively long LNK (obfuscation in arguments)
    if len(data) > 4096:
        indicators.append(f"Unusually large LNK file ({len(data)} bytes) — obfuscation in arguments")
        risk_score += 20

    # Icon path tricks (pointing to PDF/Word icon)
    pdf_icon = re.search(r"AcroRd32|FoxitReader|sumatrapdf", combined_text, re.IGNORECASE)
    word_icon = re.search(r"winword|excel|WINWORD", combined_text, re.IGNORECASE)
    if pdf_icon:
        indicators.append("LNK uses PDF reader icon — masquerading as PDF file")
        risk_score += 15
    elif word_icon:
        indicators.append("LNK uses Word/Excel icon — masquerading as Office document")
        risk_score += 15

    # Base64 blobs in arguments
    b64_re = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
    b64_matches = b64_re.findall(combined_text)
    if b64_matches:
        indicators.append(f"Base64 blob(s) in LNK: {len(b64_matches)} ({len(b64_matches[0])} chars)")
        risk_score += 30

    result["indicators"] = indicators
    result["risk_score"] = min(risk_score, 100)
    return result
