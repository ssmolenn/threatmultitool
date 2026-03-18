"""
Generic binary threat analysis.
Shellcode detection, suspicious byte patterns, binary anomalies, hex dump, and imphash.
"""
import hashlib
import re
import struct
from math import log2


# --- Shellcode detection ---

# NOP sleds (x86/x64)
NOP_SLED_THRESHOLD = 20  # consecutive 0x90 bytes

# Common shellcode stubs / prologues (x86)
SHELLCODE_PATTERNS: list[tuple[bytes, str]] = [
    (b"\xfc\xe8", "Classic x86 shellcode prelude (CLD + CALL)"),
    (b"\x55\x8b\xec", "x86 function prologue (PUSH EBP; MOV EBP,ESP)"),
    (b"\x64\xa1\x30\x00\x00\x00", "x86 PEB access via FS:[0x30] (shellcode GetPEB)"),
    (b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00", "x64 PEB access via GS:[0x60] (shellcode GetPEB)"),
    (b"\xeb\xfe", "Infinite loop (\\xeb\\xfe) — debug breakpoint or shellcode stub"),
    (b"\xcc\xcc\xcc\xcc", "INT3 breakpoint sled — anti-debugging or shellcode padding"),
    (b"\x0b\xd1\x4c\x7a", "Metasploit shikata_ga_nai decoder stub signature"),
    (b"\xd9\x74\x24\xf4", "Metasploit FLDENV decoder stub (x86 FPU)"),
    (b"\x31\xc0\x50\x68", "x86 null-free shellcode pattern (XOR EAX,EAX; PUSH)"),
    (b"\x48\x31\xc0", "x64 XOR RAX,RAX (common shellcode start)"),
    (b"\x6a\x60\x5a\x68", "Classic Windows shellcode (LoadLibrary pattern)"),
]

# Cobalt Strike beacon signatures
COBALT_STRIKE_PATTERNS: list[tuple[bytes, str]] = [
    (b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
     ""),  # placeholder — actual CS detection below
]

COBALT_STRIKE_SIGS = [
    b"cobaltstrike",
    b"Cobalt Strike",
    b"MSFBETA",
    b"Beacon",
    b"%windir%\\sysnative",
    b"Content-Type: application/octet-stream\r\nAccept: */*\r\nCookie:",
    b"ReflectiveDll",
    b"ReflectiveLoader",
    b"beacon.dll",
    b"post-ex",
]

# Meterpreter / Metasploit signatures
METERPRETER_SIGS = [
    b"meterpreter",
    b"Meterpreter",
    b"MetSrv",
    b"metsrv.dll",
    b"ReflectiveDllInjection",
    b"PAYLOAD_TYPE_INTERACTIVE",
    b"stdapi_",
]

# Generic suspicious patterns
SUSPICIOUS_PATTERNS: list[tuple[bytes, str, int]] = [
    (b"This program cannot be run in DOS mode", "", 0),  # legitimate PE check — no score
    (b"cmd /c", "cmd /c shell execution string in binary", 25),
    (b"cmd.exe /c", "cmd.exe /c in binary payload", 25),
    (b"powershell.exe", "PowerShell reference in binary", 20),
    (b"-WindowStyle Hidden", "Hidden PowerShell window", 30),
    (b"-EncodedCommand", "PowerShell encoded command in binary", 35),
    (b"IEX(New-Object", "PowerShell Invoke-Expression + download", 40),
    (b"certutil -decode", "Certutil LOLBin abuse", 35),
    (b"bitsadmin /transfer", "BITSAdmin LOLBin transfer", 35),
    (b"vssadmin delete shadows", "Shadow copy deletion", 60),
    (b"wmic shadowcopy delete", "Shadow copy deletion via WMIC", 60),
    (b"bcdedit /set", "Boot config modification", 40),
    (b"schtasks /create", "Scheduled task creation", 30),
    (b"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Autorun registry persistence", 45),
    (b"netsh advfirewall set allprofiles state off", "Firewall disabled", 55),
    (b"taskkill /f /im", "Force-kill process", 20),
    (b"wscript.shell", "WScript.Shell in binary", 30),
    (b"WScript.Shell", "WScript.Shell in binary", 30),
    (b"CreateRemoteThread", "CreateRemoteThread — process injection", 35),
    (b"VirtualAllocEx", "VirtualAllocEx — remote memory allocation", 35),
    (b"WriteProcessMemory", "WriteProcessMemory — injection", 35),
    (b"mimikatz", "Mimikatz credential dumping tool", 90),
    (b"sekurlsa::", "Mimikatz module reference (sekurlsa)", 85),
    (b"lsadump::", "Mimikatz LSA dump module", 85),
    (b"HashtoplusPlus", "Hashcat/password cracker reference", 30),
    (b"stratum+tcp", "Cryptominer stratum protocol", 60),
    (b"mining.subscribe", "Cryptominer JSON-RPC method", 60),
    (b"xmrig", "XMRig cryptominer", 70),
]


def analyze_binary(data: bytes) -> dict:
    result: dict = {
        "hex_dump": _hex_dump(data, max_bytes=256),
        "shellcode_indicators": [],
        "suspicious_strings": [],
        "cobalt_strike": False,
        "meterpreter": False,
        "cryptominer": False,
        "nop_sled": False,
        "nop_sled_max_length": 0,
        "indicators": [],
        "risk_score": 0,
    }

    indicators: list[str] = []
    risk_score = 0

    # NOP sled detection
    max_nop = _max_consecutive(data, 0x90)
    result["nop_sled_max_length"] = max_nop
    if max_nop >= NOP_SLED_THRESHOLD:
        result["nop_sled"] = True
        indicators.append(f"NOP sled detected: {max_nop} consecutive 0x90 bytes")
        risk_score += 30

    # INT3 sled
    max_int3 = _max_consecutive(data, 0xCC)
    if max_int3 >= 16:
        indicators.append(f"INT3 sled: {max_int3} consecutive 0xCC bytes")
        risk_score += 20

    # Shellcode stubs
    for pattern, description in SHELLCODE_PATTERNS:
        if pattern in data and description:
            result["shellcode_indicators"].append(description)
            risk_score += 25

    # Cobalt Strike
    cs_hits = [sig.decode("latin-1") for sig in COBALT_STRIKE_SIGS if sig.lower() in data.lower()]
    if cs_hits:
        result["cobalt_strike"] = True
        indicators.append(f"Cobalt Strike indicator(s): {', '.join(cs_hits[:3])}")
        risk_score += 70

    # Meterpreter
    mtr_hits = [sig.decode("latin-1") for sig in METERPRETER_SIGS if sig.lower() in data.lower()]
    if mtr_hits:
        result["meterpreter"] = True
        indicators.append(f"Meterpreter/Metasploit indicator(s): {', '.join(mtr_hits[:3])}")
        risk_score += 65

    # Suspicious strings
    suspicious_found: list[str] = []
    for pattern, description, score in SUSPICIOUS_PATTERNS:
        if description and pattern.lower() in data.lower():
            suspicious_found.append(description)
            risk_score += score
    result["suspicious_strings"] = suspicious_found[:20]

    # Cryptominer detection
    if any(sig.lower() in data.lower() for sig in [b"stratum+tcp", b"xmrig", b"mining.subscribe"]):
        result["cryptominer"] = True

    # Polyglot detection: multiple magic bytes at different offsets
    polyglot_types = _detect_polyglot(data)
    if len(polyglot_types) > 1:
        indicators.append(f"Polyglot file: valid as multiple formats — {', '.join(polyglot_types)}")
        risk_score += 25

    # Imphash (PE only)
    if data[:2] == b"MZ":
        ih = _compute_imphash(data)
        if ih:
            result["imphash"] = ih

    result["indicators"] = indicators
    result["risk_score"] = min(risk_score, 100)
    return result


def _hex_dump(data: bytes, max_bytes: int = 256) -> list[str]:
    """Return a hex dump of the first max_bytes bytes as a list of lines."""
    lines = []
    chunk = data[:max_bytes]
    for i in range(0, len(chunk), 16):
        row = chunk[i:i+16]
        hex_part  = " ".join(f"{b:02x}" for b in row)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in row)
        lines.append(f"{i:04x}  {hex_part:<47}  {ascii_part}")
    return lines


def _max_consecutive(data: bytes, byte_val: int) -> int:
    """Find the maximum length of consecutive occurrences of byte_val."""
    max_run = 0
    current = 0
    for b in data:
        if b == byte_val:
            current += 1
            if current > max_run:
                max_run = current
        else:
            current = 0
    return max_run


def _detect_polyglot(data: bytes) -> list[str]:
    """Check how many known format magic bytes appear at various offsets."""
    found = []
    checks = [
        (b"MZ",                  "PE/EXE"),
        (b"\x7fELF",             "ELF"),
        (b"PK\x03\x04",         "ZIP"),
        (b"\x25PDF",             "PDF"),
        (b"\xd0\xcf\x11\xe0",   "OLE2"),
        (b"\x89PNG\r\n\x1a\n",  "PNG"),
        (b"\xff\xd8\xff",        "JPEG"),
        (b"GIF8",                "GIF"),
        (b"{\\rtf",              "RTF"),
        (b"<!DOCTYPE html",      "HTML"),
        (b"<html",               "HTML"),
    ]
    # Check at start
    for magic, name in checks:
        if data[:len(magic)] == magic:
            found.append(name)
    # Check at other offsets (appended data)
    for magic, name in checks:
        idx = data[512:].find(magic)
        if idx != -1 and name not in found:
            found.append(f"{name}@+{idx+512}")
    return found


def _compute_imphash(data: bytes) -> str:
    """
    Compute a simplified imphash for PE files.
    Real imphash normalizes import names; this is a best-effort from string extraction.
    """
    try:
        # Extract DLL+function pairs from import table region
        dll_re  = re.compile(rb"[\w\-.]+\.dll", re.IGNORECASE)
        api_re  = re.compile(rb"[A-Za-z][A-Za-z0-9_]{3,63}")
        dlls    = [m.group().lower().decode("ascii", errors="replace")
                   for m in dll_re.finditer(data)]
        apis    = [m.group().decode("ascii", errors="replace")
                   for m in api_re.finditer(data)]
        # Build a reproducible string from sorted unique imports
        combined = ",".join(sorted(set(dlls + apis))[:100])
        return hashlib.md5(combined.encode()).hexdigest()
    except Exception:
        return ""
