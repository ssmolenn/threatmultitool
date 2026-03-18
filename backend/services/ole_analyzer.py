"""
OLE2 compound document analysis.
Detects VBA macros, auto-execute triggers, and suspicious code in Office files (.doc/.xls/.ppt).
No external dependencies — pure byte parsing.
"""
import re
import struct


OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

VBA_PATTERNS = [
    (r"AutoOpen|Auto_Open|AutoExec|AutoClose|Document_Open|Workbook_Open|"
     r"Workbook_Close|DocumentBeforeClose|UserForm_Initialize", "Auto-execute macro trigger", 40),
    (r"Shell\s*\(", "Shell() function call", 40),
    (r"WScript\.Shell", "WScript.Shell object", 45),
    (r"CreateObject\s*\(\s*['\"]WScript", "CreateObject(WScript) — shell execution", 50),
    (r"CreateObject\s*\(\s*['\"]Scripting\.FileSystemObject", "FileSystemObject — filesystem access", 25),
    (r"\.DownloadString|\.DownloadFile|XMLHTTP|WinHttpRequest|ServerXMLHTTP",
     "File/HTTP download capability", 45),
    (r"URLDownloadToFile|URLDownloadToCacheFile", "URLDownloadToFile (LOLBin download)", 50),
    (r"cmd\.exe|powershell(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|mshta(?:\.exe)?",
     "Shell command execution reference", 45),
    (r"certutil\s+-decode|certutil\s+-urlcache|bitsadmin\s+/transfer",
     "LOLBin abuse (certutil/bitsadmin)", 55),
    (r"regsvr32|rundll32|msiexec|wmic\s+process", "Living-off-the-land binary reference", 40),
    (r"vssadmin|shadowcopy|bcdedit|wbadmin\s+delete", "Shadow copy/backup deletion", 70),
    (r"schtasks\s+/create|at\s+\d+", "Scheduled task creation", 40),
    (r"net\s+user.*\/add|net\s+localgroup.*administrators", "User/admin account manipulation", 55),
    (r"StrReverse\s*\(", "StrReverse() — string obfuscation", 20),
    (r"Chr\s*\(\s*\d+\s*\)", "Chr() character obfuscation", 20),
    (r"FromBase64String|DecodeBase64|Base64Decode", "Base64 decode in macro", 30),
    (r"-[Ee]nc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}", "PowerShell encoded command", 50),
    (r"Invoke-Expression|IEX\s*\(", "Invoke-Expression (dynamic eval)", 40),
    (r"HKEY_|RegWrite|RegRead|SaveSetting|GetSetting", "Registry access", 30),
    (r"environ\s*\(\s*['\"](?:APPDATA|TEMP|TMP|USERPROFILE)", "Sensitive env variable access", 20),
    (r"vbHide|WindowStyle\s*=\s*0|CreateObject.*WshShell.*Run.*,\s*0",
     "Hidden process/window launch", 30),
    (r"Kill\s+|FileCopy\s+|Name\s+.+\s+As\s+", "File manipulation (Kill/Copy/Rename)", 20),
    (r"Attribute\s+VB_Name\s*=\s*['\"]ThisDocument|Attribute\s+VB_Name\s*=\s*['\"]ThisWorkbook",
     "ThisDocument/Workbook module — direct document macro", 15),
    (r"\.exe['\"\s]|\.dll['\"\s]|\.bat['\"\s]|\.ps1['\"\s]|\.vbs['\"\s]",
     "Executable file references in macro", 25),
]

SUSPICIOUS_STRING_RE = re.compile(
    r"(cmd\.exe|powershell|wscript|cscript|mshta|regsvr32|rundll32|certutil|bitsadmin|"
    r"vssadmin|shadowcopy|bcdedit|net\s+user|schtasks|mimikatz|meterpreter|"
    r"CreateObject|Shell\s*\(|WScript\.Shell|XMLHTTP|DownloadFile|URLDownload)[^\r\n\x00]{0,150}",
    re.IGNORECASE,
)

XLM_PATTERNS = [
    rb"EXEC\(",
    rb"CALL\(",
    rb"REGISTER\(",
    rb"FOPEN\(",
    rb"FWRITE\(",
    rb"GET\.WORKSPACE",
    rb"RUN\(",
    rb"FORMULA\(",
]


def analyze_ole(data: bytes) -> dict:
    result: dict = {
        "is_ole": False,
        "has_vba": False,
        "has_xlm_macros": False,
        "auto_exec_triggers": [],
        "vba_indicators": [],
        "suspicious_strings": [],
        "embedded_objects": [],
        "risk_score": 0,
    }

    if len(data) < 8 or data[:8] != OLE2_MAGIC:
        return result

    result["is_ole"] = True

    # Check for VBA storage
    if b"_VBA_PROJECT" in data or b"VBA\x00" in data or b"\x56\x42\x41" in data:
        result["has_vba"] = True

    # Check for XLM/Excel4 macros (stored as BIFF records)
    for pattern in XLM_PATTERNS:
        if pattern in data:
            result["has_xlm_macros"] = True
            break

    # Decode as latin-1 for text pattern matching
    text = data.decode("latin-1", errors="replace")

    # Auto-execute triggers
    auto_patterns = [
        "AutoOpen", "Auto_Open", "AutoExec", "AutoClose",
        "Document_Open", "Workbook_Open", "Workbook_Close",
        "DocumentBeforeClose", "UserForm_Initialize",
        "Auto_Close", "AutoNew",
    ]
    found_triggers = [t for t in auto_patterns if re.search(re.escape(t), text, re.IGNORECASE)]
    result["auto_exec_triggers"] = found_triggers

    # VBA pattern analysis
    indicators = []
    risk_score = 0
    for pattern, description, score in VBA_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            indicators.append(description)
            risk_score += score

    # Bonus: if auto-exec + shell = very suspicious
    if found_triggers and any("shell" in i.lower() or "execute" in i.lower() or "download" in i.lower()
                               for i in indicators):
        risk_score += 25

    # XLM macros are very suspicious
    if result["has_xlm_macros"]:
        indicators.append("Excel 4.0 XLM macro sheet detected (commonly abused for malware delivery)")
        risk_score += 40

    # Suspicious string extraction
    suspicious = list({m.group()[:150] for m in SUSPICIOUS_STRING_RE.finditer(text)})[:15]
    result["suspicious_strings"] = suspicious

    # Embedded OLE objects (look for OLE header within OLE)
    # Count occurrences of OLE magic after the first
    embedded_count = data[8:].count(OLE2_MAGIC)
    if embedded_count > 0:
        result["embedded_objects"].append(f"{embedded_count} nested OLE object(s) detected")
        risk_score += 15

    # Package object (commonly used to deliver executables)
    if b"Package" in data and (b".exe" in data.lower() or b".dll" in data.lower()):
        indicators.append("OLE Package object with executable content — dropper pattern")
        risk_score += 50

    # Equation Editor reference (CVE-2017-11882)
    if b"Equation.3" in data or b"Microsoft Equation" in data:
        indicators.append("Equation Editor 3.0 object — CVE-2017-11882 / CVE-2018-0802 (CRITICAL RCE exploit)")
        risk_score += 90

    result["vba_indicators"] = indicators
    result["risk_score"] = min(risk_score, 100)
    return result
