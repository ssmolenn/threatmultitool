import struct
import re


# Suspicious imports grouped by capability
IMPORT_CATEGORIES = {
    "crypto": [
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptImportKey",
        "BCryptEncrypt", "BCryptDecrypt", "BCryptGenRandom", "BCryptOpenAlgorithmProvider",
        "CryptAcquireContext", "CryptCreateHash", "CryptHashData",
        "RtlEncryptMemory", "SystemFunction032",
    ],
    "file_enumeration": [
        "FindFirstFileW", "FindFirstFileA", "FindNextFileW", "FindNextFileA",
        "FindFirstFileExW", "GetDriveTypeW", "GetLogicalDrives",
        "GetVolumeInformationW",
    ],
    "file_destruction": [
        "DeleteFileW", "DeleteFileA", "MoveFileExW", "SetEndOfFile",
        "DeviceIoControl",
    ],
    "process_injection": [
        "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory",
        "CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread",
        "OpenProcess", "SetWindowsHookEx", "QueueUserAPC",
        "NtUnmapViewOfSection", "VirtualProtectEx",
    ],
    "anti_analysis": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugStringA", "GetTickCount", "QueryPerformanceCounter",
        "GetSystemTime", "Sleep", "NtDelayExecution",
        "GetModuleHandleA", "GetProcAddress",  # dynamic import resolution
        "LoadLibraryA", "LoadLibraryW",
    ],
    "network": [
        "WSAStartup", "socket", "connect", "send", "recv",
        "InternetOpenA", "InternetConnectA", "HttpOpenRequestA", "HttpSendRequestA",
        "URLDownloadToFileA", "WinHttpOpen", "WinHttpConnect",
        "DNSQuery_A", "getaddrinfo",
    ],
    "persistence": [
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
        "RegOpenKeyExA", "CreateServiceA", "CreateServiceW",
        "StartServiceA", "ChangeServiceConfigA",
    ],
    "privilege_escalation": [
        "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA",
        "ImpersonateLoggedOnUser", "DuplicateTokenEx",
    ],
    "shadow_copy": [
        # These show up as strings, not imports, but we include for completeness
        "vssadmin", "wmic shadowcopy", "WMI", "IVssBackupComponents",
    ],
    "ransomware_specific": [
        "CreateEncryptor", "RijndaelManaged", "AesCryptoServiceProvider",
        "RSACryptoServiceProvider",
    ],
}

SHADOW_COPY_PATTERNS = [
    r"vssadmin\s+delete\s+shadows",
    r"wmic\s+shadowcopy\s+delete",
    r"bcdedit\s+/set\s+.*(recoveryenabled|safeboot)",
    r"wbadmin\s+delete\s+catalog",
    r"IVssBackupComponents",
    r"DeleteShadowCopies",
    r"Win32_ShadowCopy",
]


def analyze_pe_imports(data: bytes) -> dict:
    """Extract and categorize PE import table."""
    result = {
        "imports_found": False,
        "dll_count": 0,
        "imports": {},
        "suspicious": {},
        "ransomware_indicators": [],
        "raw_import_strings": [],
    }

    # Extract printable strings that look like API names (fast heuristic)
    api_re = re.compile(rb"[A-Za-z][A-Za-z0-9_]{3,63}")
    raw_strings = {m.group().decode("ascii") for m in api_re.finditer(data)}

    # Match against known suspicious imports
    found_by_category: dict[str, list] = {}
    for category, apis in IMPORT_CATEGORIES.items():
        hits = [api for api in apis if api in raw_strings]
        if hits:
            found_by_category[category] = hits

    result["suspicious"] = found_by_category
    result["imports_found"] = bool(found_by_category)

    # Ransomware-specific indicators
    indicators = []
    if "crypto" in found_by_category:
        indicators.append(f"Cryptographic API imports: {', '.join(found_by_category['crypto'][:5])}")
    if "file_enumeration" in found_by_category and "file_destruction" in found_by_category:
        indicators.append("File enumeration + file deletion APIs — classic ransomware pattern")
    if "process_injection" in found_by_category:
        count = len(found_by_category["process_injection"])
        indicators.append(f"Process injection APIs ({count}): {', '.join(found_by_category['process_injection'][:4])}")
    if "shadow_copy" in found_by_category or any(
        re.search(p, data.decode("latin-1", errors="replace"), re.IGNORECASE)
        for p in SHADOW_COPY_PATTERNS
    ):
        indicators.append("Shadow copy deletion indicators — ransomware attempts to prevent recovery")
    if "persistence" in found_by_category:
        indicators.append(f"Persistence mechanisms: {', '.join(found_by_category['persistence'][:3])}")
    if "anti_analysis" in found_by_category:
        indicators.append(f"Anti-analysis techniques: {', '.join(found_by_category['anti_analysis'][:4])}")
    if "privilege_escalation" in found_by_category:
        indicators.append("Privilege escalation APIs detected")
    if "network" in found_by_category:
        indicators.append(f"Network communication APIs: {', '.join(found_by_category['network'][:4])}")

    result["ransomware_indicators"] = indicators

    # DLL name extraction (look for .dll strings)
    dll_re = re.compile(rb"[\w\-.]+\.dll", re.IGNORECASE)
    dlls = list({m.group().decode("ascii", errors="replace") for m in dll_re.finditer(data)})
    result["dll_count"] = len(dlls)
    result["dlls"] = sorted(dlls)[:40]

    return result


def analyze_script(data: bytes, filename: str) -> dict:
    """Analyze script files (.ps1, .js, .vbs, .bat, .hta)."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    text = data.decode("utf-8", errors="replace")
    indicators = []
    risk_score = 0

    patterns = {
        "powershell": [
            (r"-[Ee]nc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}", "PowerShell encoded command", 40),
            (r"Invoke-Expression|IEX\s*\(", "Invoke-Expression (code eval)", 30),
            (r"-[Ww]indowStyle\s+[Hh]idden", "Hidden window execution", 20),
            (r"-[Ee]xecutionPolicy\s+[Bb]ypass", "ExecutionPolicy bypass", 25),
            (r"DownloadString|DownloadFile|WebClient|Net\.WebClient", "Web download capability", 30),
            (r"Add-MpPreference\s+-ExclusionPath", "AV exclusion modification", 50),
            (r"Set-MpPreference\s+-DisableRealtimeMonitoring", "Disabling Windows Defender", 60),
            (r"vssadmin|wmic.*shadowcopy|bcdedit", "Shadow copy/backup deletion", 70),
            (r"Start-Process.*-Verb\s+RunAs", "UAC bypass / run as admin", 40),
            (r"[Cc]onvert[Ff]rom-[Bb]ase64|[Ss]ystem\.Convert\]::FromBase64", "Base64 decode", 25),
        ],
        "javascript": [
            (r"eval\s*\(", "eval() — code execution from string", 30),
            (r"WScript\.Shell|ActiveXObject", "WScript shell / ActiveX (Windows scripting)", 40),
            (r"new\s+ActiveXObject\s*\(\s*['\"]WScript", "WScript.Shell via ActiveX", 50),
            (r"\.Run\s*\(|\.Exec\s*\(", "Process execution", 35),
            (r"unescape\s*\(|String\.fromCharCode", "Character code obfuscation", 25),
            (r"XMLHTTP|ServerXMLHTTP|WinHttpRequest", "HTTP request capability", 30),
        ],
        "vbscript": [
            (r"WScript\.Shell|Shell\.Application", "Shell execution capability", 40),
            (r"\.Run\s*\(|\.Exec\s*\(", "Process execution", 35),
            (r"CreateObject\s*\(\s*['\"]WScript", "WScript object creation", 40),
            (r"XMLHTTP|ServerXMLHTTP", "HTTP request capability", 30),
            (r"chr\s*\(|chrw\s*\(", "Character code obfuscation", 20),
        ],
        "batch": [
            (r"powershell\s+-", "PowerShell invocation from batch", 35),
            (r"certutil\s+-decode", "Certutil decode (LOLBin)", 40),
            (r"bitsadmin\s+/transfer", "BITSAdmin transfer (LOLBin)", 35),
            (r"reg\s+add.*run", "Registry run key modification", 45),
            (r"net\s+user.*\/add", "Adding user accounts", 50),
            (r"net\s+localgroup.*administrators", "Adding to admin group", 55),
            (r"vssadmin|wmic.*shadowcopy", "Shadow copy deletion", 70),
            (r"schtasks\s+/create", "Scheduled task creation", 40),
        ],
    }

    script_type = "powershell" if ext in ("ps1", "psm1") else \
                  "javascript" if ext in ("js", "jse") else \
                  "vbscript" if ext in ("vbs", "vbe") else \
                  "batch" if ext in ("bat", "cmd") else "generic"

    checks = patterns.get(script_type, [])
    # Also run generic checks for unknown types
    if script_type == "generic":
        for cat_patterns in patterns.values():
            checks.extend(cat_patterns)

    for pattern, description, score in checks:
        if re.search(pattern, text, re.IGNORECASE):
            indicators.append(description)
            risk_score += score

    # Universal checks
    b64_blobs = re.findall(r"[A-Za-z0-9+/]{100,}={0,2}", text)
    if b64_blobs:
        indicators.append(f"Large Base64 encoded payload(s): {len(b64_blobs)} blob(s)")
        risk_score += 30

    urls = re.findall(r"https?://[^\s\"']{10,}", text)
    if urls:
        indicators.append(f"Hardcoded URL(s): {len(urls)} found")

    return {
        "script_type": script_type,
        "risk_score": min(risk_score, 100),
        "indicators": indicators,
        "urls_found": urls[:20],
        "b64_blob_count": len(b64_blobs),
    }


def analyze_archive(data: bytes, filename: str) -> dict:
    """Scan inside ZIP/archive for suspicious contents."""
    import zipfile, io
    result = {"scanned": False, "contents": [], "suspicious_files": []}

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            result["scanned"] = True
            names = z.namelist()
            result["file_count"] = len(names)
            result["contents"] = names[:50]

            DANGEROUS_EXTS = {
                "exe", "dll", "bat", "cmd", "com", "scr", "pif", "vbs", "vbe",
                "js", "jse", "wsf", "wsh", "ps1", "hta", "lnk", "jar", "msi",
                "reg", "py", "php",
            }
            for name in names:
                ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
                flags = []
                if ext in DANGEROUS_EXTS:
                    flags.append(f"Dangerous file type inside archive: {name}")
                if name.count(".") > 1:
                    flags.append(f"Double extension: {name}")
                if flags:
                    result["suspicious_files"].append({"name": name, "flags": flags})

                    # Try to read and check magic bytes
                    try:
                        content = z.read(name)
                        if content[:2] == b"MZ":
                            result["suspicious_files"][-1]["flags"].append("PE executable inside archive (MZ header)")
                    except Exception:
                        pass
    except zipfile.BadZipFile:
        result["error"] = "Not a valid ZIP file or password-protected"
    except Exception as e:
        result["error"] = str(e)

    return result
