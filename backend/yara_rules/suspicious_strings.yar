rule suspicious_powershell_encoded {
    meta:
        description = "Detects PowerShell encoded command execution"
        severity = "high"
        tags = "powershell,obfuscation"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $enc3 = "FromBase64String" nocase
        $enc4 = "Invoke-Expression" nocase
        $enc5 = "IEX(" nocase
        $enc6 = "-w hidden" nocase
        $enc7 = "bypass" nocase
    condition:
        2 of them
}

rule suspicious_cmd_execution {
    meta:
        description = "Detects suspicious cmd.exe usage patterns"
        severity = "medium"
        tags = "cmd,execution"
    strings:
        $a = "cmd.exe /c" nocase
        $b = "cmd /c" nocase
        $c = "certutil" nocase
        $d = "bitsadmin" nocase
        $e = "regsvr32" nocase
        $f = "mshta" nocase
        $g = "wscript" nocase
        $h = "cscript" nocase
    condition:
        any of them
}

rule credential_harvesting {
    meta:
        description = "Detects potential credential harvesting strings"
        severity = "high"
        tags = "credentials,harvesting"
    strings:
        $a = "mimikatz" nocase
        $b = "sekurlsa" nocase
        $c = "lsadump" nocase
        $d = "hashdump" nocase
        $e = "net user" nocase
        $f = "net localgroup administrators" nocase
        $g = "wce.exe" nocase
        $h = "fgdump" nocase
    condition:
        any of them
}

rule suspicious_network_indicators {
    meta:
        description = "Detects suspicious network connectivity patterns"
        severity = "medium"
        tags = "network,c2"
    strings:
        $a = "meterpreter" nocase
        $b = "metasploit" nocase
        $c = "reverse_tcp" nocase
        $d = "reverse_http" nocase
        $e = "cobalt strike" nocase
        $f = "beacon" nocase
        $g = "empire" nocase
    condition:
        any of them
}

rule process_injection_strings {
    meta:
        description = "Detects strings associated with process injection"
        severity = "high"
        tags = "injection,evasion"
    strings:
        $a = "VirtualAlloc" nocase
        $b = "WriteProcessMemory" nocase
        $c = "CreateRemoteThread" nocase
        $d = "NtCreateThread" nocase
        $e = "RtlCreateUserThread" nocase
        $f = "OpenProcess" nocase
        $g = "SetWindowsHookEx" nocase
    condition:
        2 of them
}
