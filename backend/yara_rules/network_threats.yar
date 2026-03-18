rule cobalt_strike_beacon {
    meta:
        description = "Detects Cobalt Strike beacon signatures"
        severity = "critical"
        tags = "cobalt_strike,c2,apt,beacon"
    strings:
        $cs1 = "cobaltstrike" nocase
        $cs2 = "ReflectiveDll" nocase
        $cs3 = "ReflectiveLoader" nocase
        $cs4 = "beacon.dll" nocase
        $cs5 = "Cobalt Strike" nocase
        $cs6 = "post-ex" nocase
        // Common beacon config marker
        $cs7 = {fc e8 89 00 00 00}
        // DNS beacon pattern
        $cs8 = "application/octet-stream" nocase
    condition:
        2 of ($cs1, $cs2, $cs3, $cs4, $cs5, $cs6) or $cs7
}

rule meterpreter_payload {
    meta:
        description = "Detects Meterpreter/Metasploit payload signatures"
        severity = "critical"
        tags = "meterpreter,metasploit,c2"
    strings:
        $m1 = "meterpreter" nocase
        $m2 = "metsrv.dll" nocase
        $m3 = "MetSrv" nocase
        $m4 = "stdapi_" nocase
        $m5 = "ReflectiveDllInjection" nocase
        $m6 = "PAYLOAD_TYPE_INTERACTIVE" nocase
        // Shikata ga nai decoder stub
        $m7 = {d9 74 24 f4 5b 31 c9 b1}
    condition:
        2 of ($m1, $m2, $m3, $m4, $m5, $m6) or $m7
}

rule reverse_shell_linux {
    meta:
        description = "Detects common Linux reverse shell patterns"
        severity = "critical"
        tags = "reverse_shell,linux,c2"
    strings:
        $s1 = "bash -i >& /dev/tcp/" nocase
        $s2 = "bash -i >& /dev/udp/" nocase
        $s3 = "/bin/sh -i" nocase
        $s4 = "nc -e /bin/bash" nocase
        $s5 = "nc -e /bin/sh" nocase
        $s6 = "mkfifo /tmp/" nocase
        $s7 = "python -c 'import socket,subprocess" nocase
        $s8 = "perl -e 'use Socket" nocase
        $s9 = "ruby -rsocket" nocase
        $s10 = "0<&196;exec 196<>/dev/tcp/" nocase
    condition:
        any of them
}

rule cryptominer {
    meta:
        description = "Detects cryptominer binaries (XMRig and similar)"
        severity = "high"
        tags = "cryptominer,monero,xmrig"
    strings:
        $s1 = "stratum+tcp://" nocase
        $s2 = "stratum+ssl://" nocase
        $s3 = "mining.subscribe" nocase
        $s4 = "mining.authorize" nocase
        $s5 = "mining.notify" nocase
        $s6 = "xmrig" nocase
        $s7 = "cryptonight" nocase
        $s8 = "pool.minexmr.com" nocase
        $s9 = "supportxmr.com" nocase
        $s10 = "hashrate" nocase
        $s11 = "worker_name" nocase
        $s12 = "nicehash" nocase
    condition:
        3 of them
}

rule dns_c2_dga {
    meta:
        description = "Detects potential DGA (Domain Generation Algorithm) C2 patterns"
        severity = "high"
        tags = "c2,dga,dns"
    strings:
        // Long random-looking domain queries
        $s1 = /[a-z0-9]{16,}\.(com|net|org|info|biz)/ nocase
        // Common DGA beacon intervals
        $s2 = "GetSystemTime" nocase
        $s3 = "GetTickCount" nocase
        $s4 = "dns.query" nocase
        $s5 = "DnsQuery" nocase
    condition:
        $s1 and ($s2 or $s3) and ($s4 or $s5)
}

rule process_injection_techniques {
    meta:
        description = "Detects multiple process injection API combinations"
        severity = "high"
        tags = "injection,process_hollowing,shellcode"
    strings:
        $a = "VirtualAllocEx" nocase
        $b = "WriteProcessMemory" nocase
        $c = "CreateRemoteThread" nocase
        $d = "NtCreateThreadEx" nocase
        $e = "RtlCreateUserThread" nocase
        $f = "QueueUserAPC" nocase
        $g = "SetThreadContext" nocase
        $h = "NtUnmapViewOfSection" nocase
        $i = "OpenProcess" nocase
    condition:
        ($a and $b and ($c or $d or $e or $f)) or
        ($h and $a and $b) or  // process hollowing
        ($g and $i and $b)     // APC injection
}

rule credential_dumping {
    meta:
        description = "Detects credential dumping tools and techniques"
        severity = "critical"
        tags = "credential_theft,mimikatz,lsass"
    strings:
        $m1 = "mimikatz" nocase
        $m2 = "sekurlsa::" nocase
        $m3 = "lsadump::" nocase
        $m4 = "kerberos::" nocase
        $m5 = "wdigest" nocase
        $m6 = "lsass.exe" nocase
        $m7 = "MiniDumpWriteDump" nocase
        $m8 = "SamIConnect" nocase
        $m9 = "NtlmHash" nocase
        $m10 = "LsaQueryInformationPolicy" nocase
    condition:
        ($m1 or $m2 or $m3) or
        (3 of ($m4, $m5, $m6, $m7, $m8, $m9, $m10))
}

rule rootkit_linux {
    meta:
        description = "Detects Linux rootkit indicators"
        severity = "critical"
        tags = "rootkit,linux,persistence"
    strings:
        $s1 = "LD_PRELOAD" nocase
        $s2 = "/etc/ld.so.preload" nocase
        $s3 = "hide_process" nocase
        $s4 = "hide_file" nocase
        $s5 = "sys_call_table" nocase
        $s6 = "kernel_symbol" nocase
        $s7 = "proc_fops" nocase
        $s8 = "__NR_" nocase
    condition:
        ($s1 or $s2) or 3 of ($s3, $s4, $s5, $s6, $s7, $s8)
}
