"""
ELF binary analysis for Linux/Unix executables.
Parses ELF headers, detects suspicious symbols, and identifies threat behaviors.
"""
import struct
import re


ELF_MACHINES = {
    0x03: "x86 (32-bit)",
    0x3E: "x86-64 (64-bit)",
    0x28: "ARM (32-bit)",
    0xB7: "AArch64 (ARM 64-bit)",
    0x08: "MIPS",
    0x14: "PowerPC (32-bit)",
    0x15: "PowerPC (64-bit)",
    0x16: "S390",
    0x02: "SPARC",
    0xF3: "RISC-V",
}

ELF_TYPES = {
    1: "Relocatable object",
    2: "Executable",
    3: "Shared object (library / PIE executable)",
    4: "Core dump",
}

ELF_OS_ABI = {
    0: "UNIX System V",
    3: "Linux",
    6: "Solaris",
    9: "FreeBSD",
}

SUSPICIOUS_SYMBOLS = {
    "process_execution": [
        b"execve", b"execl", b"execle", b"execlp", b"execv", b"execvp", b"execvpe",
        b"system", b"popen", b"posix_spawn",
    ],
    "process_injection": [
        b"ptrace", b"process_vm_writev", b"process_vm_readv",
        b"dlopen", b"dlsym", b"mmap", b"mprotect", b"memfd_create",
    ],
    "network": [
        b"socket", b"connect", b"bind", b"listen", b"accept", b"send", b"recv",
        b"sendto", b"recvfrom", b"getaddrinfo", b"inet_aton", b"gethostbyname",
        b"curl_easy_perform", b"curl_easy_setopt",
    ],
    "persistence": [
        b"crontab", b"inotify_add_watch",
    ],
    "privilege_escalation": [
        b"setuid", b"setgid", b"setreuid", b"setregid", b"seteuid",
        b"capset", b"prctl",
    ],
    "evasion": [
        b"unlink", b"unlinkat", b"seccomp", b"fork", b"setsid",
        b"chroot", b"pivot_root",
    ],
    "crypto": [
        b"EVP_EncryptInit", b"EVP_DecryptInit", b"AES_encrypt", b"AES_decrypt",
        b"RSA_public_encrypt", b"RSA_private_decrypt",
        b"BIO_new", b"SSL_CTX_new",
    ],
    "file_manipulation": [
        b"inotify_init", b"fanotify_init",
    ],
}

ROOTKIT_STRINGS = [
    b"LD_PRELOAD",
    b"ld.so.preload",
    b"/proc/self/maps",
    b"hide_process",
    b"hide_file",
    b"__libc_start_main",  # common hooking target
    b"sys_call_table",
    b"kernel_symbol",
    b"/dev/null 2>&1",
    b"HIDE_PID",
    b"MAGIC_GID",
]

BACKDOOR_STRINGS = [
    b"bash -i",
    b"/bin/sh",
    b"/bin/bash",
    b"nc -e",
    b"ncat",
    b"mkfifo",
    b"0.0.0.0",
    b"reverse shell",
    b"bind shell",
    b"meterpreter",
    b"metasploit",
]

CRYPTOMINER_STRINGS = [
    b"stratum+tcp",
    b"stratum+ssl",
    b"mining.subscribe",
    b"xmrig",
    b"monero",
    b"cryptonight",
    b"pool.minexmr",
    b"supportxmr",
    b"hashrate",
    b"worker_name",
]


def analyze_elf(data: bytes) -> dict:
    result: dict = {
        "is_elf": False,
        "architecture": "",
        "elf_type": "",
        "endian": "",
        "class": "",
        "os_abi": "",
        "is_stripped": False,
        "is_static": False,
        "entry_point": None,
        "suspicious_symbols": {},
        "indicators": [],
        "rootkit_indicators": [],
        "backdoor_indicators": [],
        "cryptominer_indicators": [],
        "risk_score": 0,
    }

    if len(data) < 64 or data[:4] != b"\x7fELF":
        return result

    result["is_elf"] = True
    ei_class = data[4]   # 1=32-bit, 2=64-bit
    ei_data  = data[5]   # 1=little-endian, 2=big-endian
    ei_osabi = data[7]
    fmt = "<" if ei_data == 1 else ">"

    result["class"]  = "32-bit" if ei_class == 1 else "64-bit" if ei_class == 2 else "unknown"
    result["endian"] = "little-endian" if ei_data == 1 else "big-endian"
    result["os_abi"] = ELF_OS_ABI.get(ei_osabi, f"Unknown (0x{ei_osabi:02x})")

    try:
        e_type    = struct.unpack_from(f"{fmt}H", data, 16)[0]
        e_machine = struct.unpack_from(f"{fmt}H", data, 18)[0]
        e_entry   = struct.unpack_from(f"{fmt}Q" if ei_class == 2 else f"{fmt}I", data, 24)[0]
        result["elf_type"]    = ELF_TYPES.get(e_type, f"Unknown (0x{e_type:04x})")
        result["architecture"] = ELF_MACHINES.get(e_machine, f"Unknown (0x{e_machine:04x})")
        result["entry_point"] = hex(e_entry)
    except Exception:
        pass

    # Stripped: no .symtab section
    result["is_stripped"] = b".symtab" not in data
    # Static: no .interp section (no dynamic linker)
    result["is_static"] = b".interp" not in data and b"libc.so" not in data

    indicators: list[str] = []
    risk_score = 0

    # Suspicious symbol matching
    found_by_category: dict[str, list] = {}
    for category, symbols in SUSPICIOUS_SYMBOLS.items():
        hits = []
        for sym in symbols:
            if re.search(rb'\b' + sym + rb'\b', data):
                hits.append(sym.decode("ascii"))
        if hits:
            found_by_category[category] = hits

    result["suspicious_symbols"] = found_by_category

    if "process_injection" in found_by_category:
        indicators.append(f"Memory injection APIs: {', '.join(found_by_category['process_injection'][:4])}")
        risk_score += 40
    if "process_execution" in found_by_category:
        indicators.append(f"Process execution APIs: {', '.join(found_by_category['process_execution'][:4])}")
        risk_score += 25
    if "network" in found_by_category:
        indicators.append(f"Network APIs: {', '.join(found_by_category['network'][:4])}")
        risk_score += 15
    if "privilege_escalation" in found_by_category:
        indicators.append(f"Privilege escalation APIs: {', '.join(found_by_category['privilege_escalation'][:4])}")
        risk_score += 30
    if "crypto" in found_by_category:
        indicators.append(f"Cryptographic APIs: {', '.join(found_by_category['crypto'][:4])}")
        risk_score += 20
    if "evasion" in found_by_category:
        indicators.append(f"Evasion/rootkit APIs: {', '.join(found_by_category['evasion'][:4])}")
        risk_score += 25

    # Stripped binary
    if result["is_stripped"]:
        indicators.append("Binary stripped of symbols (no .symtab) — common in malware to hinder analysis")
        risk_score += 15

    # Static binary with network capability (common in malware droppers)
    if result["is_static"] and "network" in found_by_category:
        indicators.append("Statically linked binary with network capability — typical dropper/implant")
        risk_score += 20

    # Rootkit indicators
    rootkit_hits = []
    for sig in ROOTKIT_STRINGS:
        if sig in data:
            rootkit_hits.append(sig.decode("latin-1"))
    if rootkit_hits:
        result["rootkit_indicators"] = rootkit_hits
        indicators.append(f"Rootkit indicators: {', '.join(rootkit_hits[:5])}")
        risk_score += 45

    # Backdoor/reverse shell indicators
    backdoor_hits = []
    for sig in BACKDOOR_STRINGS:
        if sig in data:
            backdoor_hits.append(sig.decode("latin-1"))
    if backdoor_hits:
        result["backdoor_indicators"] = backdoor_hits
        indicators.append(f"Backdoor/reverse shell strings: {', '.join(backdoor_hits[:5])}")
        risk_score += 55

    # Cryptominer indicators
    miner_hits = []
    for sig in CRYPTOMINER_STRINGS:
        if sig.lower() in data.lower():
            miner_hits.append(sig.decode("latin-1"))
    if miner_hits:
        result["cryptominer_indicators"] = miner_hits
        indicators.append(f"Cryptominer strings: {', '.join(miner_hits[:5])}")
        risk_score += 50

    # /proc/ manipulation (process hiding)
    if b"/proc/" in data:
        indicators.append("References /proc filesystem — process/file hiding or enumeration")
        risk_score += 10

    # /etc/cron persistence
    if b"/etc/cron" in data or b"crontab" in data:
        indicators.append("Cron path reference — possible persistence mechanism")
        risk_score += 25

    # SUID setuid manipulation
    if b"chmod" in data and b"4755" in data:
        indicators.append("chmod 4755 (SUID bit) — privilege escalation attempt")
        risk_score += 35

    # Self-deletion
    if b"unlink" in data and b"/proc/self/exe" in data:
        indicators.append("Self-deletion pattern (/proc/self/exe + unlink) — cleanup after execution")
        risk_score += 30

    result["indicators"] = indicators
    result["risk_score"] = min(risk_score, 100)
    return result
