"""
Consolidated IOC (Indicators of Compromise) extractor.
Collects and deduplicates all threat indicators found during file analysis.
"""
import re
import ipaddress
import hashlib


_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9\-]+\.){1,5}[a-zA-Z]{2,}\b")
_URL_RE    = re.compile(r"https?://[^\s\"'<>\x00]{10,}")
_IP_RE     = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
# Bitcoin addresses (P2PKH, P2SH, Bech32)
_BTC_RE    = re.compile(r"\b(?:1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b")
# Ethereum addresses
_ETH_RE    = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
# CVE identifiers
_CVE_RE    = re.compile(r"CVE-\d{4}-\d{4,}")
# Mutex names (common format)
_MUTEX_RE  = re.compile(r"(?:Global\\|Local\\)[A-Za-z0-9_\-\.]{6,64}")
# Registry run keys
_REGRUN_RE = re.compile(
    r"(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\x00\r\n\"']{5,150}",
    re.IGNORECASE
)


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_multicast or addr.is_reserved)
    except ValueError:
        return False


def _extract_text_pool(*sources: object) -> str:
    """Flatten a mix of str/list/dict into a single searchable string."""
    parts: list[str] = []
    for src in sources:
        if isinstance(src, str):
            parts.append(src)
        elif isinstance(src, list):
            for item in src:
                parts.append(str(item))
        elif isinstance(src, dict):
            for v in src.values():
                parts.append(str(v))
    return " ".join(parts)


def extract_iocs(analysis: dict) -> dict:
    """
    Extract and deduplicate all IOCs from a full file analysis result dict.
    Returns a structured IOC report.
    """
    ips:      set[str] = set()
    domains:  set[str] = set()
    urls:     set[str] = set()
    emails:   set[str] = set()
    registry: set[str] = set()
    mutexes:  set[str] = set()
    btc_addrs: set[str] = set()
    eth_addrs: set[str] = set()
    cves:     set[str] = set()
    filepaths: set[str] = set()

    # -- Hashes (always present) --
    hashes = analysis.get("hashes", {})

    # -- Strings section --
    strings = analysis.get("strings") or {}
    for ip in strings.get("ips", []):
        if _is_public_ip(ip):
            ips.add(ip)
    for url in strings.get("urls", []):
        urls.add(url)
        m = re.match(r"https?://([^/\s:?#@]+)", url)
        if m and "." in m.group(1):
            domains.add(m.group(1).lower())
    for reg in strings.get("registry_keys", []):
        registry.add(reg)
    for path in strings.get("file_paths", []):
        filepaths.add(path)

    # -- Script analysis --
    script = analysis.get("script_analysis") or {}
    for url in script.get("urls_found", []):
        urls.add(url)

    # -- PDF URIs --
    pdf = analysis.get("pdf_analysis") or {}
    for uri in pdf.get("uris", []):
        urls.add(uri)
    js_info = pdf.get("javascript") or {}
    for url in js_info.get("urls_in_js", []):
        urls.add(url)

    # -- LNK embedded URLs --
    lnk = analysis.get("lnk_analysis") or {}
    for url in lnk.get("embedded_urls", []):
        urls.add(url)
    for unc in lnk.get("unc_paths", []):
        # Extract hostname from UNC path
        m = re.match(r"\\\\([a-zA-Z0-9.\-]+)\\", unc)
        if m:
            h = m.group(1)
            if not _is_public_ip(h):
                domains.add(h.lower())
            else:
                ips.add(h)

    # -- RTF/OLE embedded URLs --
    for key in ("rtf_analysis", "ole_analysis"):
        obj = analysis.get(key) or {}
        for url in obj.get("embedded_urls", []):
            urls.add(url)

    # -- Binary analyzer --
    binary = analysis.get("binary_analysis") or {}

    # -- Deep text pool scan (catches anything missed above) --
    pool_sources = [
        str(strings),
        str(script),
        str(pdf),
        str(lnk),
        str(binary),
    ]
    pool = " ".join(pool_sources)

    for ip in _IP_RE.findall(pool):
        if _is_public_ip(ip):
            ips.add(ip)
    for url in _URL_RE.findall(pool):
        urls.add(url)
        m = re.match(r"https?://([^/\s:?#@]+)", url)
        if m and "." in m.group(1):
            domains.add(m.group(1).lower())
    for email in _EMAIL_RE.findall(pool):
        emails.add(email)
    for btc in _BTC_RE.findall(pool):
        btc_addrs.add(btc)
    for eth in _ETH_RE.findall(pool):
        eth_addrs.add(eth)
    for cve in _CVE_RE.findall(pool):
        cves.add(cve)
    for mutex in _MUTEX_RE.findall(pool):
        mutexes.add(mutex)
    for reg in _REGRUN_RE.findall(pool):
        registry.add(reg)

    # Remove noise from domains
    NOISE_DOMAINS = {
        "microsoft.com", "windows.com", "windowsupdate.com",
        "example.com", "localhost", "local",
    }
    domains -= NOISE_DOMAINS
    # Remove IPs that appear as part of local ranges that slipped through
    ips = {ip for ip in ips if _is_public_ip(ip)}

    return {
        "hashes": hashes,
        "ips": sorted(ips),
        "domains": sorted(domains)[:50],
        "urls": sorted(urls)[:50],
        "email_addresses": sorted(emails)[:20],
        "file_paths": sorted(filepaths)[:30],
        "registry_keys": sorted(registry)[:20],
        "mutexes": sorted(mutexes)[:15],
        "cryptocurrency_addresses": {
            "bitcoin": sorted(btc_addrs)[:10],
            "ethereum": sorted(eth_addrs)[:10],
        },
        "cve_references": sorted(cves),
        "total_indicators": (len(ips) + len(domains) + len(urls) + len(emails)
                             + len(registry) + len(btc_addrs) + len(eth_addrs)),
    }
