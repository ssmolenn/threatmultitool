import re
import dns.resolver
import dns.exception


def _extract_domain(address: str) -> str:
    match = re.search(r"@([\w.\-]+)", address)
    if match:
        return match.group(1).lower()
    # Try bare domain
    match = re.search(r"([\w.\-]+\.\w{2,})", address)
    return match.group(1).lower() if match else ""


def check_spf(domain: str) -> dict:
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        for rdata in answers:
            txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
            if txt.startswith("v=spf1"):
                policy = "pass"
                if "-all" in txt:
                    policy = "hardfail"
                elif "~all" in txt:
                    policy = "softfail"
                elif "?all" in txt:
                    policy = "neutral"
                elif "+all" in txt:
                    policy = "allow_all (DANGEROUS)"
                return {"found": True, "record": txt, "policy": policy}
        return {"found": False, "record": "", "policy": "none"}
    except (dns.exception.DNSException, Exception):
        return {"found": False, "record": "", "policy": "error"}


def check_dmarc(domain: str) -> dict:
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for rdata in answers:
            txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
            if "v=DMARC1" in txt:
                policy_match = re.search(r"p=(\w+)", txt)
                policy = policy_match.group(1) if policy_match else "none"
                pct_match = re.search(r"pct=(\d+)", txt)
                pct = int(pct_match.group(1)) if pct_match else 100
                sp_match = re.search(r"sp=(\w+)", txt)
                sp = sp_match.group(1) if sp_match else None
                rua_match = re.search(r"rua=([^;]+)", txt)
                rua = rua_match.group(1).strip() if rua_match else None
                return {
                    "found": True,
                    "record": txt,
                    "policy": policy,
                    "subdomain_policy": sp,
                    "pct": pct,
                    "reporting_uri": rua,
                }
        return {"found": False, "record": "", "policy": "none"}
    except (dns.exception.DNSException, Exception):
        return {"found": False, "record": "", "policy": "error"}


def check_dkim(domain: str, signature_header: str) -> dict:
    if not signature_header:
        return {"found": False, "selector": "", "record": ""}
    selector_match = re.search(r"s=([^;]+)", signature_header)
    if not selector_match:
        return {"found": False, "selector": "", "record": ""}
    selector = selector_match.group(1).strip()
    try:
        answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT", lifetime=5)
        for rdata in answers:
            txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
            if "p=" in txt:
                # Extract key type and algorithm
                algo_m = re.search(r"k=(\w+)", txt)
                algo = algo_m.group(1) if algo_m else "rsa"
                return {"found": True, "selector": selector, "algorithm": algo, "record": txt[:200] + "..."}
        return {"found": False, "selector": selector, "record": ""}
    except (dns.exception.DNSException, Exception):
        return {"found": False, "selector": selector, "record": ""}


def check_mx(domain: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        return sorted([str(r.exchange).rstrip(".") for r in answers])
    except Exception:
        return []


def check_ns(domain: str) -> list[str]:
    """Get authoritative nameservers for the domain."""
    try:
        answers = dns.resolver.resolve(domain, "NS", lifetime=5)
        return sorted([str(r.target).rstrip(".") for r in answers])
    except Exception:
        return []


def check_caa(domain: str) -> dict:
    """
    Check CAA (Certification Authority Authorization) records.
    Missing CAA = any CA can issue certs for this domain (weaker security).
    """
    try:
        answers = dns.resolver.resolve(domain, "CAA", lifetime=5)
        records = []
        for rdata in answers:
            records.append(str(rdata))
        return {"found": bool(records), "records": records[:10]}
    except dns.resolver.NoAnswer:
        return {"found": False, "records": []}
    except dns.resolver.NXDOMAIN:
        return {"found": False, "records": [], "error": "domain_not_found"}
    except Exception:
        return {"found": False, "records": []}


def check_bimi(domain: str) -> dict:
    """
    Check BIMI (Brand Indicators for Message Identification) record.
    Presence indicates a legitimate, well-configured mail sender.
    """
    try:
        answers = dns.resolver.resolve(f"default._bimi.{domain}", "TXT", lifetime=5)
        for rdata in answers:
            txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
            if "v=BIMI1" in txt:
                l_match = re.search(r"l=([^;]+)", txt)
                logo_url = l_match.group(1).strip() if l_match else None
                return {"found": True, "record": txt, "logo_url": logo_url}
        return {"found": False}
    except Exception:
        return {"found": False}


def check_a_record(domain: str) -> list[str]:
    """Resolve A records for the domain."""
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=5)
        return [str(r) for r in answers]
    except Exception:
        return []


def analyze_domain(from_address: str, dkim_signature: str) -> dict:
    domain = _extract_domain(from_address)
    if not domain:
        return {
            "domain": "",
            "spf": {}, "dmarc": {}, "dkim": {},
            "mx": [], "ns": [], "a_records": [],
            "caa": {}, "bimi": {},
        }
    return {
        "domain": domain,
        "spf":       check_spf(domain),
        "dmarc":     check_dmarc(domain),
        "dkim":      check_dkim(domain, dkim_signature),
        "mx":        check_mx(domain),
        "ns":        check_ns(domain),
        "a_records": check_a_record(domain),
        "caa":       check_caa(domain),
        "bimi":      check_bimi(domain),
    }
