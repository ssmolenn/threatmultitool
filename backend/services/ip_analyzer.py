import asyncio
from integrations.abuseipdb import check_ip
from integrations.ipinfo import get_ip_info
from integrations.virustotal import lookup_ip


async def analyze_ips(ip_list: list[str]) -> dict[str, dict]:
    results = {}
    tasks = {ip: _analyze_single_ip(ip) for ip in ip_list}
    gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
    for ip, result in zip(tasks.keys(), gathered):
        if isinstance(result, Exception):
            results[ip] = {"error": str(result)}
        else:
            results[ip] = result
    return results


async def _analyze_single_ip(ip: str) -> dict:
    abuse_task = check_ip(ip)
    ipinfo_task = get_ip_info(ip)
    vt_task = lookup_ip(ip)

    abuse, ipinfo, vt = await asyncio.gather(abuse_task, ipinfo_task, vt_task, return_exceptions=True)

    result: dict = {}
    if isinstance(abuse, dict):
        result.update(abuse)
    if isinstance(ipinfo, dict):
        result["geo"] = ipinfo
    if isinstance(vt, dict) and vt:
        result["virustotal"] = vt

    return result
