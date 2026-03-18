"""
ThreatFox (abuse.ch) IOC database integration.
Free API — no key required.
"""
import httpx


async def lookup_ioc(ioc: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": ioc},
            )
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}"}
            data = r.json()
            if data.get("query_status") == "no_results":
                return {"found": False}
            results = data.get("data", [])
            if not results:
                return {"found": False}
            first = results[0]
            return {
                "found": True,
                "ioc_type": first.get("ioc_type"),
                "threat_type": first.get("threat_type"),
                "malware": first.get("malware"),
                "malware_alias": first.get("malware_alias"),
                "confidence": first.get("confidence_level"),
                "tags": first.get("tags") or [],
                "first_seen": first.get("first_seen"),
                "last_seen": first.get("last_seen"),
                "reporter": first.get("reporter"),
            }
    except Exception as e:
        return {"error": str(e)}


async def lookup_hash(sha256: str) -> dict:
    return await lookup_ioc(sha256)


async def lookup_url(url: str) -> dict:
    return await lookup_ioc(url)


async def lookup_domain(domain: str) -> dict:
    return await lookup_ioc(domain)


async def lookup_ip(ip: str) -> dict:
    return await lookup_ioc(ip)
