"""
Shodan IP intelligence integration.
Requires SHODAN_API_KEY in .env — optional, degrades gracefully without it.
"""
import httpx
from config import settings


async def lookup_ip(ip: str) -> dict:
    if not settings.shodan_api_key:
        return {"error": "Shodan API key not configured"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": settings.shodan_api_key},
            )
            if r.status_code == 404:
                return {"found": False}
            if r.status_code == 401:
                return {"error": "Invalid Shodan API key"}
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}"}
            data = r.json()
            ports = data.get("ports", [])
            hostnames = data.get("hostnames", [])
            vulns = list(data.get("vulns", {}).keys())
            tags = data.get("tags", [])
            return {
                "found": True,
                "org": data.get("org"),
                "isp": data.get("isp"),
                "country": data.get("country_name"),
                "city": data.get("city"),
                "open_ports": sorted(ports)[:30],
                "hostnames": hostnames[:10],
                "vulnerabilities": vulns[:20],
                "tags": tags,
                "last_update": data.get("last_update"),
            }
    except Exception as e:
        return {"error": str(e)}
