import httpx
from config import settings


async def get_ip_info(ip: str) -> dict:
    token = settings.ipinfo_token
    url = f"https://ipinfo.io/{ip}/json"
    params = {"token": token} if token else {}
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            r = await client.get(url, params=params)
            if r.status_code != 200:
                return {}
            d = r.json()
            return {
                "city": d.get("city", ""),
                "region": d.get("region", ""),
                "country": d.get("country", ""),
                "org": d.get("org", ""),
                "hostname": d.get("hostname", ""),
                "timezone": d.get("timezone", ""),
            }
        except Exception:
            return {}
