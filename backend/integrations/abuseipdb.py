import httpx
from config import settings

BASE_URL = "https://api.abuseipdb.com/api/v2"


async def check_ip(ip: str) -> dict:
    if not settings.abuseipdb_api_key:
        return {}
    headers = {"Key": settings.abuseipdb_api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"{BASE_URL}/check", headers=headers, params=params)
        if r.status_code != 200:
            return {}
        d = r.json().get("data", {})
        return {
            "abuse_score": d.get("abuseConfidenceScore", 0),
            "country": d.get("countryCode", ""),
            "isp": d.get("isp", ""),
            "total_reports": d.get("totalReports", 0),
            "last_reported": d.get("lastReportedAt", ""),
            "domain": d.get("domain", ""),
        }
