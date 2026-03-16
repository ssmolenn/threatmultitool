import base64
import httpx
from config import settings

BASE_URL = "https://www.virustotal.com/api/v3"


def _headers() -> dict:
    return {"x-apikey": settings.virustotal_api_key}


async def lookup_file(sha256: str) -> dict:
    if not settings.virustotal_api_key:
        return {"error": "VirusTotal API key not configured"}
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(f"{BASE_URL}/files/{sha256}", headers=_headers())
        if r.status_code == 404:
            return {"found": False}
        if r.status_code == 429:
            return {"error": "rate_limited"}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "name": data.get("meaningful_name", ""),
            "type": data.get("type_description", ""),
            "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
        }


async def lookup_ip(ip: str) -> dict:
    if not settings.virustotal_api_key:
        return {}
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"{BASE_URL}/ip_addresses/{ip}", headers=_headers())
        if r.status_code != 200:
            return {}
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
        }


async def lookup_url(url: str) -> dict:
    if not settings.virustotal_api_key:
        return {"error": "VirusTotal API key not configured"}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(f"{BASE_URL}/urls/{url_id}", headers=_headers())
        if r.status_code == 404:
            return {"found": False}
        if r.status_code == 429:
            return {"error": "rate_limited"}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
        }
