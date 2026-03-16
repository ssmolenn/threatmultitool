import httpx

BASE_URL = "https://urlhaus-api.abuse.ch/v1/"


async def lookup_url(url: str) -> dict:
    """Query URLhaus for a malicious URL. No API key required."""
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(f"{BASE_URL}url/", data={"url": url})
            if r.status_code != 200:
                return {"found": False}
            data = r.json()
            if data.get("query_status") == "no_results":
                return {"found": False}
            return {
                "found": True,
                "url_status": data.get("url_status", ""),  # online/offline
                "threat": data.get("threat", ""),
                "tags": data.get("tags") or [],
                "blacklists": data.get("blacklists", {}),
                "first_seen": data.get("date_added", ""),
                "permalink": data.get("urlhaus_reference", ""),
            }
    except Exception as e:
        return {"error": str(e)}


async def lookup_hash(sha256: str) -> dict:
    """Query URLhaus for a file hash (payload database)."""
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(f"{BASE_URL}payload/", data={"sha256_hash": sha256})
            if r.status_code != 200:
                return {"found": False}
            data = r.json()
            if data.get("query_status") == "no_results":
                return {"found": False}
            return {
                "found": True,
                "file_type": data.get("file_type", ""),
                "signature": data.get("signature", ""),
                "first_seen": data.get("firstseen", ""),
                "url_count": data.get("url_count", 0),
                "urls_associated": [u.get("url", "") for u in (data.get("urls", []) or [])[:5]],
                "permalink": data.get("urlhaus_reference", ""),
            }
    except Exception as e:
        return {"error": str(e)}
