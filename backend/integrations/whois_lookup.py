"""
WHOIS domain lookup integration.
Uses python-whois library (synchronous) wrapped in asyncio.to_thread.
"""
import asyncio
from datetime import datetime, timezone


async def lookup_domain(domain: str) -> dict:
    try:
        return await asyncio.to_thread(_sync_whois, domain)
    except Exception as e:
        return {"error": str(e)}


def _sync_whois(domain: str) -> dict:
    try:
        import whois  # type: ignore
        w = whois.whois(domain)

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        age_days = None
        if creation_date:
            if isinstance(creation_date, datetime):
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - creation_date).days

        return {
            "registrar": w.registrar,
            "creation_date": str(creation_date) if creation_date else None,
            "expiration_date": str(expiration_date) if expiration_date else None,
            "age_days": age_days,
            "country": w.country,
            "org": w.org,
            "name_servers": list(w.name_servers or [])[:5],
            "status": list(w.status or [])[:3] if isinstance(w.status, (list, set)) else [w.status] if w.status else [],
        }
    except ImportError:
        return {"error": "python-whois not installed"}
    except Exception as e:
        return {"error": str(e)}
