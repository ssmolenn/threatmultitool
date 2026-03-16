import email
import email.policy
import re
import hashlib
import ipaddress
from email.header import decode_header
from typing import Any


IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def _decode_header_value(value: str) -> str:
    if not value:
        return ""
    parts = decode_header(value)
    result = []
    for raw, charset in parts:
        if isinstance(raw, bytes):
            try:
                result.append(raw.decode(charset or "utf-8", errors="replace"))
            except Exception:
                result.append(raw.decode("utf-8", errors="replace"))
        else:
            result.append(raw)
    return "".join(result)


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)
    except ValueError:
        return False


def _parse_received_header(received: str) -> dict:
    hop: dict[str, Any] = {"raw": received}
    # Extract IP in brackets
    bracket_ip = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", received)
    if bracket_ip:
        hop["ip"] = bracket_ip.group(1)
    # from clause
    from_match = re.search(r"from\s+(\S+)", received, re.IGNORECASE)
    if from_match:
        hop["from"] = from_match.group(1)
    # by clause
    by_match = re.search(r"by\s+(\S+)", received, re.IGNORECASE)
    if by_match:
        hop["by"] = by_match.group(1)
    # with clause
    with_match = re.search(r"with\s+(\S+)", received, re.IGNORECASE)
    if with_match:
        hop["with"] = with_match.group(1)
    # timestamp (after semicolon)
    ts_match = re.search(r";\s*(.+)$", received, re.MULTILINE)
    if ts_match:
        hop["timestamp"] = ts_match.group(1).strip()
    return hop


def parse_eml(raw_bytes: bytes) -> dict:
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)

    summary = {
        "from": _decode_header_value(msg.get("From", "")),
        "to": _decode_header_value(msg.get("To", "")),
        "reply_to": _decode_header_value(msg.get("Reply-To", "")),
        "subject": _decode_header_value(msg.get("Subject", "")),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "x_mailer": msg.get("X-Mailer", ""),
        "x_originating_ip": msg.get("X-Originating-IP", ""),
    }

    # Routing hops — Received headers come newest-first, reverse for timeline
    received_headers = msg.get_all("Received") or []
    hops = []
    for i, rec in enumerate(reversed(received_headers)):
        hop = _parse_received_header(rec)
        hop["hop"] = i + 1
        hops.append(hop)

    # Extract all public IPs from all headers
    all_headers_text = "\n".join(f"{k}: {v}" for k, v in msg.items())
    all_ips = list({ip for ip in IP_RE.findall(all_headers_text) if _is_public_ip(ip)})

    # Body parts
    body_text = ""
    body_html = ""
    attachments = []

    for part in msg.walk():
        ct = part.get_content_type()
        cd = part.get("Content-Disposition", "")
        filename = part.get_filename()

        if "attachment" in cd or (filename and ct not in ("text/plain", "text/html")):
            payload = part.get_payload(decode=True)
            if payload:
                sha256 = hashlib.sha256(payload).hexdigest()
                md5 = hashlib.md5(payload).hexdigest()
                ext = filename.rsplit(".", 1)[-1].lower() if filename and "." in filename else ""
                attachments.append({
                    "filename": filename or "unnamed",
                    "content_type": ct,
                    "size_bytes": len(payload),
                    "md5": md5,
                    "sha256": sha256,
                    "extension": ext,
                    "double_extension": filename.count(".") > 1 if filename else False,
                    "flags": _flag_attachment(filename or "", ct, payload),
                })
        elif ct == "text/plain" and not body_text:
            try:
                body_text = part.get_payload(decode=True).decode(
                    part.get_content_charset() or "utf-8", errors="replace"
                )
            except Exception:
                pass
        elif ct == "text/html" and not body_html:
            try:
                body_html = part.get_payload(decode=True).decode(
                    part.get_content_charset() or "utf-8", errors="replace"
                )
            except Exception:
                pass

    # Extract URLs from body
    urls = list(set(URL_RE.findall(body_text + " " + body_html)))

    # Authentication headers (raw values, actual validation done in domain_analyzer)
    auth = {
        "spf_header": msg.get("Received-SPF", ""),
        "dkim_signature": msg.get("DKIM-Signature", ""),
        "dmarc_result": msg.get("Authentication-Results", ""),
        "arc_seal": msg.get("ARC-Seal", ""),
    }

    return {
        "summary": summary,
        "routing_hops": hops,
        "all_ips": all_ips,
        "authentication_headers": auth,
        "urls": urls,
        "attachments": attachments,
        "body_text": body_text[:5000],  # cap for response size
        "body_html_preview": body_html[:2000],
        "raw_headers": all_headers_text,
    }


DANGEROUS_EXTENSIONS = {
    "exe", "bat", "cmd", "com", "scr", "pif", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "ps1", "ps2", "msi", "reg", "hta", "lnk", "jar",
}

DANGEROUS_MIME = {
    "application/x-msdownload",
    "application/x-executable",
    "application/x-msdos-program",
    "application/octet-stream",
}


def _flag_attachment(filename: str, content_type: str, payload: bytes) -> list[str]:
    flags = []
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in DANGEROUS_EXTENSIONS:
        flags.append(f"Dangerous extension: .{ext}")
    if content_type in DANGEROUS_MIME:
        flags.append(f"Dangerous MIME type: {content_type}")
    if filename.count(".") > 1:
        flags.append("Double extension detected")
    # Check for PE magic bytes (MZ header)
    if payload[:2] == b"MZ":
        flags.append("PE executable signature (MZ header)")
    # Check for zip with password (local file header with encryption flag)
    if payload[:4] == b"PK\x03\x04" and len(payload) > 6 and payload[6] & 0x01:
        flags.append("Password-protected ZIP")
    return flags
