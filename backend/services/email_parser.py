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
        "cc": _decode_header_value(msg.get("Cc", "")),
        "reply_to": _decode_header_value(msg.get("Reply-To", "")),
        "return_path": _decode_header_value(msg.get("Return-Path", "")),
        "subject": _decode_header_value(msg.get("Subject", "")),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "x_mailer": msg.get("X-Mailer", ""),
        "user_agent": msg.get("User-Agent", ""),
        "x_originating_ip": msg.get("X-Originating-IP", ""),
        "x_sender_ip": msg.get("X-Sender-IP", ""),
        "x_forwarded_to": msg.get("X-Forwarded-To", ""),
        "x_spam_status": msg.get("X-Spam-Status", ""),
        "x_spam_score": msg.get("X-Spam-Score", ""),
        "x_spam_flag": msg.get("X-Spam-Flag", ""),
        "x_virus_scanned": msg.get("X-Virus-Scanned", ""),
        "x_php_originating_script": msg.get("X-PHP-Originating-Script", ""),
        "content_transfer_encoding": msg.get("Content-Transfer-Encoding", ""),
        "mime_version": msg.get("MIME-Version", ""),
        "precedence": msg.get("Precedence", ""),
        "list_unsubscribe": msg.get("List-Unsubscribe", ""),
        "sensitivity": msg.get("Sensitivity", ""),
        "thread_topic": msg.get("Thread-Topic", ""),
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
        "arc_message_signature": msg.get("ARC-Message-Signature", ""),
        "arc_authentication_results": msg.get("ARC-Authentication-Results", ""),
    }

    # Header anomaly detection
    header_anomalies = _detect_header_anomalies(msg, all_headers_text, summary)

    return {
        "summary": summary,
        "routing_hops": hops,
        "all_ips": all_ips,
        "authentication_headers": auth,
        "header_anomalies": header_anomalies,
        "urls": urls,
        "attachments": attachments,
        "body_text": body_text[:5000],
        "body_html": body_html,
        "body_html_preview": body_html[:2000],
        "raw_headers": all_headers_text,
    }


def _detect_header_anomalies(msg: Any, all_headers_text: str, summary: dict) -> list[str]:
    """Detect suspicious header patterns that may indicate spoofing or injection."""
    anomalies = []

    # X-PHP-Originating-Script — sent from hacked PHP app
    if summary.get("x_php_originating_script"):
        anomalies.append(
            f"X-PHP-Originating-Script header present — email sent via PHP script "
            f"({summary['x_php_originating_script'][:100]})"
        )

    # Spam flag headers from receiving MTA
    if summary.get("x_spam_flag", "").upper() == "YES":
        anomalies.append("X-Spam-Flag: YES — receiving mail server flagged as spam")

    spam_score = summary.get("x_spam_score", "")
    if spam_score:
        try:
            score_val = float(spam_score.split()[0])
            if score_val > 5.0:
                anomalies.append(f"High spam score from receiving server: {score_val}")
        except Exception:
            pass

    # Missing Message-ID (unusual for legitimate senders)
    if not summary.get("message_id"):
        anomalies.append("No Message-ID header — unusual for legitimate mail servers")

    # Missing MIME-Version with multipart content
    if not summary.get("mime_version") and ("multipart" in all_headers_text.lower()):
        anomalies.append("Missing MIME-Version header in multipart message")

    # Excessive Received headers (more than 10 hops = unusual)
    received_count = all_headers_text.lower().count("\nreceived:")
    if received_count > 10:
        anomalies.append(f"Excessive routing hops: {received_count} Received headers (obfuscation risk)")

    # Header injection: newlines in subject/from
    for field in ("subject", "from", "reply_to"):
        value = summary.get(field, "")
        if "\n" in value or "\r" in value or "%0a" in value.lower() or "%0d" in value.lower():
            anomalies.append(f"Header injection attempt in {field} field")

    # Precedence: bulk/list (auto-generated)
    prec = summary.get("precedence", "").lower()
    if prec in ("bulk", "list", "junk"):
        anomalies.append(f"Precedence: {prec} — automated/mass-sent email")

    # List-Unsubscribe present (mass mail)
    if summary.get("list_unsubscribe"):
        anomalies.append("List-Unsubscribe header present (mass mailing)")

    # Sensitivity: Company-Confidential etc.
    if summary.get("sensitivity"):
        anomalies.append(f"Sensitivity header: {summary['sensitivity']} (social engineering signal)")

    return anomalies


DANGEROUS_EXTENSIONS = {
    "exe", "bat", "cmd", "com", "scr", "pif", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "ps1", "ps2", "msi", "reg", "hta", "lnk", "jar",
    "iso", "img", "vhd", "vhdx", "dll", "sys", "ocx", "cpl", "inf",
    "sct", "wsc", "jnlp", "py", "rb", "pl", "sh", "bash", "zsh",
    "elf", "dylib",
}

DANGEROUS_MIME = {
    "application/x-msdownload",
    "application/x-executable",
    "application/x-msdos-program",
    "application/octet-stream",
    "application/x-sh",
    "application/x-python",
    "application/x-elf",
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

    # Magic byte checks
    if payload[:2] == b"MZ":
        flags.append("PE executable signature (MZ header)")
    if payload[:4] == b"\x7fELF":
        flags.append("ELF executable (Linux binary)")
    if payload[:4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        flags.append("Mach-O executable (macOS binary)")
    if payload[:4] == b"PK\x03\x04" and len(payload) > 6 and payload[6] & 0x01:
        flags.append("Password-protected ZIP")
    if payload[:4] == b"MSCF":
        flags.append("Microsoft Cabinet (CAB) file — often used in malware delivery")
    if payload[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        flags.append("OLE2 document (possible macro-enabled Office file)")
    if payload[:4] == b"{\\rt":
        flags.append("RTF document — check for embedded exploits")
    if payload[:2] == b"MZ" and b"Equation.3" in payload[:65536]:
        flags.append("PE with Equation Editor reference — CVE-2017-11882 risk")

    # Unicode RTL override in filename
    if "\u202e" in filename:
        flags.append("RTL override character in filename — extension spoofing attack")

    # ISO/disk image
    if ext in ("iso", "img", "vhd", "vhdx"):
        flags.append(f"Disk image attachment (.{ext}) — used to bypass attachment filters")

    return flags
