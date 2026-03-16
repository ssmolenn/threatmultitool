import hashlib
import re
import string
import struct
import os
from pathlib import Path


def compute_hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def detect_file_type(data: bytes, filename: str) -> dict:
    magic_type = _check_magic(data)
    declared_ext = Path(filename).suffix.lower().lstrip(".") if filename else ""
    mime = _magic_to_mime(magic_type)
    ext_match = _ext_matches_magic(declared_ext, magic_type)
    return {
        "magic": magic_type,
        "mime": mime,
        "declared_extension": declared_ext,
        "extension_match": ext_match,
    }


def extract_strings(data: bytes, min_len: int = 6) -> dict:
    printable = set(string.printable.encode())
    results = []
    current = []
    for byte in data:
        if byte in printable:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                results.append("".join(current))
            current = []
    if len(current) >= min_len:
        results.append("".join(current))

    # Categorize
    url_re = re.compile(r"https?://[^\s\"'<>]{8,}", re.IGNORECASE)
    ip_re = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    reg_re = re.compile(r"HKEY_[A-Z_]+\\[^\x00\n]{4,}", re.IGNORECASE)
    path_re = re.compile(r"(?:[A-Za-z]:\\|/etc/|/tmp/|/var/|/usr/)[^\x00\n]{4,}")
    suspicious_re = re.compile(
        r"(cmd\.exe|powershell|certutil|bitsadmin|regsvr32|wscript|cscript|"
        r"FromBase64String|-enc |-encodedcommand|invoke-expression|iex\(|"
        r"net user|net localgroup|whoami|mimikatz|meterpreter|"
        r"CreateRemoteThread|VirtualAlloc|WriteProcessMemory|ShellExecute)",
        re.IGNORECASE,
    )
    b64_re = re.compile(r"[A-Za-z0-9+/]{50,}={0,2}")

    urls = list({m.group() for s in results for m in url_re.finditer(s)})[:30]
    ips = list({m.group() for s in results for m in ip_re.finditer(s)})[:30]
    registry = list({m.group() for s in results for m in reg_re.finditer(s)})[:20]
    paths = list({m.group() for s in results for m in path_re.finditer(s)})[:20]
    suspicious = list({s for s in results if suspicious_re.search(s)})[:20]
    b64_blobs = list({m.group() for s in results for m in b64_re.finditer(s)})[:10]

    return {
        "total_strings": len(results),
        "urls": urls,
        "ips": ips,
        "registry_keys": registry,
        "file_paths": paths,
        "suspicious_commands": suspicious,
        "base64_blobs": b64_blobs,
    }


def extract_metadata(data: bytes, filename: str, file_type: dict) -> dict:
    magic = file_type.get("magic", "")
    meta: dict = {}

    # PDF metadata
    if "PDF" in magic or filename.lower().endswith(".pdf"):
        meta.update(_extract_pdf_meta(data))

    # ZIP-based (Office files, APK, JAR)
    if magic in ("ZIP archive", "Microsoft Office document"):
        meta.update(_extract_zip_meta(data))

    # PE file info
    if "PE" in magic or magic.startswith("MS-DOS"):
        meta.update(_extract_pe_meta(data))

    return meta


def _extract_pdf_meta(data: bytes) -> dict:
    result = {}
    try:
        import io
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data))
        info = reader.metadata
        if info:
            result = {k.lstrip("/"): str(v) for k, v in info.items() if v}
    except Exception:
        pass
    return result


def _extract_zip_meta(data: bytes) -> dict:
    import zipfile
    import io
    result = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            namelist = z.namelist()
            result["zip_contents"] = namelist[:50]
            if "docProps/core.xml" in namelist:
                core = z.read("docProps/core.xml").decode(errors="replace")
                for field in ["creator", "lastModifiedBy", "created", "modified"]:
                    m = re.search(rf"<[^>]*{field}[^>]*>([^<]+)<", core, re.IGNORECASE)
                    if m:
                        result[field] = m.group(1)
    except Exception:
        pass
    return result


def _extract_pe_meta(data: bytes) -> dict:
    result = {}
    try:
        # Check MZ header
        if data[:2] != b"MZ":
            return result
        # PE offset at 0x3C
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 6 > len(data):
            return result
        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return result
        machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
        result["pe_machine"] = {
            0x014C: "x86 (32-bit)",
            0x8664: "x64 (64-bit)",
            0x01C0: "ARM",
            0xAA64: "ARM64",
        }.get(machine, f"Unknown (0x{machine:04X})")
        # Timestamp
        ts = struct.unpack_from("<I", data, pe_offset + 8)[0]
        import datetime
        result["pe_compile_timestamp"] = datetime.datetime.utcfromtimestamp(ts).isoformat() + "Z"
        result["pe_is_executable"] = True
    except Exception:
        pass
    return result


# --- Magic byte detection ---

MAGIC_SIGNATURES = [
    (b"MZ", "PE/MZ Executable (Windows EXE/DLL)"),
    (b"\x7fELF", "ELF Executable (Linux)"),
    (b"\xca\xfe\xba\xbe", "Mach-O Executable (macOS)"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"PK\x05\x06", "ZIP archive (empty)"),
    (b"\x25PDF", "PDF document"),
    (b"\xd0\xcf\x11\xe0", "Microsoft Office document (OLE2)"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"BM", "BMP image"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"BZh", "BZIP2 archive"),
    (b"\xfd7zXZ", "XZ archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf'\x1c", "7-Zip archive"),
    (b"MSCF", "Microsoft Cabinet (CAB)"),
    (b"\x4d\x5a\x90\x00", "PE/MZ Executable (Windows EXE/DLL)"),
    (b"#!/", "Shell script"),
    (b"#!", "Script file"),
    (b"<?php", "PHP script"),
    (b"<html", "HTML document"),
    (b"<!DOCTYPE", "HTML document"),
    (b"<?xml", "XML document"),
    (b"{", "JSON/text"),
    (b"[\x00", "UTF-16 text"),
    (b"\xef\xbb\xbf", "UTF-8 BOM text"),
    (b"\x00\x00\x01\x00", "Windows ICO"),
    (b"RIFF", "RIFF container (WAV/AVI)"),
    (b"\x00\x00\x00\x20ftyp", "MP4/M4A video"),
    (b"\x1aE\xdf\xa3", "Matroska/WebM video"),
    (b"OggS", "OGG media"),
    (b"ID3", "MP3 audio"),
    (b"\xff\xfb", "MP3 audio"),
    (b"fLaC", "FLAC audio"),
    (b"SIMPLE  =", "FITS data"),
    (b"\x53\x51\x4c\x69\x74\x65", "SQLite database"),
    (b"\xac\xed", "Java serialized object"),
    (b"\xce\xfa\xed\xfe", "Mach-O binary (32-bit)"),
    (b"\xcf\xfa\xed\xfe", "Mach-O binary (64-bit)"),
]


def _check_magic(data: bytes) -> str:
    for magic, description in MAGIC_SIGNATURES:
        if data[:len(magic)] == magic:
            return description
    # Check for text
    try:
        data[:512].decode("utf-8")
        return "ASCII/UTF-8 text"
    except Exception:
        pass
    return "Unknown binary"


def _magic_to_mime(magic: str) -> str:
    mapping = {
        "PE/MZ Executable": "application/x-dosexec",
        "ELF Executable": "application/x-elf",
        "Mach-O": "application/x-mach-binary",
        "ZIP archive": "application/zip",
        "PDF document": "application/pdf",
        "Microsoft Office document": "application/vnd.ms-office",
        "PNG image": "image/png",
        "JPEG image": "image/jpeg",
        "GIF image": "image/gif",
        "BMP image": "image/bmp",
        "GZIP archive": "application/gzip",
        "BZIP2 archive": "application/x-bzip2",
        "7-Zip archive": "application/x-7z-compressed",
        "RAR archive": "application/x-rar-compressed",
        "HTML document": "text/html",
        "XML document": "application/xml",
        "Shell script": "text/x-shellscript",
        "PHP script": "text/x-php",
        "SQLite database": "application/x-sqlite3",
        "ASCII/UTF-8 text": "text/plain",
    }
    for key, mime in mapping.items():
        if key in magic:
            return mime
    return "application/octet-stream"


def _ext_matches_magic(ext: str, magic: str) -> bool:
    ext_to_magic_fragment = {
        "exe": "PE/MZ", "dll": "PE/MZ", "elf": "ELF",
        "pdf": "PDF", "zip": "ZIP", "gz": "GZIP",
        "png": "PNG", "jpg": "JPEG", "jpeg": "JPEG",
        "gif": "GIF", "bmp": "BMP", "7z": "7-Zip",
        "rar": "RAR", "doc": "Office", "xls": "Office",
        "ppt": "Office", "docx": "ZIP", "xlsx": "ZIP",
        "pptx": "ZIP", "jar": "ZIP", "apk": "ZIP",
        "html": "HTML", "htm": "HTML", "xml": "XML",
        "sh": "Shell", "php": "PHP", "sqlite": "SQLite",
        "db": "SQLite", "mp3": "MP3",
    }
    expected = ext_to_magic_fragment.get(ext.lower())
    if not expected:
        return True  # can't verify — assume OK
    return expected.lower() in magic.lower()
