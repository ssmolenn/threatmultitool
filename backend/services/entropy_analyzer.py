import math
import struct
from typing import Optional


def byte_entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence. Range: 0.0 (uniform) to 8.0 (random/encrypted)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _interpret_entropy(entropy: float, context: str = "") -> dict:
    if entropy >= 7.5:
        level = "CRITICAL"
        description = "Extremely high entropy — file is likely encrypted, packed, or compressed (strong ransomware/packer indicator)"
    elif entropy >= 7.0:
        level = "HIGH"
        description = "Very high entropy — likely packed executable or encrypted payload"
    elif entropy >= 6.5:
        level = "MEDIUM"
        description = "Elevated entropy — may be compressed, obfuscated, or contain encrypted data"
    elif entropy >= 5.0:
        level = "LOW"
        description = "Moderate entropy — normal for binaries and compiled code"
    else:
        level = "CLEAN"
        description = "Low entropy — typical of text files or uncompressed data"
    return {"entropy": entropy, "level": level, "description": description, "context": context}


def analyze_entropy(data: bytes, file_type: dict) -> dict:
    """Full entropy analysis: whole file + PE sections if applicable."""
    result = {
        "overall": _interpret_entropy(byte_entropy(data), "whole file"),
        "sections": [],
    }

    # PE section entropy
    magic = file_type.get("magic", "")
    if "PE" in magic or "MZ" in magic:
        sections = _pe_section_entropy(data)
        result["sections"] = sections

    return result


def _pe_section_entropy(data: bytes) -> list:
    """Parse PE section table and compute entropy per section."""
    sections = []
    try:
        if data[:2] != b"MZ":
            return sections
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 4 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return sections

        # COFF header
        machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
        num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
        optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]

        # Section table starts after PE signature (4) + COFF header (20) + optional header
        section_table_offset = pe_offset + 24 + optional_header_size

        for i in range(min(num_sections, 96)):
            sec_offset = section_table_offset + i * 40
            if sec_offset + 40 > len(data):
                break

            name_raw = data[sec_offset:sec_offset + 8]
            name = name_raw.rstrip(b"\x00").decode("ascii", errors="replace")
            vsize = struct.unpack_from("<I", data, sec_offset + 16)[0]
            raw_offset = struct.unpack_from("<I", data, sec_offset + 20)[0]
            raw_size = struct.unpack_from("<I", data, sec_offset + 16)[0]
            characteristics = struct.unpack_from("<I", data, sec_offset + 36)[0]

            # Characteristics flags
            flags = []
            if characteristics & 0x20:
                flags.append("CODE")
            if characteristics & 0x40:
                flags.append("INITIALIZED_DATA")
            if characteristics & 0x80:
                flags.append("UNINITIALIZED_DATA")
            if characteristics & 0x20000000:
                flags.append("EXECUTABLE")
            if characteristics & 0x40000000:
                flags.append("READABLE")
            if characteristics & 0x80000000:
                flags.append("WRITABLE")

            # Suspicious: writable + executable (W+X)
            wx = (characteristics & 0x20000000) and (characteristics & 0x80000000)

            sec_data = data[raw_offset:raw_offset + raw_size] if raw_offset and raw_size else b""
            ent = byte_entropy(sec_data) if sec_data else 0.0

            info = _interpret_entropy(ent, f"section [{name}]")
            info["name"] = name
            info["raw_size"] = raw_size
            info["flags"] = flags
            info["wx_section"] = wx  # write+execute = suspicious (shellcode injection target)
            if wx:
                info["wx_warning"] = "Write+Execute section detected — common in shellcode loaders"

            # Known suspicious section names
            suspicious_names = {
                "UPX0", "UPX1", "UPX2",  # UPX packer
                ".packed", ".shrink", ".themida",  # Themida packer
                ".vmp0", ".vmp1",  # VMProtect
                ".ndata",  # NSIS installer
                ".textbss",  # some malware
            }
            if name.upper() in {s.upper() for s in suspicious_names}:
                info["suspicious_name"] = f"Known packer/protector section name: {name}"

            sections.append(info)

    except Exception:
        pass
    return sections
