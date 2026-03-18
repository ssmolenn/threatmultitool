import asyncio
from fastapi import APIRouter, UploadFile, File, HTTPException

from services.file_analyzer import compute_hashes, detect_file_type, extract_strings, extract_metadata
from services.entropy_analyzer import analyze_entropy
from services.pe_analyzer import analyze_pe_imports, analyze_script, analyze_archive
from services.pdf_analyzer import analyze_pdf
from services.yara_scanner import scan as yara_scan
from services.ole_analyzer import analyze_ole
from services.elf_analyzer import analyze_elf
from services.lnk_analyzer import analyze_lnk
from services.rtf_analyzer import analyze_rtf
from services.binary_analyzer import analyze_binary
from services.ioc_extractor import extract_iocs
from integrations.virustotal import lookup_file
from integrations.malwarebazaar import lookup_hash as mb_lookup
from integrations.urlhaus import lookup_hash as urlhaus_lookup
from integrations.threatfox import lookup_hash as tf_lookup
from config import settings

router = APIRouter(prefix="/api/file", tags=["file"])

MAX_BYTES = settings.max_file_size_mb * 1024 * 1024

SCRIPT_EXTENSIONS  = {"ps1", "psm1", "js", "jse", "vbs", "vbe", "bat", "cmd", "hta", "wsf"}
ARCHIVE_EXTENSIONS = {"zip", "jar", "apk", "docx", "xlsx", "pptx", "odt", "ods", "odp"}
OLE_EXTENSIONS     = {"doc", "xls", "ppt", "dot", "xlt", "pot", "msg"}
RTF_EXTENSIONS     = {"rtf"}
LNK_EXTENSIONS     = {"lnk"}
ELF_EXTENSIONS     = {"elf", "so", "axf", "o"}


@router.post("/analyze")
async def analyze_file(file: UploadFile = File(...)):
    data = await file.read()
    if len(data) > MAX_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds {settings.max_file_size_mb}MB limit")
    if len(data) == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    filename = file.filename or "unknown"
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    # --- Core analysis (local, fast) ---
    hashes    = compute_hashes(data)
    file_type = detect_file_type(data, filename)
    strings   = extract_strings(data)
    metadata  = extract_metadata(data, filename, file_type)
    entropy   = analyze_entropy(data, file_type)
    yara_result = yara_scan(data)
    binary_analysis = analyze_binary(data)

    magic = file_type.get("magic", "")

    # --- Format-specific analysis ---
    pe_analysis      = None
    script_analysis  = None
    archive_analysis = None
    pdf_analysis     = None
    ole_analysis     = None
    elf_analysis     = None
    lnk_analysis     = None
    rtf_analysis     = None

    # PE (Windows executable/DLL)
    if "PE" in magic or "MZ" in magic or ext in ("exe", "dll", "sys", "ocx", "cpl"):
        pe_analysis = analyze_pe_imports(data)

    # Scripts
    if ext in SCRIPT_EXTENSIONS:
        script_analysis = analyze_script(data, filename)

    # ZIP-based archives
    if ext in ARCHIVE_EXTENSIONS or "ZIP" in magic:
        archive_analysis = analyze_archive(data, filename)

    # PDF
    if ext == "pdf" or "PDF" in magic or data[:4] == b"%PDF":
        pdf_analysis = analyze_pdf(data)

    # OLE2 documents (Office 97-2003)
    if (
        ext in OLE_EXTENSIONS
        or magic.startswith("Microsoft Office")
        or data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    ):
        ole_analysis = analyze_ole(data)

    # ELF binaries
    if (
        ext in ELF_EXTENSIONS
        or "ELF" in magic
        or data[:4] == b"\x7fELF"
    ):
        elf_analysis = analyze_elf(data)

    # LNK shortcuts
    if ext == "lnk" or (len(data) >= 4 and data[:4] == b"L\x00\x00\x00"):
        lnk_analysis = analyze_lnk(data)

    # RTF documents
    if ext in RTF_EXTENSIONS or data[:4] in (b"{\\rt", b"{\\ r"):
        rtf_analysis = analyze_rtf(data)

    # --- External lookups (async, parallel) ---
    vt_result, mb_result, urlhaus_result, tf_result = await asyncio.gather(
        lookup_file(hashes["sha256"]),
        mb_lookup(hashes["sha256"]),
        urlhaus_lookup(hashes["sha256"]),
        tf_lookup(hashes["sha256"]),
        return_exceptions=True,
    )
    if isinstance(vt_result,      Exception): vt_result      = {"error": str(vt_result)}
    if isinstance(mb_result,      Exception): mb_result      = {"error": str(mb_result)}
    if isinstance(urlhaus_result, Exception): urlhaus_result = {"error": str(urlhaus_result)}
    if isinstance(tf_result,      Exception): tf_result      = {"error": str(tf_result)}

    # --- Risk assessment ---
    risk = _assess_risk(
        file_type, vt_result, mb_result, urlhaus_result, tf_result,
        yara_result, strings, entropy, pe_analysis, script_analysis, pdf_analysis,
        ole_analysis, elf_analysis, lnk_analysis, rtf_analysis, binary_analysis,
    )

    # --- IOC extraction ---
    analysis_for_ioc = {
        "hashes": hashes,
        "strings": strings,
        "script_analysis": script_analysis,
        "pdf_analysis": pdf_analysis,
        "lnk_analysis": lnk_analysis,
        "rtf_analysis": rtf_analysis,
        "ole_analysis": ole_analysis,
        "binary_analysis": binary_analysis,
    }
    iocs = extract_iocs(analysis_for_ioc)

    return {
        "status": "success",
        "filename": filename,
        "file_size_bytes": len(data),
        "hashes": hashes,
        "file_type": file_type,
        "entropy": entropy,
        "virustotal": vt_result,
        "malwarebazaar": mb_result,
        "urlhaus": urlhaus_result,
        "threatfox": tf_result,
        "pe_analysis": pe_analysis,
        "ole_analysis": ole_analysis,
        "elf_analysis": elf_analysis,
        "lnk_analysis": lnk_analysis,
        "rtf_analysis": rtf_analysis,
        "script_analysis": script_analysis,
        "archive_analysis": archive_analysis,
        "pdf_analysis": pdf_analysis,
        "binary_analysis": binary_analysis,
        "metadata": metadata,
        "strings": strings,
        "yara": yara_result,
        "risk_assessment": risk,
        "iocs": iocs,
    }


def _assess_risk(
    file_type, vt, mb, urlhaus, threatfox, yara, strings, entropy,
    pe, script, pdf, ole, elf, lnk, rtf, binary,
) -> dict:
    score = 0
    indicators = []

    # --- Threat intelligence hits ---
    malicious    = vt.get("malicious", 0) if isinstance(vt, dict) else 0
    suspicious_vt = vt.get("suspicious", 0) if isinstance(vt, dict) else 0
    if malicious > 5:
        score += 70
        indicators.append(f"VirusTotal: {malicious} engines flagged as MALICIOUS")
    elif malicious > 0:
        score += 45
        indicators.append(f"VirusTotal: {malicious} engine(s) flagged as malicious")
    if suspicious_vt > 3:
        score += 15
        indicators.append(f"VirusTotal: {suspicious_vt} engines flagged as suspicious")

    if isinstance(mb, dict) and mb.get("found"):
        score += 80
        sig = mb.get("signature", "unknown family")
        indicators.append(f"MalwareBazaar: KNOWN MALWARE — family: {sig}")

    if isinstance(urlhaus, dict) and urlhaus.get("found"):
        score += 60
        threat = urlhaus.get("signature") or urlhaus.get("file_type", "")
        indicators.append(f"URLhaus: Found in malware payload database ({threat})")

    if isinstance(threatfox, dict) and threatfox.get("found"):
        score += 65
        malware = threatfox.get("malware", "unknown")
        threat_type = threatfox.get("threat_type", "")
        indicators.append(f"ThreatFox: Known IOC — {malware} ({threat_type})")

    # --- File type anomalies ---
    if not file_type.get("extension_match", True):
        score += 35
        indicators.append(
            f"Extension mismatch: .{file_type.get('declared_extension')} "
            f"vs actual type '{file_type.get('magic')}'"
        )

    # --- Entropy ---
    overall_entropy = entropy.get("overall", {})
    ent_level = overall_entropy.get("level", "")
    if ent_level == "CRITICAL":
        score += 40
        indicators.append(f"Entropy CRITICAL ({overall_entropy.get('entropy')}) — packed/encrypted payload")
    elif ent_level == "HIGH":
        score += 20
        indicators.append(f"High entropy ({overall_entropy.get('entropy')}) — possible packer/encryption")

    for sec in entropy.get("sections", []):
        if sec.get("wx_section"):
            score += 25
            indicators.append(f"Write+Execute PE section '{sec.get('name')}' — shellcode injection")
        if sec.get("suspicious_name"):
            score += 20
            indicators.append(sec["suspicious_name"])
        if sec.get("level") == "CRITICAL":
            score += 15
            indicators.append(f"Packed PE section '{sec.get('name')}' (entropy {sec.get('entropy')})")

    # --- PE analysis ---
    if pe and pe.get("ransomware_indicators"):
        for ind in pe["ransomware_indicators"]:
            score += 20
            indicators.append(f"PE: {ind}")

    # --- OLE/VBA macros ---
    if ole and ole.get("is_ole"):
        ole_score = ole.get("risk_score", 0)
        if ole_score > 0:
            score += min(ole_score, 70)
        for ind in ole.get("vba_indicators", []):
            indicators.append(f"OLE/VBA: {ind}")
        if ole.get("auto_exec_triggers"):
            indicators.append(f"Auto-execute macro triggers: {', '.join(ole['auto_exec_triggers'][:4])}")

    # --- ELF analysis ---
    if elf and elf.get("is_elf"):
        elf_score = elf.get("risk_score", 0)
        if elf_score > 0:
            score += min(elf_score // 2, 35)
        for ind in elf.get("indicators", []):
            indicators.append(f"ELF: {ind}")

    # --- LNK shortcut ---
    if lnk and lnk.get("is_lnk"):
        lnk_score = lnk.get("risk_score", 0)
        if lnk_score > 0:
            score += min(lnk_score, 60)
        for ind in lnk.get("indicators", []):
            indicators.append(f"LNK: {ind}")

    # --- RTF document ---
    if rtf and rtf.get("is_rtf"):
        rtf_score = rtf.get("risk_score", 0)
        if rtf_score > 0:
            score += min(rtf_score, 70)
        for ind in rtf.get("indicators", []):
            indicators.append(f"RTF: {ind}")

    # --- Script analysis ---
    if script and script.get("indicators"):
        score += min(script.get("risk_score", 0), 60)
        for ind in script["indicators"]:
            indicators.append(f"Script: {ind}")

    # --- Binary/shellcode analysis ---
    if binary:
        bin_score = binary.get("risk_score", 0)
        if bin_score > 0:
            score += min(bin_score, 50)
        for ind in binary.get("indicators", []):
            indicators.append(f"Binary: {ind}")
        for ind in binary.get("shellcode_indicators", []):
            indicators.append(f"Shellcode: {ind}")
        if binary.get("cobalt_strike"):
            indicators.append("COBALT STRIKE beacon signatures detected")
        if binary.get("meterpreter"):
            indicators.append("METERPRETER/Metasploit signatures detected")
        if binary.get("cryptominer"):
            indicators.append("Cryptominer signatures detected")
        if binary.get("nop_sled"):
            pass  # already in indicators

    # --- YARA matches ---
    for m in yara.get("matches", []):
        sev = m.get("meta", {}).get("severity", "medium")
        pts = {"critical": 40, "high": 25, "medium": 15}.get(sev, 10)
        score += pts
        indicators.append(f"YARA: {m['rule']} [{sev.upper()}]")

    # --- Suspicious strings ---
    if strings.get("suspicious_commands"):
        score += 15
        indicators.append(f"Suspicious command strings: {len(strings['suspicious_commands'])}")
    if strings.get("base64_blobs"):
        score += 10
        indicators.append(f"Large Base64 blobs: {len(strings['base64_blobs'])}")

    # --- PDF-specific ---
    if pdf and not pdf.get("error"):
        pdf_score = pdf.get("risk_score", 0)
        if pdf_score > 0:
            score += min(pdf_score, 60)
            for ind in pdf.get("indicators", []):
                indicators.append(f"PDF: {ind}")

    # --- Executable baseline ---
    exec_types = ("PE/MZ", "ELF", "Mach-O")
    if any(t in file_type.get("magic", "") for t in exec_types):
        score += 5
        indicators.append(f"Executable file: {file_type.get('magic')}")

    score = min(score, 100)
    level = "CRITICAL" if score >= 70 else "HIGH" if score >= 45 else "MEDIUM" if score >= 20 else "LOW"

    return {"score": score, "level": level, "indicators": indicators}
