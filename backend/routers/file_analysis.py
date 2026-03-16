import asyncio
from fastapi import APIRouter, UploadFile, File, HTTPException

from services.file_analyzer import compute_hashes, detect_file_type, extract_strings, extract_metadata
from services.entropy_analyzer import analyze_entropy
from services.pe_analyzer import analyze_pe_imports, analyze_script, analyze_archive
from services.pdf_analyzer import analyze_pdf
from services.yara_scanner import scan as yara_scan
from integrations.virustotal import lookup_file
from integrations.malwarebazaar import lookup_hash as mb_lookup
from integrations.urlhaus import lookup_hash as urlhaus_lookup
from config import settings

router = APIRouter(prefix="/api/file", tags=["file"])

MAX_BYTES = settings.max_file_size_mb * 1024 * 1024

SCRIPT_EXTENSIONS = {"ps1", "psm1", "js", "jse", "vbs", "vbe", "bat", "cmd", "hta", "wsf"}
ARCHIVE_EXTENSIONS = {"zip", "jar", "apk", "docx", "xlsx", "pptx", "odt", "ods"}


@router.post("/analyze")
async def analyze_file(file: UploadFile = File(...)):
    data = await file.read()
    if len(data) > MAX_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds {settings.max_file_size_mb}MB limit")
    if len(data) == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    filename = file.filename or "unknown"
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    # Core analysis (all local, fast)
    hashes = compute_hashes(data)
    file_type = detect_file_type(data, filename)
    strings = extract_strings(data)
    metadata = extract_metadata(data, filename, file_type)
    entropy = analyze_entropy(data, file_type)
    yara_result = yara_scan(data)

    # PE-specific analysis
    pe_analysis = None
    magic = file_type.get("magic", "")
    if "PE" in magic or "MZ" in magic or ext in ("exe", "dll", "sys", "ocx"):
        pe_analysis = analyze_pe_imports(data)

    # Script analysis
    script_analysis = None
    if ext in SCRIPT_EXTENSIONS:
        script_analysis = analyze_script(data, filename)

    # Archive analysis
    archive_analysis = None
    if ext in ARCHIVE_EXTENSIONS or "ZIP" in magic:
        archive_analysis = analyze_archive(data, filename)

    # PDF-specific analysis
    pdf_analysis = None
    if ext == "pdf" or "PDF" in magic or data[:4] == b"%PDF":
        pdf_analysis = analyze_pdf(data)

    # External lookups (async, parallel)
    vt_result, mb_result, urlhaus_result = await asyncio.gather(
        lookup_file(hashes["sha256"]),
        mb_lookup(hashes["sha256"]),
        urlhaus_lookup(hashes["sha256"]),
        return_exceptions=True,
    )
    if isinstance(vt_result, Exception):
        vt_result = {"error": str(vt_result)}
    if isinstance(mb_result, Exception):
        mb_result = {"error": str(mb_result)}
    if isinstance(urlhaus_result, Exception):
        urlhaus_result = {"error": str(urlhaus_result)}

    # Risk assessment
    risk = _assess_risk(file_type, vt_result, mb_result, urlhaus_result,
                        yara_result, strings, entropy, pe_analysis, script_analysis, pdf_analysis)

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
        "pe_analysis": pe_analysis,
        "script_analysis": script_analysis,
        "archive_analysis": archive_analysis,
        "pdf_analysis": pdf_analysis,
        "metadata": metadata,
        "strings": strings,
        "yara": yara_result,
        "risk_assessment": risk,
    }


def _assess_risk(file_type, vt, mb, urlhaus, yara, strings, entropy, pe, script, pdf=None) -> dict:
    score = 0
    indicators = []

    # VT detections
    malicious = vt.get("malicious", 0) if isinstance(vt, dict) else 0
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

    # MalwareBazaar
    if isinstance(mb, dict) and mb.get("found"):
        score += 80
        sig = mb.get("signature", "unknown family")
        indicators.append(f"MalwareBazaar: KNOWN MALWARE — family: {sig}")

    # URLhaus
    if isinstance(urlhaus, dict) and urlhaus.get("found"):
        score += 60
        threat = urlhaus.get("signature") or urlhaus.get("file_type", "")
        indicators.append(f"URLhaus: Found in malware payload database ({threat})")

    # Extension mismatch
    if not file_type.get("extension_match", True):
        score += 35
        indicators.append(
            f"Extension mismatch: .{file_type.get('declared_extension')} "
            f"vs actual type '{file_type.get('magic')}'"
        )

    # Entropy
    overall_entropy = entropy.get("overall", {})
    ent_level = overall_entropy.get("level", "")
    if ent_level == "CRITICAL":
        score += 40
        indicators.append(f"Entropy CRITICAL ({overall_entropy.get('entropy')}) — likely packed/encrypted payload")
    elif ent_level == "HIGH":
        score += 20
        indicators.append(f"High entropy ({overall_entropy.get('entropy')}) — possible packer or encryption")

    # Suspicious PE sections
    for sec in entropy.get("sections", []):
        if sec.get("wx_section"):
            score += 25
            indicators.append(f"Write+Execute PE section '{sec.get('name')}' — shellcode injection indicator")
        if sec.get("suspicious_name"):
            score += 20
            indicators.append(sec["suspicious_name"])
        if sec.get("level") == "CRITICAL":
            score += 15
            indicators.append(f"Packed/encrypted PE section '{sec.get('name')}' (entropy {sec.get('entropy')})")

    # PE ransomware indicators
    if pe and pe.get("ransomware_indicators"):
        for ind in pe["ransomware_indicators"]:
            score += 20
            indicators.append(f"PE: {ind}")

    # Script analysis
    if script and script.get("indicators"):
        score += min(script.get("risk_score", 0), 60)
        for ind in script["indicators"]:
            indicators.append(f"Script: {ind}")

    # YARA matches
    yara_matches = yara.get("matches", [])
    for m in yara_matches:
        sev = m.get("meta", {}).get("severity", "medium")
        pts = {"critical": 40, "high": 25, "medium": 15}.get(sev, 10)
        score += pts
        indicators.append(f"YARA: {m['rule']} [{sev.upper()}]")

    # Suspicious strings
    if strings.get("suspicious_commands"):
        score += 15
        indicators.append(f"Suspicious command strings: {len(strings['suspicious_commands'])} found")
    if strings.get("base64_blobs"):
        score += 10
        indicators.append(f"Large Base64 blobs: {len(strings['base64_blobs'])}")

    # PDF-specific risk
    if pdf and not pdf.get("error"):
        pdf_score = pdf.get("risk_score", 0)
        if pdf_score > 0:
            score += min(pdf_score, 60)
            for ind in pdf.get("indicators", []):
                indicators.append(f"PDF: {ind}")

    # Executable type
    exec_types = ("PE/MZ", "ELF", "Mach-O")
    if any(t in file_type.get("magic", "") for t in exec_types):
        score += 5
        indicators.append(f"Executable file: {file_type.get('magic')}")

    score = min(score, 100)
    if score >= 70:
        level = "CRITICAL"
    elif score >= 45:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {"score": score, "level": level, "indicators": indicators}
