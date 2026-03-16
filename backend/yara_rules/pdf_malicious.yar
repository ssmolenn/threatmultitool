rule pdf_javascript_with_openaction {
    meta:
        description = "PDF with JavaScript and OpenAction — auto-executes on open"
        severity = "critical"
        tags = "pdf,javascript,exploit"
    strings:
        $js     = "/JavaScript" nocase
        $js2    = "/JS" nocase
        $action = "/OpenAction" nocase
    condition:
        ($js or $js2) and $action
}

rule pdf_launch_action {
    meta:
        description = "PDF with /Launch action — can execute external programs"
        severity = "critical"
        tags = "pdf,launch,rce"
    strings:
        $a = "/Launch" nocase
        $b = "/Win" nocase
        $c = "/Unix" nocase
        $d = "/F " nocase
    condition:
        $a and ($b or $c or $d)
}

rule pdf_suspicious_js_patterns {
    meta:
        description = "PDF containing known malicious JavaScript exploitation patterns"
        severity = "high"
        tags = "pdf,javascript,exploit"
    strings:
        $eval      = "eval(" nocase
        $unescape  = "unescape(" nocase
        $spray     = "util.printf" nocase
        $collab    = "Collab.collectEmailInfo" nocase
        $media     = "media.newPlayer" nocase
        $spell     = "spell.customDictionaryOpen" nocase
        $getAnnots = "getAnnots" nocase
    condition:
        2 of them
}

rule pdf_embedded_executable {
    meta:
        description = "PDF with embedded executable file"
        severity = "critical"
        tags = "pdf,embedded,dropper"
    strings:
        $embed = "/EmbeddedFile" nocase
        $mz    = "MZ"
        $pe    = "PE\x00\x00"
        $exe   = ".exe" nocase
        $dll   = ".dll" nocase
    condition:
        $embed and ($mz or $pe or $exe or $dll)
}

rule pdf_jbig2_exploit {
    meta:
        description = "PDF with JBIG2Decode filter — associated with CVE-2009-0658"
        severity = "high"
        tags = "pdf,cve,jbig2"
    strings:
        $a = "/JBIG2Decode" nocase
        $b = "/JavaScript" nocase
        $c = "/OpenAction" nocase
    condition:
        $a and ($b or $c)
}

rule pdf_obfuscated_streams {
    meta:
        description = "PDF with multiple encoding layers — obfuscation indicator"
        severity = "medium"
        tags = "pdf,obfuscation"
    strings:
        $a = "/ASCIIHexDecode" nocase
        $b = "/ASCII85Decode" nocase
        $c = "/FlateDecode" nocase
        $d = "/LZWDecode" nocase
        $e = "/ObjStm" nocase
    condition:
        3 of them
}

rule pdf_xfa_with_js {
    meta:
        description = "PDF with XFA forms and JavaScript — used in targeted attacks"
        severity = "high"
        tags = "pdf,xfa,javascript"
    strings:
        $xfa = "/XFA" nocase
        $js  = "/JavaScript" nocase
        $js2 = "/JS" nocase
    condition:
        $xfa and ($js or $js2)
}
