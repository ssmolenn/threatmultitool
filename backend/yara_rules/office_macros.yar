rule vba_macro_suspicious {
    meta:
        description = "Detects suspicious VBA macro patterns in Office documents"
        severity = "high"
        tags = "office,macro,vba"
    strings:
        $a = "AutoOpen" nocase
        $b = "Document_Open" nocase
        $c = "Workbook_Open" nocase
        $d = "Shell" nocase
        $e = "CreateObject" nocase
        $f = "WScript.Shell" nocase
        $g = "Chr(" nocase
        $h = "StrReverse" nocase
    condition:
        ($a or $b or $c) and 2 of ($d,$e,$f,$g,$h)
}

rule excel_4_macro {
    meta:
        description = "Detects Excel 4 XLM macro indicators"
        severity = "high"
        tags = "office,xlm,macro"
    strings:
        $a = "EXEC(" nocase
        $b = "CALL(" nocase
        $c = "REGISTER(" nocase
        $d = "xlm" nocase
        $e = "XLM"
    condition:
        2 of them
}
