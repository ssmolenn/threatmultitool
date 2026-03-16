rule ransomware_shadow_copy_deletion {
    meta:
        description = "Detects shadow copy / backup deletion commands used by ransomware"
        severity = "critical"
        tags = "ransomware,defense_evasion,backup_deletion"
    strings:
        $a = "vssadmin" nocase
        $b = "shadowcopy" nocase
        $c = "wbadmin" nocase
        $d = "bcdedit" nocase
        $e = "recoveryenabled" nocase
        $f = "delete shadows" nocase
        $g = "delete catalog" nocase
        $h = "Win32_ShadowCopy" nocase
    condition:
        2 of them
}

rule ransomware_file_extension_targeting {
    meta:
        description = "Detects strings targeting common ransomware file extensions"
        severity = "high"
        tags = "ransomware,file_targeting"
    strings:
        $doc  = ".docx" nocase
        $xls  = ".xlsx" nocase
        $pdf  = ".pdf" nocase
        $jpg  = ".jpg" nocase
        $db   = ".sql" nocase
        $bak  = ".bak" nocase
        $enc  = ".encrypted" nocase
        $lock = ".locked" nocase
        $pay  = "ransom" nocase
        $pay2 = "bitcoin" nocase
        $pay3 = "decrypt" nocase
        $pay4 = "wallet" nocase
    condition:
        ($enc or $lock) and ($pay or $pay2 or $pay3 or $pay4)
        or (5 of ($doc,$xls,$pdf,$jpg,$db,$bak) and ($pay or $pay2 or $pay3))
}

rule ransomware_note_content {
    meta:
        description = "Detects ransomware note content patterns"
        severity = "critical"
        tags = "ransomware,extortion"
    strings:
        $a = "Your files have been encrypted" nocase
        $b = "All your files are encrypted" nocase
        $c = "your personal files are encrypted" nocase
        $d = "files were encrypted" nocase
        $e = "pay the ransom" nocase
        $f = "to decrypt your files" nocase
        $g = "send bitcoin" nocase
        $h = "send btc" nocase
        $i = "unique decryption key" nocase
        $j = "recovery key" nocase
        $k = ".onion" nocase
        $l = "do not rename" nocase
    condition:
        2 of them
}

rule ransomware_crypto_api_combo {
    meta:
        description = "Detects combination of crypto API + file enumeration (ransomware pattern)"
        severity = "critical"
        tags = "ransomware,crypto,file_operations"
    strings:
        $crypto1 = "CryptEncrypt" nocase
        $crypto2 = "BCryptEncrypt" nocase
        $crypto3 = "CryptGenKey" nocase
        $crypto4 = "BCryptOpenAlgorithmProvider" nocase
        $enum1   = "FindFirstFileW" nocase
        $enum2   = "FindFirstFileA" nocase
        $enum3   = "FindNextFileW" nocase
        $del1    = "DeleteFileW" nocase
        $del2    = "MoveFileExW" nocase
    condition:
        1 of ($crypto*) and 1 of ($enum*) and 1 of ($del*)
}

rule suspicious_wiper {
    meta:
        description = "Detects disk/MBR wiping patterns used by destructive malware"
        severity = "critical"
        tags = "wiper,destructive"
    strings:
        $mbr1 = "\\\\.\\\\.PhysicalDrive0" nocase
        $mbr2 = "\\\\.\\PhysicalDrive" nocase
        $mbr3 = "IOCTL_DISK_SET_DRIVE_LAYOUT" nocase
        $wipe1 = "DeviceIoControl" nocase
        $wipe2 = "WriteFile" nocase
    condition:
        ($mbr1 or $mbr2 or $mbr3) and ($wipe1 or $wipe2)
}

rule keylogger_indicators {
    meta:
        description = "Detects keylogger API patterns"
        severity = "high"
        tags = "keylogger,spyware,credential_theft"
    strings:
        $a = "SetWindowsHookEx" nocase
        $b = "GetAsyncKeyState" nocase
        $c = "GetKeyState" nocase
        $d = "GetKeyboardState" nocase
        $e = "MapVirtualKey" nocase
        $f = "RegisterHotKey" nocase
        $g = "keylog" nocase
        $h = "keystroke" nocase
    condition:
        3 of them
}

rule infostealer_indicators {
    meta:
        description = "Detects credential/data stealing patterns"
        severity = "high"
        tags = "infostealer,credential_theft"
    strings:
        $browser1 = "Login Data" nocase
        $browser2 = "Cookies" nocase
        $browser3 = "Web Data" nocase
        $browser4 = "Local State" nocase
        $browser5 = "\\Google\\Chrome\\" nocase
        $browser6 = "\\Mozilla\\Firefox\\" nocase
        $wallet1  = "wallet.dat" nocase
        $wallet2  = "Electrum" nocase
        $wallet3  = "MetaMask" nocase
        $cred1    = "DPAPI" nocase
        $cred2    = "CryptUnprotectData" nocase
        $cred3    = "NCryptOpenKey" nocase
    condition:
        3 of ($browser*) or 2 of ($wallet*) or (1 of ($cred*) and 2 of ($browser*))
}
