rule phishing_html_form {
    meta:
        description = "Detects phishing-style HTML credential harvest forms"
        severity = "medium"
        tags = "phishing,html,form"
    strings:
        $form = "<form" nocase
        $pass = "type=\"password\"" nocase
        $action_ext = "action=\"http" nocase
        $hidden = "type=\"hidden\"" nocase
        $brand1 = "paypal" nocase
        $brand2 = "microsoft" nocase
        $brand3 = "apple" nocase
        $brand4 = "google" nocase
        $brand5 = "amazon" nocase
    condition:
        $form and $pass and ($action_ext or $hidden) and 1 of ($brand1,$brand2,$brand3,$brand4,$brand5)
}

rule obfuscated_javascript {
    meta:
        description = "Detects heavily obfuscated JavaScript"
        severity = "medium"
        tags = "javascript,obfuscation"
    strings:
        $eval = /eval\s*\(/ nocase
        $unescape = "unescape(" nocase
        $fromCharCode = "fromCharCode" nocase
        $atob = "atob(" nocase
        $long_var = /var [a-zA-Z_$]{1,3}=['"][A-Za-z0-9+\/=]{100,}['"]/
    condition:
        2 of them
}
