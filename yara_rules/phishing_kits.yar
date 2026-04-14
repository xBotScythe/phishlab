// phishing kit detection rules for PhishLab
// scans detonated page DOM and JS artifacts

rule credential_form_with_exfil {
    meta:
        description = "form with password field posting to external or suspicious endpoint"
        severity = "high"
        category = "credential_harvesting"
    strings:
        $pass_input = /type\s*=\s*["']password["']/ nocase
        $form_action = /action\s*=\s*["']https?:\/\// nocase
        $form_post = /method\s*=\s*["']post["']/ nocase
    condition:
        $pass_input and ($form_action or $form_post)
}

rule email_hash_extraction {
    meta:
        description = "extracts victim email from URL hash or query params"
        severity = "high"
        category = "credential_harvesting"
    strings:
        $hash_check = "window.location.hash" nocase
        $param_email = /getParameter.*email/i
        $hash_sub = ".hash.substring(1)" nocase
        $atob_decode = /atob\s*\(/ nocase
        $email_placeholder = "{EMAIL}" nocase
    condition:
        ($hash_check or $hash_sub) and ($param_email or $email_placeholder or $atob_decode)
}

rule office365_phish {
    meta:
        description = "office 365 / microsoft login impersonation"
        severity = "critical"
        category = "brand_impersonation"
        brand = "microsoft"
    strings:
        $ms_logo = "microsoftlogo" nocase
        $o365_text = "Office 365" nocase
        $ms_signin = "Sign in to your account" nocase
        $ms_branding = "microsoft.com/images" nocase
        $outlook_brand = "Outlook" nocase
        $ms_login_form = "login.microsoftonline" nocase
        $pass_field = /type\s*=\s*["']password["']/ nocase
    condition:
        $pass_field and 2 of ($ms_logo, $o365_text, $ms_signin, $ms_branding, $outlook_brand, $ms_login_form)
}

rule google_phish {
    meta:
        description = "google / gmail login impersonation"
        severity = "critical"
        category = "brand_impersonation"
        brand = "google"
    strings:
        $goog_logo = "googlelogo" nocase
        $gmail_text = "Gmail" nocase
        $goog_signin = "Sign in with Google" nocase
        $goog_accounts = "accounts.google.com" nocase
        $goog_brand = "google.com/images" nocase
        $pass_field = /type\s*=\s*["']password["']/ nocase
    condition:
        $pass_field and 2 of ($goog_logo, $gmail_text, $goog_signin, $goog_accounts, $goog_brand)
}

rule adobe_document_lure {
    meta:
        description = "adobe document sharing / pdf viewer lure"
        severity = "high"
        category = "brand_impersonation"
        brand = "adobe"
    strings:
        $adobe_brand = "adobe" nocase
        $pdf_view = /view.*pdf/i
        $doc_share = /shared?\s+(a\s+)?document/i
        $acrobat = "acrobat" nocase
        $download_btn = /download.*document/i
        $adobeclean = "adobeclean" nocase
    condition:
        2 of them
}

rule banking_phish {
    meta:
        description = "banking / financial credential harvesting"
        severity = "critical"
        category = "brand_impersonation"
        brand = "banking"
    strings:
        $account_verify = /verify\s+(your\s+)?account/i
        $bank_login = /bank.*login/i
        $card_number = /card\s*number/i
        $cvv = /\bcvv\b/i
        $ssn = /social\s*security/i
        $routing = /routing\s*number/i
        $pin_field = /\bpin\b.*input/i
        $pass_field = /type\s*=\s*["']password["']/ nocase
    condition:
        $pass_field and 2 of ($account_verify, $bank_login, $card_number, $cvv, $ssn, $routing, $pin_field)
}

rule base64_obfuscated_payload {
    meta:
        description = "large base64 blob decoded at runtime — likely obfuscated kit"
        severity = "medium"
        category = "obfuscation"
    strings:
        $atob = "atob(" nocase
        $b64_blob = /[A-Za-z0-9+\/]{200,}={0,2}/
        $eval_call = "eval(" nocase
        $doc_write = "document.write(" nocase
    condition:
        $b64_blob and ($atob or $eval_call or $doc_write)
}

rule js_keylogger {
    meta:
        description = "javascript capturing keystrokes or input values"
        severity = "critical"
        category = "credential_harvesting"
    strings:
        $keydown = "addEventListener(\"keydown\"" nocase
        $keypress = "addEventListener(\"keypress\"" nocase
        $keyup = "addEventListener(\"keyup\"" nocase
        $input_event = "addEventListener(\"input\"" nocase
        $send_keys = /XMLHttpRequest|fetch\s*\(/ nocase
    condition:
        any of ($keydown, $keypress, $keyup, $input_event) and $send_keys
}

rule telegram_exfil {
    meta:
        description = "credentials exfiltrated to telegram bot"
        severity = "critical"
        category = "exfiltration"
    strings:
        $tg_api = "api.telegram.org/bot" nocase
        $tg_send = "sendMessage" nocase
        $tg_bot = /bot[0-9]{8,}:/ nocase
    condition:
        $tg_api or ($tg_send and $tg_bot)
}

rule discord_webhook_exfil {
    meta:
        description = "credentials exfiltrated to discord webhook"
        severity = "critical"
        category = "exfiltration"
    strings:
        $discord_hook = "discord.com/api/webhooks/" nocase
        $discordapp_hook = "discordapp.com/api/webhooks/" nocase
    condition:
        any of them
}

rule php_mailer_exfil {
    meta:
        description = "form posts to php handler — classic kit exfil pattern"
        severity = "high"
        category = "exfiltration"
    strings:
        $php_action = /action\s*=\s*["'][^"']*\.php["']/ nocase
        $post_method = /method\s*=\s*["']post["']/ nocase
        $pass_field = /type\s*=\s*["']password["']/ nocase
    condition:
        all of them
}

rule evilproxy_indicators {
    meta:
        description = "evilproxy reverse proxy phishing kit markers"
        severity = "critical"
        category = "kit_signature"
        kit = "evilproxy"
    strings:
        $proxy_header = "X-Proxy-" nocase
        $mitm_cookie = "__ev_proxy" nocase
        $session_relay = /session.*relay/i
        $transparent_proxy = /transparent.*proxy/i
    condition:
        2 of them
}

rule sixteen_shop_kit {
    meta:
        description = "16shop phishing kit indicators"
        severity = "critical"
        category = "kit_signature"
        kit = "16shop"
    strings:
        $sixteen = "16shop" nocase
        $antibot = /antibot.*16/i
        $kit_panel = "panel/admin" nocase
        $result_file = "result.txt" nocase
        $blocker_js = "blocker.js" nocase
    condition:
        2 of them
}

rule storm1575_dadsec {
    meta:
        description = "storm-1575 / dadsec phishing kit"
        severity = "critical"
        category = "kit_signature"
        kit = "storm-1575"
    strings:
        $dadsec = "dadsec" nocase
        $cf_turnstile = "challenges.cloudflare.com/turnstile" nocase
        $captcha_gate = /captcha.*verify/i
        $multi_step = /step[_-]?[0-9]/ nocase
    condition:
        $dadsec or ($cf_turnstile and $captcha_gate and $multi_step)
}

rule greatness_kit {
    meta:
        description = "greatness phishing-as-a-service kit"
        severity = "critical"
        category = "kit_signature"
        kit = "greatness"
    strings:
        $greatness = "greatness" nocase
        $mfa_relay = /mfa.*relay/i
        $token_capture = /capture.*token/i
        $session_hijack = /session.*hijack/i
    condition:
        $greatness or 2 of ($mfa_relay, $token_capture, $session_hijack)
}

rule nakivo_download_lure {
    meta:
        description = "file download lure — zip/exe/html attachment bait"
        severity = "high"
        category = "malware_delivery"
    strings:
        $download_btn = /download.*\.(zip|exe|msi|html|iso|img)/i
        $href_download = /href\s*=\s*["'][^"']*\.(zip|exe|msi|html|iso|img)["']/i
        $blob_download = "blob:" nocase
        $file_save = "saveAs" nocase
    condition:
        any of them
}

rule htaccess_cloaking {
    meta:
        description = "server-side cloaking redirecting bots vs victims"
        severity = "medium"
        category = "evasion"
    strings:
        $ua_check = /navigator\.userAgent.*bot/i
        $referer_check = /document\.referrer/i
        $redirect_bot = /location\s*=.*google|bing|yahoo/i
    condition:
        $ua_check and ($referer_check or $redirect_bot)
}

rule crypto_wallet_phish {
    meta:
        description = "cryptocurrency wallet / seed phrase harvesting"
        severity = "critical"
        category = "credential_harvesting"
        brand = "crypto"
    strings:
        $seed_phrase = /seed\s*phrase/i
        $recovery_phrase = /recovery\s*phrase/i
        $private_key = /private\s*key/i
        $wallet_connect = "walletconnect" nocase
        $metamask = "metamask" nocase
        $mnemonic = "mnemonic" nocase
        $twelve_words = /12\s*words/i
    condition:
        2 of them
}
