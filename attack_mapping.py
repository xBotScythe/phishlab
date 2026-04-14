# deterministic MITRE ATT&CK technique mapping for phishing verdicts
# maps delivery vectors, user interactions, YARA hits, and form exfil to technique IDs

# delivery vector -> initial access techniques
VECTOR_MAP = {
    "email_link":       [("T1566.002", "Phishing: Spearphishing Link")],
    "sms":              [("T1566.002", "Phishing: Spearphishing Link"), ("T1660", "Phishing (Mobile)")],
    "ad_redirect":      [("T1583.008", "Acquire Infrastructure: Malvertising")],
    "search_poisoning": [("T1608.005", "Stage Capabilities: SEO Poisoning")],
    "social_media":     [("T1566.003", "Phishing: Spearphishing via Service")],
    "qr_code":          [("T1566.002", "Phishing: Spearphishing Link")],
    "redirect_chain":   [("T1204.001", "User Execution: Malicious Link")],
}

# user interaction -> execution / collection techniques
INTERACTION_MAP = {
    "credential_entry":   [("T1056.002", "Input Capture: GUI Input Capture"),
                           ("T1078",     "Valid Accounts")],
    "file_download":      [("T1204.002", "User Execution: Malicious File")],
    "oauth_grant":        [("T1550.001", "Use Alternate Authentication: Application Access Token")],
    "mfa_relay":          [("T1111",     "Multi-Factor Authentication Interception")],
    "seed_phrase_entry":  [("T1056.002", "Input Capture: GUI Input Capture")],
    "browser_extension":  [("T1176",     "Browser Extensions")],
}

# YARA category -> techniques
YARA_CATEGORY_MAP = {
    "credential_harvesting": [("T1056.002", "Input Capture: GUI Input Capture"),
                              ("T1078",     "Valid Accounts")],
    "brand_impersonation":   [("T1036.005", "Masquerading: Match Legitimate Name or Location")],
    "exfiltration":          [("T1041",     "Exfiltration Over C2 Channel")],
    "obfuscation":           [("T1027",     "Obfuscated Files or Information")],
    "malware_delivery":      [("T1204.002", "User Execution: Malicious File")],
    "evasion":               [("T1036",     "Masquerading")],
    "kit_signature":         [("T1583.001", "Acquire Infrastructure: Domains")],
}

# exfil endpoint patterns -> techniques
EXFIL_PATTERNS = {
    "telegram":  [("T1567.002", "Exfiltration Over Web Service: Exfiltration to Cloud Storage"),
                  ("T1071.001", "Application Layer Protocol: Web Protocols")],
    "discord":   [("T1567.002", "Exfiltration Over Web Service: Exfiltration to Cloud Storage")],
    "php":       [("T1041",     "Exfiltration Over C2 Channel")],
}


def map_techniques(verdict: dict, yara_matches: list[dict] = None,
                   form_data: dict = None) -> list[dict]:
    """map verdict + yara + form data to ATT&CK technique IDs. returns deduplicated list."""
    seen = set()
    techniques = []

    def _add(tid: str, name: str, source: str):
        if tid not in seen:
            seen.add(tid)
            techniques.append({"id": tid, "name": name, "source": source})

    # delivery vector
    vector = verdict.get("delivery_vector", "").lower().replace(" ", "_")
    for tid, name in VECTOR_MAP.get(vector, []):
        _add(tid, name, f"delivery vector: {vector}")

    # user interaction
    interaction = verdict.get("user_interaction", "").lower().replace(" ", "_")
    for tid, name in INTERACTION_MAP.get(interaction, []):
        _add(tid, name, f"user interaction: {interaction}")

    # always add the base phishing technique for non-benign verdicts
    severity = verdict.get("severity", "medium")
    if severity not in ("benign",):
        _add("T1566", "Phishing", "verdict severity")

    # credential harvesting implied by form exfil
    if form_data:
        exfil_url = ""
        submission = form_data.get("submission")
        if submission:
            exfil_url = submission.get("url", "").lower()

        if exfil_url:
            _add("T1041", "Exfiltration Over C2 Channel", "form exfil endpoint")

            if "telegram" in exfil_url:
                for tid, name in EXFIL_PATTERNS["telegram"]:
                    _add(tid, name, "telegram exfil")
            elif "discord" in exfil_url:
                for tid, name in EXFIL_PATTERNS["discord"]:
                    _add(tid, name, "discord exfil")
            elif ".php" in exfil_url:
                for tid, name in EXFIL_PATTERNS["php"]:
                    _add(tid, name, "php handler exfil")

        if form_data.get("fields_filled"):
            _add("T1056.002", "Input Capture: GUI Input Capture", "form credential capture")

    # YARA rule categories
    if yara_matches:
        for match in yara_matches:
            category = match.get("category", "")
            for tid, name in YARA_CATEGORY_MAP.get(category, []):
                _add(tid, name, f"yara: {match.get('rule', '')}")

            # specific kit signatures
            kit = match.get("kit", "")
            if kit:
                _add("T1583.001", "Acquire Infrastructure: Domains", f"kit: {kit}")

    return techniques


def format_for_display(techniques: list[dict]) -> str:
    """format techniques as compact text for API/frontend"""
    if not techniques:
        return ""
    return ", ".join(f"{t['id']}" for t in techniques)


def enrich_stix_bundle(bundle: dict, techniques: list[dict], target_url: str) -> dict:
    """add ATT&CK attack-pattern objects and relationships to a STIX bundle"""
    import uuid as _uuid

    objects = bundle.get("objects", [])

    for tech in techniques:
        pattern_id = f"attack-pattern--{_uuid.uuid5(_uuid.NAMESPACE_URL, tech['id'])}"
        objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": pattern_id,
            "name": tech["name"],
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": tech["id"],
            }],
        })

        # relate the target URL to this technique
        if target_url:
            target_id = f"phishlab--{_uuid.uuid5(_uuid.NAMESPACE_URL, target_url)}"
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{_uuid.uuid4()}",
                "relationship_type": "uses",
                "source_ref": target_id,
                "target_ref": pattern_id,
            })

    bundle["objects"] = objects
    return bundle
