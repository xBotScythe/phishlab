# scan detonation artifacts against phishing kit yara rules
import os
import tempfile

import yara

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_rules")
MAX_SCAN_SIZE = 2 * 1024 * 1024  # 2MB — truncate huge DOM dumps

# compile once at import time
_compiled = None


def _get_rules() -> yara.Rules | None:
    global _compiled
    if _compiled is not None:
        return _compiled
    rule_files = {}
    for f in os.listdir(RULES_DIR):
        if f.endswith((".yar", ".yara")):
            namespace = f.rsplit(".", 1)[0]
            rule_files[namespace] = os.path.join(RULES_DIR, f)
    if not rule_files:
        return None
    _compiled = yara.compile(filepaths=rule_files)
    return _compiled


def scan_folder(folder: str) -> list[dict]:
    """scan html/js artifacts in a detonation folder. returns list of matches."""
    rules = _get_rules()
    if not rules:
        return []

    # files worth scanning
    targets = [
        ("page_dom.html", "html"),
        ("extracted_iocs.json", "iocs"),
        ("js_runtime.json", "js_runtime"),
    ]

    matches = []
    seen = set()

    for filename, source in targets:
        path = os.path.join(folder, filename)
        if not os.path.exists(path):
            continue

        try:
            # truncate oversized files to avoid yara timeouts
            file_size = os.path.getsize(path)
            if file_size > MAX_SCAN_SIZE:
                with open(path, "rb") as f:
                    data = f.read(MAX_SCAN_SIZE)
                hits = rules.match(data=data, timeout=30)
            else:
                hits = rules.match(path, timeout=30)
        except yara.TimeoutError:
            print(f"YARA: timeout scanning {filename}")
            continue
        except Exception as e:
            print(f"YARA: error scanning {filename}: {e}")
            continue

        for hit in hits:
            # dedupe same rule across files
            if hit.rule in seen:
                continue
            seen.add(hit.rule)

            meta = hit.meta
            matches.append({
                "rule": hit.rule,
                "severity": meta.get("severity", "medium"),
                "category": meta.get("category", "unknown"),
                "description": meta.get("description", ""),
                "kit": meta.get("kit", ""),
                "brand": meta.get("brand", ""),
                "source_file": filename,
            })

    if matches:
        names = [m["rule"] for m in matches]
        print(f"YARA: {len(matches)} matches in {os.path.basename(folder)}: {', '.join(names)}")

    return matches


def format_for_prompt(matches: list[dict]) -> str:
    """format yara hits as context for the llm prompt"""
    if not matches:
        return ""

    lines = ["YARA Kit Detection:"]
    for m in matches:
        kit_note = f" (kit: {m['kit']})" if m.get("kit") else ""
        brand_note = f" [brand: {m['brand']}]" if m.get("brand") else ""
        lines.append(f"- {m['rule']}: {m['description']}{kit_note}{brand_note} ({m['severity']})")

    return "\n".join(lines)
