"""
parse iocs from run artifacts and export as stix 2.1 json or csv.
sources: network_traffic.har (network), report.md (llm ioc table)
"""
import csv
import io
import json
import os
import re
import uuid
import datetime


def _extract_from_har(folder: str) -> list[dict]:
    iocs = []
    har_path = os.path.join(folder, "network_traffic.har")
    if not os.path.exists(har_path):
        return iocs
    try:
        with open(har_path, encoding="utf-8") as f:
            har = json.load(f)
        for entry in har.get("log", {}).get("entries", []):
            req = entry.get("request", {})
            url = req.get("url", "")
            if url and url.startswith("http"):
                iocs.append({"type": "url", "value": url})
            # remote ip in response
            ip = entry.get("serverIPAddress", "")
            if ip and ip not in ("", "::1", "127.0.0.1"):
                iocs.append({"type": "ip", "value": ip})
    except Exception:
        pass
    return iocs


def _extract_from_report(report: str) -> list[dict]:
    """parse the ioc markdown table from the llm report"""
    iocs = []
    if not report:
        return iocs

    # find the ioc section
    ioc_section = re.search(
        r"Indicators of Compromise.*?(?=##|\Z)", report, re.DOTALL | re.IGNORECASE
    )
    if not ioc_section:
        return iocs

    section = ioc_section.group(0)

    # extract table rows — grab values from second column (indicator value)
    for row in re.finditer(r"\|([^|]+)\|([^|]+)\|", section):
        raw_value = row.group(2).strip().strip("`").strip()
        if not raw_value or raw_value.lower() in ("indicator value", "value", "---"):
            continue

        # classify by content
        if re.match(r"https?://", raw_value):
            iocs.append({"type": "url", "value": raw_value})
        elif re.match(r"(\d{1,3}\.){3}\d{1,3}", raw_value):
            iocs.append({"type": "ip", "value": raw_value})
        elif re.match(r"[a-f0-9]{32,64}$", raw_value, re.IGNORECASE):
            iocs.append({"type": "hash", "value": raw_value})
        else:
            # treat as domain/generic indicator
            iocs.append({"type": "domain", "value": raw_value})

    return iocs


def collect_iocs(folder: str, target_url: str, report: str) -> list[dict]:
    """gather unique iocs from all available sources"""
    iocs = []
    if target_url:
        iocs.append({"type": "url", "value": target_url})
    iocs += _extract_from_har(folder)
    iocs += _extract_from_report(report)

    # dedupe by (type, value)
    seen = set()
    unique = []
    for ioc in iocs:
        key = (ioc["type"], ioc["value"])
        if key not in seen:
            seen.add(key)
            unique.append(ioc)
    return unique


def export_csv(iocs: list[dict], run_id: str) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["type", "value", "run_id"])
    writer.writeheader()
    for ioc in iocs:
        writer.writerow({"type": ioc["type"], "value": ioc["value"], "run_id": run_id})
    return output.getvalue()


def export_stix(iocs: list[dict], run_id: str, target_url: str) -> str:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    objects = []

    for ioc in iocs:
        t = ioc["type"]
        v = ioc["value"]
        obj_id = f"phishlab--{uuid.uuid5(uuid.NAMESPACE_URL, v)}"

        if t == "url":
            objects.append({"type": "url", "spec_version": "2.1", "id": obj_id, "value": v})
        elif t == "domain":
            objects.append({"type": "domain-name", "spec_version": "2.1", "id": obj_id, "value": v})
        elif t == "ip":
            objects.append({"type": "ipv4-addr", "spec_version": "2.1", "id": obj_id, "value": v})
        elif t == "hash":
            objects.append({
                "type": "file",
                "spec_version": "2.1",
                "id": obj_id,
                "hashes": {"SHA-256" if len(v) == 64 else "MD5": v},
            })

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "created": now,
        "objects": objects,
    }
    return json.dumps(bundle, indent=2)
