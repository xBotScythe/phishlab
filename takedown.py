"""
generate pre-filled abuse report templates for a phishing run.
sources: rdap (registrar abuse contact), ipinfo.io (hosting asn), har (server ips)
"""
import json
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

import base64

import requests as _requests

RDAP_BASE = "https://rdap.org/domain"
IPINFO_BASE = "https://ipinfo.io"


def _vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _parse_vcard_field(vcardArray, field: str) -> str | None:
    if not vcardArray or len(vcardArray) < 2:
        return None
    for entry in vcardArray[1]:
        if entry[0] == field:
            return entry[3] if len(entry) > 3 else None
    return None


def _rdap_registrar(url: str) -> dict:
    domain = urlparse(url).netloc.split(":")[0]
    parts = domain.split(".")
    root = ".".join(parts[-2:])
    try:
        resp = _requests.get(
            f"{RDAP_BASE}/{root}",
            headers={"Accept": "application/rdap+json"},
            timeout=8,
        )
        if resp.status_code != 200:
            return {}
        data = resp.json()

        registrar_name = None
        abuse_email = None

        for entity in data.get("entities", []):
            if "registrar" not in entity.get("roles", []):
                continue
            registrar_name = _parse_vcard_field(entity.get("vcardArray"), "fn") or registrar_name
            for sub in entity.get("entities", []):
                if "abuse" in sub.get("roles", []):
                    abuse_email = (
                        _parse_vcard_field(sub.get("vcardArray"), "email")
                        or abuse_email
                    )

        return {
            "registrar": registrar_name,
            "abuse_email": abuse_email,
            "domain": root,
        }
    except Exception:
        return {}


def _server_ips_from_har(folder: str) -> list[str]:
    har_path = os.path.join(folder, "network_traffic.har")
    if not os.path.exists(har_path):
        return []
    try:
        with open(har_path, encoding="utf-8") as f:
            har = json.load(f)
        ips = []
        seen: set[str] = set()
        for entry in har.get("log", {}).get("entries", []):
            ip = entry.get("serverIPAddress", "")
            if ip and ip not in ("", "::1", "127.0.0.1") and ip not in seen:
                seen.add(ip)
                ips.append(ip)
        return ips
    except Exception:
        return []


def _ip_info(ip: str) -> dict:
    try:
        resp = _requests.get(f"{IPINFO_BASE}/{ip}/json", timeout=6)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}


def _is_cloudflare(org: str) -> bool:
    return "cloudflare" in org.lower() or "as13335" in org.lower()


def build_takedown(url: str, folder: str, run_meta: dict) -> dict:
    """
    returns {
      registrar: {name, abuse_email, domain},
      hosting: {ip, org, asn, country, is_cloudflare},
      templates: {registrar, hosting, cloudflare?},
      cloudflare_detected: bool,
    }
    """
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    domain = urlparse(url).netloc

    vt_malicious = run_meta.get("vt_malicious")
    kit = run_meta.get("kit_fingerprint") or ""

    vt_note = f"VirusTotal flags this URL as malicious ({vt_malicious} engines as of {date_str}): https://www.virustotal.com/gui/url/{_vt_url_id(url)}" if vt_malicious else ""
    kit_note = f"The page matches known phishing kit patterns ({kit})." if kit else ""

    registrar_data = _rdap_registrar(url)
    registrar_name = registrar_data.get("registrar") or "the registrar"
    abuse_email = registrar_data.get("abuse_email") or "abuse@<registrar>"
    root_domain = registrar_data.get("domain") or domain

    server_ips = _server_ips_from_har(folder)
    hosting_info: dict = {}
    cloudflare_detected = False

    for ip in server_ips:
        info = _ip_info(ip)
        org = info.get("org", "")
        if org:
            hosting_info = {
                "ip": ip,
                "org": org,
                "asn": org.split(" ")[0] if org else "",
                "country": info.get("country", ""),
                "is_cloudflare": _is_cloudflare(org),
            }
            if _is_cloudflare(org):
                cloudflare_detected = True
            break

    evidence_parts = [p for p in [vt_note, kit_note] if p]
    evidence_block = ("\n\n" + "\n".join(evidence_parts)) if evidence_parts else ""

    registrar_template = f"""To: {abuse_email}
Subject: Phishing page on {root_domain} — takedown request

Hi,

I'd like to report a phishing page on a domain registered through {registrar_name}. The page is impersonating a legitimate service to steal login credentials.

URL: {url}
Reported: {date_str}{evidence_block}

Could you please suspend or remove this domain? Happy to provide more details if needed."""

    hosting_template = ""
    if hosting_info:
        ip = hosting_info["ip"]
        provider = hosting_info["org"]
        hosting_template = f"""To: abuse@<{provider}>
Subject: Phishing page hosted at {ip} — takedown request

Hi,

I'd like to report a phishing page hosted on your network. It's impersonating a legitimate service to collect user credentials.

URL: {url}
IP: {ip}
Reported: {date_str}{evidence_block}

Could you take this content offline? Happy to provide more details if needed."""

    cloudflare_template = ""
    if cloudflare_detected:
        cloudflare_template = f"""To: abuse@cloudflare.com
Subject: Phishing page on {domain} — takedown request

Hi,

I'd like to report a phishing page that appears to be using Cloudflare. It's impersonating a legitimate service to steal user credentials.

URL: {url}
Reported: {date_str}{evidence_block}

Could you terminate services for this domain? Happy to provide more details if needed."""

    templates: dict = {"registrar": registrar_template}
    if hosting_template:
        templates["hosting"] = hosting_template
    if cloudflare_template:
        templates["cloudflare"] = cloudflare_template

    return {
        "registrar": registrar_data,
        "hosting": hosting_info,
        "cloudflare_detected": cloudflare_detected,
        "templates": templates,
    }
