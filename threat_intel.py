import os
import base64
import asyncio
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests as _requests

VT_BASE = "https://www.virustotal.com/api/v3"
URLSCAN_BASE = "https://urlscan.io/api/v1"
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1"
RDAP_BASE = "https://rdap.org/domain"


def _vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def vt_lookup(url: str) -> dict | None:
    # read key at call time so .env loaded after import is picked up
    api_key = os.environ.get("VT_API_KEY", "")
    if not api_key:
        return None
    try:
        resp = _requests.get(
            f"{VT_BASE}/urls/{_vt_url_id(url)}",
            headers={"x-apikey": api_key},
            timeout=10,
        )
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }
        if resp.status_code == 404:
            # not indexed yet — submit for background analysis
            _requests.post(
                f"{VT_BASE}/urls",
                headers={"x-apikey": api_key},
                data={"url": url},
                timeout=10,
            )
            print(f"VT: submitted {url} for analysis")
        else:
            print(f"VT: unexpected status {resp.status_code} for {url}")
        return None
    except Exception as e:
        print(f"VT: lookup failed: {e}")
        return None


def urlscan_lookup(url: str) -> dict | None:
    """search urlscan for existing scans of this domain. no key needed."""
    from urllib.parse import urlparse
    domain = urlparse(url).netloc
    if not domain:
        return None
    try:
        resp = _requests.get(
            f"{URLSCAN_BASE}/search/",
            params={"q": f"domain:{domain}", "size": 1},
            timeout=10,
        )
        if resp.status_code == 200:
            results = resp.json().get("results", [])
            if results:
                r = results[0]
                verdicts = r.get("verdicts", {}).get("overall", {})
                return {
                    "score": verdicts.get("score", 0),
                    "malicious": verdicts.get("malicious", False),
                    "uuid": r.get("task", {}).get("uuid", ""),
                }
        return None
    except Exception:
        return None


def urlhaus_lookup(url: str) -> dict | None:
    """check urlhaus (abuse.ch) for prior reports — free, no key needed."""
    try:
        resp = _requests.post(
            f"{URLHAUS_API}/url/",
            data={"url": url},
            timeout=8,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if data.get("query_status") == "no_results":
            return None
        return {
            "threat": data.get("threat", ""),
            "url_status": data.get("url_status", ""),
            "date_added": data.get("date_added", ""),
            "tags": data.get("tags") or [],
            "urlhaus_reference": data.get("urlhaus_reference", ""),
        }
    except Exception as e:
        print(f"URLhaus: lookup failed: {e}")
        return None


def domain_age_lookup(url: str) -> dict | None:
    """fetch domain registration date from RDAP and return age in days."""
    try:
        domain = urlparse(url).netloc.split(":")[0]
        if not domain or "." not in domain:
            return None
        # strip subdomain for RDAP
        parts = domain.split(".")
        root = ".".join(parts[-2:])

        resp = _requests.get(
            f"{RDAP_BASE}/{root}",
            headers={"Accept": "application/rdap+json"},
            timeout=8,
        )
        if resp.status_code != 200:
            return None

        for event in resp.json().get("events", []):
            if event.get("eventAction") == "registration":
                date_str = event.get("eventDate", "")
                if not date_str:
                    continue
                created = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                days_old = (datetime.now(timezone.utc) - created).days
                return {
                    "domain_created": date_str[:10],
                    "days_old": days_old,
                    "fresh": days_old < 30,
                }
    except Exception as e:
        print(f"RDAP: domain age lookup failed: {e}")
    return None


def vt_scan_file(path: str) -> dict | None:
    api_key = os.environ.get("VT_API_KEY", "")
    if not api_key or not os.path.exists(path):
        return None
    try:
        with open(path, "rb") as f:
            upload = _requests.post(
                f"{VT_BASE}/files",
                headers={"x-apikey": api_key},
                files={"file": (os.path.basename(path), f)},
                timeout=30,
            )
        if upload.status_code not in (200, 201):
            print(f"VT file upload: unexpected status {upload.status_code}")
            return None
        analysis_id = upload.json().get("data", {}).get("id", "")
        if not analysis_id:
            return None

        # poll for result — up to 60s
        for _ in range(6):
            import time; time.sleep(10)
            result = _requests.get(
                f"{VT_BASE}/analyses/{analysis_id}",
                headers={"x-apikey": api_key},
                timeout=10,
            )
            if result.status_code != 200:
                continue
            data = result.json().get("data", {})
            if data.get("attributes", {}).get("status") == "completed":
                stats = data["attributes"]["stats"]
                return {
                    "filename": os.path.basename(path),
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "analysis_id": analysis_id,
                }
        print(f"VT file scan: timed out waiting for {os.path.basename(path)}")
        return None
    except Exception as e:
        print(f"VT file scan failed: {e}")
        return None


async def run_threat_intel(url: str) -> dict:
    vt, us, urlhaus, domain_age = await asyncio.gather(
        asyncio.to_thread(vt_lookup, url),
        asyncio.to_thread(urlscan_lookup, url),
        asyncio.to_thread(urlhaus_lookup, url),
        asyncio.to_thread(domain_age_lookup, url),
    )
    return {"virustotal": vt, "urlscan": us, "urlhaus": urlhaus, "domain_age": domain_age}


def format_intel_section(intel: dict) -> str:
    """append threat intel block to an existing prompt string"""
    lines = ["\n\nExternal Threat Intelligence:"]

    vt = intel.get("virustotal")
    if vt:
        total = vt["malicious"] + vt["suspicious"] + vt["harmless"] + vt["undetected"]
        lines.append(
            f"VirusTotal: {vt['malicious']} malicious, {vt['suspicious']} suspicious "
            f"out of {total} engines"
        )
    else:
        lines.append("VirusTotal: no data (key not configured or URL not yet indexed)")

    us = intel.get("urlscan")
    if us:
        verdict = "malicious" if us["malicious"] else f"score {us['score']}"
        lines.append(f"URLScan.io: {verdict} — https://urlscan.io/result/{us['uuid']}/")
    else:
        lines.append("URLScan.io: no existing scan found")

    urlhaus = intel.get("urlhaus")
    if urlhaus:
        tags = ", ".join(urlhaus["tags"]) if urlhaus["tags"] else "none"
        lines.append(
            f"URLhaus: KNOWN MALICIOUS — threat={urlhaus['threat']}, "
            f"status={urlhaus['url_status']}, tags={tags}, "
            f"reported={urlhaus['date_added'][:10] if urlhaus['date_added'] else 'unknown'}"
        )
    else:
        lines.append("URLhaus: not in database")

    domain_age = intel.get("domain_age")
    if domain_age:
        fresh_flag = " ⚠ FRESH DOMAIN" if domain_age["fresh"] else ""
        lines.append(
            f"Domain registration: {domain_age['domain_created']} "
            f"({domain_age['days_old']} days old){fresh_flag}"
        )

    return "\n".join(lines)
