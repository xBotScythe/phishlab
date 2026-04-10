import os
import base64
import asyncio
import requests as _requests

VT_BASE = "https://www.virustotal.com/api/v3"
URLSCAN_BASE = "https://urlscan.io/api/v1"


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


async def run_threat_intel(url: str) -> dict:
    vt, us = await asyncio.gather(
        asyncio.to_thread(vt_lookup, url),
        asyncio.to_thread(urlscan_lookup, url),
    )
    return {"virustotal": vt, "urlscan": us}


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

    return "\n".join(lines)
