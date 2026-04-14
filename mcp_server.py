from mcp.server.fastmcp import FastMCP
import json
from bs4 import BeautifulSoup
import os
import re
import ssl
import socket
from difflib import SequenceMatcher
from urllib.parse import urlparse
from datetime import datetime

mcp = FastMCP("phishing_cage")

# resolve once at startup
BASE_DIR = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "CageDrop"))


def is_safe_path(filepath: str) -> bool:
    """reject path traversal attempts"""
    try:
        target = os.path.realpath(os.path.abspath(filepath))
        return target.startswith(BASE_DIR)
    except Exception:
        return False


CTA_KEYWORDS = ["download", "invoice", "account", "update", "verify", "login", "signin", "unlock", "security"]
RECREATIONAL_KEYWORDS = [
    "portfolio", "resume", "personal project", "hobby", "blog",
    "my site", "welcome to my", "coming soon", "under construction",
    "guestbook", "gallery", "handmade", "built with"
]


def _compress_url(url: str, keep_params: bool = False) -> str:
    """strip query params unless flagged to keep them"""
    if keep_params:
        return url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


@mcp.tool()
def analyze_har(filepath: str) -> str:
    """extract network calls from har capture, compressed for llm context"""
    if not is_safe_path(filepath):
        return "error: path outside allowed directory"
    if not os.path.exists(filepath):
        return "file not found"

    with open(filepath, 'r') as f:
        har_data = json.load(f)

    skip_ext = (".jpg", ".png", ".css", ".woff", ".woff2", ".gif", ".ico", ".svg", ".ttf", ".eot")

    interesting = []   # redirects, posts, errors - keep full detail
    routine = {}       # normal GETs grouped by domain

    for entry in har_data.get("log", {}).get("entries", []):
        req = entry.get("request", {})
        res = entry.get("response", {})
        url = req.get("url", "")
        method = req.get("method", "GET")
        status = res.get("status", 0)
        redirect = res.get("redirectURL", "")

        if any(url.lower().endswith(ext) for ext in skip_ext):
            continue

        # keep full detail for interesting entries (redirects, posts, errors)
        is_interesting = method != "GET" or redirect or status >= 300

        if is_interesting:
            interesting.append({
                "method": method,
                "url": _compress_url(url, keep_params=True),
                "status": status,
                "redirect_url": redirect
            })
        else:
            # group routine GETs by domain
            try:
                domain = urlparse(url).netloc
            except Exception:
                domain = "unknown"
            if domain not in routine:
                routine[domain] = {"count": 0, "sample_path": ""}
            routine[domain]["count"] += 1
            if not routine[domain]["sample_path"]:
                routine[domain]["sample_path"] = urlparse(url).path

    # build compact output
    result = {
        "notable_requests": interesting[:30],
        "routine_domains": {
            domain: f"{info['count']} requests (e.g. {info['sample_path']})"
            for domain, info in routine.items()
        },
        "total_entries": len(interesting) + sum(d["count"] for d in routine.values())
    }

    return json.dumps(result, indent=2)


def _parse_obfuscation(html_raw: str):
    """check for base64 blobs and eval/unescape calls"""
    base64_chunks = re.findall(r'[A-Za-z0-9+/]{100,}={0,2}', html_raw)
    obfuscation_count = html_raw.count('eval(') + html_raw.count('unescape(')
    return base64_chunks, obfuscation_count


def _find_ctas(html_raw: str) -> list:
    """find suspicious call-to-action buttons/links"""
    found = []
    try:
        soup = BeautifulSoup(html_raw, 'html.parser')
        for tag in soup.find_all(['button', 'a']):
            text = tag.get_text().lower()
            if any(k in text for k in CTA_KEYWORDS):
                found.append(text[:50])
    except Exception:
        pass
    return found[:10]


def _count_links(links: list, target_domain: str):
    """split links into internal vs external"""
    internal = external = 0
    for href in links:
        if href.startswith("/") or target_domain in href:
            internal += 1
        elif href.startswith("http"):
            external += 1
    return internal, external


@mcp.tool()
def extract_dom_iocs(filepath: str, target_url: str = "") -> str:
    """extract dom artifacts, brand indicators, and obfuscation markers"""
    if not is_safe_path(filepath):
        return "error: path outside allowed directory"
    if not os.path.exists(filepath):
        return "file not found"

    target_domain = ""
    if target_url:
        try:
            target_domain = urlparse(target_url).netloc
        except Exception:
            pass

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            html_raw = f.read()
    except Exception:
        html_raw = ""

    base64_chunks, obfuscation_count = _parse_obfuscation(html_raw)
    found_markers = [k for k in RECREATIONAL_KEYWORDS if k in html_raw.lower()]
    found_ctas = _find_ctas(html_raw)

    # prefer js-extracted iocs (more accurate than static parsing)
    extracted_json_path = os.path.join(os.path.dirname(filepath), "extracted_iocs.json")

    if os.path.exists(extracted_json_path):
        with open(extracted_json_path, 'r', encoding='utf-8') as f:
            js_iocs = json.load(f)

        internal, external = _count_links(js_iocs.get("links", []), target_domain)

        iocs = {
            "scripts": js_iocs.get("scripts", [])[:20],
            "iframes": js_iocs.get("iframes", [])[:10],
            "forms": js_iocs.get("forms", [])[:5],
            "brand_indicators": {
                "title": js_iocs.get("title", ""),
                "headers": js_iocs.get("h1s", [])[:5],
                "meta_description": js_iocs.get("metaDesc", "")
            },
            "link_ratio": {"internal_decoy_links": internal, "external_links": external},
            "obfuscation": {"large_base64_chunks_found": len(base64_chunks), "eval_unescape_calls": obfuscation_count},
            "recreational_markers": found_markers,
            "suspicious_ctas": found_ctas
        }
        return json.dumps(iocs, indent=2)

    # bs4 fallback (js extraction failed or page errored before injection)
    soup = BeautifulSoup(html_raw, 'html.parser')
    title = soup.title.string if soup.title else ""
    h1s = [h1.get_text(strip=True) for h1 in soup.find_all("h1")]
    meta_desc = soup.find("meta", attrs={"name": "description"})
    meta_desc_text = meta_desc["content"] if meta_desc and "content" in meta_desc.attrs else ""

    all_links = [link.get("href", "") for link in soup.find_all("a", href=True)]
    internal, external = _count_links(all_links, target_domain)

    iocs = {
        "scripts": [s.get("src") for s in soup.find_all("script") if s.get("src")][:20],
        "iframes": [i.get("src") for i in soup.find_all("iframe") if i.get("src")][:10],
        "forms": [f.get("action") for f in soup.find_all("form")][:5],
        "brand_indicators": {
            "title": title,
            "headers": h1s[:5],
            "meta_description": meta_desc_text
        },
        "link_ratio": {"internal_decoy_links": internal, "external_links": external},
        "obfuscation": {"large_base64_chunks_found": len(base64_chunks), "eval_unescape_calls": obfuscation_count},
        "recreational_markers": found_markers,
        "suspicious_ctas": found_ctas
    }
    return json.dumps(iocs, indent=2)


def _rdap_lookup(domain: str) -> dict | None:
    """query rdap for accurate registration data (whois replacement)"""
    import requests
    try:
        resp = requests.get(
            f"https://rdap.org/domain/{domain}",
            headers={"Accept": "application/rdap+json"},
            timeout=8
        )
        if resp.status_code != 200:
            return None

        data = resp.json()
        result = {}

        for event in data.get("events", []):
            action = event.get("eventAction", "")
            date = event.get("eventDate", "")
            if action == "registration":
                result["domain_created"] = date.split("T")[0]
            elif action == "expiration":
                result["domain_expires"] = date.split("T")[0]

        # grab registrar name
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [None, []])[1]
                for field in vcard:
                    if field[0] == "fn":
                        result["registrar"] = field[3]
                        break
        return result
    except Exception:
        return None


def _whois_fallback(domain: str) -> dict:
    """cli whois fallback when rdap is unavailable"""
    result = {}
    try:
        import whois as whois_lib
        w = whois_lib.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            result["domain_created"] = str(creation)
            return result
    except Exception:
        pass

    # raw cli fallback
    try:
        import subprocess
        raw = subprocess.check_output(["whois", domain], timeout=5, stderr=subprocess.STDOUT).decode()
        # skip iana tld block - look for registrar section
        if "Domain Name:" in raw:
            relevant = raw.split("Domain Name:", 1)[1]
        elif "Registry Domain ID" in raw:
            relevant = raw.split("Registry Domain ID", 1)[1]
        else:
            relevant = raw

        dates = re.findall(r"(?:Creation Date|created|Registered on):?\s*(.*)", relevant, re.IGNORECASE)
        if dates:
            result["domain_created"] = dates[0].strip().split(" ")[0]
        else:
            result["whois_error"] = "could not parse creation date"
    except Exception:
        result["whois_error"] = "DNS resolution failed or WHOIS unavailable"

    return result


BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix", "facebook",
    "instagram", "twitter", "linkedin", "dropbox", "outlook", "onedrive",
    "office365", "chase", "wellsfargo", "bankofamerica", "citibank",
    "steam", "spotify", "adobe", "docusign", "dhl", "fedex", "ups",
    "coinbase", "binance", "metamask", "robinhood", "venmo", "cashapp",
]


def _similar_brand(domain: str) -> dict | None:
    name = domain.replace("www.", "").split(".")[0].lower()
    best, best_score = None, 0.0
    for brand in BRANDS:
        score = SequenceMatcher(None, name, brand).ratio()
        if score > best_score:
            best, best_score = brand, score
    if best_score >= 0.72 and best and best not in name:
        return {"brand": best, "similarity_pct": round(best_score * 100)}
    return None


@mcp.tool()
def analyze_domain(target_url: str) -> str:
    """extract domain age, registrar, and ssl certificate info"""
    try:
        parsed = urlparse(target_url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        domain = domain.split(':')[0]

        if not domain or '.' not in domain:
            return "invalid domain or unreachable host"

        result = {"domain": domain}

        # rdap first (structured, accurate), whois as fallback
        rdap = _rdap_lookup(domain)
        if rdap:
            result.update(rdap)
        else:
            result.update(_whois_fallback(domain))

        # ssl cert check (try verified first, fall back to unverified)
        for verify in [True, False]:
            try:
                ctx = ssl.create_default_context()
                if not verify:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

                with socket.create_connection((domain, 443), timeout=3) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert_dict = ssock.getpeercert()
                        if cert_dict:
                            issuer = dict(x[0] for x in cert_dict.get('issuer', []))
                            result["ssl_issuer"] = issuer.get('organizationName', 'Unknown')
                            result["ssl_expires"] = cert_dict.get('notAfter', 'Unknown')
                            break
            except (socket.gaierror, socket.timeout):
                result["ssl_error"] = "host unreachable or DNS failure"
                break
            except Exception:
                result["ssl_error"] = "likely self-signed or invalid cert"
                continue

        similar = _similar_brand(domain)
        if similar:
            result["brand_similarity"] = similar

        try:
            import requests
            geo = requests.get(f"http://ip-api.com/json/{domain}?fields=country,regionName,city,isp,org,as", timeout=4).json()
            if geo.get("status") != "fail":
                result["hosting"] = {k: v for k, v in geo.items() if k != "status"}
        except Exception:
            pass

        return json.dumps(result, indent=2)
    except Exception as e:
        return f"failed to analyze domain: {e}"

@mcp.tool()
def analyze_js_runtime(folder: str) -> str:
    """analyze js runtime artifacts: kit globals, storage, inline scripts, final url"""
    if not is_safe_path(folder):
        return "error: path outside allowed directory"

    path = os.path.join(folder, "js_runtime.json")
    if not os.path.exists(path):
        return "js_runtime.json not found — container may predate this feature"

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return f"failed to read js_runtime.json: {e}"

    result = {}

    final_url = data.get("finalUrl", "")
    result["final_url"] = final_url

    kit_globals = data.get("kitGlobals", [])
    if kit_globals:
        result["kit_globals"] = kit_globals

    ls = data.get("localStorage", {})
    if ls:
        result["local_storage"] = ls

    ss = data.get("sessionStorage", {})
    if ss:
        result["session_storage"] = ss

    cookies = data.get("cookieNames", [])
    if cookies:
        result["cookie_names"] = cookies

    lang = data.get("pageLanguage", "")
    if lang:
        result["page_language"] = lang

    # flag inline scripts that look obfuscated
    suspicious_inline = []
    for script in data.get("inlineScripts", []):
        # high ratio of non-alphanumeric chars = likely obfuscated
        non_alnum = sum(1 for c in script if not c.isalnum() and c not in (' ', '\n', '\t'))
        ratio = non_alnum / max(len(script), 1)
        if ratio > 0.3 or 'eval(' in script or 'unescape(' in script or 'atob(' in script:
            suspicious_inline.append(script[:300])

    if suspicious_inline:
        result["suspicious_inline_scripts"] = suspicious_inline

    return json.dumps(result, indent=2)


@mcp.tool()
def analyze_form_submission(folder: str) -> str:
    """analyze form interaction results — exfil endpoint, post data, redirect behavior"""
    if not is_safe_path(folder):
        return "error: path outside allowed directory"

    path = os.path.join(folder, "form_submission.json")
    if not os.path.exists(path):
        return "no form submission captured — page may not have credential forms"

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return f"failed to read form_submission.json: {e}"

    result = {
        "form_action": data.get("form_action", ""),
        "form_method": data.get("form_method", ""),
        "input_count": data.get("input_count", 0),
        "fields_filled": data.get("fields_filled", {}),
        "post_submit_url": data.get("post_submit_url", ""),
    }

    submission = data.get("submission")
    if submission:
        result["exfil_endpoint"] = submission.get("url", "")
        result["exfil_method"] = submission.get("method", "")
        # flag if credentials were sent to a different domain
        try:
            action_domain = urlparse(data.get("form_action", "")).netloc
            exfil_domain = urlparse(submission.get("url", "")).netloc
            result["cross_domain_exfil"] = action_domain != exfil_domain and exfil_domain != ""
        except Exception:
            pass
    else:
        result["exfil_endpoint"] = "no outbound request captured"

    return json.dumps(result, indent=2)


@mcp.tool()
def analyze_downloads(folder: str) -> str:
    """surface any files downloaded during detonation and their virustotal scan results"""
    if not is_safe_path(folder):
        return "error: path outside allowed directory"

    downloads_path = os.path.join(folder, "downloads.json")
    scans_path = os.path.join(folder, "file_scan_results.json")

    if not os.path.exists(downloads_path):
        return "no downloads captured during detonation"

    try:
        with open(downloads_path) as f:
            downloads = json.load(f)
    except Exception as e:
        return f"failed to read downloads.json: {e}"

    scans: dict[str, dict] = {}
    if os.path.exists(scans_path):
        try:
            with open(scans_path) as f:
                for entry in json.load(f):
                    scans[entry.get("filename", "")] = entry
        except Exception:
            pass

    result = []
    for dl in downloads:
        filename = dl.get("filename", "unknown")
        entry: dict = {
            "filename": filename,
            "source_url": dl.get("url", ""),
        }
        scan = scans.get(filename)
        if scan:
            total = scan["malicious"] + scan["suspicious"] + scan["harmless"] + scan["undetected"]
            entry["vt_malicious"] = scan["malicious"]
            entry["vt_suspicious"] = scan["suspicious"]
            entry["vt_total"] = total
            entry["vt_analysis_id"] = scan.get("analysis_id", "")
        else:
            entry["vt_result"] = "not scanned (no VT API key or scan pending)"
        result.append(entry)

    return json.dumps(result, indent=2)


if __name__ == "__main__":
    mcp.run()
