import json
import os
from urllib.parse import urlparse

MAX_CHAIN_DEPTH = 2
MAX_PER_RUN = 3

SKIP_DOMAINS = {
    # google
    "googleapis.com", "gstatic.com", "google.com", "google-analytics.com",
    "googletagmanager.com", "doubleclick.net", "ggpht.com",
    # social
    "facebook.com", "fbcdn.net", "instagram.com",
    "twitter.com", "x.com", "twimg.com",
    "linkedin.com", "youtube.com", "ytimg.com",
    # cdn / infra
    "cloudflare.com", "cloudflareinsights.com",
    "akamai.com", "akamaiedge.net", "fastly.net",
    "cloudfront.net", "amazonaws.com",
    # js libs
    "jquery.com", "bootstrapcdn.com", "cdnjs.cloudflare.com",
    "unpkg.com", "jsdelivr.net", "fontawesome.com",
    # big tech platforms (login/auth flows are not exfil)
    "microsoft.com", "azureedge.net", "msftauth.net", "live.com",
    "apple.com", "icloud.com",
    "amazon.com", "stripe.com", "paypal.com",
    # dev / code hosting (not phish targets in chain context)
    "github.com", "githubusercontent.com",
    # cms asset cdns — static files only, not the platform itself
    "wixstatic.com", "squarespaceassets.com", "shopifycdn.com",
    "hubspotusercontent.com", "adobedtm.com", "typekit.net",
    # analytics / monitoring
    "hotjar.com", "mouseflow.com", "sentry.io", "segment.com",
    "intercom.io", "intercomcdn.com",
    "zendesk.com", "zdassets.com",
    "cookiebot.com", "cookiepro.com",
    # wordpress infra (not self-hosted wp sites)
    "wp.com", "gravatar.com",
    # recaptcha
    "recaptcha.net",
}

# hosting platforms intentionally excluded from SKIP_DOMAINS:
# vercel.app, netlify.app, weebly.com, wix.com, squarespace.com, editmysite.com, etc.
# phishing kits are frequently hosted on these — a form submitting to another
# subdomain on the same platform is a valid chain target.

SKIP_EXTENSIONS = {
    ".js", ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".mp4", ".webm", ".mp3", ".ogg",
    ".map", ".json",
}


def _root(domain: str) -> str:
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _skip(domain: str) -> bool:
    return _root(domain) in SKIP_DOMAINS or domain in SKIP_DOMAINS


def _skip_url(url: str) -> bool:
    path = urlparse(url).path.lower().split("?")[0]
    return any(path.endswith(ext) for ext in SKIP_EXTENSIONS)


async def extract_candidates(folder: str, origin_url: str) -> list[str]:
    origin_root = _root(urlparse(origin_url).netloc)
    candidates = []

    iocs_path = os.path.join(folder, "extracted_iocs.json")
    if os.path.exists(iocs_path):
        try:
            with open(iocs_path) as f:
                iocs = json.load(f)
            for url in iocs.get("forms", []):
                if url and url.startswith("http"):
                    candidates.append(url)
            for url in iocs.get("iframes", []):
                if url and url.startswith("http"):
                    candidates.append(url)
        except Exception:
            pass

    har_path = os.path.join(folder, "network_traffic.har")
    if os.path.exists(har_path):
        try:
            with open(har_path) as f:
                har = json.load(f)
            for entry in har.get("log", {}).get("entries", []):
                status = entry.get("response", {}).get("status", 0)
                if status not in (301, 302, 303, 307, 308):
                    continue
                redirect = entry.get("response", {}).get("redirectURL", "")
                if redirect and redirect.startswith("http"):
                    candidates.append(redirect)
        except Exception:
            pass

    seen = set()
    result = []
    for url in candidates:
        domain = urlparse(url).netloc
        root = _root(domain)
        if root == origin_root or root in seen or _skip(domain) or _skip_url(url):
            continue
        seen.add(root)
        result.append(url)

    return result[:MAX_PER_RUN]


async def hunt_chain(run_id: str, origin_url: str, folder: str, depth: int, prisma) -> list[str]:
    if depth >= MAX_CHAIN_DEPTH:
        return []

    candidates = await extract_candidates(folder, origin_url)
    if not candidates:
        return []

    to_queue = []
    for url in candidates:
        existing = await prisma.analysisrun.find_first(
            where={"url": url, "status": {"in": ["complete", "detonating", "extracting", "queued", "generating"]}}
        )
        if existing:
            print(f"CHAIN: skipping {url} (already in pipeline)")
            continue
        print(f"CHAIN: discovered {url} (depth {depth + 1}, parent {run_id})")
        to_queue.append(url)

    return to_queue
