import asyncio
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse

BULLETPROOF_ASNS = {
    "AS9009",    # M247
    "AS395954",  # Frantech / BuyVM
    "AS34788",   # Neue Medien Muennich
    "AS59711",   # HZ Hosting
    "AS206092",  # Serverius
    "AS49981",   # WorldStream
    "AS206898",  # Shinjiru
    "AS136787",  # TEFINCOM
    "AS8100",    # QuadraNet
    "AS29802",   # Hivelocity
    "AS20473",   # Choopa / Vultr
    "AS14061",   # DigitalOcean
}


def _asn(domain: str) -> str | None:
    try:
        data = requests.get(
            f"http://ip-api.com/json/{domain}?fields=as,status", timeout=4
        ).json()
        if data.get("status") != "fail":
            return data.get("as", "").split(" ")[0]
    except Exception:
        pass
    return None


def _domain_age_days(domain: str) -> int | None:
    try:
        data = requests.get(f"https://rdap.org/domain/{domain}", timeout=5).json()
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                created = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                return (datetime.now(timezone.utc) - created).days
    except Exception:
        pass
    return None


def triage_url(url: str) -> tuple[bool, str, int]:
    """returns (should_process, reason, priority 0-3)"""
    domain = urlparse(url).netloc.split(":")[0]

    asn = _asn(domain)
    if asn in BULLETPROOF_ASNS:
        return True, f"bulletproof ASN {asn}", 3

    age = _domain_age_days(domain)

    if age is not None and age < 7:
        return True, f"brand new domain ({age}d old)", 3

    if age is not None and age > 730:
        return True, f"established domain ({age}d old)", 1

    return True, "normal", 2


async def triage_urls(urls: list[str]) -> list[tuple[str, int]]:
    """returns (url, priority) list sorted high→low, concurrent lookups"""
    results = await asyncio.gather(*[
        asyncio.to_thread(triage_url, url) for url in urls
    ])

    scored = []
    for url, (ok, reason, priority) in zip(urls, results):
        print(f"  triage [{priority}] {url}: {reason}")
        if ok:
            scored.append((url, priority))

    scored.sort(key=lambda x: x[1], reverse=True)
    return scored
