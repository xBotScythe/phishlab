# feed ingestion pipeline — phishstats (primary) or openphish (fallback)
import os
import requests
import asyncio
from urllib.parse import urlparse
import datetime

from analyzer import run_analysis
from detonation import run_container
from ollama_manager import start_ollama
from threat_intel import run_threat_intel, format_intel_section
from clustering import compute_screenshot_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CAGEDROP = os.path.join(BASE_DIR, "CageDrop")

from prisma import Prisma
prisma = Prisma()

PHISHSTATS_FEED = "https://api.phishstats.info/api/phishing?_size=100"
OPENPHISH_FEED = "https://openphish.com/feed.txt"


def get_phishstats_urls() -> list[str]:
    try:
        resp = requests.get(
            PHISHSTATS_FEED,
            headers={"User-Agent": "PhishLab/1.0"},
            timeout=15,
        )
        if resp.status_code == 200:
            return [e["url"] for e in resp.json() if e.get("url")]
        return []
    except Exception:
        return []


def get_openphish_urls() -> list[str]:
    try:
        resp = requests.get(
            OPENPHISH_FEED,
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=10,
        )
        if resp.status_code == 200:
            return [u for u in resp.text.strip().split("\n") if u]
        return []
    except Exception:
        return []


async def get_urls() -> tuple[list[str], str]:
    urls = await asyncio.to_thread(get_phishstats_urls)
    if urls:
        return urls, "phishstats"
    print("phishstats fetch failed, falling back to openphish")
    urls = await asyncio.to_thread(get_openphish_urls)
    return urls, "openphish"


def is_reachable(url: str) -> bool:
    """head check with get fallback — some servers ignore HEAD"""
    for method in (requests.head, requests.get):
        try:
            resp = method(
                url,
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=5,
                allow_redirects=True,
                stream=True,
            )
            resp.close()
            return resp.status_code < 500
        except Exception:
            continue
    return False


async def filter_live(urls: list[str]) -> list[str]:
    """check reachability for all urls concurrently, return only live ones"""
    async def check(url):
        alive = await asyncio.to_thread(is_reachable, url)
        if not alive:
            print(f"  -- dead: {url}")
        return url if alive else None

    results = await asyncio.gather(*[check(u) for u in urls])
    return [u for u in results if u]


async def process_url(url, semaphore, on_ready=None):
    async with semaphore:
        parsed = urlparse(url)
        safe_domain = parsed.netloc.replace(":", "_").replace("/", "_")
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        run_id = f"{timestamp}_{safe_domain}"
        mac_folder = os.path.join(CAGEDROP, run_id)
        os.makedirs(mac_folder, exist_ok=True)

        print(f"  -> detonating: {url}")

        if prisma.is_connected():
            await prisma.analysisrun.create(data={
                "id": run_id,
                "url": url,
                "status": "detonating",
                "folder": mac_folder,
            })

        success = await run_container(url, mac_folder)
        if not success:
            print(f"  !! detonation failed: {url}")
            if prisma.is_connected():
                await prisma.analysisrun.update(
                    where={"id": run_id},
                    data={"status": "failed", "error": "detonation failed"},
                )
            return

        if prisma.is_connected():
            await prisma.analysisrun.update(
                where={"id": run_id},
                data={"status": "extracting", "hasScreenshot": True},
            )

        # screenshot hash for clustering
        phash = await compute_screenshot_hash(mac_folder)

        with open(os.path.join(mac_folder, "target.txt"), "w") as f:
            f.write(url)

        try:
            print(f"  -> extracting + intel: {url}")
            prompt, intel = await asyncio.gather(
                run_analysis(mac_folder),
                run_threat_intel(url),
            )
            prompt += format_intel_section(intel)

            try:
                with open(os.path.join(mac_folder, "prompt.txt"), "w", encoding="utf-8") as pf:
                    pf.write(prompt)
            except Exception:
                pass

            if prisma.is_connected():
                vt = intel.get("virustotal")
                us = intel.get("urlscan")
                intel_update: dict = {"status": "queued"}
                if phash:
                    intel_update["screenshotHash"] = phash
                if vt:
                    intel_update.update({
                        "vtMalicious": vt["malicious"],
                        "vtSuspicious": vt["suspicious"],
                        "vtTotal": vt["malicious"] + vt["suspicious"] + vt["harmless"] + vt["undetected"],
                    })
                if us:
                    intel_update.update({"urlscanScore": float(us["score"]), "urlscanId": us["uuid"]})
                await prisma.analysisrun.update(where={"id": run_id}, data=intel_update)

            print(f"  -> queued for generation: {url}")
            if on_ready:
                await on_ready(run_id)

        except Exception as e:
            if prisma.is_connected():
                await prisma.analysisrun.update(
                    where={"id": run_id}, data={"status": "failed", "error": str(e)}
                )


async def start_feed(limit: int = 5, on_ready=None):
    if not prisma.is_connected():
        await prisma.connect()

    start_ollama()

    urls, source = await get_urls()
    print(f"fetched {len(urls)} urls from {source}")

    # dedupe against previously processed runs
    try:
        if prisma.is_connected():
            existing = await prisma.analysisrun.find_many(where={"url": {"in": urls}})
            seen = {r.url for r in existing if r.url}
            urls = [u for u in urls if u not in seen]
    except Exception:
        pass

    # check more than needed so dead sites don't eat into the limit
    candidates = urls[:limit * 5]
    print(f"checking reachability for {len(candidates)} candidates...")
    live = await filter_live(candidates)
    subset = live[:limit]
    print(f"{len(subset)} live urls to detonate")

    semaphore = asyncio.Semaphore(3)

    async def wrapped(url):
        try:
            await asyncio.wait_for(process_url(url, semaphore, on_ready), timeout=300)
        except asyncio.TimeoutError:
            print(f"  !! timed out: {url}")
        except Exception as e:
            print(f"  !! failed: {url}: {e}")

    tasks = [asyncio.create_task(wrapped(url)) for url in subset]
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(start_feed(3))
