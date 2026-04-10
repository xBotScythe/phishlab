# feed ingestion pipeline — phishtank (with key) or openphish (fallback)
import os
import requests
import asyncio
from urllib.parse import urlparse
import datetime

from analyzer import run_analysis
from detonation import run_container
from ollama_manager import start_ollama

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CAGEDROP = os.path.join(BASE_DIR, "CageDrop")

from prisma import Prisma
prisma = Prisma()

PHISHTANK_FEED = "https://data.phishtank.com/data/{key}/online-valid.json"
OPENPHISH_FEED = "https://openphish.com/feed.txt"


def get_phishtank_urls(api_key: str) -> list[str]:
    try:
        resp = requests.get(
            PHISHTANK_FEED.format(key=api_key),
            headers={"User-Agent": "PhishLab/1.0 phishing-analysis-tool"},
            timeout=30,
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


async def get_urls(api_key: str = "") -> tuple[list[str], str]:
    """return (urls, source) using phishtank if key is set, else openphish"""
    if api_key:
        urls = await asyncio.to_thread(get_phishtank_urls, api_key)
        if urls:
            return urls, "phishtank"
        print("phishtank fetch failed, falling back to openphish")

    urls = await asyncio.to_thread(get_openphish_urls)
    return urls, "openphish"


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

        print(f"  -> extracting: {url}")
        if prisma.is_connected():
            await prisma.analysisrun.update(
                where={"id": run_id},
                data={"status": "extracting", "hasScreenshot": True},
            )

        with open(os.path.join(mac_folder, "target.txt"), "w") as f:
            f.write(url)

        try:
            prompt = await run_analysis(mac_folder)

            try:
                with open(os.path.join(mac_folder, "prompt.txt"), "w", encoding="utf-8") as pf:
                    pf.write(prompt)
            except Exception:
                pass

            if prisma.is_connected():
                await prisma.analysisrun.update(
                    where={"id": run_id}, data={"status": "ready"}
                )
            print(f"  -> ready for generation: {url}")

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

    # pull api key from settings if available
    api_key = ""
    try:
        settings = await prisma.settings.find_unique(where={"id": 1})
        if settings and settings.phishtankKey:
            api_key = settings.phishtankKey
    except Exception:
        pass

    urls, source = await get_urls(api_key)
    print(f"fetched {len(urls)} urls from {source}")

    # dedupe against previously processed runs
    try:
        if prisma.is_connected():
            existing = await prisma.analysisrun.find_many(where={"url": {"in": urls}})
            seen = {r.url for r in existing if r.url}
            urls = [u for u in urls if u not in seen]
    except Exception:
        pass

    print(f"{len(urls)} candidates after dedupe, processing top {limit}...")
    subset = urls[:limit]

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
