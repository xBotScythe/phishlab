# feed ingestion pipeline — phishstats (primary) or openphish (fallback)
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
    """quick head check — skip urls where the server isn't responding"""
    try:
        resp = requests.head(
            url,
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=5,
            allow_redirects=True,
        )
        return resp.status_code < 500
    except Exception:
        return False


async def process_url(url, semaphore, on_ready=None):
    async with semaphore:
        if not await asyncio.to_thread(is_reachable, url):
            print(f"  -- skipping unreachable: {url}")
            return

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
                    where={"id": run_id}, data={"status": "queued"}
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
