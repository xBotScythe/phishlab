# feed ingestion pipeline for openphish
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


def get_phishing_urls():
    """pull live urls from openphish feed"""
    try:
        response = requests.get(
            "https://openphish.com/feed.txt",
            headers={'User-Agent': 'Mozilla/5.0'},
            timeout=10
        )
        if response.status_code == 200:
            return [u for u in response.text.strip().split('\n') if u]
        return []
    except Exception:
        return []


async def process_url(url, semaphore):
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
                'id': run_id,
                'url': url,
                'status': 'detonating',
                'folder': mac_folder
            })

        success = await run_container(url, mac_folder)
        if not success:
            print(f"  !! detonation failed: {url}")
            if prisma.is_connected():
                await prisma.analysisrun.update(where={'id': run_id}, data={'status': 'failed', 'error': 'detonation failed'})
            return

        print(f"  -> extracting: {url}")
        if prisma.is_connected():
            await prisma.analysisrun.update(where={'id': run_id}, data={'status': 'extracting', 'hasScreenshot': True})

        with open(os.path.join(mac_folder, "target.txt"), "w") as f:
            f.write(url)

        try:
            # extract only, don't generate -- the sse endpoint handles streaming
            # when a user opens the run page
            await run_analysis(mac_folder)

            if prisma.is_connected():
                await prisma.analysisrun.update(where={'id': run_id}, data={'status': 'ready'})
            print(f"  -> ready for generation: {url}")
        except Exception as e:
            if prisma.is_connected():
                await prisma.analysisrun.update(where={'id': run_id}, data={'status': 'failed', 'error': str(e)})


async def start_feed(limit: int = 5):
    if not prisma.is_connected():
        await prisma.connect()

    start_ollama()
    print("fetching latest urls from openphish...")
    urls = get_phishing_urls()
    # dedupe against previously processed runs in the DB
    try:
        if prisma.is_connected():
            existing = await prisma.analysisrun.find_many(where={"url": {"in": urls}})
            seen = set(r.url for r in existing if r.url)
            urls = [u for u in urls if u not in seen]
    except Exception:
        # if anything goes wrong with DB lookup, fall back to raw feed
        pass

    print(f"retrieved {len(urls)} candidates after dedupe, processing top {limit}...")
    subset = urls[:limit]

    # 3 concurrent containers max to avoid resource exhaustion
    semaphore = asyncio.Semaphore(3)

    async def wrapped(url):
        try:
            await asyncio.wait_for(process_url(url, semaphore), timeout=300)
        except asyncio.TimeoutError:
            print(f"  !! timed out: {url}")
        except Exception as e:
            print(f"  !! failed: {url}: {e}")

    tasks = [asyncio.create_task(wrapped(url)) for url in subset]
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(start_feed(3))
