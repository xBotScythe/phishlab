import os
import asyncio

# imagehash + pillow required: pip install imagehash Pillow
try:
    import imagehash
    from PIL import Image
    _HASH_AVAILABLE = True
except ImportError:
    _HASH_AVAILABLE = False

# runs with a hash distance <= this are considered the same campaign
HASH_THRESHOLD = 10


async def compute_screenshot_hash(folder: str) -> str | None:
    if not _HASH_AVAILABLE:
        return None
    path = os.path.join(folder, "screenshot.png")
    if not os.path.exists(path):
        return None
    try:
        def _hash():
            img = Image.open(path)
            return str(imagehash.phash(img))
        return await asyncio.to_thread(_hash)
    except Exception:
        return None


async def find_campaign(prisma, run_id: str, screenshot_hash: str, current_url: str = "") -> str | None:
    """compare hash against completed runs on DIFFERENT domains. returns campaign id if close enough."""
    if not _HASH_AVAILABLE or not screenshot_hash:
        return None

    from urllib.parse import urlparse
    current_domain = urlparse(current_url).netloc if current_url else ""

    try:
        runs = await prisma.analysisrun.find_many(
            where={
                "screenshotHash": {"not": None},
                "id": {"not": run_id},
                "status": "complete",
            }
        )
        current = imagehash.hex_to_hash(screenshot_hash)
        for run in runs:
            if not run.screenshotHash:
                continue
            # skip runs of the same domain — repeated detonations aren't a campaign
            run_domain = urlparse(run.url or "").netloc
            if current_domain and run_domain == current_domain:
                continue
            try:
                other = imagehash.hex_to_hash(run.screenshotHash)
                if (current - other) <= HASH_THRESHOLD:
                    return run.campaignId or run.id
            except Exception:
                continue
    except Exception:
        pass
    return None
