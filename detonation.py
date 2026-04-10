# shared docker detonation logic
import asyncio
import os


async def run_container(url: str, output_dir: str) -> bool:
    """run phishing-cage container against target url, returns success bool.
    also checks that screenshot.png was written — if not, playwright couldn't
    reach the site (docker has a different network stack than the host check)."""
    process = await asyncio.create_subprocess_exec(
        "docker", "run", "--rm",
        "-v", f"{output_dir}:/cage_drop",
        "-e", f"TARGET_URL={url}",
        "phishing-cage",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await process.communicate()
    if process.returncode != 0:
        return False
    return os.path.exists(os.path.join(output_dir, "screenshot.png"))
