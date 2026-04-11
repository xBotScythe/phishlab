# shared docker detonation logic
import asyncio
import os

CONTAINER_TIMEOUT = 120  # seconds before we kill a stuck container


async def run_container(url: str, output_dir: str) -> tuple[bool, str]:
    """returns (success, error_message)"""
    process = await asyncio.create_subprocess_exec(
        "docker", "run", "--rm",
        "--stop-timeout", "5",
        "-v", f"{output_dir}:/cage_drop",
        "-e", f"TARGET_URL={url}",
        "phishing-cage",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=CONTAINER_TIMEOUT)
    except asyncio.TimeoutError:
        print(f"CONTAINER: timeout for {url}, killing")
        try:
            process.kill()
            await process.wait()
        except Exception:
            pass
        return False, f"container timed out after {CONTAINER_TIMEOUT}s"

    output = stdout.decode(errors="replace").strip() if stdout else ""
    for line in output.splitlines():
        print(f"CONTAINER: {line}")

    if process.returncode != 0:
        # surface the last meaningful line as the error
        lines = [l for l in output.splitlines() if l.strip()]
        detail = lines[-1] if lines else "unknown error"
        return False, f"container exited {process.returncode}: {detail}"

    if not os.path.exists(os.path.join(output_dir, "screenshot.png")):
        # read error.log if the script wrote one
        error_log = os.path.join(output_dir, "error.log")
        if os.path.exists(error_log):
            content = open(error_log).read().strip()
            detail = content.splitlines()[0] if content else "no screenshot saved"
        else:
            detail = "no screenshot saved"
        return False, detail

    return True, ""
