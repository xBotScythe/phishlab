import json
import os
import asyncio
from urllib.parse import urlparse

try:
    import imagehash
    from PIL import Image
    _HASH_AVAILABLE = True
except ImportError:
    _HASH_AVAILABLE = False

# minimum score to be considered the same campaign
CAMPAIGN_THRESHOLD = 3


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


def _extract_signals(folder: str, agent_verdict_json: str | None) -> dict:
    """pull campaign-relevant signals from run artifacts"""
    signals: dict = {}

    # form exfil + action
    form_path = os.path.join(folder, "form_submission.json")
    if os.path.exists(form_path):
        try:
            with open(form_path) as f:
                form = json.load(f)
            action = form.get("form_action", "")
            if action:
                signals["form_action_domain"] = urlparse(action).netloc.lower()
            sub = form.get("submission") or {}
            exfil = sub.get("url", "")
            if exfil:
                signals["exfil_domain"] = urlparse(exfil).netloc.lower()
        except Exception:
            pass

    # server IPs + final redirect destination from HAR
    har_path = os.path.join(folder, "network_traffic.har")
    if os.path.exists(har_path):
        try:
            with open(har_path) as f:
                har = json.load(f)
            entries = har.get("log", {}).get("entries", [])
            ips: set[str] = set()
            for entry in entries:
                ip = entry.get("serverIPAddress", "")
                if ip and ip not in ("", "::1", "127.0.0.1"):
                    ips.add(ip)
            if ips:
                signals["server_ips"] = ips
            if entries:
                last_url = entries[-1].get("request", {}).get("url", "")
                if last_url:
                    signals["final_domain"] = urlparse(last_url).netloc.lower()
        except Exception:
            pass

    # yara rule names
    yara_path = os.path.join(folder, "yara_matches.json")
    if os.path.exists(yara_path):
        try:
            with open(yara_path) as f:
                matches = json.load(f)
            rules = {m.get("rule") for m in matches if m.get("rule")}
            if rules:
                signals["yara_rules"] = rules
        except Exception:
            pass

    # js kit globals
    runtime_path = os.path.join(folder, "js_runtime.json")
    if os.path.exists(runtime_path):
        try:
            with open(runtime_path) as f:
                rt = json.load(f)
            globals_list = rt.get("kitGlobals") or []
            if globals_list:
                signals["kit_globals"] = set(globals_list)
        except Exception:
            pass

    if agent_verdict_json:
        try:
            verdict = json.loads(agent_verdict_json)
            fp = verdict.get("kit_fingerprint", "").strip().lower()
            if fp:
                signals["kit_fingerprint"] = fp
            dv = verdict.get("delivery_vector", "").strip().lower()
            if dv and dv != "unknown":
                signals["delivery_vector"] = dv
        except Exception:
            pass

    return signals


def _score(current: dict, other: dict, phash_dist: int | None) -> int:
    score = 0

    if phash_dist is not None:
        if phash_dist <= 10:
            score += 3
        elif phash_dist <= 20:
            score += 1

    # same physical server — strongest infrastructure signal
    cur_ips = current.get("server_ips", set())
    oth_ips = other.get("server_ips", set())
    if cur_ips and oth_ips and cur_ips & oth_ips:
        score += 5

    # same exfil collection endpoint
    if current.get("exfil_domain") and current["exfil_domain"] == other.get("exfil_domain"):
        score += 4

    # same form handler
    if current.get("form_action_domain") and current["form_action_domain"] == other.get("form_action_domain"):
        score += 3

    # shared yara rules — +2 per rule, capped at +6
    cur_yara = current.get("yara_rules", set())
    oth_yara = other.get("yara_rules", set())
    shared_rules = cur_yara & oth_yara
    if shared_rules:
        score += min(len(shared_rules) * 2, 6)

    # kit fingerprint from agent verdict
    if current.get("kit_fingerprint") and current["kit_fingerprint"] == other.get("kit_fingerprint"):
        score += 3

    # js global variable overlap — meaningful overlap suggests same kit codebase
    cur_globals = current.get("kit_globals", set())
    oth_globals = other.get("kit_globals", set())
    overlap = cur_globals & oth_globals
    if len(overlap) >= 5:
        score += 3
    elif len(overlap) >= 3:
        score += 2

    # same delivery vector — weak on its own, tiebreaker
    if current.get("delivery_vector") and current["delivery_vector"] == other.get("delivery_vector"):
        score += 1

    # same final redirect destination
    if current.get("final_domain") and current["final_domain"] == other.get("final_domain"):
        score += 2

    return score


async def find_campaign(prisma, run_id: str, screenshot_hash: str,
                        current_url: str = "", folder: str = "",
                        agent_verdict_json: str | None = None) -> str | None:
    from urllib.parse import urlparse as _up
    current_domain = _up(current_url).netloc if current_url else ""
    current_signals = _extract_signals(folder, agent_verdict_json) if folder else {}

    try:
        runs = await prisma.analysisrun.find_many(
            where={"id": {"not": run_id}, "status": "complete"},
        )

        current_hash = None
        if _HASH_AVAILABLE and screenshot_hash:
            try:
                current_hash = imagehash.hex_to_hash(screenshot_hash)
            except Exception:
                pass

        best_id: str | None = None
        best_score = 0

        for run in runs:
            run_domain = _up(run.url or "").netloc
            if current_domain and run_domain == current_domain:
                continue

            phash_dist: int | None = None
            if current_hash and run.screenshotHash:
                try:
                    phash_dist = current_hash - imagehash.hex_to_hash(run.screenshotHash)
                except Exception:
                    pass

            other_signals = _extract_signals(run.folder, run.agentVerdict)
            score = _score(current_signals, other_signals, phash_dist)

            if score >= CAMPAIGN_THRESHOLD and score > best_score:
                best_score = score
                best_id = run.campaignId or run.id

        if best_id:
            print(f"CLUSTERING: matched campaign {best_id[:12]} (score={best_score})")
        return best_id

    except Exception as e:
        print(f"CLUSTERING: failed ({e})")
        return None
