import asyncio
import datetime
import json
import os
import shutil
from urllib.parse import urlparse

# load .env before anything else so api keys are available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

os.environ.setdefault("OLLAMA_HOST", "127.0.0.1:11434")

import ollama
import requests as _requests
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

from analyzer import run_analysis, MODEL
from detonation import run_container
from ollama_manager import start_ollama, stop_ollama
from feed_the_cage import start_feed
from threat_intel import run_threat_intel, format_intel_section
from clustering import compute_screenshot_hash, find_campaign
from ioc_export import collect_iocs, export_csv, export_stix
from chain_hunter import hunt_chain, extract_candidates
from orchestrator import AgentOrchestrator
from prisma import Prisma

app = FastAPI(title="PhishLab API", version="1.0.0")
prisma = Prisma()
orchestrator = AgentOrchestrator()

# generation queue -- runs go in when extraction finishes, worker processes one at a time
generation_queue: asyncio.Queue = asyncio.Queue()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000", "http://localhost:3001",
        "http://127.0.0.1:3000", "http://127.0.0.1:3001"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

CAGEDROP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "CageDrop")

class DetonateRequest(BaseModel):
    url: str

class FeedRequest(BaseModel):
    limit: int = 5




async def _spawn_chain_run(url: str, parent_id: str, depth: int):
    if not prisma.is_connected():
        return
    import datetime as dt
    from urllib.parse import urlparse as _up
    safe_domain = _up(url).netloc.replace(":", "_").replace("/", "_")
    run_id = f"{dt.datetime.now().strftime('%Y%m%d%H%M%S%f')[:17]}_{safe_domain}"
    folder = os.path.join(CAGEDROP, run_id)
    os.makedirs(folder, exist_ok=True)
    await prisma.analysisrun.create(data={
        "id": run_id,
        "url": url,
        "status": "pending",
        "folder": folder,
        "chainDepth": depth,
        "chainParentId": parent_id,
    })
    await _run_detonation(run_id, url)


def _build_webhook_payload(webhook_url: str, run_id: str, url: str, run, escalation: dict) -> dict:
    vt = getattr(run, "vtMalicious", None)
    score = getattr(run, "urlscanScore", None)
    campaign = getattr(run, "campaignId", None)
    severity = escalation.get("severity", "unknown").upper()
    summary = escalation.get("summary", "")

    vt_str = f"{vt} malicious detections" if vt else "no detections"
    score_str = f"{score:.0f}/100" if score is not None else "n/a"
    sev_emoji = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵", "BENIGN": "🟢"}.get(severity, "⚪")

    if "hooks.slack.com" in webhook_url:
        return {
            "text": f"{sev_emoji} {severity} — PhishLab run complete",
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": f"PhishLab: {sev_emoji} {severity}"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": summary}} if summary else None,
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*URL:*\n{url}"},
                    {"type": "mrkdwn", "text": f"*VirusTotal:*\n{vt_str}"},
                    {"type": "mrkdwn", "text": f"*URLScan score:*\n{score_str}"},
                    {"type": "mrkdwn", "text": f"*Campaign:*\n{campaign or 'none'}"},
                ]},
                {"type": "context", "elements": [
                    {"type": "mrkdwn", "text": f"run `{run_id}`"}
                ]},
            ],
        }

    if "discord.com/api/webhooks" in webhook_url:
        sev_color = {"CRITICAL": 0xFF0000, "HIGH": 0xFF4444, "MEDIUM": 0xFFAA00, "LOW": 0x4488FF, "BENIGN": 0x44BB44}
        color = sev_color.get(severity, 0x888888)
        fields = [
            {"name": "URL", "value": url, "inline": False},
            {"name": "Severity", "value": f"{sev_emoji} {severity}", "inline": True},
            {"name": "VirusTotal", "value": vt_str, "inline": True},
            {"name": "URLScan", "value": score_str, "inline": True},
            {"name": "Campaign", "value": campaign or "none", "inline": True},
        ]
        return {
            "embeds": [{
                "title": f"PhishLab: {sev_emoji} {severity}",
                "description": summary or None,
                "color": color,
                "fields": fields,
                "footer": {"text": f"run {run_id}"},
            }]
        }

    return {
        "run_id": run_id,
        "url": url,
        "status": "complete",
        "severity": escalation.get("severity"),
        "threat_summary": summary,
        "vt_malicious": vt,
        "urlscan_score": score,
        "campaign_id": campaign,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


async def _fire_webhook(run_id: str, url: str, run, escalation: dict):
    webhook_url = os.environ.get("WEBHOOK_URL", "")
    if not webhook_url:
        return
    payload = _build_webhook_payload(webhook_url, run_id, url, run, escalation)
    # remove None blocks (Slack)
    if "blocks" in payload:
        payload["blocks"] = [b for b in payload["blocks"] if b is not None]
    try:
        await asyncio.to_thread(_requests.post, webhook_url, json=payload, timeout=5)
        print(f"webhook fired for {run_id}")
    except Exception as e:
        print(f"webhook failed: {e}")


async def _post_report_agents(run_id: str, url: str, report: str, completed):
    """escalation, webhook, and chain hunting via mcp orchestrator."""
    if not prisma.is_connected():
        return
    try:
        # load parent verdict for chain children
        parent_verdict = ""
        parent_id = getattr(completed, "chainParentId", None)
        if parent_id:
            parent = await prisma.analysisrun.find_unique(where={'id': parent_id})
            if parent and parent.agentVerdict:
                try:
                    pv = json.loads(parent.agentVerdict)
                    parent_verdict = f"{pv.get('severity', 'unknown')} — {pv.get('summary', '')}"
                except Exception:
                    pass

        verdict = await orchestrator.run_verdict(
            url=url,
            report=report,
            vt_malicious=getattr(completed, "vtMalicious", None),
            urlscan_score=getattr(completed, "urlscanScore", None),
            parent_verdict=parent_verdict,
        )

        await prisma.analysisrun.update(where={'id': run_id}, data={
            'severity': verdict.get('severity', 'medium'),
            'threatSummary': verdict.get('summary', ''),
            'agentVerdict': json.dumps(verdict),
        })

        # webhook if severity meets threshold
        min_severity = os.environ.get("WEBHOOK_MIN_SEVERITY", "high")
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "benign": 0}
        if severity_rank.get(verdict.get('severity', 'medium'), 0) >= severity_rank.get(min_severity, 3):
            fresh = await prisma.analysisrun.find_unique(where={'id': run_id})
            asyncio.create_task(_fire_webhook(run_id, url, fresh, verdict))

        # chain hunting
        depth = getattr(completed, "chainDepth", 0) or 0
        if depth < 2:
            should_hunt = await orchestrator.run_hunt(
                report=report,
                url=url,
                severity=verdict.get('severity', 'medium'),
                confidence=verdict.get('confidence', 'low'),
            )
            if should_hunt:
                raw_candidates = await extract_candidates(getattr(completed, "folder", ""), url)
                filtered = await orchestrator.run_chain_filter(raw_candidates, report, url)
                for chain_url in filtered:
                    existing = await prisma.analysisrun.find_first(
                        where={"url": chain_url, "status": {"in": ["complete", "detonating", "extracting", "queued", "generating"]}}
                    )
                    if not existing:
                        asyncio.create_task(_spawn_chain_run(chain_url, run_id, depth + 1))
    except Exception as e:
        print(f"POST-REPORT: agents failed for {run_id}: {e}")


async def _generate_report(run_id: str):
    """generate llm report for a single run. called by the queue worker."""
    if not prisma.is_connected():
        return
    run = await prisma.analysisrun.find_unique(where={'id': run_id})
    if not run or run.status not in ('queued', 'generating'):
        return

    await prisma.analysisrun.update(where={'id': run_id}, data={'status': 'generating'})
    print(f"GENERATE: starting report for {run_id}")

    # read cached prompt from disk
    prompt_path = os.path.join(run.folder, "prompt.txt")
    if os.path.exists(prompt_path):
        with open(prompt_path, "r", encoding="utf-8") as f:
            prompt = f.read()
    else:
        # fallback: re-run mcp extraction (slow but recoverable)
        try:
            prompt = await run_analysis(run.folder)
        except Exception as e:
            await prisma.analysisrun.update(where={'id': run_id}, data={'status': 'failed', 'error': str(e)})
            return

    try:
        message: dict = {"role": "user", "content": prompt}

        # attach screenshot if available — gemma4 is vision-capable
        screenshot_path = os.path.join(run.folder, "screenshot.png")
        if os.path.exists(screenshot_path):
            with open(screenshot_path, "rb") as img_f:
                message["images"] = [img_f.read()]

        response = await asyncio.to_thread(
            ollama.chat,
            model=MODEL,
            messages=[message],
            keep_alive="10m",
        )
        report = response.message.content

        with open(os.path.join(run.folder, "report.md"), "w", encoding="utf-8") as f:
            f.write(report)

        completed = await prisma.analysisrun.find_unique(where={'id': run_id})
        if completed and completed.screenshotHash:
            campaign_id = await find_campaign(prisma, run_id, completed.screenshotHash, completed.url or "")
            if campaign_id:
                await prisma.analysisrun.update(where={'id': run_id}, data={'campaignId': campaign_id})

        await prisma.analysisrun.update(where={'id': run_id}, data={
            'status': 'complete',
            'report': report
        })
        print(f"GENERATE: finished report for {run_id}")

        # agent work runs in background so the queue worker can move to the next run immediately
        asyncio.create_task(_post_report_agents(run_id, run.url or "", report, completed))
    except Exception as e:
        await prisma.analysisrun.update(where={'id': run_id}, data={
            'status': 'failed',
            'error': f"llm error: {e}"
        })
        print(f"GENERATE: failed for {run_id}: {e}")


async def _generation_worker():
    """background worker that processes report generation one at a time"""
    while True:
        run_id = await generation_queue.get()
        try:
            await _generate_report(run_id)
        except Exception as e:
            print(f"GENERATE: unexpected error for {run_id}: {e}")
        generation_queue.task_done()



@app.on_event("startup")
async def startup():
    try:
        await asyncio.wait_for(prisma.connect(), timeout=5.0)
    except Exception as e:
        print(f"ERROR: failed to connect to database: {e}")

    # clear any leftover active feed status from a previous crash
    try:
        status = await prisma.feedstatus.find_unique(where={'id': 1})
        if not status:
            await prisma.feedstatus.create(data={'id': 1, 'active': False})
        else:
            await prisma.feedstatus.update(where={'id': 1}, data={'active': False})
    except Exception:
        pass

    start_ollama()
    os.makedirs(CAGEDROP, exist_ok=True)

    try:
        await orchestrator.start()
    except Exception as e:
        print(f"WARNING: orchestrator failed to start ({e}), agent features disabled")

    asyncio.create_task(_generation_worker())

    # re-queue runs that were mid-generation when the server went down
    try:
        stuck = await prisma.analysisrun.find_many(
            where={'status': {'in': ['queued', 'generating']}},
            order={'createdAt': 'asc'}
        )
        for run in stuck:
            print(f"STARTUP: re-queuing stuck run {run.id}")
            await generation_queue.put(run.id)
    except Exception:
        pass

    # resume runs stuck mid-detonation or mid-extraction
    try:
        early_stuck = await prisma.analysisrun.find_many(
            where={'status': {'in': ['pending', 'detonating', 'extracting']}},
            order={'createdAt': 'asc'}
        )
        for run in early_stuck:
            if run.url:
                print(f"STARTUP: resuming {run.id}")
                asyncio.create_task(_run_detonation(run.id, run.url))
    except Exception:
        pass

@app.on_event("shutdown")
async def shutdown():
    await orchestrator.stop()
    await prisma.disconnect()
    stop_ollama()


def sse(event_type: str, content: str) -> str:
    return f"data: {json.dumps({'type': event_type, 'content': content})}\n\n"


def _detonation_complete(folder: str) -> bool:
    return os.path.exists(os.path.join(folder, "screenshot.png"))


def _extraction_complete(folder: str) -> bool:
    """check if mcp extraction saved the assembled prompt"""
    return os.path.exists(os.path.join(folder, "prompt.txt"))


async def _run_detonation(run_id: str, url: str):
    """run (or resume) the detonation pipeline. skips any stage whose artifacts already exist."""
    if not prisma.is_connected():
        return
    run = await prisma.analysisrun.find_unique(where={'id': run_id})
    if not run:
        return

    try:
        with open(os.path.join(run.folder, "target.txt"), "w") as f:
            f.write(url)

        if _detonation_complete(run.folder):
            print(f"RESUME: skipping detonation for {run_id}")
            await prisma.analysisrun.update(where={'id': run_id}, data={'hasScreenshot': True})
        else:
            await prisma.analysisrun.update(where={'id': run_id}, data={'status': 'detonating'})
            success, container_error = await run_container(url, run.folder)
            if not success:
                await prisma.analysisrun.update(where={'id': run_id}, data={
                    'status': 'failed',
                    'error': container_error,
                })
                return
            await prisma.analysisrun.update(where={'id': run_id}, data={'hasScreenshot': True})

        # compute screenshot hash for campaign clustering (after detonation)
        phash = await compute_screenshot_hash(run.folder)
        if phash:
            await prisma.analysisrun.update(where={'id': run_id}, data={'screenshotHash': phash})

        if _extraction_complete(run.folder):
            print(f"RESUME: skipping extraction for {run_id}")
        else:
            await prisma.analysisrun.update(where={'id': run_id}, data={'status': 'extracting'})
            # run mcp extraction and threat intel concurrently
            prompt, intel = await asyncio.gather(
                run_analysis(run.folder),
                run_threat_intel(url),
            )
            prompt += format_intel_section(intel)
            vt = intel.get("virustotal")
            us = intel.get("urlscan")
            intel_update = {}
            if vt:
                intel_update.update({
                    'vtMalicious': vt['malicious'],
                    'vtSuspicious': vt['suspicious'],
                    'vtTotal': vt['malicious'] + vt['suspicious'] + vt['harmless'] + vt['undetected'],
                })
            if us:
                intel_update.update({'urlscanScore': float(us['score']), 'urlscanId': us['uuid']})
            if intel_update:
                await prisma.analysisrun.update(where={'id': run_id}, data=intel_update)
            try:
                with open(os.path.join(run.folder, "prompt.txt"), "w", encoding="utf-8") as pf:
                    pf.write(prompt)
            except Exception:
                pass

        await prisma.analysisrun.update(where={'id': run_id}, data={'status': 'queued'})
        await generation_queue.put(run_id)

    except Exception as e:
        if prisma.is_connected():
            await prisma.analysisrun.update(where={'id': run_id}, data={
                'status': 'failed',
                'error': str(e)
            })


@app.get("/api/health")
async def health():
    try:
        r = _requests.get("http://127.0.0.1:11434/", timeout=2)
        ollama_ok = r.status_code == 200
    except Exception:
        ollama_ok = False

    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "info",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.communicate()
        docker_ok = proc.returncode == 0
    except Exception:
        docker_ok = False

    return {"ollama": ollama_ok, "docker": docker_ok, "queue_size": generation_queue.qsize()}


@app.post("/api/detonate")
async def detonate(req: DetonateRequest, background_tasks: BackgroundTasks):
    parsed = urlparse(req.url)
    if parsed.scheme not in ["http", "https"]:
        raise HTTPException(status_code=400, detail="only http/https urls are allowed")

    domain = (parsed.netloc or "unknown").replace(":", "_").replace("/", "_")
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S%f")[:17]
    run_id = f"{timestamp}_{domain}"
    mac_folder = os.path.join(CAGEDROP, run_id)
    os.makedirs(mac_folder, exist_ok=True)

    await prisma.analysisrun.create(data={
        "id": run_id,
        "url": req.url,
        "folder": mac_folder,
        "status": "pending"
    })

    background_tasks.add_task(_run_detonation, run_id, req.url)
    return {"run_id": run_id, "status": "pending"}


def _load_iocs(folder: str) -> dict:
    path = os.path.join(folder, "extracted_iocs.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def _ioc_delta(iocs_a: dict, iocs_b: dict) -> dict:
    delta: dict = {}
    keys = set(iocs_a) | set(iocs_b)
    for key in keys:
        a_vals = set(iocs_a.get(key, []) if isinstance(iocs_a.get(key), list) else [iocs_a[key]] if key in iocs_a else [])
        b_vals = set(iocs_b.get(key, []) if isinstance(iocs_b.get(key), list) else [iocs_b[key]] if key in iocs_b else [])
        added = list(b_vals - a_vals)
        removed = list(a_vals - b_vals)
        if added or removed:
            delta[key] = {"added": added, "removed": removed}
    return delta


@app.get("/api/runs/diff")
async def diff_runs(a: str, b: str):
    """compare two runs side by side with ioc delta"""
    run_a = await prisma.analysisrun.find_unique(where={'id': a})
    run_b = await prisma.analysisrun.find_unique(where={'id': b})
    if not run_a or not run_b:
        raise HTTPException(status_code=404, detail="one or both runs not found")

    iocs_a = _load_iocs(run_a.folder)
    iocs_b = _load_iocs(run_b.folder)
    delta = _ioc_delta(iocs_a, iocs_b)

    # surface final_url change explicitly
    url_changed = iocs_a.get("final_url") != iocs_b.get("final_url") and iocs_b.get("final_url")

    return {
        "a": {
            "id": run_a.id, "url": run_a.url, "status": run_a.status,
            "report": run_a.report, "has_screenshot": run_a.hasScreenshot,
            "created_at": run_a.createdAt.strftime("%Y-%m-%dT%H:%M:%SZ") if run_a.createdAt else None,
            "severity": run_a.severity, "threat_summary": run_a.threatSummary,
            "vt_malicious": run_a.vtMalicious, "urlscan_score": run_a.urlscanScore,
        },
        "b": {
            "id": run_b.id, "url": run_b.url, "status": run_b.status,
            "report": run_b.report, "has_screenshot": run_b.hasScreenshot,
            "created_at": run_b.createdAt.strftime("%Y-%m-%dT%H:%M:%SZ") if run_b.createdAt else None,
            "severity": run_b.severity, "threat_summary": run_b.threatSummary,
            "vt_malicious": run_b.vtMalicious, "urlscan_score": run_b.urlscanScore,
        },
        "delta": delta,
        "url_changed": {"from": iocs_a.get("final_url"), "to": iocs_b.get("final_url")} if url_changed else None,
    }


@app.get("/api/runs/{run_id}/status")
async def get_status(run_id: str):
    run = await prisma.analysisrun.find_unique(where={'id': run_id})
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    return {"run_id": run_id, "status": run.status, "url": run.url, "error": run.error}


@app.get("/api/runs/{run_id}/stream")
async def stream_analysis(run_id: str):
    """sse endpoint -- polls status and dumps report when complete"""
    run = await prisma.analysisrun.find_unique(where={'id': run_id})
    if not run:
        raise HTTPException(status_code=404, detail="run not found")

    async def event_generator():
        # poll until terminal state (generation happens in background worker)
        for _ in range(300):
            db_run = await prisma.analysisrun.find_unique(where={'id': run_id})
            if not db_run:
                return

            if db_run.status == "complete":
                if db_run.report:
                    yield sse("token", db_run.report)
                yield sse("done", "")
                return
            elif db_run.status == "failed":
                yield sse("error", db_run.error or "unknown error")
                return
            else:
                yield sse("status", db_run.status)
                await asyncio.sleep(1)

        yield sse("error", "timeout waiting for report generation")

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/runs")
async def list_runs(q: str = "", status: str = "", url: str = ""):
    db_runs = await prisma.analysisrun.find_many(order={'createdAt': 'desc'})

    results = []
    for run in db_runs:
        if url and run.url != url:
            continue
        if q and q.lower() not in (run.url or "").lower() and q.lower() not in run.id.lower():
            continue
        if status and run.status != status:
            continue
        results.append({
            "id": run.id,
            "url": run.url,
            "status": run.status,
            "has_report": run.report is not None,
            "has_screenshot": run.hasScreenshot,
            "created_at": run.createdAt.strftime("%Y-%m-%dT%H:%M:%SZ") if run.createdAt else None,
            "vt_malicious": run.vtMalicious,
            "campaign_id": run.campaignId,
            "severity": run.severity,
            "chain_depth": run.chainDepth or 0,
            "chain_parent_id": run.chainParentId,
        })
    return {"runs": results}


@app.get("/api/runs/{run_id}")
async def get_run(run_id: str):
    run = await prisma.analysisrun.find_unique(where={'id': run_id})
    if not run:
        raise HTTPException(status_code=404, detail="run not found")

    return {
        "id": run.id,
        "url": run.url,
        "report": run.report,
        "status": run.status,
        "has_screenshot": run.hasScreenshot,
        "created_at": run.createdAt.strftime("%Y-%m-%dT%H:%M:%SZ") if run.createdAt else None,
        "files": os.listdir(run.folder) if os.path.exists(run.folder) else [],
        "vt_malicious": run.vtMalicious,
        "vt_suspicious": run.vtSuspicious,
        "vt_total": run.vtTotal,
        "urlscan_score": run.urlscanScore,
        "urlscan_id": run.urlscanId,
        "campaign_id": run.campaignId,
        "chain_depth": run.chainDepth or 0,
        "chain_parent_id": run.chainParentId,
        "severity": run.severity,
        "threat_summary": run.threatSummary,
        "agent_verdict": json.loads(run.agentVerdict) if run.agentVerdict else None,
    }


@app.delete("/api/runs/{run_id}")
async def delete_run(run_id: str):
    run = await prisma.analysisrun.find_unique(where={'id': run_id})
    if not run:
        raise HTTPException(status_code=404, detail="run not found")

    if os.path.exists(run.folder):
        shutil.rmtree(run.folder)

    await prisma.analysisrun.delete(where={'id': run_id})
    return {"message": "run deleted"}


@app.get("/api/runs/{run_id}/screenshot")
async def get_screenshot(run_id: str):
    path = os.path.join(CAGEDROP, run_id, "screenshot.png")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="screenshot not found")
    return FileResponse(path, media_type="image/png")


@app.get("/api/runs/{run_id}/export")
async def export_iocs(run_id: str, format: str = "csv"):
    run = await prisma.analysisrun.find_unique(where={'id': run_id})
    if not run:
        raise HTTPException(status_code=404, detail="run not found")

    iocs = collect_iocs(run.folder, run.url or "", run.report or "")

    if format == "stix":
        content = export_stix(iocs, run_id, run.url or "")
        return StreamingResponse(
            iter([content]),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="phishlab_{run_id}.stix.json"'},
        )
    else:
        content = export_csv(iocs, run_id)
        return StreamingResponse(
            iter([content]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="phishlab_{run_id}.csv"'},
        )


@app.get("/api/runs/{run_id}/redirects")
async def get_redirects(run_id: str):
    har_path = os.path.join(CAGEDROP, run_id, "network_traffic.har")
    if not os.path.exists(har_path):
        return {"chain": []}

    with open(har_path) as f:
        har = json.load(f)

    entries = har.get("log", {}).get("entries", [])
    url_map = {}
    for entry in entries:
        url = entry["request"]["url"]
        if url not in url_map:
            url_map[url] = entry

    chain = []
    current = entries[0] if entries else None
    visited = set()

    while current:
        url = current["request"]["url"]
        if url in visited:
            break
        visited.add(url)

        status = current["response"]["status"]
        redirect_to = current["response"].get("redirectURL", "")
        chain.append({"url": url, "status": status})

        if redirect_to and redirect_to in url_map:
            current = url_map[redirect_to]
        else:
            break

    return {"chain": chain}


@app.get("/api/analytics")
async def get_analytics():
    from collections import Counter, defaultdict
    all_runs = await prisma.analysisrun.find_many(order={"createdAt": "asc"})
    complete = [r for r in all_runs if r.status == "complete"]

    daily: dict = defaultdict(int)
    for run in complete:
        if run.createdAt:
            day = run.createdAt.strftime("%Y-%m-%d")
            daily[day] += 1

    threat_dist: Counter = Counter()
    for run in complete:
        vt = run.vtMalicious
        if vt is None:
            threat_dist["unscored"] += 1
        elif vt >= 5:
            threat_dist["malicious"] += 1
        elif vt > 0:
            threat_dist["suspicious"] += 1
        else:
            threat_dist["clean"] += 1

    status_counts: Counter = Counter(r.status for r in all_runs)

    campaign_runs = [r for r in complete if r.campaignId]
    campaign_counts: Counter = Counter(r.campaignId for r in campaign_runs)

    return {
        "totals": {
            "total": len(all_runs),
            "complete": len(complete),
            "malicious": threat_dist.get("malicious", 0),
            "campaigns": len(campaign_counts),
        },
        "runs_per_day": [{"date": k, "count": v} for k, v in sorted(daily.items())],
        "threat_distribution": [{"name": k, "value": v} for k, v in threat_dist.items()],
        "status_breakdown": [{"status": k, "count": v} for k, v in status_counts.items()],
        "top_campaigns": [
            {"id": cid[:12], "runs": count}
            for cid, count in campaign_counts.most_common(8)
        ],
    }


@app.get("/api/campaigns")
async def list_campaigns():
    runs = await prisma.analysisrun.find_many(
        where={"campaignId": {"not": None}, "status": "complete"},
        order={"createdAt": "desc"},
    )
    campaigns: dict = {}
    for run in runs:
        cid = run.campaignId
        if cid not in campaigns:
            campaigns[cid] = {
                "campaign_id": cid,
                "run_count": 0,
                "runs": [],
                "first_seen": run.createdAt.strftime("%Y-%m-%dT%H:%M:%SZ") if run.createdAt else None,
                "last_seen": run.createdAt.strftime("%Y-%m-%dT%H:%M:%SZ") if run.createdAt else None,
            }
        campaigns[cid]["run_count"] += 1
        campaigns[cid]["last_seen"] = run.createdAt.strftime("%Y-%m-%dT%H:%M:%SZ") if run.createdAt else None
        campaigns[cid]["runs"].append({
            "id": run.id,
            "url": run.url,
            "created_at": run.createdAt.strftime("%Y-%m-%dT%H:%M:%SZ") if run.createdAt else None,
        })
    return {"campaigns": list(campaigns.values())}

async def _run_feed_background(limit: int):
    print(f"INFO: starting automated feed ingestion (limit={limit})")
    try:
        if prisma.is_connected():
            await prisma.feedstatus.update(where={'id': 1}, data={'active': True, 'batchSize': limit})

        async def on_ready(run_id):
            await generation_queue.put(run_id)

        await start_feed(limit, on_ready=on_ready)
    finally:
        print("INFO: automated feed ingestion complete.")
        if prisma.is_connected():
            await prisma.feedstatus.update(where={'id': 1}, data={
                'active': False,
                'lastRun': datetime.datetime.now(datetime.timezone.utc)
            })

@app.post("/api/feed/start")
async def trigger_feed(req: FeedRequest, background_tasks: BackgroundTasks):
    status = await prisma.feedstatus.find_unique(where={'id': 1})
    if status and status.active:
        raise HTTPException(status_code=400, detail="ingestion already in progress")

    background_tasks.add_task(_run_feed_background, req.limit)
    return {"message": "ingestion started", "limit": req.limit}

@app.post("/api/feed/reset")
async def reset_feed():
    await prisma.feedstatus.update(where={'id': 1}, data={'active': False})
    return {"message": "feed status reset"}

@app.get("/api/feed/status")
async def get_feed_status():
    status = await prisma.feedstatus.find_unique(where={'id': 1})
    if not status:
        return {"active": False, "last_run": None, "batch_size": 0}
    return {
        "active": status.active,
        "last_run": status.lastRun.strftime("%Y-%m-%dT%H:%M:%SZ") if status.lastRun else None,
        "batch_size": status.batchSize
    }

