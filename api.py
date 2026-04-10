import asyncio
import datetime
import json
import os
import shutil
from urllib.parse import urlparse

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
from prisma import Prisma

app = FastAPI(title="PhishLab API", version="1.0.0")
prisma = Prisma()

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



# --- generation worker ---

async def _generate_report(run_id: str):
    """generate llm report for a single run. called by the queue worker."""
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
        response = await asyncio.to_thread(
            ollama.chat,
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            keep_alive="10m",
        )
        report = response.message.content

        with open(os.path.join(run.folder, "report.md"), "w", encoding="utf-8") as f:
            f.write(report)

        await prisma.analysisrun.update(where={'id': run_id}, data={
            'status': 'complete',
            'report': report
        })
        print(f"GENERATE: finished report for {run_id}")
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


# --- lifecycle ---

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
    await prisma.disconnect()
    stop_ollama()


def sse(event_type: str, content: str) -> str:
    return f"data: {json.dumps({'type': event_type, 'content': content})}\n\n"


def _detonation_complete(folder: str) -> bool:
    """check if the container finished writing its artifacts cleanly"""
    return os.path.exists(os.path.join(folder, "extracted_iocs.json"))


def _extraction_complete(folder: str) -> bool:
    """check if mcp extraction saved the assembled prompt"""
    return os.path.exists(os.path.join(folder, "prompt.txt"))


async def _run_detonation(run_id: str, url: str):
    """run (or resume) the detonation pipeline. skips any stage whose artifacts already exist."""
    run = await prisma.analysisrun.find_unique(where={'id': run_id})
    if not run:
        return

    try:
        with open(os.path.join(run.folder, "target.txt"), "w") as f:
            f.write(url)

        if _detonation_complete(run.folder):
            print(f"RESUME: skipping detonation for {run_id}, artifacts found on disk")
            await prisma.analysisrun.update(where={'id': run_id}, data={'hasScreenshot': True})
        else:
            await prisma.analysisrun.update(where={'id': run_id}, data={'status': 'detonating'})
            success = await run_container(url, run.folder)
            if not success:
                await prisma.analysisrun.update(where={'id': run_id}, data={
                    'status': 'failed',
                    'error': "docker container exited with non-zero code"
                })
                return
            await prisma.analysisrun.update(where={'id': run_id}, data={'hasScreenshot': True})

        if _extraction_complete(run.folder):
            print(f"RESUME: skipping extraction for {run_id}, prompt.txt found on disk")
        else:
            await prisma.analysisrun.update(where={'id': run_id}, data={'status': 'extracting'})
            prompt = await run_analysis(run.folder)
            try:
                with open(os.path.join(run.folder, "prompt.txt"), "w", encoding="utf-8") as pf:
                    pf.write(prompt)
            except Exception:
                pass

        # stage 3: queue for generation (worker serializes via ollama_lock)
        await prisma.analysisrun.update(where={'id': run_id}, data={'status': 'queued'})
        await generation_queue.put(run_id)

    except Exception as e:
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
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
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


@app.get("/api/runs/diff")
async def diff_runs(a: str, b: str):
    """compare two runs side by side"""
    run_a = await prisma.analysisrun.find_unique(where={'id': a})
    run_b = await prisma.analysisrun.find_unique(where={'id': b})
    if not run_a or not run_b:
        raise HTTPException(status_code=404, detail="one or both runs not found")

    return {
        "a": {"id": run_a.id, "url": run_a.url, "status": run_a.status, "report": run_a.report, "has_screenshot": run_a.hasScreenshot},
        "b": {"id": run_b.id, "url": run_b.url, "status": run_b.status, "report": run_b.report, "has_screenshot": run_b.hasScreenshot}
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
async def list_runs(q: str = "", status: str = ""):
    db_runs = await prisma.analysisrun.find_many(order={'createdAt': 'desc'})

    results = []
    for run in db_runs:
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
            "created_at": run.createdAt.isoformat() if run.createdAt else None,
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
        "created_at": run.createdAt.isoformat() if run.createdAt else None,
        "files": os.listdir(run.folder) if os.path.exists(run.folder) else []
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


# --- feed ingestion ---

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
        "last_run": status.lastRun.isoformat() if status.lastRun else None,
        "batch_size": status.batchSize
    }

