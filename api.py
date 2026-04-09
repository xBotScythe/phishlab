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

# serialize access to the Ollama LLM so summaries run in a single queue
ollama_lock = asyncio.Lock()

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


@app.on_event("startup")
async def startup():
    try:
        await asyncio.wait_for(prisma.connect(), timeout=5.0)
    except Exception as e:
        print(f"ERROR: failed to connect to database: {e}")

    # reset stuck feed status from previous run
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

@app.on_event("shutdown")
async def shutdown():
    await prisma.disconnect()
    stop_ollama()


def sse(event_type: str, content: str) -> str:
    return f"data: {json.dumps({'type': event_type, 'content': content})}\n\n"


async def _run_detonation(run_id: str, url: str):
    run = await prisma.analysisrun.find_unique(where={'id': run_id})
    if not run:
        return

    try:
        with open(os.path.join(run.folder, "target.txt"), "w") as f:
            f.write(url)

        await prisma.analysisrun.update(where={'id': run_id}, data={'status': 'detonating'})
        success = await run_container(url, run.folder)

        if not success:
            await prisma.analysisrun.update(where={'id': run_id}, data={
                'status': 'failed',
                'error': "docker container exited with non-zero code"
            })
            return

        # mcp extraction phase
        await prisma.analysisrun.update(
            where={'id': run_id},
            data={'status': 'extracting', 'hasScreenshot': True}
        )
        # run MCP extraction and save assembled prompt to disk so SSE doesn't need
        # to re-run heavyweight extraction during streaming.
        prompt = await run_analysis(run.folder)
        try:
            with open(os.path.join(run.folder, "prompt.txt"), "w", encoding="utf-8") as pf:
                pf.write(prompt)
        except Exception:
            pass

        # prompt cached on disk, ready for llm streaming
        await prisma.analysisrun.update(where={'id': run_id}, data={'status': 'ready'})

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

    return {"ollama": ollama_ok, "docker": docker_ok}


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
    run = await prisma.analysisrun.find_unique(where={'id': run_id})
    if not run:
        raise HTTPException(status_code=404, detail="run not found")

    async def event_generator():
        # poll until ready or terminal state
        for _ in range(180):
            db_run = await prisma.analysisrun.find_unique(where={'id': run_id})
            if not db_run:
                return
            status = db_run.status

            if status == "complete":
                if db_run.report:
                    yield sse("token", db_run.report)
                yield sse("done", "")
                return
            elif status == "ready":
                break
            elif status == "generating":
                yield sse("status", "generating")
                await asyncio.sleep(2)
            elif status == "failed":
                yield sse("error", db_run.error or "unknown error")
                return
            else:
                yield sse("status", status)
                await asyncio.sleep(1)
        else:
            yield sse("error", "timeout waiting for analysis to progress")
            return

        yield sse("status", "generating")
        await prisma.analysisrun.update(where={'id': run_id}, data={'status': 'generating'})

        # prefer prompt cached by the detonation/extraction phase to avoid
        # re-running MCP tools in the SSE path
        prompt_path = os.path.join(run.folder, "prompt.txt")
        if os.path.exists(prompt_path):
            try:
                with open(prompt_path, "r", encoding="utf-8") as pf:
                    prompt = pf.read()
            except Exception as e:
                yield sse("error", f"failed to read prompt: {e}")
                await prisma.analysisrun.update(where={'id': run_id}, data={'status': 'failed'})
                return
        else:
            # fallback: assemble prompt on-demand (may be slow)
            try:
                prompt = await run_analysis(run.folder)
            except Exception as e:
                yield sse("error", f"analysis error: {e}")
                await prisma.analysisrun.update(where={'id': run_id}, data={'status': 'failed', 'error': str(e)})
                return

        full_report = ""

        try:
            # serialize all Ollama summary requests so they don't run concurrently
            async with ollama_lock:
                stream = await asyncio.to_thread(
                    ollama.chat,
                    model=MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    stream=True,
                    keep_alive="10m",
                )
                for chunk in stream:
                    token = chunk["message"]["content"]
                    full_report += token
                    yield sse("token", token)
        except Exception as e:
            yield sse("error", f"llm error: {e}")
            await prisma.analysisrun.update(where={'id': run_id}, data={'status': 'failed'})
            return

        # persist report
        report_path = os.path.join(run.folder, "report.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(full_report)

        await prisma.analysisrun.update(where={'id': run_id}, data={
            'status': 'complete',
            'report': full_report
        })
        yield sse("done", "")

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
        # search filter (matches url or run id)
        if q and q.lower() not in (run.url or "").lower() and q.lower() not in run.id.lower():
            continue
        # status filter
        if status and run.status != status:
            continue
        results.append({
            "id": run.id,
            "url": run.url,
            "status": run.status,
            "has_report": run.report is not None,
            "has_screenshot": run.hasScreenshot
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
        "files": os.listdir(run.folder) if os.path.exists(run.folder) else []
    }


@app.delete("/api/runs/{run_id}")
async def delete_run(run_id: str):
    run = await prisma.analysisrun.find_unique(where={'id': run_id})
    if not run:
        raise HTTPException(status_code=404, detail="run not found")

    # clean up artifacts on disk
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
        await start_feed(limit)
    finally:
        print("INFO: automated feed ingestion complete.")
        if prisma.is_connected():
            await prisma.feedstatus.update(where={'id': 1}, data={
                'active': False,
                'lastRun': datetime.datetime.utcnow()
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
        "last_run": status.lastRun.isoformat() + "Z" if status.lastRun else None,
        "batch_size": status.batchSize
    }
