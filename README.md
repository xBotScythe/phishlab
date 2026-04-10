# PhishLab

local threat detonation and AI analysis environment. isolates suspicious URLs in Docker containers, extracts indicators of compromise via MCP tools, and generates threat intelligence reports using a local LLM.

## how it works

```
URL submitted
    |
    v
[Docker Container] -- playwright captures screenshot, HAR, DOM, JS runtime
    |
    v
[MCP Server] -- extracts network calls, DOM IoCs, WHOIS/SSL, JS runtime artifacts
    |
    v
[Threat Intel] -- VirusTotal + URLScan enrichment (optional)
    |
    v
[Local LLM] -- vision-capable model analyzes screenshot + structured data
    |
    v
[Next.js Dashboard] -- streams report, clusters campaigns, exports IoCs
```

**key design decisions:**
- detonation happens inside disposable Docker containers -- nothing touches the host
- analysis uses MCP (model context protocol) for structured tool invocation
- LLM runs locally via Ollama -- no data leaves your machine
- reports stream token-by-token via SSE to the frontend
- browser fingerprint is spoofed (UA, plugins, WebGL, webdriver flag) to reduce WAF blocks

## requirements

- Python 3.10+
- Node.js 18+
- Docker Desktop
- [Ollama](https://ollama.com) with a vision-capable model pulled (default: `gemma4:e4b`)

## setup

```bash
git clone https://github.com/xbotscythe/phishlab.git
cd phishlab

cp .env.example .env

ollama pull gemma4:e4b

./run.sh
```

`run.sh` handles everything: venv, pip install, npm install, Docker image build (only when source changes), database setup, and launching all services.

- **dashboard**: http://localhost:3000
- **api**: http://localhost:8000/docs

## usage

### manual detonation
navigate to `/detonate`, paste a suspicious URL, and submit. the system will:
1. spin up a container to visit the URL
2. capture screenshot, network traffic (HAR), DOM, and JS runtime state
3. extract IoCs via MCP tools (HAR analysis, DOM parsing, WHOIS/SSL, JS runtime)
4. enrich with VirusTotal + URLScan if keys are configured
5. stream a threat report from the local LLM (screenshot passed to vision model)

### automated feed
feed control pulls live phishing URLs from [PhishStats](https://phishstats.info) and processes them in batches. pre-filters dead sites before queuing. configurable batch size, runs up to 3 containers concurrently.

### campaigns
runs with visually similar screenshots (perceptual hash) are automatically grouped into campaigns. view clustered runs at `/campaigns`.

### ioc export
from any completed run, export indicators as:
- **markdown** — the raw report
- **csv** — type/value table of all IoCs
- **stix** — STIX 2.1 bundle JSON for ingestion into threat platforms

### search & compare
search by URL or run ID, filter by status. select two runs and diff their reports and screenshots side by side.

## configuration

| env var | default | description |
|---------|---------|-------------|
| `DATABASE_URL` | (see .env.example) | postgres connection string |
| `NEXT_PUBLIC_API_URL` | `http://127.0.0.1:8000` | backend API url for frontend |
| `OLLAMA_HOST` | `127.0.0.1:11434` | ollama server address |
| `PHISHLAB_MODEL` | `gemma4:e4b` | ollama model for report generation |
| `VT_API_KEY` | — | VirusTotal API key (optional) |

## REST API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | check Docker + Ollama status |
| `POST` | `/api/detonate` | submit a URL for detonation |
| `GET` | `/api/runs?q=&status=` | list/search runs |
| `GET` | `/api/runs/diff?a=&b=` | compare two runs side by side |
| `GET` | `/api/runs/{id}` | full run metadata + report |
| `GET` | `/api/runs/{id}/status` | poll run status |
| `GET` | `/api/runs/{id}/stream` | SSE stream (status + LLM tokens) |
| `GET` | `/api/runs/{id}/screenshot` | serve captured screenshot |
| `GET` | `/api/runs/{id}/export?format=csv\|stix` | export IoCs |
| `DELETE` | `/api/runs/{id}` | delete run + artifacts |
| `POST` | `/api/feed/start` | trigger batch feed ingestion |
| `POST` | `/api/feed/reset` | force-reset stuck feed status |
| `GET` | `/api/feed/status` | feed ingestion state |
| `GET` | `/api/campaigns` | list campaign clusters |

### SSE stream event types

```json
{"type": "status",  "content": "detonating"}
{"type": "status",  "content": "extracting"}
{"type": "status",  "content": "generating"}
{"type": "token",   "content": "..."}
{"type": "done",    "content": ""}
{"type": "error",   "content": "..."}
```

## architecture

```
phishlab/
├── api.py              # fastapi rest api + sse streaming
├── analyzer.py         # mcp client, builds prompt from extracted data
├── mcp_server.py       # mcp tools: HAR, DOM, WHOIS/SSL, JS runtime
├── detonation.py       # shared docker container runner
├── detonate_url.py     # runs inside the container (playwright)
├── threat_intel.py     # virustotal + urlscan enrichment
├── clustering.py       # perceptual hash campaign grouping
├── ioc_export.py       # csv + stix 2.1 export
├── feed_the_cage.py    # automated phishstats feed ingestion
├── ollama_manager.py   # ollama process lifecycle
├── launcher.py         # unified startup (deps, docker build, db, api, frontend)
├── Dockerfile          # detonation container image
├── docker-compose.yml  # postgres database
├── frontend/           # next.js dashboard
│   ├── app/            # pages (dashboard, detonate, run detail, diff, campaigns)
│   ├── components/     # shared ui (RunsList, FeedControl, StatusBadge, HealthIndicator)
│   └── prisma/         # database schema
└── requirements.txt    # python dependencies
```
