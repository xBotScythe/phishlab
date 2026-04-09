# PhishLab

local threat detonation and AI analysis environment. isolates suspicious URLs in Docker containers, extracts indicators of compromise via MCP tools, and generates threat intelligence reports using a local LLM.

## how it works

```
URL submitted
    |
    v
[Docker Container] -- playwright captures screenshot, HAR, DOM
    |
    v
[MCP Server] -- extracts network calls, DOM iocs, whois/ssl intel
    |
    v
[Local LLM] -- generates structured threat report (streamed to frontend)
    |
    v
[Next.js Dashboard] -- displays report + screenshot in real time
```

**key design decisions:**
- detonation happens inside disposable Docker containers -- nothing touches the host
- analysis uses MCP (model context protocol) for structured tool invocation
- LLM runs locally via Ollama -- no data leaves your machine
- reports stream token-by-token via SSE to the frontend

## requirements

- Python 3.10+
- Node.js 18+
- Docker Desktop
- [Ollama](https://ollama.com) with a model pulled (default: `gemma4:e4b`)

## setup

```bash
# clone and enter
git clone https://github.com/xbotscythe/phishlab.git
cd phishlab

# copy env template
cp .env.example .env

# pull the default model
ollama pull gemma4:e4b

# build the detonation container
docker build -t phishing-cage .

# run everything (installs deps, starts db, api, frontend)
./run.sh
```

the launcher handles venv creation, pip install, npm install, database setup, and starting all services. once running:

- **dashboard**: http://localhost:3000
- **api**: http://localhost:8000
- **api docs**: http://localhost:8000/docs

## usage

### manual detonation
navigate to `/detonate`, paste a suspicious URL, and hit submit. the system will:
1. spin up a container to visit the URL
2. capture screenshot + network traffic + DOM
3. extract IoCs via MCP tools (HAR analysis, DOM parsing, WHOIS/SSL)
4. stream a threat report from the local LLM

### automated feed
the dashboard has a feed control that pulls live URLs from [OpenPhish](https://openphish.com) and processes them in batches. configurable batch size (3/5/10), runs up to 3 containers concurrently.

### search & compare
the runs list supports real-time search (by URL or run ID) and status filtering. select two runs and use the diff view to compare reports and screenshots side by side.

### configuration

| env var | default | description |
|---------|---------|-------------|
| `DATABASE_URL` | (see .env.example) | postgres connection string |
| `NEXT_PUBLIC_API_URL` | `http://127.0.0.1:8000` | backend API url for frontend |
| `OLLAMA_HOST` | `127.0.0.1:11434` | ollama server address |
| `PHISHLAB_MODEL` | `gemma4:e4b` | ollama model for report generation |

## REST API

the API is available at `http://localhost:8000`. interactive OpenAPI docs at `/docs`.

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
| `DELETE` | `/api/runs/{id}` | delete run + artifacts |
| `POST` | `/api/feed/start` | trigger batch feed ingestion |
| `POST` | `/api/feed/reset` | force-reset stuck feed status |
| `GET` | `/api/feed/status` | feed ingestion state |

### SSE stream event types

```json
{"type": "status",  "content": "detonating"}
{"type": "status",  "content": "extracting"}
{"type": "status",  "content": "generating"}
{"type": "token",   "content": "..."}
{"type": "done",    "content": ""}
{"type": "error",   "content": "..."}
```

### example

```bash
# submit url
curl -X POST http://localhost:8000/api/detonate \
  -H "Content-Type: application/json" \
  -d '{"url": "http://suspicious-site.com"}'

# stream the analysis (SSE)
curl -N http://localhost:8000/api/runs/{run_id}/stream
```

## architecture

```
phishlab/
├── api.py              # fastapi rest api + sse streaming
├── analyzer.py         # mcp client, builds prompt from extracted data
├── mcp_server.py       # mcp tools: HAR, DOM, WHOIS/SSL extraction
├── detonation.py       # shared docker container runner
├── detonate_url.py     # runs inside the container (playwright)
├── feed_the_cage.py    # automated openphish feed ingestion
├── ollama_manager.py   # ollama process lifecycle
├── launcher.py         # unified startup (db, api, frontend)
├── Dockerfile          # detonation container image
├── docker-compose.yml  # postgres database
├── frontend/           # next.js dashboard
│   ├── app/            # pages (dashboard, detonate, run detail, diff)
│   ├── components/     # shared ui (RunsList, FeedControl, StatusBadge, HealthIndicator)
│   └── prisma/         # database schema
└── requirements.txt    # python dependencies
```