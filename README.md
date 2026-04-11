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
[MCP Server] -- HAR, DOM IoCs, WHOIS/SSL, IP geolocation, brand similarity, JS runtime
    |
    v
[Threat Intel] -- VirusTotal + URLScan enrichment (optional)
    |
    v
[Local LLM] -- vision-capable model analyzes screenshot + structured data
    |
    v
[Agent: Escalation] -- assigns severity (critical/high/medium/low/benign) + one-line summary
    |
    v
[Webhook] -- fires on completion if severity meets threshold (optional)
    |
    v
[Agent: Chain Hunt Decision] -- decides if site warrants following its infrastructure
    |
    v
[Agent: Chain Filter] -- approves specific secondary URLs worth detonating
    |
    v
[Chain Hunter] -- queues approved URLs as child runs (max depth 2, max 3 per run)
```

**key design decisions:**
- detonation happens inside disposable Docker containers — nothing touches the host
- analysis uses MCP (model context protocol) for structured tool invocation
- LLM runs locally via Ollama — no data leaves your machine
- reports stream token-by-token via SSE to the frontend
- browser fingerprint is spoofed (UA, plugins, WebGL, webdriver flag) to reduce WAF blocks
- chain hunting is agent-gated — the LLM decides if infrastructure is worth following before spawning any child runs

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
3. extract IoCs via MCP tools (HAR, DOM, WHOIS/SSL, IP geolocation, JS runtime, brand similarity)
4. enrich with VirusTotal + URLScan if keys are configured
5. stream a threat report from the local LLM (screenshot passed to vision model)
6. assign a severity level and one-line threat summary via LLM escalation
7. fire a webhook notification if severity meets the configured threshold
8. agent decides whether to hunt secondary infrastructure — if yes, queues child runs automatically

### severity & escalation
after each report, a local LLM agent assigns a severity level and writes a one-line threat summary:

| severity | meaning |
|----------|---------|
| `critical` | active credential harvesting, confirmed malicious kit, live exfil |
| `high` | strong phishing indicators, brand impersonation, suspicious behavior |
| `medium` | some indicators, unclear intent |
| `low` | minimal indicators, likely benign |
| `benign` | personal site, portfolio, false positive |

severity badges appear in the run list, run detail page, and diff comparisons. chain hunting is skipped entirely for `low` and `benign` runs.

### chain hunting
after each completed analysis, an LLM agent first decides whether the site's infrastructure is worth following (it skips benign/low-severity sites and CMS pages with no suspicious secondary URLs). if approved, a second agent reviews the candidates extracted from the run's artifacts (form action targets, embedded iframes, HAR redirect hops) and approves only the ones worth detonating.

static assets (`.js`, `.css`, images, fonts) are filtered before the agent even sees them. known CDN and analytics domains are excluded. hosting platforms (Vercel, Weebly, Wix, etc.) are intentionally kept eligible — phishing kits are frequently hosted on them.

chain runs appear nested under their parent in the dashboard rather than as separate top-level entries. chains go up to 2 levels deep.

### feed triage
the automated feed scores each candidate URL before spending container time on it:
- **priority 3** — bulletproof-hosted ASN (M247, Frantech, DigitalOcean, etc.) or domain registered <7 days ago
- **priority 2** — normal
- **priority 1** — established domain (2+ years old), deprioritized

the feed processes URLs sorted high→low priority, so fresh infrastructure on shady ASNs goes first.

### automated feed
feed control pulls live phishing URLs from [PhishStats](https://phishstats.info) and processes them in batches. pre-filters dead sites before queuing. configurable batch size, runs up to 3 containers concurrently.

### url history & timeline
the dashboard groups repeated analyses of the same URL. clicking a URL that has been detonated multiple times opens a vertical timeline — each entry is expandable to show the screenshot and report for that run. useful for tracking phishing kits that rotate content or go offline between scans. individual runs can be re-detonated in one click from the run detail page.

### campaigns
runs with visually similar screenshots (perceptual hash) are automatically grouped into campaigns. view clustered runs at `/campaigns`.

### analytics
`/analytics` shows aggregate stats across all runs: threat distribution, runs over time, status breakdown, and top campaign clusters.

### diff & ioc delta
compare any two runs at `/diff?a=RUN_A&b=RUN_B`. the diff view shows:
- ioc delta: added/removed scripts, iframes, forms, links between runs (green `+` / red strikethrough)
- final URL change if the landing page shifted between runs
- severity badge and threat summary for each run side
- side-by-side screenshots and full reports

### ioc export
from any completed run, export indicators as:
- **markdown** — the raw report
- **csv** — type/value table of all IoCs
- **stix** — STIX 2.1 bundle JSON for ingestion into threat platforms

### redirect chain
run detail pages display the full redirect chain extracted from the HAR capture, showing each hop's URL and HTTP status code.

### webhook notifications
set `WEBHOOK_URL` in `.env` to receive a POST when a run completes at or above `WEBHOOK_MIN_SEVERITY`.

**slack:** create an [Incoming Webhook](https://api.slack.com/messaging/webhooks) in your Slack app settings and paste the webhook URL.

**discord:** Server Settings → Integrations → Webhooks → New Webhook → Copy Webhook URL.

**custom endpoint:** any HTTP server that accepts a POST with a JSON body.

payload includes severity and the LLM's one-line threat summary:
```json
{
  "run_id": "20250101120000_suspicious-site.com",
  "url": "https://suspicious-site.com/login",
  "status": "complete",
  "severity": "high",
  "threat_summary": "credential harvesting page impersonating a banking portal",
  "vt_malicious": 5,
  "urlscan_score": 85.0,
  "campaign_id": "20250101110000_similar-site.com",
  "timestamp": "2025-01-01T12:00:00Z"
}
```

## configuration

| env var | default | description |
|---------|---------|-------------|
| `DATABASE_URL` | (see .env.example) | postgres connection string |
| `NEXT_PUBLIC_API_URL` | `http://127.0.0.1:8000` | backend API url for frontend |
| `OLLAMA_HOST` | `127.0.0.1:11434` | ollama server address |
| `PHISHLAB_MODEL` | `gemma4:e4b` | ollama model for report generation and agent decisions |
| `VT_API_KEY` | — | VirusTotal API key (optional) |
| `URLSCAN_API_KEY` | — | URLScan API key (optional, search is free without it) |
| `WEBHOOK_URL` | — | HTTP endpoint to notify on run completion (optional) |
| `WEBHOOK_MIN_SEVERITY` | `high` | minimum severity to fire webhook: `critical`, `high`, `medium`, `low`, `benign` |

## REST API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | check Docker + Ollama status |
| `POST` | `/api/detonate` | submit a URL for detonation |
| `GET` | `/api/runs?q=&status=&url=` | list/search/filter runs |
| `GET` | `/api/runs/diff?a=&b=` | compare two runs with IoC delta |
| `GET` | `/api/runs/{id}` | full run metadata + report + severity |
| `GET` | `/api/runs/{id}/status` | poll run status |
| `GET` | `/api/runs/{id}/stream` | SSE stream (status + LLM tokens) |
| `GET` | `/api/runs/{id}/screenshot` | serve captured screenshot |
| `GET` | `/api/runs/{id}/redirects` | redirect chain extracted from HAR |
| `GET` | `/api/runs/{id}/export?format=csv\|stix` | export IoCs |
| `DELETE` | `/api/runs/{id}` | delete run + artifacts |
| `GET` | `/api/analytics` | aggregate stats across all runs |
| `GET` | `/api/campaigns` | list campaign clusters |
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

## architecture

```
phishlab/
├── api.py              # fastapi rest api + sse streaming
├── agent.py            # LLM agents: escalation, chain hunt decision, chain candidate filter
├── analyzer.py         # mcp client, builds prompt from extracted data
├── mcp_server.py       # mcp tools: HAR, DOM, WHOIS/SSL, IP geo, JS runtime, brand similarity
├── detonation.py       # shared docker container runner
├── detonate_url.py     # runs inside the container (playwright + stealth)
├── threat_intel.py     # virustotal + urlscan enrichment
├── clustering.py       # perceptual hash campaign grouping
├── chain_hunter.py     # secondary url extraction and filtering (static assets, CDNs excluded)
├── triage.py           # feed candidate scoring by ASN and domain age
├── ioc_export.py       # csv + stix 2.1 export
├── feed_the_cage.py    # automated phishstats feed ingestion
├── ollama_manager.py   # ollama process lifecycle
├── launcher.py         # unified startup (deps, docker build, db, api, frontend)
├── Dockerfile          # detonation container image
├── docker-compose.yml  # postgres database
├── frontend/           # next.js dashboard
│   ├── app/            # pages (dashboard, detonate, run detail, diff, campaigns, analytics, history)
│   ├── components/     # shared ui (RunsList, FeedControl, StatusBadge, HealthIndicator)
│   └── prisma/         # database schema
└── requirements.txt    # python dependencies
```
