# PhishLab

local threat detonation and AI analysis environment. isolates suspicious URLs in Docker containers, extracts indicators of compromise via MCP tools, and generates threat intelligence reports using a local LLM.

## how it works

```
URL submitted
    |
    v
[Docker Container] -- playwright captures screenshot, HAR, DOM, JS runtime, form interaction
    |
    v
[MCP Extraction Server] -- HAR, DOM IoCs, WHOIS/SSL, IP geo, brand similarity, JS runtime, form exfil
    |
    +--[YARA Scanner]-----------> deterministic kit detection against phishing rulesets
    |
    v
[Threat Intel] -- VirusTotal + URLScan enrichment (optional)
    |
    v
[Local LLM] -- vision-capable model analyzes screenshot + structured data + YARA hits
    |
    v
[Orchestrator] -- MCP client connecting to all agent servers
    |
    +--[MCP: Memory Server]------> cross-sample correlation (prior verdicts, kit fingerprints)
    |
    +--[MCP: Escalation Server]--> structured verdict (severity, delivery vector, kit fingerprint,
    |                               user interaction, reasoning) via schema-enforced LLM output
    |
    +--[ATT&CK Mapping]---------> verdict + YARA + form exfil -> MITRE technique IDs
    |
    +--[MCP: Hunt Server]--------> chain hunt decision + candidate filtering
    |
    v
[Chain Hunter] -- queues approved URLs as child runs (max depth 2, max 3 per run)
```

**key design decisions:**
- detonation happens inside disposable Docker containers — nothing touches the host
- analysis uses MCP (model context protocol) for structured tool invocation
- agent decisions use real MCP servers connected via stdio — not prompt chains
- all agent output is schema-enforced via ollama's `format=json_schema` — no regex parsing
- cross-sample memory correlates kit fingerprints and domains across runs
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
6. orchestrator queries cross-sample memory, then runs escalation for a structured verdict (severity, delivery vector, kit fingerprint, user interaction, reasoning)
7. verdict stored in memory for future correlation
8. fire a webhook notification if severity meets the configured threshold
9. hunt server decides whether to follow secondary infrastructure — if yes, filter server approves specific URLs and child runs are queued

### multi-agent verdict system
after each report, an orchestrator coordinates three MCP agent servers to produce a structured verdict:

1. **memory server** — queries prior observations for cross-sample context (same domain, same kit fingerprint, recent activity)
2. **escalation server** — produces a full `ThreatVerdict` with severity, confidence, delivery vector, user interaction model, kit fingerprint, and analytical reasoning
3. **memory server** — stores the new verdict for future correlation

all agent output is schema-enforced — ollama's `format=json_schema` parameter guarantees valid structured JSON matching the pydantic model. no regex parsing needed.

the verdict includes:
- **severity** — `critical`, `high`, `medium`, `low`, or `benign`
- **confidence** — `high`, `medium`, or `low` (based on corroborating signals)
- **delivery vector** — how the victim likely arrived (email link, SMS, ad redirect, search poisoning, etc.)
- **user interaction** — what the kit wants the victim to do (credential entry, file download, oauth grant, etc.)
- **kit fingerprint** — recognizable markers (js globals, form field names, exfil endpoints, css naming conventions)
- **reasoning** — 2-3 sentence chain of thought explaining the assessment

for chain children, the parent's verdict is passed as context so the LLM understands where in the attack chain this URL sits.

severity badges appear in the run list, run detail page, and diff comparisons. chain hunting is skipped entirely for `low` and `benign` runs.

### YARA kit detection
detonation artifacts (HTML, JS runtime, IoC data) are scanned against phishing-specific YARA rules before the LLM even runs. rules cover:
- **credential harvesting** — forms with password fields, email hash extraction from URL params
- **brand impersonation** — Office 365, Google, Adobe, banking portal signatures
- **exfiltration patterns** — Telegram bot exfil, Discord webhook exfil, PHP mailer handlers
- **kit signatures** — EvilProxy, 16shop, Storm-1575/DadSec, Greatness PaaS
- **obfuscation** — base64 decoded at runtime, eval/unescape chains
- **evasion** — bot cloaking via user-agent/referrer checks

YARA matches are deterministic — they anchor the LLM's verdict with concrete evidence rather than relying solely on inference. results feed into both the report prompt and the escalation server.

custom rules can be added to `yara_rules/` — any `.yar` file in that directory is compiled at startup.

### form interaction
after capturing the screenshot and DOM (preserving original state), the container attempts to interact with credential forms:
1. finds forms with password inputs
2. fills with honeypot data (`test@phishlab.local` / `PhishLab2024!`)
3. submits the form and intercepts the outbound request
4. captures the exfil endpoint URL, HTTP method, and POST data

the exfil endpoint is the most actionable artifact for takedowns — it reveals where stolen credentials are actually sent (often a Telegram bot, Discord webhook, or PHP handler on a different domain). the endpoint is included in IoC exports and displayed in the run detail.

form interaction is best-effort: it works on standard `<form>` submissions (covering most phishing kits). JS-only fetch/XHR submissions without a `<form>` element are already captured in the HAR.

### MITRE ATT&CK mapping
each verdict is automatically mapped to ATT&CK technique IDs based on:
- **delivery vector** → initial access techniques (T1566.002 for email links, T1660 for SMS, etc.)
- **user interaction** → execution/collection techniques (T1056.002 for credential capture, T1204.002 for file downloads)
- **YARA matches** → category-specific techniques (T1027 for obfuscation, T1036.005 for brand masquerading)
- **form exfil** → exfiltration techniques (T1041 for C2, T1567.002 for web service exfil)

technique IDs are clickable links to the MITRE ATT&CK knowledge base in the run detail page. they're also embedded as `attack-pattern` objects with relationships in the STIX 2.1 export, making it directly ingestible by threat intelligence platforms.

### cross-sample memory
the memory server maintains a persistent store of all verdict observations. when a new URL is analyzed, the orchestrator queries memory for:
- exact domain matches (score: 3)
- same root domain (score: 2)
- same kit fingerprint (score: 2)
- recent activity within 24h (score: 1)

the top 7 matches are formatted as context for the escalation LLM. if 2+ entries share a kit fingerprint, a pattern note is included (e.g. "kit 'evilproxy' seen across 4 samples").

memory auto-compacts when it exceeds 200 entries: benign entries expire after 7 days, low after 30 days, duplicates are deduped (newest kept), and critical/high entries persist indefinitely.

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
├── api.py                      # fastapi rest api + sse streaming
├── orchestrator.py             # mcp client connecting to all agent servers (singleton)
├── agent_escalation_server.py  # mcp server: structured threat verdicts via schema-enforced llm
├── agent_hunt_server.py        # mcp server: chain hunt decisions + candidate filtering
├── agent_memory_server.py      # mcp server: cross-sample memory with auto-compaction
├── schemas.py                  # shared pydantic models for all agent communication
├── yara_scanner.py             # YARA rule scanning against detonation artifacts
├── attack_mapping.py           # MITRE ATT&CK technique mapping from verdicts + YARA + form data
├── analyzer.py                 # mcp client, builds prompt from extracted data
├── mcp_server.py               # mcp tools: HAR, DOM, WHOIS/SSL, IP geo, JS runtime, brand similarity, form submission
├── detonation.py               # shared docker container runner
├── detonate_url.py             # runs inside the container (playwright + stealth)
├── threat_intel.py             # virustotal + urlscan enrichment
├── clustering.py               # perceptual hash campaign grouping
├── chain_hunter.py             # secondary url extraction and filtering
├── triage.py                   # feed candidate scoring by ASN and domain age
├── ioc_export.py               # csv + stix 2.1 export
├── feed_the_cage.py            # automated phishstats feed ingestion
├── ollama_manager.py           # ollama process lifecycle
├── launcher.py                 # unified startup (deps, docker build, db, api, frontend)
├── Dockerfile                  # detonation container image
├── docker-compose.yml          # postgres database
├── agent_memory.json           # persistent verdict memory (managed by memory server)
├── yara_rules/                 # phishing kit YARA rulesets (add custom .yar files here)
├── frontend/                   # next.js dashboard
│   ├── app/                    # pages (dashboard, detonate, run detail, diff, campaigns, analytics, history)
│   ├── components/             # shared ui (RunsList, FeedControl, StatusBadge, HealthIndicator)
│   └── prisma/                 # database schema
└── requirements.txt            # python dependencies
```
