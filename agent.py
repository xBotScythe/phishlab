import asyncio
import json
import os

import ollama

MODEL = os.environ.get("PHISHLAB_MODEL", "gemma4:e4b")

SEVERITY_LEVELS = ("critical", "high", "medium", "low", "benign")


def _extract_json(text: str) -> dict:
    start = text.find("{")
    end = text.rfind("}") + 1
    if start >= 0 and end > start:
        return json.loads(text[start:end])
    return {}


async def agent_escalate(report: str, url: str, vt_malicious: int | None, urlscan_score: float | None) -> dict:
    vt_line = f"{vt_malicious} malicious VT detections" if vt_malicious else "no VT detections"
    score_line = f"URLScan score {urlscan_score:.0f}/100" if urlscan_score is not None else "no URLScan data"

    prompt = f"""You are a threat analyst. Assess the severity of this analyzed URL: {url}
Intel: {vt_line}. {score_line}.

Report:
{report[:3000]}

Severity definitions:
- critical: active credential harvesting, confirmed malicious kit, live exfil to external host
- high: strong phishing indicators, brand impersonation, suspicious behavior
- medium: some indicators, unclear intent
- low: minimal indicators, likely benign
- benign: personal site, portfolio, false positive, no threat

Respond with JSON only:
{{"severity": "critical|high|medium|low|benign", "summary": "one sentence"}}"""

    try:
        response = await asyncio.to_thread(
            ollama.chat, model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            keep_alive="10m",
        )
        data = _extract_json(response.message.content)
        severity = data.get("severity", "medium")
        summary = data.get("summary", "")
        if severity not in SEVERITY_LEVELS:
            severity = "medium"
        print(f"ESCALATE: {severity.upper()} — {summary}")
        return {"severity": severity, "summary": summary}
    except Exception as e:
        print(f"ESCALATE: failed ({e})")
        return {"severity": "medium", "summary": ""}


async def agent_should_hunt(report: str, url: str, severity: str) -> bool:
    """decide whether the site warrants chain hunting at all."""
    if severity in ("benign", "low"):
        return False

    prompt = f"""Phishing analysis target: {url}
Severity: {severity}

Report summary:
{report[:1500]}

Should we detonate secondary URLs found in this site's infrastructure?
Hunt if: active credential harvesting, suspicious redirects, embedded kit loaders, form exfil endpoints.
Skip if: generic low-risk site, no meaningful secondary infrastructure, CMS/site-builder with no malicious behavior.

Respond with JSON only:
{{"hunt": true|false, "reason": "one sentence"}}"""

    try:
        response = await asyncio.to_thread(
            ollama.chat, model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            keep_alive="10m",
        )
        data = _extract_json(response.message.content)
        hunt = bool(data.get("hunt", False))
        reason = data.get("reason", "")
        print(f"HUNT DECISION: {'yes' if hunt else 'no'} — {reason}")
        return hunt
    except Exception as e:
        print(f"HUNT DECISION: failed ({e}), defaulting to severity gate")
        return severity in ("critical", "high")


async def agent_filter_chain(candidates: list[str], report: str, origin_url: str) -> list[str]:
    if not candidates:
        return []

    prompt = f"""Phishing site: {origin_url}

Report summary:
{report[:1500]}

Secondary URLs found in site artifacts:
{chr(10).join(f'- {u}' for u in candidates)}

Which URLs are worth detonating as phishing infrastructure?
Approve: form submission targets, exfil endpoints, redirect hops to suspicious domains, embedded kit loaders.
Skip: CDNs, analytics, social media, legitimate services.

Respond with JSON only:
{{"approve": ["url1"], "skip": ["url2"], "reason": "one sentence"}}"""

    try:
        response = await asyncio.to_thread(
            ollama.chat, model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            keep_alive="10m",
        )
        data = _extract_json(response.message.content)
        approved = data.get("approve", [])
        reason = data.get("reason", "")
        if reason:
            print(f"CHAIN AGENT: {reason}")
        candidate_set = set(candidates)
        return [u for u in approved if u in candidate_set]
    except Exception as e:
        print(f"CHAIN AGENT: failed ({e}), queuing all candidates")
        return candidates
