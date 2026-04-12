import asyncio
import json
import os

import ollama
from mcp.server.fastmcp import FastMCP

from schemas import ThreatVerdict

mcp = FastMCP("phishlab_escalation")

MODEL = os.environ.get("PHISHLAB_MODEL", "gemma4:e4b")
SEVERITY_LEVELS = ("critical", "high", "medium", "low", "benign")

SYSTEM_PROMPT = """you are a phishing threat analyst. your job is to assess detonated URLs
and produce structured verdicts. you think in terms of attack chains, not individual signals.

when assessing, consider:
- what does the attacker want the victim to do? (credential entry, file download, oauth grant, etc.)
- what delivery mechanism brought the victim here? (email link, sms, ad redirect, search poisoning, etc.)
- does this match a known kit pattern? (16shop, evilproxy, greatness, storm-1575, etc.)
- how does this fit with prior samples from the same infrastructure?

severity definitions:
- critical: active credential harvesting with confirmed exfil, known kit fingerprint, or multi-stage attack chain
- high: strong phishing indicators — brand impersonation, deceptive forms, suspicious redirects, download lures
- medium: some indicators but unclear intent — could be staging, parking, or partial kit deployment
- low: minimal indicators, likely benign but not conclusively safe
- benign: personal site, portfolio, legitimate service, false positive — no threat

confidence:
- high: multiple corroborating signals (e.g. brand + form + suspicious domain age + known kit markers)
- medium: some indicators align but gaps remain
- low: limited data, conflicting signals, or ambiguous intent

delivery_vector options: email_link, sms, ad_redirect, search_poisoning, social_media, qr_code, redirect_chain, unknown
- infer from: referrer patterns, url structure, utm params, short link usage, mobile-optimized layout

kit_fingerprint: leave empty if no recognizable markers. otherwise note what you see —
specific js globals, form field names, obfuscation patterns, exfil endpoints, css class naming conventions.

summary should be analytical, not just rewording the data. note what the kit is trying to accomplish,
what stage of the attack chain this represents, and any cross-sample patterns from memory."""


def _build_prompt(report: str, url: str, vt_malicious: int | None,
                  urlscan_score: float | None, memory_context: str,
                  parent_verdict: str) -> str:
    """assemble the assessment prompt from all available context"""
    lines = [f"target: {url}"]

    if vt_malicious is not None:
        lines.append(f"virustotal: {vt_malicious} malicious detections")
    if urlscan_score is not None:
        lines.append(f"urlscan score: {urlscan_score:.0f}/100")

    if memory_context:
        lines.append(f"\nprior observations from memory:\n{memory_context}")

    if parent_verdict:
        lines.append(f"\nthis is a child URL discovered during chain hunting. parent verdict:\n{parent_verdict}")

    lines.append(f"\nanalysis report:\n{report[:4000]}")

    return "\n".join(lines)


@mcp.tool()
def assess_threat(
    report: str,
    url: str,
    vt_malicious: int | None = None,
    urlscan_score: float | None = None,
    memory_context: str = "",
    parent_verdict: str = "",
) -> ThreatVerdict:
    """produce a structured threat verdict for a detonated url"""
    prompt = _build_prompt(report, url, vt_malicious, urlscan_score,
                           memory_context, parent_verdict)

    try:
        response = ollama.chat(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            format=ThreatVerdict.model_json_schema(),
            keep_alive="10m",
        )

        verdict = ThreatVerdict.model_validate_json(response.message.content)

        # clamp to valid severity
        if verdict.severity not in SEVERITY_LEVELS:
            verdict.severity = "medium"

        print(f"ESCALATE: {verdict.severity.upper()} ({verdict.confidence}) — {verdict.summary}")
        return verdict

    except Exception as e:
        print(f"ESCALATE: failed ({e}), returning fallback")
        return ThreatVerdict(
            severity="medium",
            confidence="low",
            summary=f"assessment failed: {e}",
            delivery_vector="unknown",
            user_interaction="unknown",
            kit_fingerprint="",
            reasoning="llm call failed, defaulting to medium for manual review",
        )


if __name__ == "__main__":
    mcp.run()
