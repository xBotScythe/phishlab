import os

import ollama
from mcp.server.fastmcp import FastMCP

from schemas import ChainFilter, HuntDecision

mcp = FastMCP("phishlab_hunt")

MODEL = os.environ.get("PHISHLAB_MODEL", "gemma4:e4b")


@mcp.tool()
def should_hunt(
    report: str,
    url: str,
    severity: str,
    confidence: str,
) -> HuntDecision:
    """decide whether a site warrants chain hunting for secondary urls"""

    # hard gates — skip without burning an llm call
    if severity in ("benign", "low"):
        return HuntDecision(hunt=False, reason=f"severity {severity}, not worth hunting")
    if severity == "medium" and confidence == "low":
        return HuntDecision(hunt=False, reason="medium severity with low confidence, skipping")

    prompt = f"""target: {url}
severity: {severity} (confidence: {confidence})

report summary:
{report[:2000]}

should we detonate secondary URLs found in this site's infrastructure?

hunt if: active credential harvesting, suspicious redirects, embedded kit loaders,
form exfil endpoints, multi-stage attack chain, iframe injections.

skip if: generic low-risk site, no meaningful secondary infrastructure,
standard cms with no malicious behavior, single-page with no external calls."""

    try:
        response = ollama.chat(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            format=HuntDecision.model_json_schema(),
            keep_alive="10m",
        )
        decision = HuntDecision.model_validate_json(response.message.content)
        print(f"HUNT: {'yes' if decision.hunt else 'no'} — {decision.reason}")
        return decision

    except Exception as e:
        print(f"HUNT: failed ({e}), falling back to severity gate")
        fallback = severity in ("critical", "high")
        return HuntDecision(hunt=fallback, reason=f"llm failed, defaulting based on {severity} severity")


@mcp.tool()
def filter_chain(
    candidates: list[str],
    report: str,
    origin_url: str,
) -> ChainFilter:
    """filter chain hunting candidates — keep only urls worth detonating"""
    if not candidates:
        return ChainFilter(approve=[], skip=[], reason="no candidates")

    prompt = f"""phishing site: {origin_url}

report summary:
{report[:1500]}

secondary URLs found in site artifacts:
{chr(10).join(f'- {u}' for u in candidates)}

which URLs are worth detonating as potential phishing infrastructure?

approve: form submission targets, exfil endpoints, redirect hops, embedded kit loaders,
suspicious domains receiving credentials or data.

skip: CDNs, analytics, social media, fonts, legitimate services, same-origin static assets."""

    try:
        response = ollama.chat(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            format=ChainFilter.model_json_schema(),
            keep_alive="10m",
        )
        result = ChainFilter.model_validate_json(response.message.content)

        # only approve urls that were actually in the candidate list
        candidate_set = set(candidates)
        result.approve = [u for u in result.approve if u in candidate_set]

        print(f"CHAIN FILTER: {len(result.approve)} approved, {len(result.skip)} skipped — {result.reason}")
        return result

    except Exception as e:
        print(f"CHAIN FILTER: failed ({e}), approving all candidates")
        return ChainFilter(approve=candidates, skip=[], reason=f"llm failed, passing all through")


if __name__ == "__main__":
    mcp.run()
