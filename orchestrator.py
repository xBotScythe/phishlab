import json
import os
import sys
from contextlib import AsyncExitStack
from urllib.parse import urlparse

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class AgentOrchestrator:
    """mcp client that connects to escalation, hunt, and memory servers via stdio.
    singleton — spawn once at api startup, reuse across all runs."""

    def __init__(self):
        self._stack: AsyncExitStack | None = None
        self._escalation: ClientSession | None = None
        self._hunt: ClientSession | None = None
        self._memory: ClientSession | None = None

    async def start(self):
        self._stack = AsyncExitStack()

        servers = [
            ("_escalation", "agent_escalation_server.py"),
            ("_hunt", "agent_hunt_server.py"),
            ("_memory", "agent_memory_server.py"),
        ]

        for attr, script in servers:
            params = StdioServerParameters(
                command=sys.executable,
                args=[os.path.join(BASE_DIR, script)],
            )
            transport = await self._stack.enter_async_context(stdio_client(params))
            read_stream, write_stream = transport
            session = await self._stack.enter_async_context(ClientSession(read_stream, write_stream))
            await session.initialize()
            setattr(self, attr, session)
            print(f"ORCHESTRATOR: connected to {script}")

    async def stop(self):
        if self._stack:
            try:
                await self._stack.aclose()
            except Exception:
                pass
            print("ORCHESTRATOR: all servers stopped")

    async def _call(self, session: ClientSession, tool: str, args: dict) -> dict:
        """call an mcp tool and parse the json response"""
        result = await session.call_tool(tool, args)
        if result.isError:
            error_text = result.content[0].text if result.content else "unknown error"
            raise RuntimeError(f"tool {tool} failed: {error_text}")
        text = result.content[0].text
        return json.loads(text)

    def _format_memory(self, memory_result: dict) -> str:
        """turn memory query results into a compact context string for the llm"""
        entries = memory_result.get("entries", [])
        if not entries:
            return ""

        lines = []
        for e in entries:
            fp = e.get("kit_fingerprint", "")
            fp_note = f" [kit: {fp}]" if fp else ""
            lines.append(f"- {e['domain']}: {e['severity']} via {e['delivery_vector']}{fp_note} ({e['timestamp'][:10]})")

        pattern = memory_result.get("pattern_note", "")
        if pattern:
            lines.append(f"pattern detected: {pattern}")

        return "\n".join(lines)

    async def run_verdict(self, url: str, report: str,
                          vt_malicious: int | None = None,
                          urlscan_score: float | None = None,
                          parent_verdict: str = "",
                          yara_context: str = "",
                          has_malicious_download: bool = False) -> dict:
        """full verdict pipeline: memory query -> escalation -> memory store"""
        domain = urlparse(url).netloc

        # query memory for cross-sample context
        memory_context = ""
        try:
            mem = await self._call(self._memory, "query_memory", {
                "domain": domain,
            })
            memory_context = self._format_memory(mem)
            if memory_context:
                print(f"ORCHESTRATOR: memory returned {len(mem.get('entries', []))} entries for {domain}")
        except Exception as e:
            print(f"ORCHESTRATOR: memory query failed ({e}), continuing without context")

        # run escalation
        try:
            # combine memory and yara into enrichment context
            enrichment = memory_context
            if yara_context:
                enrichment = f"{enrichment}\n\n{yara_context}" if enrichment else yara_context

            verdict = await self._call(self._escalation, "assess_threat", {
                "report": report,
                "url": url,
                "vt_malicious": vt_malicious,
                "urlscan_score": urlscan_score,
                "memory_context": enrichment,
                "parent_verdict": parent_verdict,
            })
        except Exception as e:
            print(f"ORCHESTRATOR: escalation failed ({e}), using fallback")
            verdict = {
                "severity": "medium",
                "confidence": "low",
                "summary": f"escalation failed: {e}",
                "delivery_vector": "unknown",
                "user_interaction": "unknown",
                "kit_fingerprint": "",
                "reasoning": "orchestrator fallback — escalation server unreachable",
            }

        # store verdict in memory for future correlation
        try:
            await self._call(self._memory, "store_memory", {
                "url": url,
                "domain": domain,
                "severity": verdict.get("severity", "medium"),
                "kit_fingerprint": verdict.get("kit_fingerprint", ""),
                "delivery_vector": verdict.get("delivery_vector", "unknown"),
                "has_malicious_download": has_malicious_download,
            })
        except Exception as e:
            print(f"ORCHESTRATOR: memory store failed ({e})")

        return verdict

    async def run_hunt(self, report: str, url: str, severity: str, confidence: str) -> bool:
        """decide whether chain hunting is warranted"""
        try:
            result = await self._call(self._hunt, "should_hunt", {
                "report": report,
                "url": url,
                "severity": severity,
                "confidence": confidence,
            })
            return result.get("hunt", False)
        except Exception as e:
            print(f"ORCHESTRATOR: hunt decision failed ({e}), falling back to severity gate")
            return severity in ("critical", "high")

    async def run_takedown(self, url: str, report: str, registrar: dict,
                           hosting: dict, cloudflare_detected: bool,
                           vt_malicious: int | None, vt_url: str, date_str: str) -> dict:
        """generate abuse report emails via the hunt agent — one call per target, run concurrently"""
        import asyncio as _asyncio

        shared = {
            "url": url,
            "report": report,
            "vt_malicious": vt_malicious or 0,
            "vt_url": vt_url,
            "date_str": date_str,
            "hosting_org": hosting.get("org") or "",
            "server_ip": hosting.get("ip") or "",
        }

        async def _email(target: str, recipient_name: str, abuse_email: str) -> str:
            try:
                result = await self._call(self._hunt, "write_takedown_email", {
                    "target": target,
                    "recipient_name": recipient_name,
                    "abuse_email": abuse_email,
                    **shared,
                })
                return result.get("email", "")
            except Exception as e:
                print(f"ORCHESTRATOR: {target} takedown failed ({e})")
                return ""

        tasks = [_email("registrar", registrar.get("registrar") or "", registrar.get("abuse_email") or "")]
        if hosting:
            tasks.append(_email("hosting", hosting.get("org") or "", ""))
        if cloudflare_detected:
            tasks.append(_email("cloudflare", "Cloudflare", "abuse@cloudflare.com"))

        results = await _asyncio.gather(*tasks)

        templates: dict = {"registrar": results[0]}
        idx = 1
        if hosting:
            templates["hosting"] = results[idx]; idx += 1
        if cloudflare_detected:
            templates["cloudflare"] = results[idx]

        return templates

    async def run_chain_filter(self, candidates: list[str], report: str, url: str) -> list[str]:
        """filter chain candidates down to urls worth detonating"""
        if not candidates:
            return []
        try:
            result = await self._call(self._hunt, "filter_chain", {
                "candidates": candidates,
                "report": report,
                "origin_url": url,
            })
            return result.get("approve", [])
        except Exception as e:
            print(f"ORCHESTRATOR: chain filter failed ({e}), passing all candidates")
            return candidates
