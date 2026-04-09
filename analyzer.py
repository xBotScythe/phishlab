import sys
import os
import asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

MODEL = os.environ.get("PHISHLAB_MODEL", "gemma4:e4b")


async def run_analysis(output_dir: str) -> str:
    """run mcp extraction tools and return the assembled llm prompt"""
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["mcp_server.py"]
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            har_file = os.path.join(output_dir, "network_traffic.har")
            html_file = os.path.join(output_dir, "page_dom.html")
            target_file = os.path.join(output_dir, "target.txt")

            target_url = ""
            if os.path.exists(target_file):
                with open(target_file, "r") as f:
                    target_url = f.read().strip()

            # run all three extractions concurrently, with per-tool timeouts
            print("extracting data via MCP tools...")
            # wrap each call in asyncio.wait_for to avoid indefinite hangs
            timeout_sec = 30
            tasks = [
                asyncio.create_task(asyncio.wait_for(
                    session.call_tool("analyze_har", {"filepath": har_file}),
                    timeout=timeout_sec
                )),
                asyncio.create_task(asyncio.wait_for(
                    session.call_tool("extract_dom_iocs", {"filepath": html_file, "target_url": target_url}),
                    timeout=timeout_sec
                )),
                asyncio.create_task(asyncio.wait_for(
                    session.call_tool("analyze_domain", {"target_url": target_url}),
                    timeout=timeout_sec
                )),
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # log timeouts or errors for diagnostics
            for idx, r in enumerate(results):
                if isinstance(r, asyncio.TimeoutError):
                    print(f"MCP tool {idx} timed out after {timeout_sec}s")
                elif isinstance(r, Exception):
                    print(f"MCP tool {idx} error: {r}")

            har_data = results[0].content[0].text if not isinstance(results[0], Exception) else f"failed to extract HAR data: {results[0]}"
            dom_data = results[1].content[0].text if not isinstance(results[1], Exception) else f"failed to extract DOM data: {results[1]}"
            domain_data = results[2].content[0].text if not isinstance(results[2], Exception) else f"failed to extract domain OSINT: {results[2]}"

            return f"""Analyze the following phishing threat data extracted from a target URL.

OSINT Domain & SSL Intelligence:
{domain_data}

HAR Network Analysis:
{har_data}

HTML DOM Indicators of Compromise (includes Brand, Decoy Links, and Obfuscation):
{dom_data}

Instructions for Formatting:
1. DO NOT include hallucinated metadata such as "Analyst Name", "Date", or "Source". Start the report immediately.
2. Structure the report exactly with these headers:
   - **Executive Summary & Threat Assessment**
   - **Detailed Technical Analysis**
   - **Indicators of Compromise (IoCs)**
   - **Conclusion & Recommendations**
3. Keep the tone clinical, objective, and strictly tied to the provided data. No emojis.
4. ANALYZE BEHAVIORAL INTENT (Looking beyond just forms):
   - PHISHING INTENT: Look for deceptive "Call to Action" buttons (e.g., "Download Invoice", "Update Browser", "Verify Identity"), brand impersonation, and urgent/threatening language.
   - MALWARE/LURES: A site with a single prominent "Download" button for unexpected file types (zip, exe, html lures) on a low-reputation domain is a HIGH THREAT even if it has zero <form> elements.
   - BENIGN INTENT: Markers of personal expression (portfolios, homepages, blogs, hobbyist scripts) should be treated as strong MITIGATING FACTORS.
   - BALANCED JUDGMENT: A personal project (memes, blogs) on a new domain is likely BENIGN. An "Office 365" file lure or "Bank Security" alert on a new domain is HIGHLY MALICIOUS.
"""
