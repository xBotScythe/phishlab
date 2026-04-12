import json
import os
from collections import Counter
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from schemas import MemoryEntry, MemoryQueryResult

mcp = FastMCP("phishlab_memory")

MEMORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_memory.json")
MAX_ENTRIES = 200
COMPACT_TARGET = 150


def _load() -> list[dict]:
    if not os.path.exists(MEMORY_FILE):
        return []
    try:
        with open(MEMORY_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def _save(entries: list[dict]):
    with open(MEMORY_FILE, "w") as f:
        json.dump(entries, f, indent=2)


def _root(domain: str) -> str:
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _age_days(timestamp: str) -> float:
    try:
        ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - ts).total_seconds() / 86400
    except Exception:
        return 999


def _compact(entries: list[dict]) -> list[dict]:
    kept = []
    seen_keys = set()

    for e in sorted(entries, key=lambda x: x.get("timestamp", ""), reverse=True):
        age = _age_days(e.get("timestamp", ""))
        sev = e.get("severity", "medium")

        # benign: expire after 7 days
        if sev == "benign" and age > 7:
            continue
        # low: expire after 30 days
        if sev == "low" and age > 30:
            continue

        # dedupe same domain+severity+fingerprint, keep newest
        key = (e.get("domain", ""), sev, e.get("kit_fingerprint", ""))
        if key in seen_keys:
            continue
        seen_keys.add(key)

        kept.append(e)

    # if still over target, trim oldest medium entries
    if len(kept) > COMPACT_TARGET:
        critical_high = [e for e in kept if e.get("severity") in ("critical", "high")]
        rest = [e for e in kept if e.get("severity") not in ("critical", "high")]
        rest.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        kept = critical_high + rest[:COMPACT_TARGET - len(critical_high)]

    return kept


@mcp.tool()
def query_memory(domain: str, kit_fingerprint: str = "") -> MemoryQueryResult:
    """find relevant memory entries for cross-sample correlation"""
    entries = _load()
    if not entries:
        return MemoryQueryResult(entries=[], pattern_note="")

    query_root = _root(domain)

    scored = []
    for e in entries:
        score = 0
        if e.get("domain") == domain:
            score += 3
        elif _root(e.get("domain", "")) == query_root:
            score += 2
        if kit_fingerprint and e.get("kit_fingerprint") == kit_fingerprint:
            score += 2
        if _age_days(e.get("timestamp", "")) < 1:
            score += 1
        if score > 0:
            scored.append((score, e))

    scored.sort(key=lambda x: x[0], reverse=True)
    top = [e for _, e in scored[:7]]

    # detect patterns across results
    pattern_note = ""
    if len(top) >= 2:
        fps = [e.get("kit_fingerprint", "") for e in top if e.get("kit_fingerprint")]
        fp_counts = Counter(fps)
        common = [(fp, n) for fp, n in fp_counts.items() if n >= 2]
        if common:
            pattern_note = f"kit '{common[0][0]}' seen across {common[0][1]} samples"
        else:
            domains = [_root(e.get("domain", "")) for e in top]
            dom_counts = Counter(domains)
            shared = [(d, n) for d, n in dom_counts.items() if n >= 2]
            if shared:
                pattern_note = f"domain '{shared[0][0]}' analyzed {shared[0][1]} times"

    return MemoryQueryResult(
        entries=[MemoryEntry(**{k: e.get(k, "") for k in MemoryEntry.model_fields}) for e in top],
        pattern_note=pattern_note,
    )


@mcp.tool()
def store_memory(
    url: str,
    domain: str,
    severity: str,
    kit_fingerprint: str,
    delivery_vector: str,
) -> str:
    """store a verdict observation for future cross-sample correlation"""
    entries = _load()

    entries.append({
        "url": url,
        "domain": domain,
        "severity": severity,
        "kit_fingerprint": kit_fingerprint,
        "delivery_vector": delivery_vector,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    })

    if len(entries) > MAX_ENTRIES:
        before = len(entries)
        entries = _compact(entries)
        _save(entries)
        return f"stored + compacted {before} -> {len(entries)} entries"

    _save(entries)
    return "stored"


@mcp.tool()
def auto_compact() -> str:
    """manually trigger memory compaction"""
    entries = _load()
    before = len(entries)
    entries = _compact(entries)
    _save(entries)
    return f"compacted {before} -> {len(entries)} entries"


if __name__ == "__main__":
    mcp.run()
