"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import StatusBadge from "./StatusBadge";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type Run = {
  id: string;
  url: string | null;
  status: string;
  has_report: boolean;
  has_screenshot: boolean;
  created_at: string | null;
  vt_malicious: number | null;
  campaign_id: string | null;
  severity: string | null;
  chain_depth: number;
  chain_parent_id: string | null;
};

const SEV_STYLES: Record<string, string> = {
  critical: "text-[#ff4444] border-[#ff4444]",
  high: "text-[var(--error)] border-[var(--error)]",
  medium: "text-[#ffaa00] border-[#ffaa00]",
  low: "text-[#4488ff] border-[#4488ff]",
  benign: "text-[var(--success)] border-[var(--success)]",
};

type UrlGroup = {
  url: string;
  runs: Run[];
  latest: Run;
  chainChildren: Run[];
};

export default function RunsList({ limit }: { limit?: number }) {
  const [runs, setRuns] = useState<Run[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  const fetchRuns = async () => {
    try {
      const params = new URLSearchParams();
      if (search) params.set("q", search);
      if (statusFilter) params.set("status", statusFilter);
      const res = await fetch(`${API}/api/runs?${params}`, { cache: "no-store", signal: AbortSignal.timeout(5000) });
      const data = await res.json();
      setRuns(data.runs ?? []);
      setError(false);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRuns();
    const interval = setInterval(fetchRuns, 3000);
    return () => clearInterval(interval);
  }, [search, statusFilter]);

  // build a map of run_id -> run for parent lookup
  const runById = Object.fromEntries(runs.map((r) => [r.id, r]));

  // group top-level runs by URL, attach chain children to their root parent
  const groupMap: Record<string, UrlGroup> = {};

  for (const run of runs) {
    if (run.chain_depth > 0) continue; // handled below as children
    const key = run.url ?? run.id;
    if (!groupMap[key]) groupMap[key] = { url: key, runs: [], latest: run, chainChildren: [] };
    groupMap[key].runs.push(run);
    if (run.status !== "failed" && groupMap[key].latest.status === "failed") {
      groupMap[key].latest = run;
    }
  }

  // attach chain children to the root parent's group
  for (const run of runs) {
    if (!run.chain_parent_id) continue;
    // walk up to root
    let parentId: string | null = run.chain_parent_id;
    let root: Run | undefined;
    while (parentId) {
      root = runById[parentId];
      parentId = root?.chain_parent_id ?? null;
    }
    if (!root) continue;
    const key = root.url ?? root.id;
    if (groupMap[key]) groupMap[key].chainChildren.push(run);
  }

  const grouped: UrlGroup[] = Object.values(groupMap);

  const display = limit ? grouped.slice(0, limit) : grouped;

  if (loading && runs.length === 0) {
    return (
      <div className="card p-8 text-center text-dim">
        <p className="mono text-sm">loading clinical datasets...</p>
      </div>
    );
  }

  if (error && runs.length === 0) {
    return (
      <div className="card text-center p-12 border-[var(--error)]">
        <p className="mono text-sm text-[var(--error)]">// SYSTEM OFFLINE: backend unreachable</p>
        <p className="mono text-xs text-dim mt-2">ensure uvicorn is running on {API}</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex gap-3 items-center flex-wrap">
        <input
          type="text"
          placeholder="search urls or run ids..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="flex-1 min-w-[200px] bg-[var(--bg)] border border-[var(--border)] p-2 text-xs focus:border-[var(--purple)] outline-none"
        />
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="bg-[var(--bg)] text-xs border border-[var(--border)] p-2 focus:border-[var(--purple)] outline-none"
        >
          <option value="">all statuses</option>
          <option value="complete">complete</option>
          <option value="failed">failed</option>
          <option value="pending">pending</option>
          <option value="detonating">detonating</option>
          <option value="extracting">extracting</option>
          <option value="queued">queued</option>
          <option value="generating">generating</option>
        </select>
      </div>

      {grouped.length === 0 && !loading ? (
        <div className="card text-center p-12 text-dim">
          <p className="mono text-sm">
            {search || statusFilter ? "no matching runs." : <>no runs found. <Link href="/detonate" className="text-[var(--purple-bright)]">detonate a url</Link> to begin.</>}
          </p>
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          {display.map((group) => {
            const latest = group.latest;
            const href = group.runs.length > 1
              ? `/history?url=${encodeURIComponent(group.url)}`
              : `/runs/${encodeURIComponent(latest.id)}`;

            return (
              <div key={group.url} className="flex flex-col gap-0.5">
                <Link href={href} className="flex-1 min-w-0">
                  <div className="card px-4 py-3 flex items-center justify-between hover:bg-[var(--bg-raised)] transition-colors overflow-hidden">
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-bold text-[var(--purple-bright)] truncate tracking-tight">
                        {group.url}
                      </p>
                      <p className="text-[0.65rem] text-dim uppercase tracking-widest mt-0.5">
                        {latest.created_at ? new Date(latest.created_at).toLocaleString() : `ID: ${latest.id}`}
                      </p>
                    </div>
                    <div className="flex items-center gap-3 ml-4">
                      {group.runs.length > 1 && (
                        <span className="text-[0.6rem] uppercase tracking-widest text-dim border border-[var(--border)] px-1.5 py-0.5">
                          {group.runs.length}x
                        </span>
                      )}
                      {latest.vt_malicious != null && latest.vt_malicious > 0 && (
                        <span className="text-[0.6rem] uppercase tracking-widest text-[var(--error)]">
                          VT:{latest.vt_malicious}
                        </span>
                      )}
                      {latest.severity && SEV_STYLES[latest.severity] && (
                        <span className={`text-[0.6rem] uppercase tracking-widest border px-1.5 py-0.5 ${SEV_STYLES[latest.severity]}`}>
                          {latest.severity}
                        </span>
                      )}
                      {latest.campaign_id && (
                        <span className="text-[0.6rem] uppercase tracking-widest text-[var(--purple-bright)]">
                          campaign
                        </span>
                      )}
                      <StatusBadge status={latest.status} />
                    </div>
                  </div>
                </Link>

                {group.chainChildren.length > 0 && (
                  <div className="ml-6 flex flex-col gap-0.5 border-l border-[var(--border)] pl-3">
                    {group.chainChildren.map((child) => (
                      <Link key={child.id} href={`/runs/${child.id}`}>
                        <div className="card px-3 py-2 flex items-center justify-between hover:bg-[var(--bg-raised)] transition-colors overflow-hidden">
                          <div className="min-w-0 flex-1">
                            <p className="text-[0.65rem] text-dim truncate">
                              <span className="text-[var(--purple-bright)] mr-1">↳</span>
                              {child.url}
                            </p>
                          </div>
                          <div className="flex items-center gap-2 ml-3">
                            {child.severity && SEV_STYLES[child.severity] && (
                              <span className={`text-[0.55rem] uppercase tracking-widest border px-1 py-0.5 ${SEV_STYLES[child.severity]}`}>
                                {child.severity}
                              </span>
                            )}
                            <StatusBadge status={child.status} />
                          </div>
                        </div>
                      </Link>
                    ))}
                  </div>
                )}
              </div>
            );
          })}

          {limit && grouped.length > limit && (
            <div className="text-center mt-4">
              <span className="text-xs text-dim uppercase tracking-widest">
                + {grouped.length - limit} more
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
