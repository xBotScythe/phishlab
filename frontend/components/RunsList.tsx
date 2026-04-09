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
};

export default function RunsList({ limit }: { limit?: number }) {
  const [runs, setRuns] = useState<Run[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [diffMode, setDiffMode] = useState(false);
  const [diffSelection, setDiffSelection] = useState<string[]>([]);

  const fetchRuns = async () => {
    try {
      const params = new URLSearchParams();
      if (search) params.set("q", search);
      if (statusFilter) params.set("status", statusFilter);
      const res = await fetch(`${API}/api/runs?${params}`, { cache: "no-store", signal: AbortSignal.timeout(5000) });
      const data = await res.json();
      setRuns(data.runs ?? []);
      setError(false);
    } catch (err) {
      console.error("failed to fetch runs", err);
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

  const toggleDiffSelect = (id: string) => {
    setDiffSelection((prev) => {
      if (prev.includes(id)) return prev.filter((x) => x !== id);
      if (prev.length >= 2) return [prev[1], id];
      return [...prev, id];
    });
  };

  const displayRuns = limit ? runs.slice(0, limit) : runs;

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
      {/* search + filters */}
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
          <option value="generating">generating</option>
        </select>
        <button
          onClick={() => { setDiffMode(!diffMode); setDiffSelection([]); }}
          className={`btn-outline btn py-1.5 px-3 text-xs ${diffMode ? "!border-[var(--purple)] text-[var(--purple-bright)]" : ""}`}
        >
          {diffMode ? "cancel diff" : "compare"}
        </button>
        {diffMode && diffSelection.length === 2 && (
          <Link href={`/diff?a=${encodeURIComponent(diffSelection[0])}&b=${encodeURIComponent(diffSelection[1])}`} className="btn py-1.5 px-3 text-xs">
            view diff
          </Link>
        )}
      </div>

      {diffMode && (
        <p className="text-[0.65rem] text-dim uppercase tracking-widest">
          select 2 runs to compare ({diffSelection.length}/2 selected)
        </p>
      )}

      {runs.length === 0 && !loading ? (
        <div className="card text-center p-12 text-dim">
          <p className="mono text-sm">
            {search || statusFilter ? "no matching runs." : <>no runs found. <Link href="/detonate" className="text-[var(--purple-bright)]">detonate a url</Link> to begin.</>}
          </p>
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          {displayRuns.map((run) => (
            <div key={run.id} className="flex items-center gap-2">
              {diffMode && (
                <input
                  type="checkbox"
                  checked={diffSelection.includes(run.id)}
                  onChange={() => toggleDiffSelect(run.id)}
                  className="accent-[var(--purple)]"
                />
              )}
              <Link href={`/runs/${encodeURIComponent(run.id)}`} className="flex-1">
                <div className="card px-4 py-3 flex items-center justify-between hover:bg-[var(--bg-raised)] transition-colors">
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-bold text-[var(--purple-bright)] truncate tracking-tight">
                      {run.url ?? "// UNKNOWN_TARGET"}
                    </p>
                    <p className="text-[0.65rem] text-dim uppercase tracking-widest mt-0.5">
                      ID: {run.id}
                    </p>
                  </div>
                  <div className="flex items-center gap-4 ml-4">
                    <StatusBadge status={run.status} />
                  </div>
                </div>
              </Link>
            </div>
          ))}

          {limit && runs.length > limit && (
            <button onClick={() => {/* parent should remove limit */}} className="text-center mt-4">
              <span className="text-xs text-dim uppercase tracking-widest hover:text-[var(--purple-bright)]">
                + {runs.length - limit} more runs
              </span>
            </button>
          )}
        </div>
      )}
    </div>
  );
}
