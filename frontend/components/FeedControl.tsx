"use client";

import { useState, useEffect } from "react";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export default function FeedControl() {
  const [status, setStatus] = useState<{ active: boolean; batch_size: number; last_run: string | null }>({ active: false, batch_size: 0, last_run: null });
  const [loading, setLoading] = useState(false);
  const [limit, setLimit] = useState(5);

  const fetchStatus = async () => {
    try {
      const res = await fetch(`${API}/api/feed/status`);
      const data = await res.json();
      setStatus(data);
    } catch (err) {
      console.error("failed to fetch feed status", err);
    }
  };

  useEffect(() => {
    fetchStatus();
    // refresh status
  }, []);

  const triggerFeed = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/feed/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ limit }),
      });
      if (!res.ok) throw new Error("failed to start feed");
      fetchStatus();
    } catch (err) {
      alert("failed to trigger feed ingestion");
    } finally {
      setLoading(false);
    }
  };

  const resetFeed = async () => {
    if (!confirm("Are you sure you want to force-reset the ingestion status? Only do this if it is truly stuck.")) return;
    try {
      const res = await fetch(`${API}/api/feed/reset`, { method: "POST" });
      if (res.ok) fetchStatus();
    } catch (err) {
      alert("failed to reset feed status");
    }
  };

  return (
    <div className="card space-y-6">
      <div className="flex-between">
        <div>
          <h2 className="text-sm font-bold text-[var(--purple-bright)] uppercase tracking-tight">automated_ingestion</h2>
          <p className="text-xs text-dim mt-1">
            source: open_phish // active: <span className={status.active ? "text-[var(--success)]" : "text-dim"}>{status.active ? "READY" : "IDLE"}</span>
          </p>
        </div>

        <div className="flex gap-4 items-center">
          {!status.active && (
            <div className="flex items-center gap-2">
              <span className="text-[0.7rem] uppercase text-dim">batch:</span>
              <select
                value={limit}
                onChange={(e) => setLimit(Number(e.target.value))}
                className="bg-[var(--bg)] text-xs border border-[var(--border)] p-1 focus:border-[var(--purple)] outline-none"
              >
                <option value={3}>3</option>
                <option value={5}>5</option>
                <option value={10}>10</option>
              </select>
            </div>
          )}

          <button
            onClick={triggerFeed}
            disabled={loading || status.active}
            className="btn py-1.5 px-4"
          >
            {status.active ? "ingesting..." : "trigger_batch"}
          </button>

          {status.active && (
            <button
              onClick={resetFeed}
              className="btn btn-outline py-1.5 px-4 !border-[var(--error)] text-[var(--error)] hover:bg-[var(--error)] hover:text-white"
            >
              reset
            </button>
          )}
        </div>
      </div>

      {status.last_run && !status.active && (
        <div className="pt-4 border-t border-[var(--border)] text-[0.65rem] text-dim uppercase tracking-widest">
          last_ingestion_finished: {(() => {
            const d = new Date(status.last_run);
            return isNaN(d.getTime()) ? "unknown" : d.toLocaleString();
          })()}
        </div>
      )}
    </div>
  );
}
