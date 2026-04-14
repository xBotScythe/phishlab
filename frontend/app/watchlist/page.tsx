"use client";

import { useEffect, useState } from "react";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type WatchEntry = {
  id: string;
  url: string;
  interval_hours: number;
  last_run: string | null;
  created_at: string | null;
  active: boolean;
  label: string | null;
};

export default function WatchlistPage() {
  const [entries, setEntries] = useState<WatchEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [url, setUrl] = useState("");
  const [label, setLabel] = useState("");
  const [intervalHours, setIntervalHours] = useState(24);
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState("");

  const fetchEntries = async () => {
    try {
      const res = await fetch(`${API}/api/watchlist`);
      const data = await res.json();
      setEntries(data.entries ?? []);
    } catch {
      //
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEntries();
    const interval = setInterval(fetchEntries, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    setAdding(true);
    setError("");
    try {
      const res = await fetch(`${API}/api/watchlist`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim(), interval_hours: intervalHours, label: label.trim() }),
      });
      if (res.status === 409) {
        setError("url already in watchlist");
      } else if (!res.ok) {
        setError("failed to add");
      } else {
        setUrl("");
        setLabel("");
        setIntervalHours(24);
        await fetchEntries();
      }
    } catch {
      setError("failed to add");
    } finally {
      setAdding(false);
    }
  };

  const handleRemove = async (id: string) => {
    await fetch(`${API}/api/watchlist/${id}`, { method: "DELETE" });
    await fetchEntries();
  };

  const nextScan = (entry: WatchEntry) => {
    if (!entry.last_run) return "pending";
    const next = new Date(new Date(entry.last_run).getTime() + entry.interval_hours * 3600000);
    const now = new Date();
    if (next <= now) return "due now";
    const diffH = Math.round((next.getTime() - now.getTime()) / 3600000);
    if (diffH < 1) {
      const diffM = Math.round((next.getTime() - now.getTime()) / 60000);
      return `in ${diffM}m`;
    }
    return `in ${diffH}h`;
  };

  return (
    <div className="space-y-8">
      <div className="border-b border-[var(--border)] pb-6">
        <h1 className="text-xl mb-1">watchlist</h1>
        <p className="text-[0.65rem] text-dim uppercase tracking-widest">
          urls rescanned automatically while server is running
        </p>
      </div>

      <form onSubmit={handleAdd} className="card space-y-4">
        <h3 className="text-xs uppercase tracking-widest text-dim font-bold">add url</h3>
        <div className="flex gap-3 flex-wrap">
          <input
            type="text"
            placeholder="https://..."
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="flex-1 min-w-[260px] bg-[var(--bg)] border border-[var(--border)] p-2 text-xs focus:border-[var(--purple)] outline-none"
          />
          <input
            type="text"
            placeholder="label (optional)"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            className="w-40 bg-[var(--bg)] border border-[var(--border)] p-2 text-xs focus:border-[var(--purple)] outline-none"
          />
          <select
            value={intervalHours}
            onChange={(e) => setIntervalHours(Number(e.target.value))}
            className="bg-[var(--bg)] text-xs border border-[var(--border)] p-2 focus:border-[var(--purple)] outline-none"
          >
            <option value={6}>every 6h</option>
            <option value={12}>every 12h</option>
            <option value={24}>every 24h</option>
            <option value={48}>every 48h</option>
          </select>
          <button type="submit" disabled={adding || !url.trim()} className="btn btn-outline py-2 px-4 text-xs">
            {adding ? "adding..." : "add"}
          </button>
        </div>
        {error && <p className="text-[0.65rem] text-[var(--error)]">{error}</p>}
      </form>

      {loading ? (
        <p className="text-dim text-xs uppercase tracking-widest">loading...</p>
      ) : entries.length === 0 ? (
        <div className="card text-center p-12 text-dim">
          <p className="text-sm mono">no watched urls. add one above.</p>
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          {entries.map((entry) => (
            <div key={entry.id} className="card px-4 py-3 flex items-center gap-4">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <p className="text-xs font-bold text-[var(--purple-bright)] truncate">{entry.url}</p>
                  {entry.label && (
                    <span className="text-[0.6rem] uppercase tracking-widest text-dim border border-[var(--border)] px-1.5 py-0.5">
                      {entry.label}
                    </span>
                  )}
                </div>
                <p className="text-[0.65rem] text-dim uppercase tracking-widest mt-0.5">
                  every {entry.interval_hours}h
                  {" · "}last run: {entry.last_run ? new Date(entry.last_run).toLocaleString() : "never"}
                  {" · "}next: {nextScan(entry)}
                </p>
              </div>
              <button
                onClick={() => handleRemove(entry.id)}
                className="btn-outline btn py-1 px-3 text-xs !border-[var(--error)] text-[var(--error)] hover:bg-[var(--error)] hover:text-white shrink-0"
              >
                remove
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
