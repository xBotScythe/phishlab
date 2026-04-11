"use client";

import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import StatusBadge from "@/components/StatusBadge";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type Run = {
  id: string;
  url: string | null;
  status: string;
  has_screenshot: boolean;
  created_at: string | null;
  vt_malicious: number | null;
  vt_suspicious: number | null;
  vt_total: number | null;
  urlscan_score: number | null;
  urlscan_id: string | null;
  campaign_id: string | null;
  report: string | null;
};

export default function HistoryPage() {
  return (
    <Suspense fallback={<div className="text-dim p-8 uppercase text-xs tracking-widest">loading...</div>}>
      <HistoryView />
    </Suspense>
  );
}

function HistoryView() {
  const params = useSearchParams();
  const url = params.get("url") ?? "";
  const [runs, setRuns] = useState<Run[]>([]);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [loadedReports, setLoadedReports] = useState<Record<string, string>>({});

  useEffect(() => {
    if (!url) return;
    fetch(`${API}/api/runs?url=${encodeURIComponent(url)}`)
      .then((r) => r.json())
      .then((d) => setRuns(d.runs ?? []));
  }, [url]);

  const toggle = async (run: Run) => {
    const next = !expanded[run.id];
    setExpanded((prev) => ({ ...prev, [run.id]: next }));

    if (next && !loadedReports[run.id]) {
      const data = await fetch(`${API}/api/runs/${run.id}`).then((r) => r.json());
      if (data.report) {
        setLoadedReports((prev) => ({ ...prev, [run.id]: data.report }));
      }
    }
  };

  const deleteRun = async (e: React.MouseEvent, runId: string) => {
    e.stopPropagation();
    if (!confirm("delete this run and all its artifacts?")) return;
    const res = await fetch(`${API}/api/runs/${runId}`, { method: "DELETE" });
    if (res.ok) {
      setRuns((prev) => prev.filter((r) => r.id !== runId));
    }
  };

  if (!url) return <div className="text-dim p-8 text-xs uppercase tracking-widest">no url specified</div>;

  return (
    <div className="space-y-8">
      <div>
        <p className="text-[0.65rem] text-dim uppercase tracking-widest mb-1">url history</p>
        <h1 className="text-lg font-bold text-[var(--purple-bright)] break-all">{url}</h1>
        <p className="text-dim text-xs mt-1">{runs.length} analysis run{runs.length !== 1 ? "s" : ""}</p>
      </div>

      {runs.length === 0 ? (
        <div className="card p-12 text-center text-dim text-xs uppercase tracking-widest">no runs found</div>
      ) : (
        <div className="relative">
          {/* vertical line */}
          <div className="absolute left-[7px] top-2 bottom-2 w-px bg-[var(--border)]" />

          <div className="flex flex-col gap-4">
            {runs.map((run) => {
              const isExpanded = expanded[run.id];
              const report = loadedReports[run.id];

              return (
                <div key={run.id} className="flex gap-4">
                  {/* dot */}
                  <div className={`shrink-0 w-[15px] h-[15px] rounded-full border-2 mt-1 z-10 ${
                    run.status === "complete" ? "bg-[var(--purple)] border-[var(--purple-bright)]" :
                    run.status === "failed" ? "bg-[var(--error)] border-[var(--error)]" :
                    "bg-[var(--bg-raised)] border-[var(--border)]"
                  }`} />

                  <div className="flex-1 min-w-0 space-y-2">
                    {/* collapsed row */}
                    <button
                      onClick={() => toggle(run)}
                      className="w-full card px-4 py-3 text-left hover:bg-[var(--bg-raised)] transition-colors"
                    >
                      <div className="flex items-center justify-between gap-4 flex-wrap">
                        <div className="flex items-center gap-3 flex-wrap">
                          <StatusBadge status={run.status} />
                          <span className="text-[0.65rem] text-dim uppercase tracking-widest">
                            {run.created_at ? new Date(run.created_at).toLocaleString() : run.id}
                          </span>
                          {run.vt_malicious != null && run.vt_malicious > 0 && (
                            <span className="text-[0.6rem] uppercase tracking-widest text-[var(--error)]">
                              VT:{run.vt_malicious} malicious
                            </span>
                          )}
                          {run.campaign_id && (
                            <span className="text-[0.6rem] uppercase tracking-widest text-[var(--purple-bright)]">campaign</span>
                          )}
                        </div>
                        <div className="flex items-center gap-3">
                          <Link
                            href={`/runs/${run.id}`}
                            onClick={(e) => e.stopPropagation()}
                            className="text-[0.6rem] uppercase tracking-widest text-dim hover:text-[var(--purple-bright)]"
                          >
                            full report →
                          </Link>
                          <button
                            onClick={(e) => deleteRun(e, run.id)}
                            className="text-[0.6rem] uppercase tracking-widest text-[var(--error)] hover:underline"
                          >
                            delete
                          </button>
                          <span className="text-dim text-xs">{isExpanded ? "▲" : "▼"}</span>
                        </div>
                      </div>
                    </button>

                    {/* expanded view */}
                    {isExpanded && (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pl-0">
                        {run.has_screenshot && (
                          <div className="card !p-0 overflow-hidden">
                            <img
                              src={`${API}/api/runs/${run.id}/screenshot`}
                              alt="screenshot"
                              className="w-full h-auto block"
                            />
                          </div>
                        )}
                        <div className="card bg-[var(--bg-card)] max-h-[400px] overflow-y-auto">
                          {report ? (
                            <div className="report-content text-sm">
                              <ReactMarkdown remarkPlugins={[remarkGfm]}>{report}</ReactMarkdown>
                            </div>
                          ) : run.status === "complete" ? (
                            <p className="text-dim text-xs uppercase tracking-widest">loading report...</p>
                          ) : (
                            <p className="text-dim text-xs uppercase tracking-widest">no report available</p>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
