"use client";

import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import StatusBadge from "@/components/StatusBadge";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type RunSide = {
  id: string;
  url: string | null;
  status: string;
  report: string | null;
  has_screenshot: boolean;
  created_at: string | null;
  severity: string | null;
  threat_summary: string | null;
  vt_malicious: number | null;
  urlscan_score: number | null;
};

type DeltaEntry = { added: string[]; removed: string[] };

const SEV_STYLES: Record<string, string> = {
  critical: "bg-[#ff000022] text-[#ff4444] border-[#ff4444]",
  high: "bg-[#ff444422] text-[var(--error)] border-[var(--error)]",
  medium: "bg-[#ffaa0022] text-[#ffaa00] border-[#ffaa00]",
  low: "bg-[#4488ff22] text-[#4488ff] border-[#4488ff]",
  benign: "bg-[#44bb4422] text-[var(--success)] border-[var(--success)]",
};

function SeverityBadge({ severity }: { severity: string }) {
  const cls = SEV_STYLES[severity] ?? "text-dim border-[var(--border)]";
  return (
    <span className={`text-[0.6rem] uppercase tracking-widest border px-1.5 py-0.5 ${cls}`}>
      {severity}
    </span>
  );
}

export default function DiffPage() {
  return (
    <Suspense fallback={<div className="text-dim p-8 uppercase text-xs tracking-widest">loading diff...</div>}>
      <DiffView />
    </Suspense>
  );
}

function DiffView() {
  const params = useSearchParams();
  const [a, setA] = useState<RunSide | null>(null);
  const [b, setB] = useState<RunSide | null>(null);
  const [delta, setDelta] = useState<Record<string, DeltaEntry>>({});
  const [urlChanged, setUrlChanged] = useState<{ from: string | null; to: string | null } | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    const idA = params.get("a");
    const idB = params.get("b");
    if (!idA || !idB) {
      setError("missing run ids");
      return;
    }

    fetch(`${API}/api/runs/diff?a=${idA}&b=${idB}`)
      .then((res) => {
        if (!res.ok) throw new Error("failed to load diff");
        return res.json();
      })
      .then((data) => {
        setA(data.a);
        setB(data.b);
        setDelta(data.delta ?? {});
        setUrlChanged(data.url_changed ?? null);
      })
      .catch((e) => setError(e.message));
  }, [params]);

  if (error) {
    return <div className="text-[var(--error)] p-8 uppercase text-xs tracking-widest">{error}</div>;
  }

  if (!a || !b) {
    return <div className="text-dim p-8 uppercase text-xs tracking-widest">// loading diff...</div>;
  }

  const hasDelta = urlChanged || Object.keys(delta).length > 0;

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl">// report_diff</h1>
        <p className="text-dim text-sm mt-1">side-by-side comparison of two analysis runs</p>
      </div>

      {/* ioc delta */}
      {hasDelta && (
        <div className="card space-y-4">
          <h3 className="text-xs uppercase tracking-widest text-dim font-bold">ioc_delta</h3>

          {urlChanged && (
            <div className="space-y-1">
              <p className="text-[0.6rem] uppercase tracking-widest text-dim">final_url changed</p>
              {urlChanged.from && <p className="text-xs text-[var(--error)] line-through break-all">{urlChanged.from}</p>}
              {urlChanged.to && <p className="text-xs text-[var(--success)] break-all">→ {urlChanged.to}</p>}
            </div>
          )}

          {Object.entries(delta).map(([key, entry]) => (
            <div key={key} className="space-y-1">
              <p className="text-[0.6rem] uppercase tracking-widest text-dim">{key}</p>
              {entry.added.map((v) => (
                <p key={v} className="text-xs text-[var(--success)] break-all">+ {v}</p>
              ))}
              {entry.removed.map((v) => (
                <p key={v} className="text-xs text-[var(--error)] line-through break-all">- {v}</p>
              ))}
            </div>
          ))}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {[a, b].map((run, i) => (
          <div key={run.id} className="space-y-4">
            {/* header */}
            <div className="flex-between">
              <div className="min-w-0 flex-1">
                <p className="text-xs font-bold text-[var(--purple-bright)] truncate">{run.url ?? "unknown"}</p>
                <p className="text-[0.6rem] text-dim uppercase tracking-widest mt-0.5">{run.id}</p>
              </div>
              <div className="flex items-center gap-2">
                {run.severity && <SeverityBadge severity={run.severity} />}
                <StatusBadge status={run.status} />
              </div>
            </div>
            {run.threat_summary && (
              <p className="text-xs text-dim">{run.threat_summary}</p>
            )}

            {/* screenshot */}
            {run.has_screenshot && (
              <div className="card !p-0 overflow-hidden">
                <img
                  src={`${API}/api/runs/${run.id}/screenshot`}
                  alt={`screenshot ${i === 0 ? "A" : "B"}`}
                  className="w-full h-auto block"
                />
              </div>
            )}

            {/* report */}
            <div className="card min-h-[400px] bg-[var(--bg-card)]">
              {run.report ? (
                <div className="report-content text-sm">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{run.report}</ReactMarkdown>
                </div>
              ) : (
                <p className="text-dim text-xs uppercase tracking-widest">no report available</p>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
