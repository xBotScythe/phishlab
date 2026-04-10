"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import StatusBadge from "@/components/StatusBadge";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type RunData = {
  id: string;
  url: string | null;
  report: string | null;
  status: string;
  has_screenshot: boolean;
  created_at: string | null;
  error?: string;
  vt_malicious: number | null;
  vt_suspicious: number | null;
  vt_total: number | null;
  urlscan_score: number | null;
  urlscan_id: string | null;
  campaign_id: string | null;
};

export default function RunDetails() {
  const { run_id } = useParams();
  const router = useRouter();
  const [run, setRun] = useState<RunData | null>(null);
  const [streamingToken, setStreamingToken] = useState("");
  const [completeReport, setCompleteReport] = useState("");
  const [status, setStatus] = useState("loading");

  useEffect(() => {
    let isMounted = true;
    let eventSource: EventSource | null = null;

    fetch(`${API}/api/runs/${run_id}`)
      .then((res) => {
        if (!res.ok) throw new Error("run not found");
        return res.json();
      })
      .then((data) => {
        if (!isMounted) return;

        setRun(data);
        setStatus(data.status);
        if (data.report) {
          setCompleteReport(data.report);
        }

        // stream if still in progress
        if (data.status !== "complete" && data.status !== "failed") {
          eventSource = new EventSource(`${API}/api/runs/${run_id}/stream`);

          eventSource.onmessage = (event) => {
            if (!isMounted) return;
            const streamData = JSON.parse(event.data);
            if (streamData.type === "status") {
              setStatus(streamData.content);
            } else if (streamData.type === "token") {
              setStreamingToken((prev) => prev + streamData.content);
              setStatus("generating");
            } else if (streamData.type === "done") {
              setStatus("complete");
              eventSource?.close();
            } else if (streamData.type === "error") {
              setStatus("failed");
              setRun((prev) => prev ? { ...prev, error: streamData.content } : null);
              eventSource?.close();
            }
          };

          eventSource.onerror = () => {
            eventSource?.close();
          };
        }
      })
      .catch((err) => {
        if (!isMounted) return;
        console.error("fetch error:", err);
        setStatus("failed");
      });

    return () => {
      isMounted = false;
      eventSource?.close();
    };
  }, [run_id]);

  const displayReport = completeReport || streamingToken;

  const handleExport = () => {
    if (!displayReport) return;
    const blob = new Blob([displayReport], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `phishlab_${run_id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDelete = async () => {
    if (!confirm("delete this run and all its artifacts?")) return;
    try {
      const res = await fetch(`${API}/api/runs/${run_id}`, { method: "DELETE" });
      if (res.ok) router.push("/");
    } catch {
      alert("failed to delete run");
    }
  };

  if (!run) return <div className="text-dim p-8 uppercase text-xs tracking-widest">// loading run metadata...</div>;

  return (
    <div className="space-y-8">
      {/* header */}
      <div className="border-b border-[var(--border)] pb-6 space-y-4">
        <div className="flex-between">
          <h1 className="text-xl truncate flex-1">{run.url || "UNKNOWN_TARGET"}</h1>
          <div className="flex items-center gap-3">
            <StatusBadge status={status} />
          </div>
        </div>

        <div className="flex-between flex-wrap gap-3">
          <p className="text-[0.65rem] text-dim uppercase tracking-widest">
            {run.created_at ? new Date(run.created_at).toLocaleString() : `RUN_ID: ${run_id}`}
          </p>
          <div className="flex gap-2 flex-wrap">
            {displayReport && (
              <>
                <button onClick={handleExport} className="btn-outline btn py-1 px-3 text-xs">export .md</button>
                <a href={`${API}/api/runs/${run_id}/export?format=csv`} download className="btn-outline btn py-1 px-3 text-xs">export .csv</a>
                <a href={`${API}/api/runs/${run_id}/export?format=stix`} download className="btn-outline btn py-1 px-3 text-xs">export stix</a>
              </>
            )}
            <button onClick={handleDelete} className="btn-outline btn py-1 px-3 text-xs !border-[var(--error)] text-[var(--error)] hover:bg-[var(--error)] hover:text-white">delete</button>
          </div>
        </div>

        {/* threat intel row — always shown for complete runs */}
        {status === "complete" && (
          <div className="flex gap-6 flex-wrap text-[0.65rem] uppercase tracking-widest">
            {run.vt_total != null ? (
              <span className={(run.vt_malicious ?? 0) > 0 ? "text-[var(--error)]" : "text-[var(--success)]"}>
                VT: {run.vt_malicious ?? 0} malicious / {run.vt_suspicious ?? 0} suspicious / {run.vt_total} engines
              </span>
            ) : (
              <span className="text-dim">VT: no data</span>
            )}

            {run.urlscan_id ? (
              <a
                href={`https://urlscan.io/result/${run.urlscan_id}/`}
                target="_blank"
                rel="noopener noreferrer"
                className={`hover:underline ${(run.urlscan_score ?? 0) > 50 ? "text-[var(--error)]" : "text-dim"}`}
              >
                urlscan: score {run.urlscan_score ?? 0} →
              </a>
            ) : (
              <span className="text-dim">urlscan: no existing scan</span>
            )}

            {run.campaign_id && (
              <span className="text-[var(--purple-bright)]">
                campaign: {run.campaign_id.slice(0, 20)}
              </span>
            )}
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        {/* screenshot */}
        <section className="space-y-4">
          <h3 className="text-xs uppercase tracking-widest text-dim font-bold">visual_capture</h3>
          <div className="card !p-0 overflow-hidden min-h-[300px] flex items-center justify-center bg-[var(--bg-raised)] border-[var(--border)] relative">
            {status === "complete" || status === "generating" || status === "queued" || status === "extracting" || run.has_screenshot ? (
              <img
                src={`${API}/api/runs/${run_id}/screenshot`}
                alt="screenshot"
                className="w-full h-auto block"
                onError={(e) => {
                  (e.target as HTMLImageElement).style.display = 'none';
                }}
              />
            ) : (
              <div className="text-center text-dim p-12">
                <div className="spinner mb-4 grayscale opacity-50"></div>
                <p className="text-[0.65rem] uppercase tracking-widest">
                  {status === "detonating" ? "capturing_screenshot..." : "preparing_environment..."}
                </p>
              </div>
            )}
          </div>
        </section>

        {/* report */}
        <section className="space-y-4">
          <h3 className="text-xs uppercase tracking-widest text-dim font-bold">analysis_report</h3>
          <div className="card min-h-[500px] bg-[var(--bg-card)] border-[var(--border)]">
            {displayReport ? (
              <div className="report-content">
                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                  {displayReport}
                </ReactMarkdown>
              </div>
            ) : (
              <div className="text-dim text-xs uppercase tracking-widest leading-relaxed">
                {status === "failed" ? (
                  <span className="text-[var(--error)]">ERROR: {run.error || "detonation_failed"}</span>
                ) : (
                  <div className="flex flex-col items-center gap-6 mt-12">
                    <div className="spinner grayscale"></div>
                    <span>{status === "extracting" ? "extracting_ioc_data..." : "generating_intelligence..."}</span>
                  </div>
                )}
              </div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
