"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import StatusBadge from "@/components/StatusBadge";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

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
    <span className={`text-[0.6rem] uppercase tracking-widest border px-1.5 py-0.5 shrink-0 ${cls}`}>
      {severity}
    </span>
  );
}

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
  chain_depth: number;
  chain_parent_id: string | null;
  severity: string | null;
  threat_summary: string | null;
  urlhaus_hit: boolean | null;
  domain_age_days: number | null;
  agent_verdict: {
    severity: string;
    confidence: string;
    summary: string;
    delivery_vector: string;
    user_interaction: string;
    kit_fingerprint: string;
    reasoning: string;
    attack_techniques?: { id: string; name: string; source: string }[];
  } | null;
  form_submission: {
    form_action: string;
    form_method: string;
    fields_filled: Record<string, string>;
    input_count: number;
    submission: { url: string; method: string; post_data: string | null } | null;
    post_submit_url: string;
  } | null;
  file_scans: { filename: string; vt_malicious: number; vt_suspicious: number; vt_total: number; vt_analysis_id: string }[] | null;
  downloads: { filename: string; url: string }[] | null;
};

type TakedownData = {
  registrar: { registrar: string | null; abuse_email: string | null; domain: string | null };
  hosting: { ip: string; org: string; asn: string; country: string; is_cloudflare: boolean } | null;
  cloudflare_detected: boolean;
  templates: { registrar: string; hosting?: string; cloudflare?: string };
};

export default function RunDetails() {
  const { run_id } = useParams();
  const router = useRouter();
  const [run, setRun] = useState<RunData | null>(null);
  const [streamingToken, setStreamingToken] = useState("");
  const [completeReport, setCompleteReport] = useState("");
  const [status, setStatus] = useState("loading");
  const [redirectChain, setRedirectChain] = useState<{ url: string; status: number }[]>([]);
  const [takedown, setTakedown] = useState<TakedownData | null>(null);
  const [takedownLoading, setTakedownLoading] = useState(false);
  const [takedownOpen, setTakedownOpen] = useState(false);
  const [activeTemplate, setActiveTemplate] = useState<"registrar" | "hosting" | "cloudflare">("registrar");
  const [copied, setCopied] = useState(false);

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

        fetch(`${API}/api/runs/${run_id}/redirects`)
          .then((r) => r.json())
          .then((d) => { if (d.chain?.length > 1) setRedirectChain(d.chain); })
          .catch(() => {});

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

  const handleRerun = async () => {
    if (!run?.url) return;
    try {
      const res = await fetch(`${API}/api/detonate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: run.url }),
      });
      const data = await res.json();
      if (data.run_id) router.push(`/runs/${data.run_id}`);
    } catch {
      alert("failed to start re-run");
    }
  };

  const handleTakedown = async () => {
    if (takedown) { setTakedownOpen((o) => !o); return; }
    setTakedownLoading(true);
    try {
      const res = await fetch(`${API}/api/runs/${run_id}/takedown`);
      if (res.ok) {
        const data = await res.json();
        setTakedown(data);
        setTakedownOpen(true);
        if (data.cloudflare_detected) setActiveTemplate("cloudflare");
        else if (data.templates?.hosting) setActiveTemplate("hosting");
        else setActiveTemplate("registrar");
      }
    } catch { /* ignore */ }
    finally { setTakedownLoading(false); }
  };

  const handleCopy = useCallback(() => {
    if (!takedown) return;
    const text = takedown.templates[activeTemplate] ?? "";
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [takedown, activeTemplate]);

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
            {run.url && (
              <button onClick={handleRerun} className="btn-outline btn py-1 px-3 text-xs">re-run</button>
            )}
            {status === "complete" && (
              <button onClick={handleTakedown} className="btn-outline btn py-1 px-3 text-xs">
                {takedownLoading ? "loading..." : takedownOpen ? "hide takedown" : "takedown"}
              </button>
            )}
            <button onClick={handleDelete} className="btn-outline btn py-1 px-3 text-xs !border-[var(--error)] text-[var(--error)] hover:bg-[var(--error)] hover:text-white">delete</button>
          </div>
        </div>

        {/* agent verdict */}
        {run.agent_verdict ? (
          <div className="space-y-3">
            <div className="flex items-start gap-3">
              <SeverityBadge severity={run.agent_verdict.severity} />
              <span className="text-[0.6rem] uppercase tracking-widest text-dim border border-[var(--border)] px-1.5 py-0.5">
                {run.agent_verdict.confidence} confidence
              </span>
              <p className="text-xs text-dim">{run.agent_verdict.summary}</p>
            </div>
            <div className="flex gap-6 flex-wrap text-[0.6rem] uppercase tracking-widest text-dim">
              {run.agent_verdict.delivery_vector && run.agent_verdict.delivery_vector !== "unknown" && (
                <span>vector: <span className="text-[var(--fg)]">{run.agent_verdict.delivery_vector}</span></span>
              )}
              {run.agent_verdict.user_interaction && run.agent_verdict.user_interaction !== "unknown" && (
                <span>interaction: <span className="text-[var(--fg)]">{run.agent_verdict.user_interaction}</span></span>
              )}
              {run.agent_verdict.kit_fingerprint && (
                <span>kit: <span className="text-[var(--purple-bright)]">{run.agent_verdict.kit_fingerprint}</span></span>
              )}
            </div>
            {run.agent_verdict.reasoning && (
              <p className="text-[0.65rem] text-dim leading-relaxed">{run.agent_verdict.reasoning}</p>
            )}
            {run.agent_verdict.attack_techniques && run.agent_verdict.attack_techniques.length > 0 && (
              <div className="flex gap-2 flex-wrap">
                {run.agent_verdict.attack_techniques.map((t) => (
                  <a
                    key={t.id}
                    href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    title={`${t.name} (${t.source})`}
                    className="text-[0.55rem] font-mono uppercase tracking-wider border border-[var(--border)] px-1.5 py-0.5 text-dim hover:text-[var(--purple-bright)] hover:border-[var(--purple-bright)] transition-colors"
                  >
                    {t.id}
                  </a>
                ))}
              </div>
            )}
          </div>
        ) : run.severity ? (
          <div className="flex items-start gap-3">
            <SeverityBadge severity={run.severity} />
            {run.threat_summary && (
              <p className="text-xs text-dim">{run.threat_summary}</p>
            )}
          </div>
        ) : null}

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

            {run.urlhaus_hit && (
              <span className="text-[#ff4444]">urlhaus: known malicious</span>
            )}
            {run.domain_age_days != null && (
              <span className={run.domain_age_days < 30 ? "text-[#ffaa00]" : "text-dim"}>
                domain: {run.domain_age_days}d old{run.domain_age_days < 30 ? " ⚠" : ""}
              </span>
            )}
            {run.campaign_id && (
              <span className="text-[var(--purple-bright)]">
                campaign: {run.campaign_id.slice(0, 20)}
              </span>
            )}
            {run.chain_depth > 0 && (
              <span className="text-[var(--purple-bright)]">
                chain depth: {run.chain_depth}
                {run.chain_parent_id && (
                  <a href={`/runs/${run.chain_parent_id}`} className="ml-1 text-dim hover:text-[var(--purple-bright)]">← parent</a>
                )}
              </span>
            )}
          </div>
        )}
      </div>

      {/* takedown templates */}
      {takedownOpen && takedown && (
        <div className="card space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-3">
            <h3 className="text-xs uppercase tracking-widest text-dim font-bold">takedown_templates</h3>
            <div className="flex gap-2 flex-wrap">
              <button
                onClick={() => setActiveTemplate("registrar")}
                className={`text-[0.6rem] uppercase tracking-widest border px-2 py-0.5 transition-colors ${activeTemplate === "registrar" ? "border-[var(--purple-bright)] text-[var(--purple-bright)]" : "border-[var(--border)] text-dim"}`}
              >
                registrar
              </button>
              {takedown.templates.hosting && (
                <button
                  onClick={() => setActiveTemplate("hosting")}
                  className={`text-[0.6rem] uppercase tracking-widest border px-2 py-0.5 transition-colors ${activeTemplate === "hosting" ? "border-[var(--purple-bright)] text-[var(--purple-bright)]" : "border-[var(--border)] text-dim"}`}
                >
                  hosting
                </button>
              )}
              {takedown.templates.cloudflare && (
                <button
                  onClick={() => setActiveTemplate("cloudflare")}
                  className={`text-[0.6rem] uppercase tracking-widest border px-2 py-0.5 transition-colors ${activeTemplate === "cloudflare" ? "border-[var(--purple-bright)] text-[var(--purple-bright)]" : "border-[var(--border)] text-dim"}`}
                >
                  cloudflare
                </button>
              )}
            </div>
          </div>

          {/* context row */}
          <div className="flex gap-6 flex-wrap text-[0.6rem] uppercase tracking-widest text-dim">
            {takedown.registrar.registrar && (
              <span>registrar: <span className="text-[var(--fg)]">{takedown.registrar.registrar}</span></span>
            )}
            {takedown.registrar.abuse_email && (
              <span>abuse contact: <span className="text-[var(--fg)]">{takedown.registrar.abuse_email}</span></span>
            )}
            {takedown.hosting?.org && (
              <span>hosting: <span className="text-[var(--fg)]">{takedown.hosting.org}</span></span>
            )}
            {takedown.hosting?.ip && (
              <span>server ip: <span className="text-[var(--fg)]">{takedown.hosting.ip}</span></span>
            )}
            {takedown.cloudflare_detected && (
              <span className="text-[#ffaa00]">cloudflare detected</span>
            )}
          </div>

          <div className="relative">
            <pre className="text-[0.65rem] font-mono text-dim bg-[var(--bg)] border border-[var(--border)] p-4 whitespace-pre-wrap break-words leading-relaxed">
              {takedown.templates[activeTemplate]}
            </pre>
            <button
              onClick={handleCopy}
              className="absolute top-2 right-2 btn-outline btn py-0.5 px-2 text-[0.6rem] uppercase tracking-widest"
            >
              {copied ? "copied" : "copy"}
            </button>
          </div>
        </div>
      )}

      {/* redirect chain */}
      {redirectChain.length > 0 && (
        <div className="card space-y-3">
          <h3 className="text-xs uppercase tracking-widest text-dim font-bold">redirect_chain</h3>
          <div className="flex flex-col gap-1">
            {redirectChain.map((hop, i) => (
              <div key={i} className="flex items-start gap-3 text-xs">
                <span className={`shrink-0 w-10 text-right font-bold ${hop.status >= 400 ? "text-[var(--error)]" : hop.status >= 300 ? "text-[#f59e0b]" : "text-[var(--success)]"}`}>
                  {hop.status}
                </span>
                <span className="text-dim shrink-0">{i === 0 ? "→" : "↳"}</span>
                <span className="text-[var(--purple-bright)] break-all">{hop.url}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* form submission */}
      {run.form_submission && (
        <div className="card space-y-3">
          <h3 className="text-xs uppercase tracking-widest text-dim font-bold">form_interaction</h3>
          <div className="flex flex-col gap-2 text-xs">
            <div className="flex gap-6 flex-wrap text-[0.65rem] uppercase tracking-widest">
              <span>action: <span className="text-[var(--purple-bright)] break-all normal-case">{run.form_submission.form_action}</span></span>
              <span>method: <span className="text-[var(--fg)]">{run.form_submission.form_method}</span></span>
              <span>inputs: <span className="text-[var(--fg)]">{run.form_submission.input_count}</span></span>
            </div>
            {run.form_submission.submission ? (
              <div className="flex flex-col gap-1">
                <span className="text-[0.65rem] uppercase tracking-widest text-dim">exfil endpoint</span>
                <span className="text-[var(--error)] break-all text-[0.7rem]">{run.form_submission.submission.url}</span>
                {run.form_submission.submission.post_data && (
                  <span className="text-[0.6rem] text-dim font-mono break-all">{run.form_submission.submission.post_data.slice(0, 300)}</span>
                )}
              </div>
            ) : (
              <span className="text-[0.65rem] text-dim">no outbound request intercepted</span>
            )}
            {run.form_submission.post_submit_url && run.form_submission.post_submit_url !== run.url && (
              <span className="text-[0.65rem] text-dim">
                post-submit url: <span className="text-[var(--fg)] break-all">{run.form_submission.post_submit_url}</span>
              </span>
            )}
          </div>
        </div>
      )}

      {/* downloaded files */}
      {run.downloads && run.downloads.length > 0 && (
        <div className="card space-y-3">
          <h3 className="text-xs uppercase tracking-widest text-dim font-bold">downloaded_files</h3>
          <div className="flex flex-col gap-2">
            {run.downloads.map((dl, i) => {
              const scan = run.file_scans?.find((s) => s.filename === dl.filename);
              const malicious = scan ? scan.vt_malicious > 0 : false;
              const vtUrl = scan?.vt_analysis_id
                ? `https://www.virustotal.com/gui/analysis/${scan.vt_analysis_id}`
                : null;
              return (
                <div key={i} className="flex items-start gap-4 text-xs flex-wrap">
                  <span className={`font-mono shrink-0 ${malicious ? "text-[var(--error)]" : "text-[var(--fg)]"}`}>
                    {dl.filename}
                  </span>
                  {scan ? (
                    <span className={`text-[0.65rem] uppercase tracking-widest shrink-0 ${malicious ? "text-[var(--error)]" : "text-[var(--success)]"}`}>
                      {vtUrl ? (
                        <a href={vtUrl} target="_blank" rel="noopener noreferrer" className="hover:underline">
                          vt: {scan.vt_malicious} malicious / {scan.vt_total} engines →
                        </a>
                      ) : (
                        <>vt: {scan.vt_malicious} malicious / {scan.vt_total} engines</>
                      )}
                    </span>
                  ) : (
                    <span className="text-[0.65rem] text-dim uppercase tracking-widest">vt: not scanned</span>
                  )}
                  <span className="text-[0.6rem] text-dim break-all">{dl.url}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

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
