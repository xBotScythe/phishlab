"use client";

import { useEffect, useState } from "react";
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
};

export default function DiffPage() {
  const params = useSearchParams();
  const [a, setA] = useState<RunSide | null>(null);
  const [b, setB] = useState<RunSide | null>(null);
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
      })
      .catch((e) => setError(e.message));
  }, [params]);

  if (error) {
    return <div className="text-[var(--error)] p-8 uppercase text-xs tracking-widest">{error}</div>;
  }

  if (!a || !b) {
    return <div className="text-dim p-8 uppercase text-xs tracking-widest">// loading diff...</div>;
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl">// report_diff</h1>
        <p className="text-dim text-sm mt-1">side-by-side comparison of two analysis runs</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {[a, b].map((run, i) => (
          <div key={run.id} className="space-y-4">
            {/* header */}
            <div className="flex-between">
              <div className="min-w-0 flex-1">
                <p className="text-xs font-bold text-[var(--purple-bright)] truncate">{run.url ?? "unknown"}</p>
                <p className="text-[0.6rem] text-dim uppercase tracking-widest mt-0.5">{run.id}</p>
              </div>
              <StatusBadge status={run.status} />
            </div>

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
