"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export default function DetonatePage() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const router = useRouter();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const res = await fetch(`${API}/api/detonate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || "failed to submit url");
      }

      const { run_id } = await res.json();
      router.push(`/runs/${encodeURIComponent(run_id)}`);
    } catch (err: any) {
      setError(err.message);
      setLoading(false);
    }
  }

  return (
    <div className="max-w-2xl mx-auto py-12">
      <h1 className="text-2xl mb-8 tracking-tight">// launch_detonation</h1>
      
      <div className="card space-y-8">
        <p className="text-xs text-dim uppercase tracking-[0.1em] leading-relaxed">
          // submission_portal: enter target url for isolated container detonation. 
          results will be streamed to the analysis engine for intelligence gathering.
        </p>

        <form onSubmit={handleSubmit} className="space-y-8">
          <div className="space-y-2">
            <label className="text-[0.65rem] uppercase tracking-widest text-[var(--purple-bright)] font-bold">
              target_url_input
            </label>
            <input
              type="url"
              required
              placeholder="https://example-phish.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="w-full bg-[var(--bg)] border border-[var(--border)] p-3 text-sm focus:border-[var(--purple)] outline-none transition-colors"
            />
          </div>

          {error && (
            <div className="bg-[var(--bg-raised)] border border-[var(--error)] text-[var(--error)] p-4 text-xs uppercase tracking-widest">
              system_error: {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="btn w-full py-3 text-sm tracking-widest uppercase"
          >
            {loading ? "executing_handshake..." : "initiate_detonation_sequence"}
          </button>
        </form>
      </div>
    </div>
  );
}
