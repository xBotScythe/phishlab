"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type CampaignRun = { id: string; url: string | null; created_at: string | null };
type Campaign = {
  campaign_id: string;
  run_count: number;
  first_seen: string | null;
  last_seen: string | null;
  runs: CampaignRun[];
};

export default function CampaignsPage() {
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API}/api/campaigns`)
      .then((r) => r.json())
      .then((d) => { setCampaigns(d.campaigns ?? []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  if (loading) return <div className="text-dim p-8 text-xs uppercase tracking-widest">loading campaigns...</div>;

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl">// campaigns</h1>
        <p className="text-dim text-sm mt-1">runs grouped by visual similarity (screenshot phash)</p>
      </div>

      {campaigns.length === 0 ? (
        <div className="card text-center p-12 text-dim">
          <p className="text-sm mono">no campaigns detected yet. campaigns form when multiple runs share a similar visual template.</p>
        </div>
      ) : (
        <div className="space-y-6">
          {campaigns.map((c) => (
            <div key={c.campaign_id} className="card space-y-4">
              <div className="flex-between">
                <div>
                  <h2 className="text-sm font-bold text-[var(--purple-bright)] uppercase tracking-tight">
                    campaign_{c.campaign_id.slice(0, 16)}
                  </h2>
                  <p className="text-[0.65rem] text-dim mt-1 uppercase tracking-widest">
                    {c.run_count} runs &mdash; first seen {c.first_seen ? new Date(c.first_seen).toLocaleString() : "unknown"}
                    {" "}&mdash; last seen {c.last_seen ? new Date(c.last_seen).toLocaleString() : "unknown"}
                  </p>
                </div>
              </div>

              <div className="flex flex-col gap-1">
                {c.runs.map((run) => (
                  <Link key={run.id} href={`/runs/${encodeURIComponent(run.id)}`}>
                    <div className="flex-between px-3 py-2 hover:bg-[var(--bg-raised)] border border-[var(--border)] text-xs">
                      <span className="text-[var(--purple-bright)] truncate flex-1">{run.url ?? "unknown"}</span>
                      <span className="text-dim ml-4 shrink-0">
                        {run.created_at ? new Date(run.created_at).toLocaleString() : run.id}
                      </span>
                    </div>
                  </Link>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
