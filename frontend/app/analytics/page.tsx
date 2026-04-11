"use client";

import { useEffect, useState } from "react";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
  BarChart, Bar,
} from "recharts";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

const THREAT_COLORS: Record<string, string> = {
  malicious: "var(--error)",
  suspicious: "#f59e0b",
  clean: "var(--success)",
  unscored: "var(--border)",
};

type Analytics = {
  totals: { total: number; complete: number; malicious: number; campaigns: number };
  runs_per_day: { date: string; count: number }[];
  threat_distribution: { name: string; value: number }[];
  status_breakdown: { status: string; count: number }[];
  top_campaigns: { id: string; runs: number }[];
};

export default function AnalyticsPage() {
  const [data, setData] = useState<Analytics | null>(null);

  useEffect(() => {
    fetch(`${API}/api/analytics`)
      .then((r) => r.json())
      .then(setData)
      .catch(console.error);
  }, []);

  if (!data) {
    return <div className="text-dim p-8 uppercase text-xs tracking-widest">loading analytics...</div>;
  }

  const { totals, runs_per_day, threat_distribution, status_breakdown, top_campaigns } = data;

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl">// analytics</h1>
        <p className="text-dim text-sm mt-1">aggregate intelligence across all runs</p>
      </div>

      {/* stat tiles */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "total runs", value: totals.total },
          { label: "complete", value: totals.complete },
          { label: "malicious", value: totals.malicious, danger: totals.malicious > 0 },
          { label: "campaigns", value: totals.campaigns },
        ].map(({ label, value, danger }) => (
          <div key={label} className="card text-center py-6">
            <p className={`text-3xl font-bold ${danger ? "text-[var(--error)]" : "text-[var(--purple-bright)]"}`}>
              {value}
            </p>
            <p className="text-[0.6rem] uppercase tracking-widest text-dim mt-1">{label}</p>
          </div>
        ))}
      </div>

      {/* runs over time */}
      {runs_per_day.length > 0 && (
        <div className="card space-y-4">
          <h3 className="text-xs uppercase tracking-widest text-dim font-bold">runs_over_time</h3>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={runs_per_day}>
              <XAxis dataKey="date" tick={{ fontSize: 9, fill: "var(--text-dim)" }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 9, fill: "var(--text-dim)" }} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: "var(--bg-card)", border: "1px solid var(--border)", fontSize: 11 }}
                labelStyle={{ color: "var(--text-dim)" }}
              />
              <Line type="monotone" dataKey="count" stroke="var(--purple-bright)" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* threat distribution */}
        {threat_distribution.length > 0 && (
          <div className="card space-y-4">
            <h3 className="text-xs uppercase tracking-widest text-dim font-bold">threat_distribution</h3>
            <div className="flex items-center gap-6">
              <ResponsiveContainer width={160} height={160}>
                <PieChart>
                  <Pie data={threat_distribution} dataKey="value" nameKey="name" innerRadius={45} outerRadius={70}>
                    {threat_distribution.map((entry) => (
                      <Cell key={entry.name} fill={THREAT_COLORS[entry.name] ?? "var(--border)"} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: "var(--bg-card)", border: "1px solid var(--border)", fontSize: 11 }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-2">
                {threat_distribution.map((entry) => (
                  <div key={entry.name} className="flex items-center gap-2 text-xs">
                    <span className="w-2 h-2 rounded-full inline-block" style={{ background: THREAT_COLORS[entry.name] ?? "var(--border)" }} />
                    <span className="text-dim uppercase tracking-widest">{entry.name}</span>
                    <span className="text-[var(--purple-bright)] ml-auto pl-4">{entry.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* status breakdown */}
        {status_breakdown.length > 0 && (
          <div className="card space-y-4">
            <h3 className="text-xs uppercase tracking-widest text-dim font-bold">status_breakdown</h3>
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={status_breakdown} layout="vertical">
                <XAxis type="number" tick={{ fontSize: 9, fill: "var(--text-dim)" }} tickLine={false} axisLine={false} />
                <YAxis dataKey="status" type="category" tick={{ fontSize: 9, fill: "var(--text-dim)" }} tickLine={false} axisLine={false} width={70} />
                <Tooltip
                  contentStyle={{ background: "var(--bg-card)", border: "1px solid var(--border)", fontSize: 11 }}
                />
                <Bar dataKey="count" fill="var(--purple)" radius={[0, 2, 2, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* top campaigns */}
      {top_campaigns.length > 0 && (
        <div className="card space-y-4">
          <h3 className="text-xs uppercase tracking-widest text-dim font-bold">top_campaigns</h3>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={top_campaigns}>
              <XAxis dataKey="id" tick={{ fontSize: 9, fill: "var(--text-dim)" }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 9, fill: "var(--text-dim)" }} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: "var(--bg-card)", border: "1px solid var(--border)", fontSize: 11 }}
              />
              <Bar dataKey="runs" fill="var(--purple-bright)" radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
