"use client";

import { useState, useEffect } from "react";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type Health = { ollama: boolean; docker: boolean };

export default function HealthIndicator() {
  const [health, setHealth] = useState<Health | null>(null);

  useEffect(() => {
    const check = async () => {
      try {
        const res = await fetch(`${API}/api/health`, { signal: AbortSignal.timeout(3000) });
        setHealth(await res.json());
      } catch {
        setHealth({ ollama: false, docker: false });
      }
    };

    check();
    // recheck every 30s
    const interval = setInterval(check, 30000);
    return () => clearInterval(interval);
  }, []);

  if (!health) return null;

  const dot = (ok: boolean) => (
    <span className={`inline-block w-1.5 h-1.5 rounded-full ${ok ? "bg-[var(--success)]" : "bg-[var(--error)]"}`} />
  );

  return (
    <div className="flex items-center gap-3 text-[0.6rem] uppercase tracking-widest text-dim">
      <span className="flex items-center gap-1">{dot(health.docker)} docker</span>
      <span className="flex items-center gap-1">{dot(health.ollama)} ollama</span>
    </div>
  );
}
