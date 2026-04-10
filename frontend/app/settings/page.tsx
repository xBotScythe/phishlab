"use client";

import { useState, useEffect } from "react";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export default function SettingsPage() {
  const [phishtankKey, setPhishtankKey] = useState("");
  const [saved, setSaved] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch(`${API}/api/settings`)
      .then((r) => r.json())
      .then((d) => {
        setPhishtankKey(d.phishtank_key ?? "");
        setLoading(false);
      })
      .catch(() => {
        setError("failed to load settings");
        setLoading(false);
      });
  }, []);

  const save = async () => {
    setError("");
    setSaved(false);
    try {
      const res = await fetch(`${API}/api/settings`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phishtank_key: phishtankKey }),
      });
      if (!res.ok) throw new Error();
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch {
      setError("failed to save settings");
    }
  };

  return (
    <div className="space-y-8 max-w-xl">
      <div>
        <h1 className="text-2xl">// settings</h1>
        <p className="text-dim text-sm mt-1">configuration & api keys</p>
      </div>

      <div className="card space-y-6">
        <div>
          <h2 className="text-sm font-bold text-[var(--purple-bright)] uppercase tracking-tight">
            feed_source
          </h2>
          <p className="text-xs text-dim mt-1">
            phishtank is used when a key is present. openphish is the fallback.
          </p>
        </div>

        <div className="space-y-2">
          <label className="text-[0.7rem] uppercase tracking-widest text-dim block">
            phishtank api key
          </label>
          <input
            type="password"
            value={phishtankKey}
            onChange={(e) => setPhishtankKey(e.target.value)}
            placeholder="leave blank to use openphish"
            disabled={loading}
            className="w-full bg-[var(--bg)] border border-[var(--border)] p-2 text-xs focus:border-[var(--purple)] outline-none font-mono"
          />
          <p className="text-[0.65rem] text-dim">
            note: phishtank closed new registrations in 2020. if you have an existing key, enter it above.{" "}
            <a
              href="https://www.phishtank.com/api_register.php"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[var(--purple-bright)] hover:underline"
            >
              registration page →
            </a>
          </p>
        </div>

        <div className="flex items-center gap-4">
          <button onClick={save} disabled={loading} className="btn py-1.5 px-4">
            save
          </button>
          {saved && (
            <span className="text-[0.7rem] text-[var(--success)] uppercase tracking-widest">
              saved
            </span>
          )}
          {error && (
            <span className="text-[0.7rem] text-[var(--error)] uppercase tracking-widest">
              {error}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
