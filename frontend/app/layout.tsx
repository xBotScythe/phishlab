import type { Metadata } from "next";
import Link from "next/link";
import { JetBrains_Mono } from "next/font/google";
import HealthIndicator from "@/components/HealthIndicator";
import "./globals.css";

const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-mono" });

export const metadata: Metadata = {
  title: "PhishLab",
  description: "Local threat detonation & ai analysis environment",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={mono.variable}>
      <body className="mono">
        <header className="border-b border-[var(--border)] py-4 bg-[var(--bg-card)]">
          <div className="container flex-between">
            <div className="flex items-center gap-4">
              <Link href="/" className="hover:text-white">
                <span className="font-bold text-lg tracking-tight text-[var(--purple-bright)]">
                  PHISHLAB_
                </span>
              </Link>
              <HealthIndicator />
            </div>
            <nav className="flex gap-6 text-xs uppercase tracking-widest text-[var(--text-dim)]">
              <Link href="/" className="hover:text-[var(--text-bright)]">/ dashboard</Link>
              <Link href="/detonate" className="hover:text-[var(--text-bright)]">/ detonate</Link>
              <Link href="/settings" className="hover:text-[var(--text-bright)]">/ settings</Link>
            </nav>
          </div>
        </header>
        <main className="container py-8">
          {children}
        </main>
      </body>
    </html>
  );
}
