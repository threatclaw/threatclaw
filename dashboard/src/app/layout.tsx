"use client";

import { Inter } from "next/font/google";
import "./globals.css";
import TopNav from "@/components/chrome/TopNav";
import { usePathname } from "next/navigation";

const inter = Inter({ subsets: ["latin"] });

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  const isSetupWizard = pathname === "/setup" && typeof window !== "undefined" && !localStorage.getItem("threatclaw_onboarded");

  return (
    <html lang="fr">
      <head>
        <title>ThreatClaw</title>
        <meta name="description" content="Agent de cybersécurité autonome" />
      </head>
      <body className={inter.className} style={{ background: "var(--tc-bg)", color: "var(--tc-text)", margin: 0, minHeight: "100vh", transition: "background 0.3s ease, color 0.3s ease" }}>
        {/* Subtle gradient overlay */}
        <div style={{
          position: "fixed", top: 0, left: 0, right: 0, bottom: 0, pointerEvents: "none", zIndex: 0,
          background: "radial-gradient(ellipse at 50% 0%, var(--tc-red-soft) 0%, transparent 60%)",
        }} />
        <div style={{ position: "relative", zIndex: 1, minHeight: "100vh", maxWidth: "1100px", margin: "0 auto" }}>
          {!isSetupWizard && <TopNav />}
          <main style={{ padding: "0 24px 48px" }}>
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
