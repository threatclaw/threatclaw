"use client";

import { Inter } from "next/font/google";
import "./globals.css";
import SocTopBar from "@/components/chrome/SocTopBar";
import { SectionSidebar } from "@/components/chrome/SectionSidebar";
import { sectionForPath } from "@/components/chrome/sections";
import { usePathname } from "next/navigation";

const inter = Inter({ subsets: ["latin"] });

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  const isSetupWizard = pathname === "/setup" && typeof window !== "undefined" && !localStorage.getItem("threatclaw_onboarded");
  const isLoginPage = pathname === "/login";

  return (
    <html lang="fr">
      <head>
        <title>ThreatClaw</title>
        <meta name="description" content="Agent de cybersécurité autonome" />
        <link rel="icon" href="/favicon.ico" />
        <link rel="apple-touch-icon" href="/apple-touch-icon.png" />
      </head>
      <body className={inter.className} style={{ background: "var(--tc-bg)", color: "var(--tc-text)", margin: 0, minHeight: "100vh", transition: "background 0.3s ease, color 0.3s ease" }}>
        {/* Grid background + red aura */}
        <div style={{
          position: "fixed", top: 0, left: 0, right: 0, bottom: 0, pointerEvents: "none", zIndex: 0,
        }}>
          {/* Grid pattern — fine red lines */}
          <div style={{
            position: "absolute", inset: 0,
            backgroundImage: "linear-gradient(rgba(208, 48, 32, 0.08) 1px, transparent 1px), linear-gradient(90deg, rgba(208, 48, 32, 0.08) 1px, transparent 1px)",
            backgroundSize: "40px 40px",
          }} />
          {/* Red aura glow from top */}
          <div style={{
            position: "absolute", inset: 0,
            background: "radial-gradient(ellipse at 50% -10%, rgba(208, 48, 32, 0.12) 0%, transparent 55%)",
          }} />
          {/* Fade grid at bottom */}
          <div style={{
            position: "absolute", bottom: 0, left: 0, right: 0, height: "40%",
            background: "linear-gradient(to top, var(--tc-bg) 0%, transparent 100%)",
          }} />
        </div>
        <div style={{ position: "relative", zIndex: 2, minHeight: "100vh" }}>
          {/* Environment banner — DEV (yellow), STAGING (orange), BETA (red), PROD (hidden) */}
          {(() => {
            const env = process.env.TC_ENV || process.env.NEXT_PUBLIC_TC_ENV || "";
            if (env === "production") return null;
            const config: Record<string, { bg: string; border: string; color: string; label: string; text: string }> = {
              dev: {
                bg: "linear-gradient(90deg, rgba(234,179,8,0.2), rgba(234,179,8,0.1))",
                border: "1px solid rgba(234,179,8,0.3)",
                color: "#eab308",
                label: "DEV",
                text: "Development environment — local builds, not for production.",
              },
              staging: {
                bg: "linear-gradient(90deg, rgba(249,115,22,0.2), rgba(249,115,22,0.1))",
                border: "1px solid rgba(249,115,22,0.3)",
                color: "#f97316",
                label: "STAGING",
                text: "Staging environment — testing before release.",
              },
              beta: {
                bg: "linear-gradient(90deg, rgba(208,48,32,0.15), rgba(208,144,32,0.1))",
                border: "1px solid rgba(208,48,32,0.2)",
                color: "#d09020",
                label: "BETA",
                text: "Early access release. Some features are still being refined.",
              },
            };
            const c = config[env] || config.beta;
            if (isLoginPage) return null;
            return (
              <div style={{
                background: c.bg,
                borderBottom: c.border,
                padding: "4px 16px", textAlign: "center",
                fontSize: "10px", color: "rgba(255,255,255,0.6)", letterSpacing: "0.03em",
              }}>
                <span style={{ fontWeight: 700, color: c.color }}>{c.label}</span> — {c.text}
              </div>
            );
          })()}
          {!isSetupWizard && !isLoginPage && <SocTopBar />}
          {(() => {
            const hasSection = pathname && sectionForPath(pathname) !== null;
            if (hasSection && !isLoginPage && !isSetupWizard) {
              return (
                <div
                  style={{
                    display: "flex",
                    minHeight: "calc(100vh - 72px)",
                    alignItems: "stretch",
                  }}
                >
                  <SectionSidebar />
                  <main style={{ flex: 1, minWidth: 0 }}>{children}</main>
                </div>
              );
            }
            return (
              <main style={{ padding: 0, minHeight: "calc(100vh - 72px)" }}>
                {children}
              </main>
            );
          })()}
        </div>
      </body>
    </html>
  );
}
