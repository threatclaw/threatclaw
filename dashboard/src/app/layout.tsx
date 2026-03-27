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
        <div style={{ position: "relative", zIndex: 2, minHeight: "100vh", maxWidth: "1100px", margin: "0 auto" }}>
          {!isSetupWizard && !isLoginPage && <TopNav />}
          <main style={{ padding: "0 24px 48px" }}>
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
