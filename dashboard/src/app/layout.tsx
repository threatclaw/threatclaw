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
    <html lang="fr" data-theme="light">
      <head>
        <title>ThreatClaw</title>
        <meta name="description" content="Agent de cybersécurité autonome" />
      </head>
      <body className={inter.className} style={{ background: "#e2dbd4", margin: 0 }}>
        <div style={{ minHeight: "100vh", maxWidth: "900px", margin: "0 auto" }}>
          {!isSetupWizard && <TopNav />}
          <main style={{ padding: "0 20px 40px" }}>
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
