import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import Sidebar from "@/components/Sidebar";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "ThreatClaw - Security Dashboard",
  description:
    "RSSI Security Posture Dashboard - Monitor vulnerabilities, compliance, and threats in real-time.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} min-h-screen bg-primary`}>
        <div className="flex min-h-screen">
          <Sidebar />
          <main className="ml-64 flex-1">
            <div className="p-8">{children}</div>
          </main>
        </div>
      </body>
    </html>
  );
}
