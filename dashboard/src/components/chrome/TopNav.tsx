"use client";

import React, { useState, useEffect } from "react";
import { usePathname } from "next/navigation";
import Link from "next/link";
import { Shield, Puzzle, Settings, Activity, Server, Wifi, WifiOff, Cpu, AlertTriangle, Bell, Play, Network, BrainCircuit, Sun, Moon, LogOut } from "lucide-react";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";

const NAV_KEYS = [
  { href: "/", key: "status", icon: Shield },
  { href: "/assets", key: "assets", icon: Server },
  { href: "/findings", key: "detections", icon: AlertTriangle },
  { href: "/intelligence", key: "intelligence", icon: BrainCircuit },
  { href: "/exports", key: "exports", icon: Activity },
  { href: "/setup", key: "config", icon: Settings },
];

type ConnStatus = "full" | "degraded" | "offline";

function NavTabs({ pathname, locale }: { pathname: string; locale: "fr" | "en" }) {
  const containerRef = React.useRef<HTMLDivElement>(null);
  const [indicator, setIndicator] = React.useState({ left: 0, width: 0 });

  React.useEffect(() => {
    if (!containerRef.current) return;
    const activeIdx = NAV_KEYS.findIndex(item =>
      item.href === "/" ? pathname === "/" : pathname.startsWith(item.href)
    );
    if (activeIdx < 0) return;
    const buttons = containerRef.current.querySelectorAll<HTMLElement>("[data-nav-btn]");
    if (buttons[activeIdx]) {
      const btn = buttons[activeIdx];
      setIndicator({ left: btn.offsetLeft, width: btn.offsetWidth });
    }
  }, [pathname]);

  return (
    <div ref={containerRef} style={{
      position: "relative", display: "flex", padding: "3px",
      borderRadius: "11px", background: "var(--tc-input)",
      border: "1px solid var(--tc-border)",
    }}>
      {/* Sliding red indicator — measured from actual button positions */}
      {indicator.width > 0 && (
        <div style={{
          position: "absolute", top: "3px", height: "calc(100% - 6px)",
          width: `${indicator.width}px`,
          left: `${indicator.left}px`,
          background: "var(--tc-red-soft)",
          borderRadius: "8px",
          border: "0.5px solid var(--tc-red-border)",
          boxShadow: "0 2px 6px rgba(208,48,32,0.15)",
          transition: "left 0.25s ease-out, width 0.25s ease-out",
          zIndex: 0,
        }} />
      )}
      {NAV_KEYS.map((item) => {
        const isActive = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
        const Icon = item.icon;
        return (
          <Link key={item.href} href={item.href} data-nav-btn style={{ textDecoration: "none", position: "relative", zIndex: 1 }}>
            <div style={{
              display: "flex", alignItems: "center", gap: "5px",
              padding: "6px 10px",
              fontSize: "10px", fontWeight: 600,
              letterSpacing: "0.03em", textTransform: "uppercase",
              color: isActive ? "var(--tc-red)" : "var(--tc-text-sec)",
              transition: "color 200ms, opacity 200ms",
              cursor: "pointer", whiteSpace: "nowrap",
              opacity: isActive ? 1 : 0.75,
            }}>
              <Icon size={12} />
              {tr(item.key, locale)}
            </div>
          </Link>
        );
      })}
    </div>
  );
}

export default function TopNav() {
  const locale = useLocale();
  const pathname = usePathname();
  const [connStatus, setConnStatus] = useState<ConnStatus>("offline");
  const [llmStatus, setLlmStatus] = useState<string>("");
  const [theme, setTheme] = useState<"dark" | "light">("dark");

  // Init theme from localStorage
  useEffect(() => {
    const saved = localStorage.getItem("tc-theme") as "dark" | "light" | null;
    if (saved) {
      setTheme(saved);
      document.documentElement.setAttribute("data-theme", saved);
    }
  }, []);

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("tc-theme", next);
  };

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await fetch("/api/tc/health", { signal: AbortSignal.timeout(5000) });
        if (res.ok) {
          setConnStatus("full");
        } else {
          setConnStatus("degraded");
        }
      } catch {
        // Try just the dashboard API proxy
        try {
          const res2 = await fetch("/api/tc/config", { signal: AbortSignal.timeout(3000) });
          setConnStatus(res2.ok ? "degraded" : "offline");
        } catch {
          setConnStatus("offline");
        }
      }

      // Check LLM status
      try {
        const res = await fetch("/api/ollama", { signal: AbortSignal.timeout(5000) });
        const data = await res.json();
        if (data.models && data.models.length > 0) {
          const names = data.models.map((m: { name: string }) => m.name.split(":")[0]);
          const hasL1 = names.some((n: string) => n.includes("threatclaw-l1") || n.includes("qwen3"));
          const hasL2 = names.some((n: string) => n.includes("threatclaw-l2") || n.includes("foundation"));
          if (hasL1 && hasL2) setLlmStatus("L1+L2");
          else if (hasL1) setLlmStatus("L1");
          else setLlmStatus(`${data.models.length}m`);
        }
      } catch {
        setLlmStatus("");
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const connColor = connStatus === "full" ? "#30a050" : connStatus === "degraded" ? "#d09020" : "var(--tc-text-muted)";
  const connLabel = connStatus === "full" ? "Full" : connStatus === "degraded" ? "Degraded" : "Offline";

  return (
    <nav style={{
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      padding: "14px 24px",
      marginBottom: "8px",
      borderBottom: "1px solid var(--tc-border)",
    }}>
      {/* Logo */}
      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
        <img src="/logo.png" alt="ThreatClaw" width={38} height={38} style={{ borderRadius: "6px" }} />
        <span style={{ fontSize: "17px", fontWeight: 900, letterSpacing: "0.15em" }}>
          <span style={{ color: "var(--tc-text)" }}>THREAT</span><span style={{ color: "#d03020" }}>CLAW</span>
        </span>
      </div>

      {/* Nav buttons — sliding indicator (measured) */}
      <div style={{ display: "flex", alignItems: "center" }}>
        <NavTabs pathname={pathname} locale={locale} />

        {/* Separator */}
        <div style={{ width: "1px", height: "20px", background: "var(--tc-border)", margin: "0 8px" }} />

        {/* Theme toggle */}
        <button onClick={toggleTheme} style={{
          display: "flex", alignItems: "center", justifyContent: "center",
          width: "30px", height: "30px", borderRadius: "var(--tc-radius-input)",
          background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
          color: theme === "dark" ? "#e0b030" : "#1a1a2e",
          cursor: "pointer", transition: "all 200ms",
        }} title={theme === "dark" ? tr("lightMode", locale) : tr("darkMode", locale)}>
          {theme === "dark" ? <Sun size={13} /> : <Moon size={13} />}
        </button>

        {/* Connectivity indicator */}
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "center",
          width: "30px", height: "30px", borderRadius: "var(--tc-radius-input)",
          background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
          color: connColor, cursor: "default",
        }} title={connLabel}>
          {connStatus === "offline" ? <WifiOff size={13} /> : <Wifi size={13} />}
        </div>

        {/* LLM status */}
        {llmStatus && (
          <div style={{
            display: "flex", alignItems: "center", gap: "5px",
            padding: "5px 10px", borderRadius: "var(--tc-radius-sm)",
            background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border-light)",
            fontSize: "10px", fontWeight: 500, color: "var(--tc-green)",
          }}>
            <Cpu size={11} />
            {llmStatus}
          </div>
        )}

        {/* Logout */}
        <button onClick={async () => {
          await fetch("/api/auth/logout", { method: "POST" });
          window.location.href = "/login";
        }} style={{
          display: "flex", alignItems: "center", justifyContent: "center",
          width: "30px", height: "30px", borderRadius: "var(--tc-radius-input)",
          background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
          color: "var(--tc-text-muted)", cursor: "pointer", transition: "all 200ms",
        }} title="Déconnexion">
          <LogOut size={13} />
        </button>
      </div>
    </nav>
  );
}
