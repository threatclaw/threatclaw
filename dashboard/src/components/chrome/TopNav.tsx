"use client";

import React, { useState, useEffect } from "react";
import { usePathname } from "next/navigation";
import Link from "next/link";
import { Shield, Puzzle, Settings, Activity, Server, Wifi, WifiOff, Cpu, AlertTriangle, Bell, Play, Network, BrainCircuit, Sun, Moon } from "lucide-react";

const NAV_ITEMS = [
  { href: "/", label: "Status", icon: Shield },
  { href: "/findings", label: "Findings", icon: AlertTriangle },
  { href: "/alerts", label: "Alertes", icon: Bell },
  { href: "/intelligence", label: "Intelligence", icon: BrainCircuit },
  { href: "/agent", label: "Agent", icon: Activity },
  { href: "/setup", label: "Config", icon: Settings },
];

type ConnStatus = "full" | "degraded" | "offline";

export default function TopNav() {
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
        const res = await fetch("/api/ollama?url=http://ollama:11434", { signal: AbortSignal.timeout(5000) });
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

  const connColor = connStatus === "full" ? "#30a050" : connStatus === "degraded" ? "#d09020" : "#5a534e";
  const connLabel = connStatus === "full" ? "Full" : connStatus === "degraded" ? "Degraded" : "Offline";

  return (
    <nav style={{
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      padding: "14px 24px",
      marginBottom: "8px",
      borderBottom: "1px solid var(--tc-border-light)",
    }}>
      {/* Logo */}
      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
        <div style={{
          width: "28px", height: "28px", borderRadius: "var(--tc-radius-input)",
          background: "linear-gradient(135deg, #d03020 0%, #a02018 100%)",
          display: "flex", alignItems: "center", justifyContent: "center",
          boxShadow: "0 2px 8px rgba(208,48,32,0.3)",
        }}>
          <Shield size={14} color="#fff" />
        </div>
        <span style={{
          fontSize: "13px",
          fontWeight: 800,
          letterSpacing: "0.2em",
          textTransform: "uppercase",
          color: "var(--tc-text)",
        }}>
          THREATCLAW
        </span>
      </div>

      {/* Nav buttons */}
      <div style={{ display: "flex", gap: "2px", alignItems: "center" }}>
        {NAV_ITEMS.map((item) => {
          const isActive = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
          const Icon = item.icon;

          return (
            <Link key={item.href} href={item.href} style={{ textDecoration: "none" }}>
              <div style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                padding: "7px 14px",
                borderRadius: "var(--tc-radius-input)",
                fontSize: "11px",
                fontWeight: 600,
                letterSpacing: "0.03em",
                textTransform: "uppercase",
                color: isActive ? "var(--tc-red)" : "var(--tc-text-muted)",
                background: isActive ? "var(--tc-red-soft)" : "transparent",
                border: isActive ? "1px solid var(--tc-red-border)" : "1px solid transparent",
                transition: "all 200ms ease",
                cursor: "pointer",
              }}>
                <Icon size={14} />
                {item.label}
              </div>
            </Link>
          );
        })}

        {/* Separator */}
        <div style={{ width: "1px", height: "20px", background: "var(--tc-border)", margin: "0 8px" }} />

        {/* Theme toggle */}
        <button onClick={toggleTheme} style={{
          display: "flex", alignItems: "center", justifyContent: "center",
          width: "30px", height: "30px", borderRadius: "var(--tc-radius-input)",
          background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
          color: theme === "dark" ? "#d09020" : "#3080d0",
          cursor: "pointer", transition: "all 200ms",
        }} title={theme === "dark" ? "Mode clair" : "Mode sombre"}>
          {theme === "dark" ? <Sun size={13} /> : <Moon size={13} />}
        </button>

        {/* Connectivity indicator */}
        <div style={{
          display: "flex", alignItems: "center", gap: "6px",
          padding: "5px 10px", borderRadius: "var(--tc-radius-sm)",
          background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border-light)",
          fontSize: "10px", fontWeight: 500, color: connColor,
        }}>
          {connStatus === "offline" ? <WifiOff size={11} /> : <Wifi size={11} />}
          {connLabel}
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
      </div>
    </nav>
  );
}
