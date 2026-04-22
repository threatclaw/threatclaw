"use client";

import React, { useState, useEffect } from "react";
import { usePathname } from "next/navigation";
import Link from "next/link";
import { Shield, Puzzle, Settings, Activity, Server, Wifi, WifiOff, Cpu, AlertTriangle, Bell, Play, Pause, Network, BrainCircuit, Sun, Moon, LogOut, Radio, Gavel, MessageSquare, ChevronDown } from "lucide-react";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";

type NavLeaf = { href: string; key: string; icon: typeof Shield };
type NavGroup = { key: string; icon: typeof Shield; items: NavLeaf[] };
type NavEntry = NavLeaf | NavGroup;

const NAV_ENTRIES: NavEntry[] = [
  { href: "/", key: "status", icon: Shield },
  {
    key: "detections",
    icon: Bell,
    items: [
      { href: "/incidents", key: "incidents", icon: Bell },
      { href: "/chat", key: "chat", icon: MessageSquare },
      { href: "/sources", key: "sources", icon: Radio },
    ],
  },
  {
    key: "analytics",
    icon: BrainCircuit,
    items: [
      { href: "/intelligence", key: "intelligence", icon: BrainCircuit },
      { href: "/governance", key: "governance", icon: Gavel },
      { href: "/exports", key: "exports", icon: Activity },
    ],
  },
  { href: "/setup", key: "config", icon: Settings },
];

function isGroup(e: NavEntry): e is NavGroup {
  return (e as NavGroup).items !== undefined;
}

function hrefMatches(pathname: string, href: string): boolean {
  return href === "/" ? pathname === "/" : pathname.startsWith(href);
}

function entryIsActive(entry: NavEntry, pathname: string): boolean {
  if (isGroup(entry)) return entry.items.some((i) => hrefMatches(pathname, i.href));
  return hrefMatches(pathname, entry.href);
}

type ConnStatus = "full" | "degraded" | "offline";

function NavTabs({ pathname, locale }: { pathname: string; locale: "fr" | "en" }) {
  const containerRef = React.useRef<HTMLDivElement>(null);
  const [indicator, setIndicator] = React.useState({ left: 0, width: 0 });
  const [openGroup, setOpenGroup] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!containerRef.current) return;
    const activeIdx = NAV_ENTRIES.findIndex((e) => entryIsActive(e, pathname));
    if (activeIdx < 0) {
      setIndicator({ left: 0, width: 0 });
      return;
    }
    const buttons = containerRef.current.querySelectorAll<HTMLElement>("[data-nav-btn]");
    if (buttons[activeIdx]) {
      const btn = buttons[activeIdx];
      setIndicator({ left: btn.offsetLeft, width: btn.offsetWidth });
    }
  }, [pathname]);

  // Close the dropdown when clicking elsewhere or hitting escape
  React.useEffect(() => {
    function onDocClick(e: MouseEvent) {
      if (!containerRef.current?.contains(e.target as Node)) setOpenGroup(null);
    }
    function onEsc(e: KeyboardEvent) {
      if (e.key === "Escape") setOpenGroup(null);
    }
    document.addEventListener("click", onDocClick);
    document.addEventListener("keydown", onEsc);
    return () => {
      document.removeEventListener("click", onDocClick);
      document.removeEventListener("keydown", onEsc);
    };
  }, []);

  return (
    <div ref={containerRef} style={{
      position: "relative", display: "flex", padding: "3px",
      borderRadius: "11px", background: "var(--tc-input)",
      border: "1px solid var(--tc-border)",
    }}>
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
      {NAV_ENTRIES.map((entry) => {
        const active = entryIsActive(entry, pathname);
        const Icon = entry.icon;
        const itemStyle: React.CSSProperties = {
          display: "flex", alignItems: "center", gap: "5px",
          padding: "6px 10px",
          fontSize: "10px", fontWeight: 600,
          letterSpacing: "0.03em", textTransform: "uppercase",
          color: active ? "var(--tc-red)" : "var(--tc-text-sec)",
          transition: "color 200ms, opacity 200ms",
          cursor: "pointer", whiteSpace: "nowrap",
          opacity: active ? 1 : 0.75,
        };
        if (!isGroup(entry)) {
          return (
            <Link key={entry.href} href={entry.href} data-nav-btn style={{ textDecoration: "none", position: "relative", zIndex: 1 }}>
              <div style={itemStyle}>
                <Icon size={12} />
                {tr(entry.key, locale)}
              </div>
            </Link>
          );
        }
        const isOpen = openGroup === entry.key;
        return (
          <div key={entry.key} data-nav-btn style={{ position: "relative", zIndex: 1 }}>
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                setOpenGroup(isOpen ? null : entry.key);
              }}
              style={{ ...itemStyle, background: "transparent", border: "none" }}
            >
              <Icon size={12} />
              {tr(entry.key, locale)}
              <ChevronDown size={10} style={{ marginLeft: "2px", transform: isOpen ? "rotate(180deg)" : undefined, transition: "transform 150ms" }} />
            </button>
            {isOpen && (
              <div
                style={{
                  position: "absolute",
                  top: "calc(100% + 6px)",
                  left: 0,
                  minWidth: "180px",
                  background: "var(--tc-surface)",
                  border: "1px solid var(--tc-border)",
                  borderRadius: "10px",
                  boxShadow: "0 6px 20px rgba(0,0,0,0.12)",
                  padding: "4px",
                  zIndex: 20,
                }}
                onClick={(e) => e.stopPropagation()}
              >
                {entry.items.map((leaf) => {
                  const leafActive = hrefMatches(pathname, leaf.href);
                  const LeafIcon = leaf.icon;
                  return (
                    <Link
                      key={leaf.href}
                      href={leaf.href}
                      onClick={() => setOpenGroup(null)}
                      style={{ textDecoration: "none" }}
                    >
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: "8px",
                          padding: "8px 12px",
                          borderRadius: "8px",
                          fontSize: "11px",
                          fontWeight: leafActive ? 700 : 500,
                          color: leafActive ? "var(--tc-red)" : "var(--tc-text)",
                          background: leafActive ? "var(--tc-red-soft)" : "transparent",
                          transition: "background 120ms",
                          cursor: "pointer",
                        }}
                        onMouseEnter={(e) => {
                          if (!leafActive) e.currentTarget.style.background = "var(--tc-input)";
                        }}
                        onMouseLeave={(e) => {
                          if (!leafActive) e.currentTarget.style.background = "transparent";
                        }}
                      >
                        <LeafIcon size={12} />
                        {tr(leaf.key, locale)}
                      </div>
                    </Link>
                  );
                })}
              </div>
            )}
          </div>
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
  const [paused, setPaused] = useState(false);

  // Check pause status
  useEffect(() => {
    fetch("/api/tc/pause").then(r => r.json()).then(d => setPaused(d.paused || false)).catch(() => {});
    const interval = setInterval(() => {
      fetch("/api/tc/pause").then(r => r.json()).then(d => setPaused(d.paused || false)).catch(() => {});
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  const togglePause = async () => {
    try {
      const res = await fetch("/api/tc/pause", { method: "POST" });
      const d = await res.json();
      setPaused(d.paused);
    } catch {}
  };

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

        {/* Language toggle */}
        <button onClick={() => {
          const next = locale === "fr" ? "en" : "fr";
          localStorage.setItem("tc-language", next);
          window.dispatchEvent(new Event("tc-locale-change"));
          window.location.reload();
        }} style={{
          display: "flex", alignItems: "center", justifyContent: "center",
          width: "30px", height: "30px", borderRadius: "var(--tc-radius-input)",
          background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
          color: "var(--tc-text-muted)", cursor: "pointer", transition: "all 200ms",
          fontSize: "10px", fontWeight: 800, letterSpacing: "0.03em",
        }} title={tr("switchLanguage", locale)}>
          {locale === "fr" ? "EN" : "FR"}
        </button>

        {/* Pause/Resume */}
        <button onClick={togglePause} style={{
          display: "flex", alignItems: "center", justifyContent: "center",
          width: "30px", height: "30px", borderRadius: "var(--tc-radius-input)",
          background: paused ? "rgba(208,48,32,0.15)" : "rgba(48,160,80,0.15)",
          border: paused ? "1px solid rgba(208,48,32,0.3)" : "1px solid rgba(48,160,80,0.3)",
          color: paused ? "#d03020" : "#30a050",
          cursor: "pointer", transition: "all 200ms",
        }} title={paused ? tr("resumeServices", locale) : tr("pauseServices", locale)}>
          {paused ? <Play size={13} /> : <Pause size={13} />}
        </button>

        {/* Logout */}
        <button onClick={async () => {
          await fetch("/api/auth/logout", { method: "POST" });
          window.location.href = "/login";
        }} style={{
          display: "flex", alignItems: "center", justifyContent: "center",
          width: "30px", height: "30px", borderRadius: "var(--tc-radius-input)",
          background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
          color: "var(--tc-text-muted)", cursor: "pointer", transition: "all 200ms",
        }} title={tr("logout", locale)}>
          <LogOut size={13} />
        </button>
      </div>
    </nav>
  );
}
