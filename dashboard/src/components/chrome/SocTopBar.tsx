"use client";

// Single top bar shared across every page of the SOC console frontend.
// Lives in the root layout; individual pages do NOT render their own
// top bar — that's what produced the "four cards" clutter before.
//
// Design language: dense, monospace, sober. Red is reserved for urgent
// / critical state. Engine pulse uses green when healthy. Everything
// else is greys and tabular numbers.

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Sun, Moon, Pause, Play, LogOut, ChevronDown } from "lucide-react";
import { t as tr, type Locale } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";

type NavLeaf = { href: string; label: (l: Locale) => string };
type NavGroup = { key: string; label: (l: Locale) => string; items: NavLeaf[] };
type NavEntry = NavLeaf | NavGroup;

// Flat nav — no dropdowns. Chat is intentionally absent: it's reachable
// from the Console right panel. Each entry opens a section whose left
// sub-menu lives in PageShell (see sections.ts). "Sources" was removed
// in favour of a unified Skills catalogue — every source listed there
// now has a matching manifest under skills-catalog/.
const NAV: NavEntry[] = [
  { href: "/", label: () => "Console" },
  { href: "/status", label: () => "Status" },
  { href: "/incidents", label: () => "Incidents" },
  { href: "/assets", label: (l) => (l === "fr" ? "Inventaire" : "Inventory") },
  { href: "/intelligence", label: () => "Investigation" },
  { href: "/skills", label: () => "Skills" },
  { href: "/scans", label: () => "Scans" },
  { href: "/exports", label: (l) => (l === "fr" ? "Rapports" : "Reports") },
  { href: "/setup", label: () => "Config" },
];

function isGroup(e: NavEntry): e is NavGroup {
  return (e as NavGroup).items !== undefined;
}

// When an entry represents a section (its href is the section's default
// page), we want the top-nav item to stay highlighted while the user
// clicks around the section's left sub-menu. Reach into the section
// registry to match any of its sibling paths, not just the default one.
import { SECTIONS, type Section } from "./sections";

const SECTION_BY_DEFAULT_HREF: Map<string, Section> = new Map(
  Object.values(SECTIONS).map((s) => [s.items[0]?.href.split("?")[0] ?? "", s]),
);

function pathMatches(pathname: string, href: string) {
  if (href === "/") return pathname === "/";
  const section = SECTION_BY_DEFAULT_HREF.get(href);
  if (section) {
    return section.matches.some(
      (p) => pathname === p || pathname.startsWith(p + "/"),
    );
  }
  return pathname.startsWith(href);
}

function entryActive(e: NavEntry, pathname: string) {
  return isGroup(e) ? e.items.some((i) => pathMatches(pathname, i.href)) : pathMatches(pathname, e.href);
}

export default function SocTopBar() {
  const locale = useLocale();
  const pathname = usePathname();
  const [clock, setClock] = useState("");
  const [openGroup, setOpenGroup] = useState<string | null>(null);
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [paused, setPaused] = useState(false);
  const [criticalCount, setCriticalCount] = useState(0);
  const [version, setVersion] = useState<string>("");

  // Wall clock tick
  useEffect(() => {
    const tick = () => setClock(new Date().toLocaleTimeString("fr-FR", { hour12: false }));
    tick();
    const iv = setInterval(tick, 1000);
    return () => clearInterval(iv);
  }, []);

  // Pause status poll
  useEffect(() => {
    const load = () =>
      fetch("/api/tc/pause")
        .then((r) => r.json())
        .then((d) => setPaused(d.paused || false))
        .catch(() => {});
    load();
    const iv = setInterval(load, 15_000);
    return () => clearInterval(iv);
  }, []);

  // Version (one-shot) — shown under the brand
  useEffect(() => {
    fetch("/api/tc/health")
      .then((r) => r.json())
      .then((d) => {
        if (d?.version) setVersion(`v${d.version}`);
      })
      .catch(() => {});
  }, []);

  // Critical incident poll — drives the red pill at the right
  useEffect(() => {
    const load = async () => {
      try {
        const r = await fetch("/api/tc/incidents?limit=500");
        const d = await r.json();
        const list: { severity?: string | null; verdict?: string; status?: string }[] = d?.incidents ?? [];
        const n = list.filter((i) => {
          const s = (i.severity ?? "").toUpperCase();
          return (s === "HIGH" || s === "CRITICAL") && i.status !== "closed" && i.verdict !== "false_positive";
        }).length;
        setCriticalCount(n);
      } catch {
        /* quiet */
      }
    };
    load();
    const iv = setInterval(load, 20_000);
    return () => clearInterval(iv);
  }, []);

  // Theme init
  useEffect(() => {
    const saved = (typeof window !== "undefined" ? localStorage.getItem("tc-theme") : null) as "dark" | "light" | null;
    if (saved) {
      setTheme(saved);
      document.documentElement.setAttribute("data-theme", saved);
    }
  }, []);

  useEffect(() => {
    function onDocClick(e: MouseEvent) {
      const target = e.target as HTMLElement;
      if (!target.closest?.("[data-nav-group]")) setOpenGroup(null);
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

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
    try {
      localStorage.setItem("tc-theme", next);
    } catch {}
  };

  const togglePause = async () => {
    try {
      const r = await fetch("/api/tc/pause", { method: "POST" });
      const d = await r.json();
      setPaused(d.paused);
    } catch {}
  };

  const toggleLocale = () => {
    const next = locale === "fr" ? "en" : "fr";
    localStorage.setItem("tc-language", next);
    window.dispatchEvent(new Event("tc-locale-change"));
    window.location.reload();
  };

  const logout = async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } catch {}
    window.location.href = "/login";
  };

  return (
    <header
      style={{
        display: "grid",
        gridTemplateColumns: "260px 1fr auto",
        alignItems: "center",
        height: "44px",
        borderBottom: "1px solid var(--tc-border)",
        padding: "0 16px",
        background: "var(--tc-surface)",
        gap: "18px",
        fontFamily: "'JetBrains Mono', ui-monospace, monospace",
      }}
    >
      {/* Brand */}
      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
        <img src="/logo.png" alt="" width={22} height={22} style={{ borderRadius: "4px" }} />
        <div style={{ lineHeight: 1.15 }}>
          <div style={{ fontSize: "12px", letterSpacing: "0.16em", fontWeight: 700, textTransform: "uppercase" }}>
            <span style={{ color: "var(--tc-text)" }}>threat</span>
            <span style={{ color: "var(--tc-red)" }}>claw</span>
          </div>
          <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", letterSpacing: "0.12em", fontVariantNumeric: "tabular-nums" }}>
            {version || "—"}
          </div>
        </div>
      </div>

      {/* Nav tabs */}
      <nav style={{ display: "flex", alignSelf: "stretch" }}>
        {NAV.map((entry) => {
          const active = entryActive(entry, pathname);
          const label = entry.label(locale);
          if (!isGroup(entry)) {
            return <Tab key={entry.href} href={entry.href} label={label} active={active} />;
          }
          const isOpen = openGroup === entry.key;
          return (
            <div
              key={entry.key}
              data-nav-group
              style={{ position: "relative", display: "flex", alignSelf: "stretch" }}
            >
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setOpenGroup(isOpen ? null : entry.key);
                }}
                style={{
                  padding: "0 14px",
                  display: "flex",
                  alignItems: "center",
                  gap: "5px",
                  color: active ? "var(--tc-text)" : "var(--tc-text-sec)",
                  fontSize: "10px",
                  letterSpacing: "0.14em",
                  textTransform: "uppercase",
                  textDecoration: "none",
                  borderRight: "1px solid var(--tc-border)",
                  background: active ? "var(--tc-surface-alt, var(--tc-surface))" : "transparent",
                  border: "none",
                  cursor: "pointer",
                  position: "relative",
                  fontFamily: "inherit",
                }}
              >
                {label}
                <ChevronDown size={11} style={{ transform: isOpen ? "rotate(180deg)" : undefined, transition: "transform 120ms" }} />
                {active && <ActiveUnderline />}
              </button>
              {isOpen && (
                <div
                  onClick={(e) => e.stopPropagation()}
                  style={{
                    position: "absolute",
                    top: "44px",
                    left: 0,
                    minWidth: "180px",
                    background: "var(--tc-surface)",
                    border: "1px solid var(--tc-border)",
                    boxShadow: "0 8px 22px rgba(0,0,0,0.28)",
                    zIndex: 40,
                    padding: "4px",
                  }}
                >
                  {entry.items.map((leaf) => {
                    const leafActive = pathMatches(pathname, leaf.href);
                    return (
                      <Link
                        key={leaf.href}
                        href={leaf.href}
                        onClick={() => setOpenGroup(null)}
                        style={{
                          display: "block",
                          padding: "8px 12px",
                          fontSize: "11px",
                          textDecoration: "none",
                          color: leafActive ? "var(--tc-red)" : "var(--tc-text)",
                          background: leafActive ? "var(--tc-red-soft)" : "transparent",
                          letterSpacing: "0.02em",
                        }}
                        onMouseEnter={(e) => {
                          if (!leafActive) e.currentTarget.style.background = "var(--tc-input)";
                        }}
                        onMouseLeave={(e) => {
                          if (!leafActive) e.currentTarget.style.background = "transparent";
                        }}
                      >
                        {leaf.label(locale)}
                      </Link>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </nav>

      {/* Right cluster */}
      <div style={{ display: "flex", alignItems: "center", gap: "10px", fontSize: "10px" }}>
        <span
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "6px",
            border: "1px solid var(--tc-border)",
            padding: "3px 8px",
            color: "var(--tc-text-sec)",
          }}
        >
          <Pulse color={paused ? "#d09020" : "#30a050"} />
          <span>engine · {paused ? "paused" : "live"}</span>
        </span>
        <span style={{ color: "var(--tc-text-muted)", letterSpacing: "0.12em" }}>
          <span style={{ marginRight: "6px", textTransform: "uppercase" }}>clock</span>
          <span style={{ color: "var(--tc-text)", fontVariantNumeric: "tabular-nums" }}>{clock}</span>
        </span>

        {criticalCount > 0 && (
          <Link
            href="/incidents"
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "6px",
              padding: "3px 8px",
              border: "1px solid var(--tc-red)",
              color: "var(--tc-red)",
              fontWeight: 700,
              letterSpacing: "0.08em",
              textDecoration: "none",
            }}
          >
            <Pulse color="var(--tc-red)" fast />
            {criticalCount} inc. HIGH+
          </Link>
        )}

        <IconButton title={paused ? "Resume" : "Pause"} onClick={togglePause}>
          {paused ? <Play size={12} /> : <Pause size={12} />}
        </IconButton>
        <IconButton title={theme === "dark" ? tr("lightMode", locale) : tr("darkMode", locale)} onClick={toggleTheme}>
          {theme === "dark" ? <Sun size={12} /> : <Moon size={12} />}
        </IconButton>
        <IconButton title={tr("switchLanguage", locale)} onClick={toggleLocale} small>
          {locale === "fr" ? "EN" : "FR"}
        </IconButton>
        <IconButton title="Logout" onClick={logout}>
          <LogOut size={12} />
        </IconButton>
      </div>
    </header>
  );
}

function Tab({ href, label, active }: { href: string; label: string; active: boolean }) {
  return (
    <Link
      href={href}
      style={{
        padding: "0 14px",
        display: "flex",
        alignItems: "center",
        color: active ? "var(--tc-text)" : "var(--tc-text-sec)",
        fontSize: "10px",
        letterSpacing: "0.14em",
        textTransform: "uppercase",
        textDecoration: "none",
        borderRight: "1px solid var(--tc-border)",
        background: active ? "var(--tc-surface-alt, var(--tc-surface))" : "transparent",
        position: "relative",
      }}
    >
      {label}
      {active && <ActiveUnderline />}
    </Link>
  );
}

function ActiveUnderline() {
  return (
    <div
      style={{
        position: "absolute",
        left: 0,
        right: 0,
        bottom: "-1px",
        height: "2px",
        background: "var(--tc-red)",
      }}
    />
  );
}

function IconButton({
  onClick,
  title,
  children,
  small,
}: {
  onClick: () => void;
  title: string;
  children: React.ReactNode;
  small?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      title={title}
      style={{
        width: small ? "26px" : "26px",
        height: "26px",
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        background: "transparent",
        border: "1px solid var(--tc-border)",
        color: "var(--tc-text-sec)",
        cursor: "pointer",
        fontSize: small ? "9px" : "11px",
        fontFamily: "inherit",
        fontWeight: small ? 700 : undefined,
        letterSpacing: small ? "0.08em" : undefined,
      }}
    >
      {children}
    </button>
  );
}

function Pulse({ color, fast }: { color: string; fast?: boolean }) {
  return (
    <span
      style={{
        width: "6px",
        height: "6px",
        borderRadius: "50%",
        background: color,
        boxShadow: `0 0 8px ${color}`,
        animation: `pulse ${fast ? "0.9s" : "1.6s"} ease-in-out infinite`,
      }}
    >
      <style>{`@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.35}}`}</style>
    </span>
  );
}
