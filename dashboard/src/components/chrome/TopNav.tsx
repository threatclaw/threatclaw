"use client";

import React from "react";
import { usePathname } from "next/navigation";
import Link from "next/link";
import { Shield, Bell, Puzzle, Settings, Activity, Server } from "lucide-react";

const NAV_ITEMS = [
  { href: "/", label: "Accueil", icon: Shield },
  { href: "/alertes", label: "Alertes", icon: Bell },
  { href: "/infrastructure", label: "Infra", icon: Server },
  { href: "/skills", label: "Skills", icon: Puzzle },
  { href: "/agent", label: "Agent", icon: Activity },
  { href: "/setup", label: "Config", icon: Settings },
];

export default function TopNav() {
  const pathname = usePathname();

  return (
    <nav style={{
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      padding: "12px 20px",
      marginBottom: "16px",
    }}>
      {/* Logo */}
      <span style={{
        fontSize: "11px",
        fontWeight: 800,
        letterSpacing: "0.25em",
        textTransform: "uppercase",
        color: "#5a3a2a",
        textShadow: "0 1px 1px rgba(255,255,255,0.4)",
      }}>
        THREATCLAW
      </span>

      {/* Nav buttons */}
      <div style={{ display: "flex", gap: "4px" }}>
        {NAV_ITEMS.map((item) => {
          const isActive = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
          const Icon = item.icon;

          return (
            <Link key={item.href} href={item.href} style={{ textDecoration: "none" }}>
              <div style={{
                display: "flex",
                alignItems: "center",
                gap: "5px",
                padding: "6px 12px",
                borderRadius: "0.5em",
                fontSize: "10px",
                fontWeight: 700,
                letterSpacing: "0.04em",
                textTransform: "uppercase",
                color: isActive ? "#903020" : "#907060",
                background: isActive ? "#e2dbd4" : "transparent",
                boxShadow: isActive
                  ? "inset 0 2px 6px rgba(60,30,15,0.2), inset 0 1px 2px rgba(60,30,15,0.15), inset 0 -1px 1px rgba(255,255,255,0.3)"
                  : "none",
                textShadow: isActive
                  ? "0 1px 0 rgba(255,245,240,0.4), 0 -1px 1px rgba(100,30,15,0.1)"
                  : "none",
                transition: "all 200ms ease",
                cursor: "pointer",
              }}>
                <Icon size={13} />
                {item.label}
              </div>
            </Link>
          );
        })}
      </div>
    </nav>
  );
}
