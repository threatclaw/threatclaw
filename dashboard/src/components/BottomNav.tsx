"use client";

import React, { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import Link from "next/link";
import {
  LayoutGrid,
  ScanSearch,
  Bell,
  FileText,
  Puzzle,
  Wrench,
  Shield,
  type LucideIcon,
} from "lucide-react";

interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  center?: boolean;
}

const FIXED_ITEMS: NavItem[] = [
  { href: "/", label: "Board", icon: LayoutGrid },
  { href: "/alertes", label: "Alertes", icon: Bell },
  { href: "/agent", label: "Agent", icon: Shield, center: true },
  { href: "/marketplace", label: "Skills", icon: Puzzle },
  { href: "/setup", label: "Config", icon: Wrench },
];

export default function BottomNav() {
  const pathname = usePathname();
  const [pinned, setPinned] = useState<NavItem[]>([]);

  useEffect(() => {
    try {
      const saved = localStorage.getItem("tc-pinned-nav");
      if (saved) {
        const parsed = JSON.parse(saved);
        const items: NavItem[] = parsed.map((p: { href: string; label: string }) => ({
          ...p,
          icon: FileText,
        }));
        setPinned(items);
      }
    } catch { /* ignore */ }
  }, []);

  const allItems = [...FIXED_ITEMS, ...pinned];

  return (
    <nav style={{
      background: "var(--bg-nav)",
      borderTop: "1px solid var(--nav-border)",
      padding: "8px 12px 14px",
      display: "flex",
      justifyContent: "space-around",
      alignItems: "center",
      position: "sticky",
      bottom: 0,
      zIndex: 50,
    }}>
      {allItems.map((item) => {
        const isActive = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
        const Icon = item.icon;

        return (
          <Link key={item.href} href={item.href} style={{ textDecoration: "none" }}>
            <div style={{
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              gap: "3px",
              padding: item.center ? "8px 14px" : "6px 10px",
              borderRadius: item.center ? "13px" : "10px",
              background: "var(--bg-pit)",
              boxShadow: item.center
                ? "var(--shadow-pit-sm)"
                : isActive
                ? "var(--shadow-pit-xs)"
                : "none",
              ...(item.center ? {
                outline: "1px solid var(--border-accent)",
                outlineOffset: "-3px",
              } : {}),
            }}>
              <Icon
                size={16}
                color={isActive || item.center ? "var(--nav-icon-on)" : "var(--nav-icon-off)"}
                strokeWidth={1.8}
              />
              <span style={{
                fontSize: "8px",
                fontWeight: 700,
                letterSpacing: "0.06em",
                textTransform: "uppercase",
                color: isActive || item.center ? "var(--nav-icon-on)" : "var(--nav-icon-off)",
              }}>
                {item.label}
              </span>
            </div>
          </Link>
        );
      })}
    </nav>
  );
}
