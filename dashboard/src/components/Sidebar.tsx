"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  ShieldCheck,
  Bell,
  FileText,
  Settings,
  Shield,
  Puzzle,
  Wrench,
} from "lucide-react";

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
}

const navItems: NavItem[] = [
  { label: "Dashboard", href: "/", icon: LayoutDashboard },
  { label: "Compliance NIS2", href: "/compliance", icon: ShieldCheck },
  { label: "Alertes SOC", href: "/alerts", icon: Bell },
  { label: "Rapports", href: "/reports", icon: FileText },
  { label: "Marketplace", href: "/marketplace", icon: Puzzle },
  { label: "Configuration", href: "/setup", icon: Wrench },
  { label: "Paramètres", href: "/settings", icon: Settings },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="fixed left-0 top-0 z-40 flex h-screen w-64 flex-col border-r border-gray-700/30 bg-primary">
      {/* Logo */}
      <div className="flex h-16 items-center gap-3 border-b border-gray-700/30 px-6">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-accent/20">
          <Shield className="h-5 w-5 text-accent" />
        </div>
        <div>
          <h1 className="text-lg font-bold tracking-tight text-white">
            ThreatClaw
          </h1>
          <p className="text-[10px] font-medium uppercase tracking-widest text-gray-500">
            Security Dashboard
          </p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-4 scrollbar-thin">
        {navItems.map((item) => {
          const isActive =
            item.href === "/"
              ? pathname === "/"
              : pathname.startsWith(item.href);
          const Icon = item.icon;

          return (
            <Link
              key={item.href}
              href={item.href}
              className={`group flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all duration-150 ${
                isActive
                  ? "bg-accent/10 text-accent"
                  : "text-gray-400 hover:bg-white/5 hover:text-gray-200"
              }`}
            >
              <Icon
                className={`h-5 w-5 flex-shrink-0 ${
                  isActive
                    ? "text-accent"
                    : "text-gray-500 group-hover:text-gray-400"
                }`}
              />
              {item.label}
              {isActive && (
                <div className="ml-auto h-1.5 w-1.5 rounded-full bg-accent" />
              )}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="border-t border-gray-700/30 p-4">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-success/50 text-xs font-bold text-white">
            RS
          </div>
          <div className="flex-1 truncate">
            <p className="text-sm font-medium text-gray-200">RSSI</p>
            <p className="text-xs text-gray-500">Security Officer</p>
          </div>
        </div>
      </div>
    </aside>
  );
}
