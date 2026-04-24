// Central section registry — single source of truth for the top nav,
// the per-section left sub-menu rendered by the root layout, and the
// reverse lookup that turns a pathname into "which section am I in?".
//
// Adding a page in an existing section: add a new item here, no edit to
// the root layout or SocTopBar required. Adding a new top-level section:
// add a new entry with a label + items, and optionally register it in
// SocTopBar's TOP_NAV.

import type { Locale } from "@/lib/i18n";
import type { LucideIcon } from "lucide-react";
import {
  Siren,
  AlertTriangle,
  Search,
  Server,
  Users,
  Brain,
  Shield,
  ShieldAlert,
  Puzzle,
  FileText,
  Gavel,
  Wrench,
  Globe,
  Cpu,
  MessageSquare,
  Activity,
  Bell,
  Clock,
  Download,
  Eye,
  Radio,
  Monitor,
  Play,
  Key,
} from "lucide-react";

export type SubNavItem = {
  /// Target URL. For section pages that are tab-based (e.g. /setup and
  /// /skills), we embed the tab in the URL so the left sub-menu drives
  /// state without extra plumbing.
  href: string;
  labelFr: string;
  labelEn: string;
  icon: LucideIcon;
};

export type Section = {
  key: SectionKey;
  /// Top nav label.
  label: (l: Locale) => string;
  /// Left sub-menu shown by the root layout when a page belongs here.
  items: SubNavItem[];
  /// Pathname prefixes that map back to this section. First match wins.
  matches: string[];
};

export type SectionKey =
  | "incidents"
  | "inventaire"
  | "investigation"
  | "skills"
  | "rapports"
  | "setup";

export const SECTIONS: Record<SectionKey, Section> = {
  incidents: {
    key: "incidents",
    label: () => "Incidents",
    matches: ["/incidents", "/findings", "/alerts", "/alertes"],
    items: [
      { href: "/incidents", labelFr: "Incidents", labelEn: "Incidents", icon: Siren },
      { href: "/findings", labelFr: "Findings", labelEn: "Findings", icon: Search },
      { href: "/alerts", labelFr: "Alertes", labelEn: "Alerts", icon: AlertTriangle },
    ],
  },
  inventaire: {
    key: "inventaire",
    label: (l) => (l === "fr" ? "Inventaire" : "Inventory"),
    matches: ["/assets", "/users"],
    items: [
      { href: "/assets", labelFr: "Assets", labelEn: "Assets", icon: Server },
      { href: "/users", labelFr: "Utilisateurs", labelEn: "Users", icon: Users },
    ],
  },
  investigation: {
    key: "investigation",
    label: () => "Investigation",
    matches: ["/intelligence", "/governance"],
    items: [
      { href: "/intelligence", labelFr: "Intelligence", labelEn: "Intelligence", icon: Brain },
      { href: "/governance", labelFr: "Gouvernance", labelEn: "Governance", icon: Shield },
    ],
  },
  skills: {
    key: "skills",
    label: () => "Skills",
    matches: ["/skills"],
    items: [
      { href: "/skills?tab=installed", labelFr: "Installés", labelEn: "Installed", icon: Puzzle },
      { href: "/skills?tab=catalog", labelFr: "Catalogue", labelEn: "Catalog", icon: Search },
    ],
  },
  rapports: {
    key: "rapports",
    label: (l) => (l === "fr" ? "Rapports" : "Reports"),
    // Dedicated page per category — cleaner than a ?category= filter.
    matches: ["/exports"],
    items: [
      { href: "/exports", labelFr: "Tous les rapports", labelEn: "All reports", icon: FileText },
      {
        href: "/exports/incident-response",
        labelFr: "Réponse à incident",
        labelEn: "Incident Response",
        icon: Siren,
      },
      {
        href: "/exports/compliance-audit",
        labelFr: "Compliance & audit",
        labelEn: "Compliance & Audit",
        icon: Gavel,
      },
      {
        href: "/exports/threat-intel",
        labelFr: "Threat Intelligence",
        labelEn: "Threat Intelligence",
        icon: Brain,
      },
      {
        href: "/exports/operations",
        labelFr: "Opérations",
        labelEn: "Operations",
        icon: Wrench,
      },
    ],
  },
  setup: {
    key: "setup",
    label: () => "Config",
    matches: ["/setup"],
    // Flattened from the old two-level structure (/setup → ConfigPage
    // with its own inner sidebar): the 13 ConfigPage sub-tabs and the 3
    // top-level setup entries now live side by side in one menu, one
    // click per destination. Tab keys stay aligned with ConfigPage's
    // internal `tabs` array so /setup?tab=<key> directly addresses the
    // right content block.
    items: [
      { href: "/setup?tab=general", labelFr: "Général", labelEn: "General", icon: Globe },
      { href: "/setup?tab=company", labelFr: "Entreprise", labelEn: "Company", icon: Shield },
      { href: "/setup?tab=llm", labelFr: "ThreatClaw AI", labelEn: "ThreatClaw AI", icon: Cpu },
      { href: "/setup?tab=channels", labelFr: "Canaux", labelEn: "Channels", icon: MessageSquare },
      { href: "/setup?tab=security", labelFr: "Sécurité", labelEn: "Security", icon: ShieldAlert },
      { href: "/setup?tab=remediation", labelFr: "Remédiation", labelEn: "Remediation", icon: Shield },
      { href: "/setup?tab=agent", labelFr: "Agent & Moteur", labelEn: "Agent Engine", icon: Activity },
      { href: "/setup?tab=notifications", labelFr: "Notifications", labelEn: "Notifications", icon: Bell },
      { href: "/setup?tab=retention", labelFr: "Rétention", labelEn: "Retention", icon: Clock },
      { href: "/setup?tab=anonymizer", labelFr: "Anonymisation", labelEn: "Anonymizer", icon: Shield },
      { href: "/setup?tab=backup", labelFr: "Sauvegarde & MAJ", labelEn: "Backup & Update", icon: Download },
      { href: "/setup?tab=logs", labelFr: "Logs", labelEn: "Logs", icon: Eye },
      { href: "/setup?tab=sources", labelFr: "Sources de logs", labelEn: "Log Sources", icon: Radio },
      { href: "/setup?tab=endpoints", labelFr: "Agents endpoint", labelEn: "Endpoint Agents", icon: Monitor },
      { href: "/setup?tab=tests", labelFr: "Simulation", labelEn: "Simulation", icon: Play },
      { href: "/setup?tab=about", labelFr: "À propos", labelEn: "About", icon: Key },
    ],
  },
};

/// Reverse lookup: which section does a pathname belong to, if any?
/// Returns null for /, /status, /login, /chat — top-level routes with
/// no sub-menu.
export function sectionForPath(pathname: string): Section | null {
  for (const section of Object.values(SECTIONS)) {
    for (const prefix of section.matches) {
      if (pathname === prefix || pathname.startsWith(prefix + "/")) {
        return section;
      }
    }
  }
  return null;
}

/// Resolve a sub-item label against the current locale.
export function subNavLabel(item: SubNavItem, locale: Locale): string {
  return locale === "fr" ? item.labelFr : item.labelEn;
}
