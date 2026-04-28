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
  Bot,
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
  Info,
  Plug,
  Crosshair,
  Zap,
  Lock,
  Network,
  Database,
} from "lucide-react";

export type SubNavItem = {
  /// Target URL. For section pages that are tab-based (e.g. /setup and
  /// /skills), we embed the tab in the URL so the left sub-menu drives
  /// state without extra plumbing.
  href: string;
  labelFr: string;
  labelEn: string;
  icon: LucideIcon;
  /// Optional nested submenu — rendered indented and auto-expanded when
  /// the parent or any child is the active route.
  children?: SubNavItem[];
  /// Optional tooltip explaining what this entry contains and what the
  /// expected volume / cadence is. Surfaced as the native title= on the
  /// sidebar item. Used to disambiguate the alerts/findings/incidents
  /// triptyque (Phase D — refoundation 27/04).
  tooltipFr?: string;
  tooltipEn?: string;
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
  | "scans"
  | "rapports"
  | "setup";

export const SECTIONS: Record<SectionKey, Section> = {
  incidents: {
    key: "incidents",
    label: () => "Incidents",
    matches: ["/incidents", "/enquetes", "/archives", "/findings", "/alerts", "/alertes"],
    items: [
      {
        href: "/incidents",
        labelFr: "Incidents",
        labelEn: "Incidents",
        icon: Siren,
        tooltipFr: "Menaces confirmées et corroborées — tu dois agir.",
        tooltipEn: "Corroborated, confirmed threats — you must act.",
      },
      {
        href: "/enquetes",
        labelFr: "Enquêtes en cours",
        labelEn: "Investigations",
        icon: Activity,
        tooltipFr: "L'IA travaille en ce moment sur ces dossiers — disparaît dès qu'un verdict tombe.",
        tooltipEn: "Investigation graphs the AI is currently running.",
      },
      {
        href: "/archives",
        labelFr: "Archives",
        labelEn: "Archives",
        icon: Search,
        tooltipFr: "Outil forensique — tout ce qui a été clos avec son motif (auto-archive ou manuel), filtrable par asset/période/motif.",
        tooltipEn: "Forensic tool — everything closed with its reason, filterable.",
      },
    ],
  },
  inventaire: {
    key: "inventaire",
    label: (l) => (l === "fr" ? "Inventaire" : "Inventory"),
    matches: ["/assets", "/users", "/network", "/threat-map"],
    items: [
      { href: "/assets", labelFr: "Assets", labelEn: "Assets", icon: Server },
      { href: "/users", labelFr: "Utilisateurs", labelEn: "Users", icon: Users },
      { href: "/network", labelFr: "Réseau", labelEn: "Network", icon: Network },
      {
        href: "/threat-map",
        labelFr: "Carte des menaces",
        labelEn: "Threat Map",
        icon: Crosshair,
        tooltipFr: "Top chemins d'attaque + fixes prioritaires — calcul automatique toutes les 6 h.",
        tooltipEn: "Top attack paths + priority fixes — auto-computed every 6h.",
      },
    ],
  },
  investigation: {
    key: "investigation",
    label: () => "Investigation",
    matches: ["/intelligence", "/governance", "/shadow-ai"],
    items: [
      { href: "/intelligence", labelFr: "Intelligence", labelEn: "Intelligence", icon: Brain },
      { href: "/governance", labelFr: "Gouvernance", labelEn: "Governance", icon: Shield },
      { href: "/shadow-ai", labelFr: "Shadow IA", labelEn: "Shadow AI", icon: Bot },
    ],
  },
  skills: {
    key: "skills",
    label: () => "Skills",
    matches: ["/skills"],
    items: [
      { href: "/skills?installed=1", labelFr: "Mes skills installés", labelEn: "My installed skills", icon: Puzzle },
      {
        href: "/skills",
        labelFr: "Catalogue",
        labelEn: "Catalog",
        icon: Search,
        children: [
          { href: "/skills?cat=network", labelFr: "Réseau", labelEn: "Network", icon: Network },
          { href: "/skills?cat=endpoints", labelFr: "Endpoints", labelEn: "Endpoints", icon: Monitor },
          { href: "/skills?cat=inventory", labelFr: "Inventaire", labelEn: "Inventory", icon: Database },
          { href: "/skills?cat=scan", labelFr: "Scan", labelEn: "Scan", icon: Crosshair },
          { href: "/skills?cat=threat-intel", labelFr: "Threat Intel", labelEn: "Threat Intel", icon: Eye },
          { href: "/skills?cat=web", labelFr: "Web", labelEn: "Web", icon: Globe },
        ],
      },
      { href: "/setup?tab=licenses", labelFr: "Mes licences", labelEn: "My licenses", icon: Lock },
    ],
  },
  scans: {
    key: "scans",
    label: () => "Scans",
    matches: ["/scans"],
    items: [
      { href: "/scans", labelFr: "Lancer un scan", labelEn: "Launch scan", icon: Play },
      { href: "/scans?tab=history", labelFr: "Historique", labelEn: "History", icon: Clock },
      { href: "/scans?tab=scheduled", labelFr: "Planifiés", labelEn: "Scheduled", icon: Bell },
      { href: "/scans?tab=library", labelFr: "Bibliothèque", labelEn: "Library", icon: Puzzle },
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
      { href: "/setup?tab=licenses", labelFr: "Licences premium", labelEn: "Premium licenses", icon: Key },
      { href: "/setup?tab=about", labelFr: "À propos", labelEn: "About", icon: Info },
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
