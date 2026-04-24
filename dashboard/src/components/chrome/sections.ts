// Central section registry — single source of truth for the top nav,
// the per-section left sub-menu rendered by PageShell, and the reverse
// lookup that turns a pathname into "which section am I in?".
//
// Adding a page in an existing section: add a new item here, no edit to
// PageShell or SocTopBar required. Adding a new top-level section: add
// a new entry with a label + items, and optionally register it in
// SocTopBar's TOP_NAV.
//
// Visible labels come through i18n locale — "fr" / "en" decided by the
// user preference loaded in useLocale().

import type { Locale } from "@/lib/i18n";

export type SubNavItem = {
  /// Target URL. Supports query strings for tab-based pages (e.g.
  /// /setup?tab=agent) so we don't need a full route restructure to
  /// expose sub-views in the left menu.
  href: string;
  labelFr: string;
  labelEn: string;
};

export type Section = {
  /// Stable key used by the URL-to-section reverse lookup and by each
  /// page to declare its affiliation.
  key: SectionKey;
  /// Top nav label.
  label: (l: Locale) => string;
  /// Left sub-menu shown by PageShell when a page belongs to this section.
  items: SubNavItem[];
  /// Pathname prefixes that map back to this section. Checked in order,
  /// first match wins. Use the more specific path (/users) before the
  /// less specific (/u).
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
      { href: "/incidents", labelFr: "Incidents", labelEn: "Incidents" },
      { href: "/findings", labelFr: "Findings", labelEn: "Findings" },
      { href: "/alerts", labelFr: "Alertes", labelEn: "Alerts" },
    ],
  },
  inventaire: {
    key: "inventaire",
    label: (l) => (l === "fr" ? "Inventaire" : "Inventory"),
    matches: ["/assets", "/users"],
    items: [
      { href: "/assets", labelFr: "Assets", labelEn: "Assets" },
      { href: "/users", labelFr: "Utilisateurs", labelEn: "Users" },
    ],
  },
  investigation: {
    key: "investigation",
    label: () => "Investigation",
    matches: ["/intelligence", "/governance"],
    items: [
      { href: "/intelligence", labelFr: "Intelligence", labelEn: "Intelligence" },
      { href: "/governance", labelFr: "Gouvernance", labelEn: "Governance" },
    ],
  },
  skills: {
    key: "skills",
    label: () => "Skills",
    matches: ["/skills"],
    items: [
      { href: "/skills?tab=installed", labelFr: "Installés", labelEn: "Installed" },
      { href: "/skills?tab=catalog", labelFr: "Catalogue", labelEn: "Catalog" },
    ],
  },
  rapports: {
    key: "rapports",
    label: (l) => (l === "fr" ? "Rapports" : "Reports"),
    matches: ["/exports"],
    // Categories map 1-1 to the ExportCategory enum declared in
    // dashboard/src/app/exports/page.tsx — keep these in sync when new
    // categories land.
    items: [
      {
        href: "/exports",
        labelFr: "Tous les rapports",
        labelEn: "All reports",
      },
      {
        href: "/exports?category=incident-response",
        labelFr: "Réponse à incident",
        labelEn: "Incident Response",
      },
      {
        href: "/exports?category=compliance-audit",
        labelFr: "Compliance & audit",
        labelEn: "Compliance & Audit",
      },
      {
        href: "/exports?category=threat-intel",
        labelFr: "Threat Intelligence",
        labelEn: "Threat Intelligence",
      },
      {
        href: "/exports?category=operations",
        labelFr: "Opérations",
        labelEn: "Operations",
      },
    ],
  },
  setup: {
    key: "setup",
    label: () => "Config",
    matches: ["/setup"],
    items: [
      { href: "/setup?tab=config", labelFr: "Général", labelEn: "General" },
      { href: "/setup?tab=agent", labelFr: "Agent", labelEn: "Agent" },
      { href: "/setup?tab=tests", labelFr: "Simulation", labelEn: "Simulation" },
      { href: "/setup?tab=about", labelFr: "À propos", labelEn: "About" },
    ],
  },
};

/// Reverse lookup: which section does a pathname belong to, if any?
/// Returns null for /, /status, /login, /chat — these sit at the top
/// level and have no left sub-menu.
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
