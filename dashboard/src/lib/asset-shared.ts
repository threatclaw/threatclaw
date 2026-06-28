/**
 * Shared types, constants and helpers used by both `/assets` (list view)
 * and `/assets/[assetId]` (detail page) — Phase 10c.
 *
 * Anything that touches the Asset shape lives here so the two pages stay
 * in lock-step when fields evolve.
 */

import {
  Server, Monitor, Smartphone, Globe, Network, Printer, Cpu, Factory, Cloud, HelpCircle,
} from "lucide-react";
import type { ElementType } from "react";

export interface Asset {
  id: string;
  name: string;
  category: string;
  subcategory: string | null;
  role: string | null;
  criticality: string;
  ip_addresses: string[];
  mac_address: string | null;
  hostname: string | null;
  fqdn: string | null;
  url: string | null;
  os: string | null;
  os_confidence: number;
  mac_vendor: string | null;
  services: any;
  source: string;
  status: string;
  last_seen: string;
  first_seen: string;
  owner: string | null;
  location: string | null;
  /** System flags only (possible-duplicate / public_ip / keep-separate). */
  tags: string[];
  /** V98 — operator tags as entities (label + colour), from the listing join. */
  user_tags?: { id: number; label: string; color: string }[];
  notes: string | null;
  classification_method: string;
  classification_confidence: number;
  software?: any;
  inventory_status?: string;
  distinct_days_seen_30d?: number;
  billable_status?: string;
  demo?: boolean;
  sources?: string[];
  excluded?: boolean;
  exclusion_reason?: string;
  exclusion_until?: string | null;
  exclusion_by?: string;
}

export interface Category {
  id: string;
  label: string;
  label_en: string | null;
  icon: string;
  color: string;
  subcategories: string[];
  is_builtin: boolean;
}

export const ICON_MAP: Record<string, ElementType> = {
  server: Server,
  monitor: Monitor,
  smartphone: Smartphone,
  globe: Globe,
  network: Network,
  printer: Printer,
  cpu: Cpu,
  factory: Factory,
  cloud: Cloud,
  "help-circle": HelpCircle,
};

/**
 * Phase 11b — `critical` is renamed to `Essentiel` in the UI and rendered
 * in violet (`#7030a0`) instead of red. Rationale: red on an asset card
 * reads as "this asset has a problem", but criticality describes how
 * precious the asset is, not its current incident state. Violet conveys
 * "mission-critical / strategic" without the danger semantics.
 *
 * The DB string `critical` is left untouched everywhere else (Rust enums,
 * scoring, scheduling) — only the rendered label changes here.
 */
export const CRIT_COLORS: Record<string, { color: string; label: string }> = {
  critical: { color: "#7030a0", label: "Essentiel" },
  high: { color: "#d07020", label: "Haut" },
  medium: { color: "#d09020", label: "Moyen" },
  low: { color: "#30a050", label: "Bas" },
};

export const SEV_COLORS: Record<string, string> = {
  critical: "#e04040",
  high: "#d07020",
  medium: "#d09020",
  low: "#30a050",
  info: "#888888",
};
