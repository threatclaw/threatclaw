// HITL action surfaced on an incident.
//
// This type mirrors the Rust struct `IncidentAction` defined in
// `src/agent/incident_action.rs`. The wire format on `incidents.proposed_actions`
// is `{actions: IncidentAction[], iocs: string[]}` — see `ProposedActionsBundle`
// below. Phase 9a / 9c made this the single source of truth across the codebase.

export type ActionKind =
  | "block_ip"
  | "unblock_ip"
  | "isolate_host"
  | "release_host"
  | "kill_process"
  | "collect_artifacts"
  | "disable_user"
  | "enable_user"
  | "reset_password"
  | "reset_krbtgt"
  | "force_mfa"
  | "manual"
  | "unknown";

export interface IncidentAction {
  /** Short typed taxonomy. Drives UI badge + filtering + metrics. */
  kind: ActionKind;
  /** Executable identifier consumed by the remediation engine. Stable string. */
  cmd_id: string;
  /** Human-readable description for the operator. */
  description: string;
  /** Stringified parameters (`ip`, `asset`, `user_id`, `pid`, ...). */
  params: Record<string, string>;
  /** Why this action is proposed (references sigma_alert / finding ids). */
  rationale: string;
  /** Always true for Phase 9 — no auto-execution. */
  requires_hitl: boolean;
  /** Skill that executes the action (`skill-opnsense`, `skill-velociraptor`...). */
  skill_id: string;
  /** Provenance for the audit trail. */
  origin: string;
}

export interface ProposedActionsBundle {
  actions: IncidentAction[];
  iocs: string[];
}

/** Human-readable badge label (mirrors `ActionKind::label` in Rust). */
export function kindLabel(kind: ActionKind | string): string {
  switch (kind) {
    case "block_ip":
      return "BLOCK_IP";
    case "unblock_ip":
      return "UNBLOCK_IP";
    case "isolate_host":
      return "ISOLATE_HOST";
    case "release_host":
      return "RELEASE_HOST";
    case "kill_process":
      return "KILL_PROCESS";
    case "collect_artifacts":
      return "COLLECT_ARTIFACTS";
    case "disable_user":
      return "DISABLE_USER";
    case "enable_user":
      return "ENABLE_USER";
    case "reset_password":
      return "RESET_PASSWORD";
    case "reset_krbtgt":
      return "RESET_KRBTGT";
    case "force_mfa":
      return "FORCE_MFA";
    case "manual":
      return "MANUAL";
    default:
      return "UNKNOWN";
  }
}

/**
 * Short, locale-aware label for the kind (operator-friendly summary in the
 * dashboard list view, where horizontal space is tight).
 */
export function kindShortLabel(kind: ActionKind | string, locale: "fr" | "en" = "fr"): string {
  const fr = locale === "fr";
  switch (kind) {
    case "block_ip":
      return fr ? "Blocage IP" : "IP block";
    case "unblock_ip":
      return fr ? "Déblocage IP" : "IP unblock";
    case "isolate_host":
      return fr ? "Isolation hôte" : "Host isolation";
    case "release_host":
      return fr ? "Levée isolation" : "Release isolation";
    case "kill_process":
      return fr ? "Kill processus" : "Kill process";
    case "collect_artifacts":
      return fr ? "Collecte forensique" : "Forensic collection";
    case "disable_user":
      return fr ? "Désactiver compte" : "Disable account";
    case "enable_user":
      return fr ? "Réactiver compte" : "Enable account";
    case "reset_password":
      return fr ? "Reset mot de passe" : "Password reset";
    case "reset_krbtgt":
      return fr ? "Rotation krbtgt" : "krbtgt rotation";
    case "force_mfa":
      return fr ? "Forcer MFA" : "Force MFA";
    case "manual":
      return fr ? "Action manuelle" : "Manual action";
    default:
      return "Action";
  }
}
