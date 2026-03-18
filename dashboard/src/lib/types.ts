export interface SecurityScore {
  score: number;
  trend: "up" | "down" | "stable";
  trendValue: number;
  breakdown: {
    vulnerabilities: number;
    compliance: number;
    cloudPosture: number;
    accessControl: number;
    dataProtection: number;
  };
}

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  source: string;
  asset: string;
  status: "open" | "in_progress" | "resolved" | "accepted";
  detectedAt: string;
  updatedAt: string;
  cve?: string;
  cvss?: number;
}

export interface FindingsSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  findings: Finding[];
}

export interface NIS2Article {
  id: string;
  name: string;
  description: string;
  score: number;
  maxScore: number;
  maturityLevel: "initial" | "developing" | "defined" | "managed" | "optimized";
  gaps: NIS2Gap[];
}

export interface NIS2Gap {
  id: string;
  articleId: string;
  description: string;
  priority: "critical" | "high" | "medium" | "low";
  status: "open" | "in_progress" | "resolved";
  remediation: string;
  dueDate: string;
}

export interface NIS2Compliance {
  overallScore: number;
  articles: NIS2Article[];
}

export interface Alert {
  id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  source: string;
  status: "new" | "investigating" | "resolved" | "false_positive";
  timestamp: string;
  assignee?: string;
  correlationGroup?: string;
  indicators: string[];
  mitreTactic?: string;
  mitretechnique?: string;
}

export interface AlertsResponse {
  alerts: Alert[];
  total: number;
  page: number;
  pageSize: number;
}

export interface AlertFilters {
  severity?: string;
  source?: string;
  status?: string;
  page?: number;
  pageSize?: number;
}

export interface CloudPosture {
  score: number;
  trend: "up" | "down" | "stable";
  trendValue: number;
  history: CloudPostureEntry[];
}

export interface CloudPostureEntry {
  date: string;
  score: number;
  findings: number;
  resources: number;
}

export interface Report {
  id: string;
  title: string;
  type: "security_posture" | "nis2_compliance" | "incident_summary" | "executive_brief";
  status: "ready" | "generating" | "failed";
  createdAt: string;
  format: "pdf" | "html";
  size: string;
  downloadUrl: string;
}

export interface ReportsResponse {
  reports: Report[];
}

export type SeverityColor = {
  [key in "critical" | "high" | "medium" | "low" | "info"]: string;
};
