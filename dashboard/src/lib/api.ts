import type {
  SecurityScore,
  FindingsSummary,
  NIS2Compliance,
  AlertsResponse,
  AlertFilters,
  CloudPosture,
  ReportsResponse,
} from "./types";

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export async function fetchSecurityScore(): Promise<SecurityScore> {
  await delay(300);
  return {
    score: 72,
    trend: "up",
    trendValue: 3.2,
    breakdown: {
      vulnerabilities: 68,
      compliance: 74,
      cloudPosture: 81,
      accessControl: 65,
      dataProtection: 72,
    },
  };
}

export async function fetchFindings(): Promise<FindingsSummary> {
  await delay(250);
  return {
    critical: 4,
    high: 12,
    medium: 38,
    low: 67,
    info: 124,
    findings: [
      {
        id: "FND-001",
        title: "Remote Code Execution in Apache Struts",
        description:
          "CVE-2023-50164 allows remote code execution via crafted file upload parameters.",
        severity: "critical",
        source: "Qualys",
        asset: "web-prod-01.threatclaw.io",
        status: "open",
        detectedAt: "2026-03-17T08:23:00Z",
        updatedAt: "2026-03-17T08:23:00Z",
        cve: "CVE-2023-50164",
        cvss: 9.8,
      },
      {
        id: "FND-002",
        title: "SQL Injection in Authentication Module",
        description:
          "Blind SQL injection vulnerability found in the login endpoint.",
        severity: "critical",
        source: "Burp Suite",
        asset: "api-gateway.threatclaw.io",
        status: "in_progress",
        detectedAt: "2026-03-16T14:11:00Z",
        updatedAt: "2026-03-17T10:05:00Z",
        cve: undefined,
        cvss: 9.1,
      },
      {
        id: "FND-003",
        title: "Outdated TLS Configuration",
        description:
          "TLS 1.0 and 1.1 are still enabled on the load balancer.",
        severity: "high",
        source: "SSL Labs",
        asset: "lb-prod.threatclaw.io",
        status: "open",
        detectedAt: "2026-03-15T09:30:00Z",
        updatedAt: "2026-03-15T09:30:00Z",
      },
      {
        id: "FND-004",
        title: "Privileged Container Running in Production",
        description:
          "Kubernetes pod running with privileged security context.",
        severity: "high",
        source: "Falco",
        asset: "k8s-cluster-prod/ns-payments",
        status: "open",
        detectedAt: "2026-03-16T22:45:00Z",
        updatedAt: "2026-03-16T22:45:00Z",
      },
      {
        id: "FND-005",
        title: "Unencrypted S3 Bucket",
        description:
          "S3 bucket containing customer data does not have server-side encryption enabled.",
        severity: "high",
        source: "AWS Config",
        asset: "s3://threatclaw-customer-data",
        status: "in_progress",
        detectedAt: "2026-03-14T11:20:00Z",
        updatedAt: "2026-03-17T07:15:00Z",
      },
      {
        id: "FND-006",
        title: "Missing Rate Limiting on API",
        description: "No rate limiting configured on public API endpoints.",
        severity: "medium",
        source: "OWASP ZAP",
        asset: "api.threatclaw.io",
        status: "open",
        detectedAt: "2026-03-13T16:00:00Z",
        updatedAt: "2026-03-13T16:00:00Z",
      },
      {
        id: "FND-007",
        title: "Weak Password Policy",
        description:
          "Password policy allows passwords shorter than 12 characters.",
        severity: "medium",
        source: "Internal Audit",
        asset: "IAM Policy",
        status: "open",
        detectedAt: "2026-03-12T10:30:00Z",
        updatedAt: "2026-03-12T10:30:00Z",
      },
      {
        id: "FND-008",
        title: "Debug Mode Enabled",
        description:
          "Application debug mode is enabled in the staging environment, exposing stack traces.",
        severity: "low",
        source: "SonarQube",
        asset: "app-staging.threatclaw.io",
        status: "open",
        detectedAt: "2026-03-11T14:00:00Z",
        updatedAt: "2026-03-11T14:00:00Z",
      },
    ],
  };
}

export async function fetchNIS2Compliance(): Promise<NIS2Compliance> {
  await delay(350);
  return {
    overallScore: 68,
    articles: [
      {
        id: "art21_2a",
        name: "Risk Analysis & Information Security Policies",
        description:
          "Policies on risk analysis and information system security.",
        score: 78,
        maxScore: 100,
        maturityLevel: "managed",
        gaps: [
          {
            id: "GAP-001",
            articleId: "art21_2a",
            description: "Risk assessment not updated quarterly as required.",
            priority: "high",
            status: "in_progress",
            remediation: "Implement automated quarterly risk assessment cycle.",
            dueDate: "2026-04-15",
          },
        ],
      },
      {
        id: "art21_2b",
        name: "Incident Handling",
        description: "Incident handling procedures and response capabilities.",
        score: 72,
        maxScore: 100,
        maturityLevel: "defined",
        gaps: [
          {
            id: "GAP-002",
            articleId: "art21_2b",
            description: "Incident response playbooks incomplete for cloud-native attacks.",
            priority: "high",
            status: "open",
            remediation: "Develop cloud-specific IR playbooks covering container escape, API abuse, and lateral movement scenarios.",
            dueDate: "2026-04-01",
          },
          {
            id: "GAP-003",
            articleId: "art21_2b",
            description: "Mean time to detect (MTTD) exceeds 24-hour target.",
            priority: "medium",
            status: "in_progress",
            remediation: "Enhance SIEM correlation rules and deploy additional detection sensors.",
            dueDate: "2026-05-01",
          },
        ],
      },
      {
        id: "art21_2c",
        name: "Business Continuity & Crisis Management",
        description:
          "Business continuity, backup management, disaster recovery, and crisis management.",
        score: 65,
        maxScore: 100,
        maturityLevel: "defined",
        gaps: [
          {
            id: "GAP-004",
            articleId: "art21_2c",
            description: "Disaster recovery plan not tested in the last 6 months.",
            priority: "critical",
            status: "open",
            remediation: "Schedule and execute full DR test with documented results.",
            dueDate: "2026-03-30",
          },
        ],
      },
      {
        id: "art21_2d",
        name: "Supply Chain Security",
        description:
          "Supply chain security including security aspects of relationships with suppliers.",
        score: 55,
        maxScore: 100,
        maturityLevel: "developing",
        gaps: [
          {
            id: "GAP-005",
            articleId: "art21_2d",
            description: "No formal vendor security assessment program.",
            priority: "critical",
            status: "open",
            remediation: "Implement third-party risk management framework with security questionnaires and periodic audits.",
            dueDate: "2026-04-15",
          },
          {
            id: "GAP-006",
            articleId: "art21_2d",
            description: "Software Bill of Materials (SBOM) not maintained for critical applications.",
            priority: "high",
            status: "open",
            remediation: "Deploy SBOM generation tooling in CI/CD pipeline.",
            dueDate: "2026-05-01",
          },
        ],
      },
      {
        id: "art21_2e",
        name: "Network & Information Systems Security",
        description:
          "Security in network and information systems acquisition, development, and maintenance.",
        score: 71,
        maxScore: 100,
        maturityLevel: "defined",
        gaps: [
          {
            id: "GAP-007",
            articleId: "art21_2e",
            description: "SAST/DAST not integrated into all CI/CD pipelines.",
            priority: "medium",
            status: "in_progress",
            remediation: "Extend security scanning coverage to remaining 3 pipelines.",
            dueDate: "2026-04-30",
          },
        ],
      },
      {
        id: "art21_2f",
        name: "Vulnerability Handling & Disclosure",
        description:
          "Policies and procedures for assessing cybersecurity risk management effectiveness.",
        score: 69,
        maxScore: 100,
        maturityLevel: "defined",
        gaps: [
          {
            id: "GAP-008",
            articleId: "art21_2f",
            description: "Vulnerability disclosure policy not published.",
            priority: "medium",
            status: "open",
            remediation: "Draft and publish a responsible disclosure policy on the corporate website.",
            dueDate: "2026-04-15",
          },
        ],
      },
      {
        id: "art21_2g",
        name: "Cybersecurity Training & Hygiene",
        description:
          "Basic cyber hygiene practices and cybersecurity training.",
        score: 82,
        maxScore: 100,
        maturityLevel: "managed",
        gaps: [
          {
            id: "GAP-009",
            articleId: "art21_2g",
            description: "Phishing simulation completion rate below 90% target.",
            priority: "low",
            status: "in_progress",
            remediation: "Launch additional phishing awareness campaign targeting non-compliant departments.",
            dueDate: "2026-04-01",
          },
        ],
      },
      {
        id: "art21_2h",
        name: "Cryptography & Encryption",
        description:
          "Policies and procedures regarding the use of cryptography and encryption.",
        score: 60,
        maxScore: 100,
        maturityLevel: "developing",
        gaps: [
          {
            id: "GAP-010",
            articleId: "art21_2h",
            description: "Cryptographic key rotation not automated for all services.",
            priority: "high",
            status: "open",
            remediation: "Implement automated key rotation via HashiCorp Vault for all production services.",
            dueDate: "2026-04-30",
          },
        ],
      },
      {
        id: "art21_2i",
        name: "Human Resources Security & Access Control",
        description:
          "Human resources security, access control policies, and asset management.",
        score: 74,
        maxScore: 100,
        maturityLevel: "managed",
        gaps: [
          {
            id: "GAP-011",
            articleId: "art21_2i",
            description: "Orphaned accounts detected in Active Directory.",
            priority: "high",
            status: "in_progress",
            remediation: "Complete access review and deactivate orphaned accounts. Implement automated deprovisioning.",
            dueDate: "2026-03-25",
          },
        ],
      },
      {
        id: "art21_2j",
        name: "Multi-Factor Authentication & Secure Communications",
        description:
          "Use of multi-factor authentication, secured voice/video/text, and secured emergency communications.",
        score: 58,
        maxScore: 100,
        maturityLevel: "developing",
        gaps: [
          {
            id: "GAP-012",
            articleId: "art21_2j",
            description: "MFA not enforced for all privileged accounts.",
            priority: "critical",
            status: "in_progress",
            remediation: "Enforce MFA via conditional access policies for all admin and privileged service accounts.",
            dueDate: "2026-03-25",
          },
          {
            id: "GAP-013",
            articleId: "art21_2j",
            description: "Encrypted emergency communication channel not established.",
            priority: "high",
            status: "open",
            remediation: "Deploy secure out-of-band communication tool for crisis scenarios.",
            dueDate: "2026-04-15",
          },
        ],
      },
    ],
  };
}

export async function fetchAlerts(
  filters?: AlertFilters
): Promise<AlertsResponse> {
  await delay(200);

  const allAlerts: AlertsResponse["alerts"] = [
    {
      id: "ALT-001",
      title: "Brute Force Attack Detected on SSH",
      description:
        "Multiple failed SSH login attempts from IP 192.168.1.105 targeting bastion host.",
      severity: "critical",
      source: "CrowdStrike",
      status: "investigating",
      timestamp: "2026-03-18T09:15:00Z",
      assignee: "analyst-1",
      correlationGroup: "CG-BF-001",
      indicators: ["192.168.1.105", "bastion-prod-01"],
      mitreTactic: "Credential Access",
      mitretechnique: "T1110.001",
    },
    {
      id: "ALT-002",
      title: "Suspicious PowerShell Execution",
      description:
        "Encoded PowerShell command executed on workstation WS-FIN-042.",
      severity: "critical",
      source: "Microsoft Defender",
      status: "new",
      timestamp: "2026-03-18T08:47:00Z",
      correlationGroup: "CG-MAL-003",
      indicators: ["WS-FIN-042", "powershell.exe", "base64"],
      mitreTactic: "Execution",
      mitretechnique: "T1059.001",
    },
    {
      id: "ALT-003",
      title: "Anomalous Data Exfiltration Pattern",
      description:
        "Unusual outbound data transfer volume detected from database server.",
      severity: "high",
      source: "Darktrace",
      status: "investigating",
      timestamp: "2026-03-18T07:32:00Z",
      assignee: "analyst-2",
      correlationGroup: "CG-EX-001",
      indicators: ["db-prod-03", "443", "upload.suspicious-domain.com"],
      mitreTactic: "Exfiltration",
      mitretechnique: "T1041",
    },
    {
      id: "ALT-004",
      title: "Unauthorized AWS API Call",
      description:
        "AssumeRole API call from unrecognized IP to production AWS account.",
      severity: "high",
      source: "AWS CloudTrail",
      status: "new",
      timestamp: "2026-03-18T06:58:00Z",
      indicators: ["arn:aws:iam::123456789012:role/admin", "203.0.113.42"],
      mitreTactic: "Privilege Escalation",
      mitretechnique: "T1078.004",
    },
    {
      id: "ALT-005",
      title: "Malware Signature Detected",
      description:
        "Known malware signature (Emotet variant) detected in email attachment.",
      severity: "high",
      source: "Proofpoint",
      status: "resolved",
      timestamp: "2026-03-18T05:20:00Z",
      assignee: "analyst-1",
      correlationGroup: "CG-MAL-003",
      indicators: ["invoice_march.xlsm", "emotet", "phishing@attacker.com"],
      mitreTactic: "Initial Access",
      mitretechnique: "T1566.001",
    },
    {
      id: "ALT-006",
      title: "Lateral Movement via RDP",
      description:
        "Unusual RDP connections between workstations in different network segments.",
      severity: "high",
      source: "CrowdStrike",
      status: "investigating",
      timestamp: "2026-03-17T23:14:00Z",
      assignee: "analyst-3",
      correlationGroup: "CG-BF-001",
      indicators: ["WS-DEV-018", "WS-FIN-042", "3389"],
      mitreTactic: "Lateral Movement",
      mitretechnique: "T1021.001",
    },
    {
      id: "ALT-007",
      title: "DNS Tunneling Suspected",
      description:
        "High volume of DNS queries with encoded subdomains to a single external domain.",
      severity: "medium",
      source: "Infoblox",
      status: "new",
      timestamp: "2026-03-17T21:45:00Z",
      indicators: ["tunneldns.example.com", "TXT records", "WS-MKT-007"],
      mitreTactic: "Command and Control",
      mitretechnique: "T1071.004",
    },
    {
      id: "ALT-008",
      title: "Certificate Transparency Alert",
      description:
        "New SSL certificate issued for lookalike domain threatc1aw.io.",
      severity: "medium",
      source: "CertStream",
      status: "new",
      timestamp: "2026-03-17T18:30:00Z",
      indicators: ["threatc1aw.io", "Let's Encrypt"],
      mitreTactic: "Resource Development",
      mitretechnique: "T1583.003",
    },
    {
      id: "ALT-009",
      title: "Failed MFA Bypass Attempt",
      description:
        "Multiple attempts to bypass MFA using legacy authentication protocols.",
      severity: "medium",
      source: "Azure AD",
      status: "resolved",
      timestamp: "2026-03-17T15:22:00Z",
      assignee: "analyst-2",
      indicators: ["user@threatclaw.io", "IMAP", "POP3"],
      mitreTactic: "Credential Access",
      mitretechnique: "T1078",
    },
    {
      id: "ALT-010",
      title: "Vulnerability Scanner Detected",
      description:
        "External vulnerability scan detected from known scanner IP range.",
      severity: "low",
      source: "WAF",
      status: "false_positive",
      timestamp: "2026-03-17T12:10:00Z",
      indicators: ["scanner.authorized-vendor.com", "Nessus User-Agent"],
      mitreTactic: "Reconnaissance",
      mitretechnique: "T1595.002",
    },
    {
      id: "ALT-011",
      title: "Unusual Login Location",
      description:
        "VPN login from new geographic location for privileged user.",
      severity: "medium",
      source: "Okta",
      status: "resolved",
      timestamp: "2026-03-17T10:05:00Z",
      assignee: "analyst-1",
      indicators: ["admin@threatclaw.io", "Singapore", "VPN"],
      mitreTactic: "Initial Access",
      mitretechnique: "T1078",
    },
    {
      id: "ALT-012",
      title: "Container Escape Attempt",
      description:
        "Detected attempt to break out of container namespace in production cluster.",
      severity: "critical",
      source: "Falco",
      status: "investigating",
      timestamp: "2026-03-17T04:33:00Z",
      assignee: "analyst-3",
      correlationGroup: "CG-K8S-001",
      indicators: ["pod/api-service-7f8d9", "nsenter", "hostPID"],
      mitreTactic: "Privilege Escalation",
      mitretechnique: "T1611",
    },
  ];

  let filtered = [...allAlerts];

  if (filters?.severity) {
    filtered = filtered.filter((a) => a.severity === filters.severity);
  }
  if (filters?.source) {
    filtered = filtered.filter((a) =>
      a.source.toLowerCase().includes(filters.source!.toLowerCase())
    );
  }
  if (filters?.status) {
    filtered = filtered.filter((a) => a.status === filters.status);
  }

  const page = filters?.page ?? 1;
  const pageSize = filters?.pageSize ?? 10;
  const start = (page - 1) * pageSize;
  const paged = filtered.slice(start, start + pageSize);

  return {
    alerts: paged,
    total: filtered.length,
    page,
    pageSize,
  };
}

export async function fetchCloudPosture(): Promise<CloudPosture> {
  await delay(300);
  return {
    score: 81,
    trend: "up",
    trendValue: 2.5,
    history: [
      { date: "2026-03-12", score: 74, findings: 28, resources: 342 },
      { date: "2026-03-13", score: 75, findings: 26, resources: 345 },
      { date: "2026-03-14", score: 76, findings: 25, resources: 348 },
      { date: "2026-03-15", score: 78, findings: 22, resources: 350 },
      { date: "2026-03-16", score: 79, findings: 20, resources: 352 },
      { date: "2026-03-17", score: 80, findings: 18, resources: 355 },
      { date: "2026-03-18", score: 81, findings: 17, resources: 358 },
    ],
  };
}

export async function fetchReports(): Promise<ReportsResponse> {
  await delay(200);
  return {
    reports: [
      {
        id: "RPT-001",
        title: "Monthly Security Posture Report - March 2026",
        type: "security_posture",
        status: "ready",
        createdAt: "2026-03-15T10:00:00Z",
        format: "pdf",
        size: "2.4 MB",
        downloadUrl: "/api/reports/RPT-001/download",
      },
      {
        id: "RPT-002",
        title: "NIS2 Compliance Assessment Q1 2026",
        type: "nis2_compliance",
        status: "ready",
        createdAt: "2026-03-10T14:30:00Z",
        format: "pdf",
        size: "4.1 MB",
        downloadUrl: "/api/reports/RPT-002/download",
      },
      {
        id: "RPT-003",
        title: "Executive Security Brief - Week 11",
        type: "executive_brief",
        status: "ready",
        createdAt: "2026-03-14T09:00:00Z",
        format: "html",
        size: "856 KB",
        downloadUrl: "/api/reports/RPT-003/download",
      },
      {
        id: "RPT-004",
        title: "Incident Summary Report - Feb 2026",
        type: "incident_summary",
        status: "ready",
        createdAt: "2026-03-01T08:00:00Z",
        format: "pdf",
        size: "1.8 MB",
        downloadUrl: "/api/reports/RPT-004/download",
      },
      {
        id: "RPT-005",
        title: "Monthly Security Posture Report - February 2026",
        type: "security_posture",
        status: "ready",
        createdAt: "2026-02-15T10:00:00Z",
        format: "pdf",
        size: "2.2 MB",
        downloadUrl: "/api/reports/RPT-005/download",
      },
      {
        id: "RPT-006",
        title: "Executive Security Brief - Week 12",
        type: "executive_brief",
        status: "generating",
        createdAt: "2026-03-18T08:00:00Z",
        format: "pdf",
        size: "",
        downloadUrl: "",
      },
    ],
  };
}

export async function generateReport(
  type: Report["type"]
): Promise<{ reportId: string; status: string }> {
  await delay(500);
  return {
    reportId: `RPT-${String(Date.now()).slice(-6)}`,
    status: "generating",
  };
}

type Report = import("./types").Report;
