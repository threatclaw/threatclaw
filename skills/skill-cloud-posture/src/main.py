"""
skill-cloud-posture — Cloud Security Posture Management
Prowler for AWS/Azure/GCP auditing with NIS2/ISO27001 compliance mapping

This module provides the business logic for cloud security posture management.
It is invoked by the ThreatClaw core via the WASM sandbox.
"""

import json
import asyncio
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
from datetime import datetime, timezone


# ── Constants ──────────────────────────────────────────────

PROWLER_TIMEOUT = 600  # 10 minutes max for a full scan
PROWLER_CONTAINER = "prowler"


# ── Data Models ────────────────────────────────────────────

class CloudProvider(Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"

    @classmethod
    def from_string(cls, s: str) -> "CloudProvider":
        mapping = {
            "aws": cls.AWS,
            "azure": cls.AZURE,
            "gcp": cls.GCP,
        }
        normalized = s.strip().lower()
        if normalized not in mapping:
            raise ValueError(
                f"Fournisseur cloud non supporté : '{s}'. "
                f"Valeurs acceptées : aws, azure, gcp"
            )
        return mapping[normalized]


class FindingSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @classmethod
    def from_string(cls, s: str) -> "FindingSeverity":
        mapping = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "low": cls.LOW,
            "informational": cls.INFORMATIONAL,
            "info": cls.INFORMATIONAL,
        }
        return mapping.get(s.strip().lower(), cls.INFORMATIONAL)


class FindingStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"

    @classmethod
    def from_string(cls, s: str) -> "FindingStatus":
        mapping = {
            "pass": cls.PASS,
            "fail": cls.FAIL,
            "warning": cls.WARNING,
            "warn": cls.WARNING,
        }
        return mapping.get(s.strip().lower(), cls.WARNING)


@dataclass
class CloudFinding:
    provider: CloudProvider
    service: str
    check_id: str
    check_title: str
    status: FindingStatus
    severity: FindingSeverity
    region: str
    resource_arn: str
    resource_name: str
    description: str
    remediation: str = ""
    compliance_frameworks: list[str] = field(default_factory=list)
    raw_result: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["provider"] = self.provider.value
        d["status"] = self.status.value
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanResult:
    findings: list[CloudFinding] = field(default_factory=list)
    summary: str = ""
    pass_count: int = 0
    fail_count: int = 0
    total_checks: int = 0
    score: float = 0.0  # 0-100
    provider: str = ""
    scan_duration: float = 0.0
    nis2_mapping: dict = field(default_factory=dict)
    iso27001_mapping: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


@dataclass
class SkillInput:
    provider: str = "aws"
    regions: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    compliance_framework: str = "nis2"  # nis2 | iso27001
    severity_filter: str = ""  # e.g. "critical,high"


@dataclass
class SkillOutput:
    success: bool = False
    result: Optional[ScanResult] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "result": self.result.to_dict() if self.result else None,
            "error": self.error,
        }


# ── NIS2 Art.21 Compliance Mapping ────────────────────────

NIS2_SECTION_MAP: dict[str, dict] = {
    "art21_s1_risk_analysis": {
        "title": "Art.21 §1 — Analyse des risques et sécurité des SI",
        "keywords": [
            "iam", "access_key", "credential", "encrypt", "kms",
            "policy", "password", "rotation", "root",
        ],
        "services": ["iam", "kms", "sts", "organizations"],
    },
    "art21_s2_incident_handling": {
        "title": "Art.21 §2 — Gestion des incidents",
        "keywords": [
            "cloudtrail", "logging", "monitoring", "alarm",
            "cloudwatch", "log_group", "flow_log", "event",
            "detector", "guardduty", "securityhub",
        ],
        "services": [
            "cloudtrail", "cloudwatch", "guardduty", "securityhub",
            "monitor", "logging",
        ],
    },
    "art21_s3_business_continuity": {
        "title": "Art.21 §3 — Continuité des activités et gestion de crise",
        "keywords": [
            "backup", "snapshot", "replication", "recovery",
            "availability", "multi_az", "failover", "dr",
            "versioning", "deletion_protection",
        ],
        "services": ["backup", "rds", "s3", "ec2", "dynamodb", "elasticache"],
    },
    "art21_s4_supply_chain": {
        "title": "Art.21 §4 — Sécurité de la chaîne d'approvisionnement",
        "keywords": [
            "third_party", "marketplace", "trusted", "vendor",
            "ecr", "image", "registry", "dependency",
        ],
        "services": ["ecr", "lambda", "config"],
    },
    "art21_s5_network_security": {
        "title": "Art.21 §5 — Sécurité des réseaux",
        "keywords": [
            "vpc", "security_group", "nacl", "firewall", "waf",
            "subnet", "public", "ingress", "egress", "port",
            "network", "cdn", "ddos", "shield",
        ],
        "services": [
            "vpc", "ec2", "waf", "shield", "networkfirewall",
            "cloudfront", "elb", "elbv2",
        ],
    },
    "art21_s6_vulnerability_mgmt": {
        "title": "Art.21 §6 — Gestion des vulnérabilités",
        "keywords": [
            "patch", "update", "ssm", "inspector", "scan",
            "vulnerability", "ami", "outdated", "eol",
            "version", "runtime",
        ],
        "services": ["ssm", "inspector", "ecr", "lambda", "config"],
    },
    "art21_s7_assessment": {
        "title": "Art.21 §7 — Évaluation de l'efficacité des mesures",
        "keywords": [
            "audit", "trail", "config", "compliance", "rule",
            "conformance", "finding", "assessment",
        ],
        "services": ["cloudtrail", "config", "securityhub", "audit"],
    },
    "art21_s8_cryptography": {
        "title": "Art.21 §8 — Cryptographie et chiffrement",
        "keywords": [
            "encrypt", "kms", "ssl", "tls", "certificate",
            "https", "cmk", "key", "cipher", "crypto",
            "at_rest", "in_transit", "acm",
        ],
        "services": ["kms", "acm", "s3", "rds", "ebs", "cloudfront"],
    },
    "art21_s9_hr_security": {
        "title": "Art.21 §9 — Sécurité des ressources humaines et contrôle d'accès",
        "keywords": [
            "access", "role", "policy", "user", "group",
            "permission", "privilege", "least_privilege",
            "admin", "separation",
        ],
        "services": ["iam", "sso", "organizations"],
    },
    "art21_s10_mfa_auth": {
        "title": "Art.21 §10 — Authentification multi-facteur",
        "keywords": [
            "mfa", "multi_factor", "2fa", "totp", "authenticat",
            "console", "login", "password_policy",
        ],
        "services": ["iam"],
    },
}


# ── ISO 27001 Control Mapping ─────────────────────────────

ISO27001_CONTROL_MAP: dict[str, dict] = {
    "A5_access_control": {
        "title": "A.5 — Contrôle d'accès",
        "keywords": [
            "iam", "access", "role", "policy", "user", "group",
            "permission", "privilege", "mfa", "password",
            "root", "admin", "console",
        ],
        "services": ["iam", "sso", "organizations"],
    },
    "A8_asset_management": {
        "title": "A.8 — Gestion des actifs",
        "keywords": [
            "inventory", "tag", "resource", "config",
            "discovery", "classification",
        ],
        "services": ["config", "resourcegroups", "tag"],
    },
    "A10_cryptography": {
        "title": "A.10 — Cryptographie",
        "keywords": [
            "encrypt", "kms", "ssl", "tls", "certificate",
            "https", "key", "cipher", "cmk", "acm",
            "at_rest", "in_transit",
        ],
        "services": ["kms", "acm", "s3", "rds", "ebs"],
    },
    "A12_operations_security": {
        "title": "A.12 — Sécurité liée à l'exploitation",
        "keywords": [
            "logging", "monitoring", "cloudtrail", "cloudwatch",
            "log_group", "alarm", "patch", "update", "backup",
            "vulnerability", "scan", "inspector",
        ],
        "services": [
            "cloudtrail", "cloudwatch", "ssm", "inspector",
            "backup", "config",
        ],
    },
    "A13_communications_security": {
        "title": "A.13 — Sécurité des communications",
        "keywords": [
            "vpc", "security_group", "nacl", "firewall", "waf",
            "network", "subnet", "ingress", "egress", "port",
            "flow_log", "tls", "ssl",
        ],
        "services": [
            "vpc", "ec2", "waf", "elb", "elbv2", "cloudfront",
            "networkfirewall",
        ],
    },
    "A16_incident_management": {
        "title": "A.16 — Gestion des incidents de sécurité",
        "keywords": [
            "guardduty", "securityhub", "detector", "event",
            "alarm", "notification", "sns", "incident",
        ],
        "services": ["guardduty", "securityhub", "sns", "cloudwatch"],
    },
    "A17_business_continuity": {
        "title": "A.17 — Continuité d'activité",
        "keywords": [
            "backup", "snapshot", "replication", "recovery",
            "multi_az", "failover", "versioning",
            "deletion_protection",
        ],
        "services": ["backup", "rds", "s3", "ec2", "dynamodb"],
    },
    "A18_compliance": {
        "title": "A.18 — Conformité",
        "keywords": [
            "audit", "trail", "config", "compliance", "rule",
            "conformance", "assessment", "finding",
        ],
        "services": ["cloudtrail", "config", "securityhub", "audit"],
    },
}


# ── Prowler Integration ───────────────────────────────────

def _build_prowler_cmd(
    provider: CloudProvider,
    regions: list[str],
    services: list[str],
    compliance: str,
) -> list[str]:
    """Build Prowler command line arguments for Docker exec."""
    cmd = [
        "docker", "exec", PROWLER_CONTAINER,
        "prowler", provider.value,
        "-M", "json",
        "--no-banner",
    ]

    if regions:
        cmd.extend(["-f", ",".join(regions)])

    if services:
        cmd.extend(["--services", ",".join(services)])

    if compliance:
        compliance_lower = compliance.lower()
        if compliance_lower == "nis2":
            cmd.extend(["--compliance", "ens_rd2022_aws"])
        elif compliance_lower == "iso27001":
            cmd.extend(["--compliance", "iso27001_2013_aws"])
        elif compliance_lower == "cis":
            cmd.extend(["--compliance", "cis_1.5_aws"])

    return cmd


def _parse_prowler_finding(data: dict, provider: CloudProvider) -> Optional[CloudFinding]:
    """Parse a single Prowler JSON result into a CloudFinding."""
    try:
        status_str = data.get("StatusExtended", data.get("Status", ""))
        status_raw = data.get("Status", "WARNING")

        severity_str = data.get("Severity", "informational")
        check_id = data.get("CheckID", data.get("check_id", "unknown"))
        check_title = data.get("CheckTitle", data.get("check_title", "Unknown check"))
        service = data.get("ServiceName", data.get("service_name", "unknown"))
        region = data.get("Region", data.get("region", ""))
        resource_arn = data.get("ResourceArn", data.get("resource_arn", ""))
        resource_name = data.get("ResourceName", data.get("resource_name", ""))
        description = data.get("StatusExtended", data.get("Description", ""))

        remediation_data = data.get("Remediation", {})
        if isinstance(remediation_data, dict):
            remediation = remediation_data.get("Recommendation", {}).get("Text", "")
            if not remediation:
                remediation = remediation_data.get("recommendation", "")
        else:
            remediation = str(remediation_data) if remediation_data else ""

        compliance_tags = data.get("Compliance", [])
        if isinstance(compliance_tags, dict):
            compliance_tags = list(compliance_tags.keys())
        elif not isinstance(compliance_tags, list):
            compliance_tags = []

        return CloudFinding(
            provider=provider,
            service=service.lower(),
            check_id=check_id,
            check_title=check_title,
            status=FindingStatus.from_string(status_raw),
            severity=FindingSeverity.from_string(severity_str),
            region=region,
            resource_arn=resource_arn,
            resource_name=resource_name,
            description=description,
            remediation=remediation,
            compliance_frameworks=compliance_tags,
            raw_result=data,
        )
    except Exception:
        return None


def parse_prowler_output(output: str, provider: CloudProvider) -> list[CloudFinding]:
    """Parse Prowler JSON output (JSON lines format) into CloudFindings."""
    findings: list[CloudFinding] = []

    for line in output.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        # Handle JSON array format
        if line.startswith("["):
            try:
                items = json.loads(line)
                for item in items:
                    finding = _parse_prowler_finding(item, provider)
                    if finding:
                        findings.append(finding)
                continue
            except json.JSONDecodeError:
                pass

        # Handle JSON lines format (one object per line)
        try:
            data = json.loads(line)
            if isinstance(data, list):
                for item in data:
                    finding = _parse_prowler_finding(item, provider)
                    if finding:
                        findings.append(finding)
            else:
                finding = _parse_prowler_finding(data, provider)
                if finding:
                    findings.append(finding)
        except json.JSONDecodeError:
            continue

    return findings


async def run_prowler(
    provider: CloudProvider,
    regions: list[str],
    services: list[str],
    compliance: str,
) -> list[CloudFinding]:
    """Run Prowler via Docker exec and return parsed findings."""
    cmd = _build_prowler_cmd(provider, regions, services, compliance)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=PROWLER_TIMEOUT
        )

        output = stdout.decode("utf-8", errors="replace")
        return parse_prowler_output(output, provider)

    except asyncio.TimeoutError:
        return [
            CloudFinding(
                provider=provider,
                service="prowler",
                check_id="SCAN-TIMEOUT",
                check_title=f"Prowler scan timeout ({PROWLER_TIMEOUT}s)",
                status=FindingStatus.WARNING,
                severity=FindingSeverity.HIGH,
                region="global",
                resource_arn="",
                resource_name="prowler-scanner",
                description=f"Le scan Prowler a dépassé le timeout de {PROWLER_TIMEOUT}s",
            )
        ]
    except FileNotFoundError:
        raise RuntimeError(
            "Docker introuvable. Assurez-vous que le conteneur Prowler est en cours d'exécution."
        )


# ── NIS2 Compliance Mapping ───────────────────────────────

def map_finding_to_nis2(finding: CloudFinding) -> list[str]:
    """Map a single cloud finding to NIS2 Art.21 section IDs."""
    matched_sections: list[str] = []
    check_lower = f"{finding.check_id} {finding.check_title} {finding.description}".lower()
    service_lower = finding.service.lower()

    for section_id, section_info in NIS2_SECTION_MAP.items():
        # Check if the finding's service matches
        service_match = any(
            svc in service_lower for svc in section_info["services"]
        )
        # Check if any keyword matches in the finding text
        keyword_match = any(
            kw in check_lower for kw in section_info["keywords"]
        )

        if service_match or keyword_match:
            matched_sections.append(section_id)

    return matched_sections


def build_nis2_mapping(findings: list[CloudFinding]) -> dict:
    """Build a full NIS2 compliance mapping from all findings."""
    mapping: dict[str, dict] = {}

    for section_id, section_info in NIS2_SECTION_MAP.items():
        mapping[section_id] = {
            "title": section_info["title"],
            "pass_count": 0,
            "fail_count": 0,
            "total": 0,
            "score": 100.0,
            "findings": [],
        }

    for finding in findings:
        sections = map_finding_to_nis2(finding)
        for section_id in sections:
            if section_id in mapping:
                mapping[section_id]["total"] += 1
                if finding.status == FindingStatus.PASS:
                    mapping[section_id]["pass_count"] += 1
                else:
                    mapping[section_id]["fail_count"] += 1
                    mapping[section_id]["findings"].append({
                        "check_id": finding.check_id,
                        "check_title": finding.check_title,
                        "severity": finding.severity.value,
                        "resource": finding.resource_arn or finding.resource_name,
                    })

    # Calculate per-section scores
    for section_id, section_data in mapping.items():
        total = section_data["total"]
        if total > 0:
            section_data["score"] = round(
                (section_data["pass_count"] / total) * 100, 1
            )
        else:
            section_data["score"] = 100.0  # no checks = compliant by default

    return mapping


# ── ISO 27001 Compliance Mapping ──────────────────────────

def map_finding_to_iso27001(finding: CloudFinding) -> list[str]:
    """Map a single cloud finding to ISO 27001 control IDs."""
    matched_controls: list[str] = []
    check_lower = f"{finding.check_id} {finding.check_title} {finding.description}".lower()
    service_lower = finding.service.lower()

    for control_id, control_info in ISO27001_CONTROL_MAP.items():
        service_match = any(
            svc in service_lower for svc in control_info["services"]
        )
        keyword_match = any(
            kw in check_lower for kw in control_info["keywords"]
        )

        if service_match or keyword_match:
            matched_controls.append(control_id)

    return matched_controls


def build_iso27001_mapping(findings: list[CloudFinding]) -> dict:
    """Build a full ISO 27001 compliance mapping from all findings."""
    mapping: dict[str, dict] = {}

    for control_id, control_info in ISO27001_CONTROL_MAP.items():
        mapping[control_id] = {
            "title": control_info["title"],
            "pass_count": 0,
            "fail_count": 0,
            "total": 0,
            "score": 100.0,
            "findings": [],
        }

    for finding in findings:
        controls = map_finding_to_iso27001(finding)
        for control_id in controls:
            if control_id in mapping:
                mapping[control_id]["total"] += 1
                if finding.status == FindingStatus.PASS:
                    mapping[control_id]["pass_count"] += 1
                else:
                    mapping[control_id]["fail_count"] += 1
                    mapping[control_id]["findings"].append({
                        "check_id": finding.check_id,
                        "check_title": finding.check_title,
                        "severity": finding.severity.value,
                        "resource": finding.resource_arn or finding.resource_name,
                    })

    for control_id, control_data in mapping.items():
        total = control_data["total"]
        if total > 0:
            control_data["score"] = round(
                (control_data["pass_count"] / total) * 100, 1
            )
        else:
            control_data["score"] = 100.0

    return mapping


# ── Score Calculation ─────────────────────────────────────

SEVERITY_PENALTY: dict[FindingSeverity, float] = {
    FindingSeverity.CRITICAL: 10.0,
    FindingSeverity.HIGH: 5.0,
    FindingSeverity.MEDIUM: 2.0,
    FindingSeverity.LOW: 1.0,
    FindingSeverity.INFORMATIONAL: 0.0,
}


def calculate_score(findings: list[CloudFinding]) -> float:
    """
    Calculate a posture score (0-100).

    Base score = (pass_count / total_checks) * 100
    Then apply severity-weighted penalties for failures:
      - CRITICAL failure: -10 pts
      - HIGH failure: -5 pts
      - MEDIUM failure: -2 pts
      - LOW failure: -1 pt
      - INFORMATIONAL: no penalty

    Minimum score is 0.
    """
    if not findings:
        return 100.0

    total = len(findings)
    pass_count = sum(1 for f in findings if f.status == FindingStatus.PASS)

    if total == 0:
        return 100.0

    base_score = (pass_count / total) * 100

    # Apply severity-weighted penalties for failures
    penalty = 0.0
    for f in findings:
        if f.status != FindingStatus.PASS:
            penalty += SEVERITY_PENALTY.get(f.severity, 0.0)

    final_score = base_score - penalty
    return max(0.0, round(final_score, 1))


# ── Filtering ─────────────────────────────────────────────

def filter_by_severity(
    findings: list[CloudFinding],
    severity_filter: str,
) -> list[CloudFinding]:
    """Filter findings by severity levels (comma-separated string)."""
    if not severity_filter:
        return findings

    allowed = {
        s.strip().lower() for s in severity_filter.split(",") if s.strip()
    }

    if not allowed:
        return findings

    return [f for f in findings if f.severity.value in allowed]


# ── Main Entry Point ───────────────────────────────────────

async def run(input: SkillInput) -> SkillOutput:
    """Main skill entry point — orchestrates cloud posture scan."""
    start_time = datetime.now(timezone.utc)

    try:
        # Validate provider
        provider = CloudProvider.from_string(input.provider)

        # Run Prowler scan
        findings = await run_prowler(
            provider=provider,
            regions=input.regions,
            services=input.services,
            compliance=input.compliance_framework,
        )

        # Apply severity filter if specified
        if input.severity_filter:
            findings = filter_by_severity(findings, input.severity_filter)

        # Calculate counts
        pass_count = sum(1 for f in findings if f.status == FindingStatus.PASS)
        fail_count = sum(1 for f in findings if f.status == FindingStatus.FAIL)
        total_checks = len(findings)

        # Calculate posture score
        score = calculate_score(findings)

        # Build compliance mappings
        nis2_mapping = build_nis2_mapping(findings)
        iso27001_mapping = build_iso27001_mapping(findings)

        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        # Build summary
        severity_counts: dict[str, int] = {}
        for f in findings:
            if f.status != FindingStatus.PASS:
                sev = f.severity.value
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        summary = (
            f"Scan {provider.value.upper()} terminé en {duration:.0f}s — "
            f"Score: {score:.0f}/100 — "
            f"{total_checks} checks ({pass_count} passés, {fail_count} échoués)"
        )
        if severity_counts:
            parts = [f"{v} {k}" for k, v in severity_counts.items()]
            summary += f" — Échecs par sévérité : {', '.join(parts)}"

        result = ScanResult(
            findings=findings,
            summary=summary,
            pass_count=pass_count,
            fail_count=fail_count,
            total_checks=total_checks,
            score=score,
            provider=provider.value,
            scan_duration=round(duration, 2),
            nis2_mapping=nis2_mapping,
            iso27001_mapping=iso27001_mapping,
        )

        return SkillOutput(success=True, result=result)

    except ValueError as e:
        return SkillOutput(success=False, error=str(e))
    except RuntimeError as e:
        return SkillOutput(success=False, error=str(e))
    except Exception as e:
        return SkillOutput(success=False, error=f"Erreur inattendue : {e}")
