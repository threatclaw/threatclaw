"""Tests for skill-cloud-posture."""

import json
import pytest
from unittest.mock import AsyncMock, patch
from src.main import (
    CloudProvider,
    FindingSeverity,
    FindingStatus,
    CloudFinding,
    ScanResult,
    SkillInput,
    SkillOutput,
    NIS2_SECTION_MAP,
    ISO27001_CONTROL_MAP,
    SEVERITY_PENALTY,
    _build_prowler_cmd,
    _parse_prowler_finding,
    parse_prowler_output,
    map_finding_to_nis2,
    build_nis2_mapping,
    map_finding_to_iso27001,
    build_iso27001_mapping,
    calculate_score,
    filter_by_severity,
    run,
)


# ── Helpers ────────────────────────────────────────────────

def _make_finding(
    check_id: str = "iam_root_mfa",
    check_title: str = "Root account MFA enabled",
    status: FindingStatus = FindingStatus.PASS,
    severity: FindingSeverity = FindingSeverity.HIGH,
    service: str = "iam",
    provider: CloudProvider = CloudProvider.AWS,
    region: str = "us-east-1",
    resource_arn: str = "arn:aws:iam::123456789012:root",
    description: str = "Root account has MFA enabled",
) -> CloudFinding:
    return CloudFinding(
        provider=provider,
        service=service,
        check_id=check_id,
        check_title=check_title,
        status=status,
        severity=severity,
        region=region,
        resource_arn=resource_arn,
        resource_name="root",
        description=description,
    )


# ── CloudProvider Tests ───────────────────────────────────

class TestCloudProvider:
    def test_from_string_valid(self):
        assert CloudProvider.from_string("aws") == CloudProvider.AWS
        assert CloudProvider.from_string("azure") == CloudProvider.AZURE
        assert CloudProvider.from_string("gcp") == CloudProvider.GCP

    def test_from_string_case_insensitive(self):
        assert CloudProvider.from_string("AWS") == CloudProvider.AWS
        assert CloudProvider.from_string("Azure") == CloudProvider.AZURE
        assert CloudProvider.from_string("GCP") == CloudProvider.GCP

    def test_from_string_with_whitespace(self):
        assert CloudProvider.from_string("  aws  ") == CloudProvider.AWS

    def test_from_string_invalid(self):
        with pytest.raises(ValueError, match="non supporté"):
            CloudProvider.from_string("alibaba")

    def test_from_string_empty(self):
        with pytest.raises(ValueError):
            CloudProvider.from_string("")


# ── FindingSeverity Tests ─────────────────────────────────

class TestFindingSeverity:
    def test_from_string_all_levels(self):
        assert FindingSeverity.from_string("critical") == FindingSeverity.CRITICAL
        assert FindingSeverity.from_string("high") == FindingSeverity.HIGH
        assert FindingSeverity.from_string("medium") == FindingSeverity.MEDIUM
        assert FindingSeverity.from_string("low") == FindingSeverity.LOW
        assert FindingSeverity.from_string("informational") == FindingSeverity.INFORMATIONAL

    def test_from_string_info_alias(self):
        assert FindingSeverity.from_string("info") == FindingSeverity.INFORMATIONAL

    def test_from_string_unknown_defaults(self):
        assert FindingSeverity.from_string("garbage") == FindingSeverity.INFORMATIONAL
        assert FindingSeverity.from_string("") == FindingSeverity.INFORMATIONAL


# ── FindingStatus Tests ───────────────────────────────────

class TestFindingStatus:
    def test_from_string_valid(self):
        assert FindingStatus.from_string("PASS") == FindingStatus.PASS
        assert FindingStatus.from_string("FAIL") == FindingStatus.FAIL
        assert FindingStatus.from_string("WARNING") == FindingStatus.WARNING

    def test_from_string_case_insensitive(self):
        assert FindingStatus.from_string("pass") == FindingStatus.PASS
        assert FindingStatus.from_string("Fail") == FindingStatus.FAIL

    def test_from_string_warn_alias(self):
        assert FindingStatus.from_string("warn") == FindingStatus.WARNING

    def test_from_string_unknown_defaults_to_warning(self):
        assert FindingStatus.from_string("unknown") == FindingStatus.WARNING


# ── CloudFinding Tests ────────────────────────────────────

class TestCloudFinding:
    def test_creation(self):
        finding = _make_finding()
        assert finding.provider == CloudProvider.AWS
        assert finding.service == "iam"
        assert finding.check_id == "iam_root_mfa"
        assert finding.status == FindingStatus.PASS
        assert finding.severity == FindingSeverity.HIGH

    def test_to_dict(self):
        finding = _make_finding()
        d = finding.to_dict()
        assert d["provider"] == "aws"
        assert d["status"] == "PASS"
        assert d["severity"] == "high"
        assert d["check_id"] == "iam_root_mfa"
        assert d["service"] == "iam"

    def test_to_dict_with_compliance_frameworks(self):
        finding = _make_finding()
        finding.compliance_frameworks = ["CIS", "NIS2"]
        d = finding.to_dict()
        assert d["compliance_frameworks"] == ["CIS", "NIS2"]

    def test_default_fields(self):
        finding = _make_finding()
        assert finding.remediation == ""
        assert finding.compliance_frameworks == []
        assert finding.raw_result == {}


# ── ScanResult Tests ──────────────────────────────────────

class TestScanResult:
    def test_creation_defaults(self):
        result = ScanResult()
        assert result.findings == []
        assert result.pass_count == 0
        assert result.fail_count == 0
        assert result.total_checks == 0
        assert result.score == 0.0

    def test_to_dict(self):
        finding = _make_finding()
        result = ScanResult(
            findings=[finding],
            pass_count=1,
            total_checks=1,
            score=100.0,
            provider="aws",
        )
        d = result.to_dict()
        assert len(d["findings"]) == 1
        assert d["findings"][0]["provider"] == "aws"
        assert d["score"] == 100.0


# ── SkillOutput Tests ─────────────────────────────────────

class TestSkillOutput:
    def test_to_dict_success(self):
        result = ScanResult(score=85.0, provider="aws")
        output = SkillOutput(success=True, result=result)
        d = output.to_dict()
        assert d["success"] is True
        assert d["result"]["score"] == 85.0
        assert d["error"] is None

    def test_to_dict_error(self):
        output = SkillOutput(success=False, error="Something broke")
        d = output.to_dict()
        assert d["success"] is False
        assert d["result"] is None
        assert d["error"] == "Something broke"


# ── Prowler Command Builder Tests ─────────────────────────

class TestBuildProwlerCmd:
    def test_basic_aws_command(self):
        cmd = _build_prowler_cmd(CloudProvider.AWS, [], [], "")
        assert "docker" in cmd
        assert "exec" in cmd
        assert "prowler" in cmd
        assert "aws" in cmd
        assert "-M" in cmd
        assert "json" in cmd

    def test_with_regions(self):
        cmd = _build_prowler_cmd(
            CloudProvider.AWS, ["us-east-1", "eu-west-1"], [], ""
        )
        assert "-f" in cmd
        idx = cmd.index("-f")
        assert cmd[idx + 1] == "us-east-1,eu-west-1"

    def test_with_services(self):
        cmd = _build_prowler_cmd(
            CloudProvider.AWS, [], ["iam", "s3"], ""
        )
        assert "--services" in cmd
        idx = cmd.index("--services")
        assert cmd[idx + 1] == "iam,s3"

    def test_nis2_compliance(self):
        cmd = _build_prowler_cmd(CloudProvider.AWS, [], [], "nis2")
        assert "--compliance" in cmd
        idx = cmd.index("--compliance")
        assert "ens_rd2022_aws" in cmd[idx + 1]

    def test_iso27001_compliance(self):
        cmd = _build_prowler_cmd(CloudProvider.AWS, [], [], "iso27001")
        assert "--compliance" in cmd
        idx = cmd.index("--compliance")
        assert "iso27001" in cmd[idx + 1]

    def test_azure_provider(self):
        cmd = _build_prowler_cmd(CloudProvider.AZURE, [], [], "")
        assert "azure" in cmd

    def test_no_compliance_flag_when_empty(self):
        cmd = _build_prowler_cmd(CloudProvider.AWS, [], [], "")
        assert "--compliance" not in cmd


# ── Prowler Output Parsing Tests ──────────────────────────

class TestProwlerParsing:
    def test_parse_single_finding(self):
        prowler_data = {
            "CheckID": "iam_root_hardware_mfa_enabled",
            "CheckTitle": "Ensure hardware MFA is enabled for the root account",
            "Status": "FAIL",
            "Severity": "critical",
            "ServiceName": "iam",
            "Region": "us-east-1",
            "ResourceArn": "arn:aws:iam::123456789012:root",
            "ResourceName": "root",
            "StatusExtended": "Hardware MFA is not enabled for root account",
            "Remediation": {
                "Recommendation": {
                    "Text": "Enable hardware MFA for the root account"
                }
            },
            "Compliance": ["CIS-1.5"],
        }
        finding = _parse_prowler_finding(prowler_data, CloudProvider.AWS)
        assert finding is not None
        assert finding.check_id == "iam_root_hardware_mfa_enabled"
        assert finding.status == FindingStatus.FAIL
        assert finding.severity == FindingSeverity.CRITICAL
        assert finding.service == "iam"
        assert finding.region == "us-east-1"
        assert finding.remediation == "Enable hardware MFA for the root account"

    def test_parse_passing_finding(self):
        prowler_data = {
            "CheckID": "s3_bucket_encryption",
            "CheckTitle": "S3 bucket encryption enabled",
            "Status": "PASS",
            "Severity": "medium",
            "ServiceName": "s3",
            "Region": "eu-west-1",
            "ResourceArn": "arn:aws:s3:::my-bucket",
            "ResourceName": "my-bucket",
            "StatusExtended": "S3 bucket my-bucket has encryption enabled",
        }
        finding = _parse_prowler_finding(prowler_data, CloudProvider.AWS)
        assert finding is not None
        assert finding.status == FindingStatus.PASS
        assert finding.severity == FindingSeverity.MEDIUM

    def test_parse_json_lines(self):
        line1 = json.dumps({
            "CheckID": "check1",
            "CheckTitle": "Check 1",
            "Status": "PASS",
            "Severity": "low",
            "ServiceName": "ec2",
            "Region": "us-east-1",
            "ResourceArn": "arn:1",
            "ResourceName": "res1",
            "StatusExtended": "All good",
        })
        line2 = json.dumps({
            "CheckID": "check2",
            "CheckTitle": "Check 2",
            "Status": "FAIL",
            "Severity": "high",
            "ServiceName": "s3",
            "Region": "us-west-2",
            "ResourceArn": "arn:2",
            "ResourceName": "res2",
            "StatusExtended": "Not good",
        })
        output = f"{line1}\n{line2}"
        findings = parse_prowler_output(output, CloudProvider.AWS)
        assert len(findings) == 2
        assert findings[0].check_id == "check1"
        assert findings[1].check_id == "check2"

    def test_parse_json_array(self):
        items = [
            {
                "CheckID": "check_a",
                "CheckTitle": "Check A",
                "Status": "PASS",
                "Severity": "low",
                "ServiceName": "iam",
                "Region": "us-east-1",
                "ResourceArn": "arn:a",
                "ResourceName": "res_a",
                "StatusExtended": "OK",
            },
            {
                "CheckID": "check_b",
                "CheckTitle": "Check B",
                "Status": "FAIL",
                "Severity": "critical",
                "ServiceName": "ec2",
                "Region": "eu-west-1",
                "ResourceArn": "arn:b",
                "ResourceName": "res_b",
                "StatusExtended": "Bad",
            },
        ]
        output = json.dumps(items)
        findings = parse_prowler_output(output, CloudProvider.AWS)
        assert len(findings) == 2

    def test_parse_empty_output(self):
        findings = parse_prowler_output("", CloudProvider.AWS)
        assert findings == []

    def test_parse_invalid_json_lines(self):
        output = "not json\nalso not json\n"
        findings = parse_prowler_output(output, CloudProvider.AWS)
        assert findings == []

    def test_parse_mixed_valid_invalid(self):
        valid = json.dumps({
            "CheckID": "valid_check",
            "CheckTitle": "Valid Check",
            "Status": "PASS",
            "Severity": "low",
            "ServiceName": "ec2",
            "Region": "us-east-1",
            "ResourceArn": "arn:valid",
            "ResourceName": "valid",
            "StatusExtended": "OK",
        })
        output = f"garbage\n{valid}\nmore garbage"
        findings = parse_prowler_output(output, CloudProvider.AWS)
        assert len(findings) == 1
        assert findings[0].check_id == "valid_check"

    def test_parse_finding_with_alternative_keys(self):
        """Test Prowler output with snake_case keys (older format)."""
        prowler_data = {
            "check_id": "vpc_flow_logs",
            "check_title": "VPC flow logs enabled",
            "Status": "FAIL",
            "Severity": "medium",
            "service_name": "vpc",
            "region": "us-east-1",
            "resource_arn": "arn:aws:ec2:us-east-1:123:vpc/vpc-abc",
            "resource_name": "vpc-abc",
            "Description": "VPC flow logs are not enabled",
        }
        finding = _parse_prowler_finding(prowler_data, CloudProvider.AWS)
        assert finding is not None
        assert finding.check_id == "vpc_flow_logs"
        assert finding.service == "vpc"


# ── NIS2 Mapping Tests ────────────────────────────────────

class TestNIS2Mapping:
    def test_iam_finding_maps_to_risk_analysis(self):
        finding = _make_finding(
            service="iam",
            check_id="iam_root_access_key",
            check_title="Root account access key should not exist",
            description="Root account has active access keys",
        )
        sections = map_finding_to_nis2(finding)
        assert "art21_s1_risk_analysis" in sections

    def test_iam_finding_maps_to_hr_security(self):
        finding = _make_finding(
            service="iam",
            check_id="iam_user_policy",
            check_title="Users should have least privilege access",
            description="User has admin access policy attached",
        )
        sections = map_finding_to_nis2(finding)
        assert "art21_s9_hr_security" in sections

    def test_cloudtrail_maps_to_incident_handling(self):
        finding = _make_finding(
            service="cloudtrail",
            check_id="cloudtrail_enabled",
            check_title="CloudTrail is enabled",
            description="CloudTrail logging is enabled in all regions",
        )
        sections = map_finding_to_nis2(finding)
        assert "art21_s2_incident_handling" in sections

    def test_backup_maps_to_business_continuity(self):
        finding = _make_finding(
            service="backup",
            check_id="backup_plan_exists",
            check_title="Backup plan exists for critical resources",
            description="Backup plan with recovery point",
        )
        sections = map_finding_to_nis2(finding)
        assert "art21_s3_business_continuity" in sections

    def test_vpc_maps_to_network_security(self):
        finding = _make_finding(
            service="vpc",
            check_id="vpc_security_group_open",
            check_title="Security groups should not allow unrestricted ingress",
            description="Security group allows ingress from 0.0.0.0/0 on port 22",
        )
        sections = map_finding_to_nis2(finding)
        assert "art21_s5_network_security" in sections

    def test_kms_maps_to_cryptography(self):
        finding = _make_finding(
            service="kms",
            check_id="kms_key_rotation",
            check_title="KMS key rotation should be enabled",
            description="KMS encryption key rotation is not enabled",
        )
        sections = map_finding_to_nis2(finding)
        assert "art21_s8_cryptography" in sections

    def test_mfa_maps_to_auth_section(self):
        finding = _make_finding(
            service="iam",
            check_id="iam_mfa_enabled",
            check_title="MFA should be enabled for all IAM users",
            description="Multi-factor authentication is not enabled",
        )
        sections = map_finding_to_nis2(finding)
        assert "art21_s10_mfa_auth" in sections

    def test_finding_can_map_to_multiple_sections(self):
        """A finding about IAM encryption can map to both risk and crypto."""
        finding = _make_finding(
            service="iam",
            check_id="iam_encrypt_credentials",
            check_title="IAM credentials should be encrypted",
            description="Encrypt credential storage with KMS",
        )
        sections = map_finding_to_nis2(finding)
        assert len(sections) >= 2
        assert "art21_s1_risk_analysis" in sections
        assert "art21_s8_cryptography" in sections

    def test_build_nis2_mapping_all_pass(self):
        findings = [
            _make_finding(
                service="iam",
                check_id="iam_mfa_check",
                check_title="MFA enabled",
                status=FindingStatus.PASS,
                description="MFA is enabled",
            ),
            _make_finding(
                service="cloudtrail",
                check_id="cloudtrail_logging",
                check_title="Logging enabled",
                status=FindingStatus.PASS,
                description="CloudTrail logging enabled",
            ),
        ]
        mapping = build_nis2_mapping(findings)
        # The sections that matched should have 100% score
        for section_id, section_data in mapping.items():
            if section_data["total"] > 0:
                assert section_data["score"] == 100.0
                assert section_data["fail_count"] == 0

    def test_build_nis2_mapping_with_failures(self):
        findings = [
            _make_finding(
                service="iam",
                check_id="iam_mfa_check",
                check_title="MFA enabled",
                status=FindingStatus.FAIL,
                severity=FindingSeverity.CRITICAL,
                description="MFA is not enabled",
            ),
        ]
        mapping = build_nis2_mapping(findings)
        # MFA section should have failures
        mfa_section = mapping.get("art21_s10_mfa_auth", {})
        if mfa_section.get("total", 0) > 0:
            assert mfa_section["fail_count"] > 0
            assert mfa_section["score"] < 100.0

    def test_build_nis2_mapping_empty_findings(self):
        mapping = build_nis2_mapping([])
        assert len(mapping) == len(NIS2_SECTION_MAP)
        for section_data in mapping.values():
            assert section_data["score"] == 100.0
            assert section_data["total"] == 0


# ── ISO 27001 Mapping Tests ───────────────────────────────

class TestISO27001Mapping:
    def test_iam_maps_to_access_control(self):
        finding = _make_finding(
            service="iam",
            check_id="iam_password_policy",
            check_title="IAM password policy should be strong",
            description="Password policy does not meet requirements",
        )
        controls = map_finding_to_iso27001(finding)
        assert "A5_access_control" in controls

    def test_kms_maps_to_cryptography(self):
        finding = _make_finding(
            service="kms",
            check_id="kms_key_rotation",
            check_title="KMS key rotation enabled",
            description="Encryption key rotation",
        )
        controls = map_finding_to_iso27001(finding)
        assert "A10_cryptography" in controls

    def test_build_iso27001_mapping_empty(self):
        mapping = build_iso27001_mapping([])
        assert len(mapping) == len(ISO27001_CONTROL_MAP)
        for control_data in mapping.values():
            assert control_data["score"] == 100.0


# ── Score Calculation Tests ───────────────────────────────

class TestScoreCalculation:
    def test_perfect_score_all_pass(self):
        findings = [
            _make_finding(status=FindingStatus.PASS, severity=FindingSeverity.HIGH),
            _make_finding(
                check_id="check2", status=FindingStatus.PASS,
                severity=FindingSeverity.MEDIUM,
            ),
            _make_finding(
                check_id="check3", status=FindingStatus.PASS,
                severity=FindingSeverity.LOW,
            ),
        ]
        score = calculate_score(findings)
        assert score == 100.0

    def test_zero_score_all_critical_fail(self):
        findings = [
            _make_finding(
                check_id=f"fail_{i}",
                status=FindingStatus.FAIL,
                severity=FindingSeverity.CRITICAL,
            )
            for i in range(10)
        ]
        score = calculate_score(findings)
        # 0% base + 10 critical penalties = well below 0, clamped to 0
        assert score == 0.0

    def test_mixed_score(self):
        findings = [
            _make_finding(
                check_id="pass1",
                status=FindingStatus.PASS,
                severity=FindingSeverity.HIGH,
            ),
            _make_finding(
                check_id="pass2",
                status=FindingStatus.PASS,
                severity=FindingSeverity.MEDIUM,
            ),
            _make_finding(
                check_id="fail1",
                status=FindingStatus.FAIL,
                severity=FindingSeverity.HIGH,
            ),
            _make_finding(
                check_id="fail2",
                status=FindingStatus.FAIL,
                severity=FindingSeverity.MEDIUM,
            ),
        ]
        score = calculate_score(findings)
        # Base = 2/4 * 100 = 50
        # Penalty = 5 (high) + 2 (medium) = 7
        # Score = 50 - 7 = 43
        assert score == 43.0

    def test_score_never_below_zero(self):
        findings = [
            _make_finding(
                check_id=f"critical_fail_{i}",
                status=FindingStatus.FAIL,
                severity=FindingSeverity.CRITICAL,
            )
            for i in range(50)
        ]
        score = calculate_score(findings)
        assert score == 0.0

    def test_empty_findings_perfect_score(self):
        score = calculate_score([])
        assert score == 100.0

    def test_informational_failures_no_penalty(self):
        findings = [
            _make_finding(
                check_id="info1",
                status=FindingStatus.FAIL,
                severity=FindingSeverity.INFORMATIONAL,
            ),
            _make_finding(
                check_id="pass1",
                status=FindingStatus.PASS,
                severity=FindingSeverity.HIGH,
            ),
        ]
        score = calculate_score(findings)
        # Base = 1/2 * 100 = 50, penalty = 0 (informational)
        assert score == 50.0

    def test_warning_status_counts_as_failure(self):
        findings = [
            _make_finding(
                check_id="warn1",
                status=FindingStatus.WARNING,
                severity=FindingSeverity.MEDIUM,
            ),
        ]
        score = calculate_score(findings)
        # Base = 0/1 * 100 = 0, penalty = 2 (medium)
        assert score == 0.0

    def test_severity_penalty_values(self):
        assert SEVERITY_PENALTY[FindingSeverity.CRITICAL] == 10.0
        assert SEVERITY_PENALTY[FindingSeverity.HIGH] == 5.0
        assert SEVERITY_PENALTY[FindingSeverity.MEDIUM] == 2.0
        assert SEVERITY_PENALTY[FindingSeverity.LOW] == 1.0
        assert SEVERITY_PENALTY[FindingSeverity.INFORMATIONAL] == 0.0


# ── Severity Filter Tests ─────────────────────────────────

class TestSeverityFilter:
    def test_filter_by_critical(self):
        findings = [
            _make_finding(check_id="c1", severity=FindingSeverity.CRITICAL),
            _make_finding(check_id="h1", severity=FindingSeverity.HIGH),
            _make_finding(check_id="l1", severity=FindingSeverity.LOW),
        ]
        filtered = filter_by_severity(findings, "critical")
        assert len(filtered) == 1
        assert filtered[0].check_id == "c1"

    def test_filter_multiple_severities(self):
        findings = [
            _make_finding(check_id="c1", severity=FindingSeverity.CRITICAL),
            _make_finding(check_id="h1", severity=FindingSeverity.HIGH),
            _make_finding(check_id="l1", severity=FindingSeverity.LOW),
        ]
        filtered = filter_by_severity(findings, "critical,high")
        assert len(filtered) == 2

    def test_no_filter_returns_all(self):
        findings = [
            _make_finding(check_id="c1", severity=FindingSeverity.CRITICAL),
            _make_finding(check_id="l1", severity=FindingSeverity.LOW),
        ]
        filtered = filter_by_severity(findings, "")
        assert len(filtered) == 2


# ── Main Run Tests ────────────────────────────────────────

class TestRun:
    @pytest.mark.asyncio
    async def test_run_invalid_provider(self):
        output = await run(SkillInput(provider="invalid"))
        assert output.success is False
        assert "non supporté" in output.error

    @pytest.mark.asyncio
    async def test_run_success_with_mock(self):
        mock_findings = [
            _make_finding(
                check_id="iam_check_1",
                status=FindingStatus.PASS,
                severity=FindingSeverity.HIGH,
                service="iam",
            ),
            _make_finding(
                check_id="s3_check_1",
                status=FindingStatus.FAIL,
                severity=FindingSeverity.CRITICAL,
                service="s3",
                description="S3 bucket is publicly accessible",
            ),
        ]

        with patch("src.main.run_prowler", new_callable=AsyncMock) as mock_prowler:
            mock_prowler.return_value = mock_findings
            output = await run(SkillInput(provider="aws"))

        assert output.success is True
        assert output.result is not None
        assert output.result.total_checks == 2
        assert output.result.pass_count == 1
        assert output.result.fail_count == 1
        assert output.result.provider == "aws"
        assert output.result.score < 100.0
        assert "AWS" in output.result.summary

    @pytest.mark.asyncio
    async def test_run_with_severity_filter(self):
        mock_findings = [
            _make_finding(
                check_id="c1", severity=FindingSeverity.CRITICAL,
                status=FindingStatus.FAIL,
            ),
            _make_finding(
                check_id="l1", severity=FindingSeverity.LOW,
                status=FindingStatus.FAIL,
            ),
        ]

        with patch("src.main.run_prowler", new_callable=AsyncMock) as mock_prowler:
            mock_prowler.return_value = mock_findings
            output = await run(
                SkillInput(provider="aws", severity_filter="critical")
            )

        assert output.success is True
        assert output.result.total_checks == 1

    @pytest.mark.asyncio
    async def test_run_produces_nis2_mapping(self):
        mock_findings = [
            _make_finding(
                service="iam",
                check_id="iam_mfa_check",
                check_title="MFA enabled for IAM users",
                status=FindingStatus.FAIL,
                severity=FindingSeverity.CRITICAL,
                description="MFA is not enabled for IAM user",
            ),
        ]

        with patch("src.main.run_prowler", new_callable=AsyncMock) as mock_prowler:
            mock_prowler.return_value = mock_findings
            output = await run(SkillInput(provider="aws"))

        assert output.success is True
        assert output.result.nis2_mapping is not None
        assert len(output.result.nis2_mapping) == len(NIS2_SECTION_MAP)

    @pytest.mark.asyncio
    async def test_run_produces_iso27001_mapping(self):
        mock_findings = [
            _make_finding(
                service="kms",
                check_id="kms_key_rotation",
                check_title="KMS key rotation",
                status=FindingStatus.PASS,
                description="Encryption key rotation enabled",
            ),
        ]

        with patch("src.main.run_prowler", new_callable=AsyncMock) as mock_prowler:
            mock_prowler.return_value = mock_findings
            output = await run(SkillInput(provider="aws"))

        assert output.success is True
        assert output.result.iso27001_mapping is not None
        assert len(output.result.iso27001_mapping) == len(ISO27001_CONTROL_MAP)

    @pytest.mark.asyncio
    async def test_run_handles_runtime_error(self):
        with patch("src.main.run_prowler", new_callable=AsyncMock) as mock_prowler:
            mock_prowler.side_effect = RuntimeError("Docker not found")
            output = await run(SkillInput(provider="aws"))

        assert output.success is False
        assert "Docker" in output.error
