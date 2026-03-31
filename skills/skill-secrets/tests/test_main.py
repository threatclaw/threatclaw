"""Tests for skill-secrets."""

import json
import pytest
from datetime import datetime, timezone, timedelta
from src.main import (
    SecretType,
    Criticality,
    SecretFinding,
    SkillInput,
    redact_secret,
    assess_criticality,
    _parse_gitleaks_output,
    run,
)


# ── Redaction Tests ────────────────────────────────────

class TestRedact:
    def test_redact_long_secret(self):
        result = redact_secret("AKIAIOSFODNN7EXAMPLE")
        assert result.startswith("AKIAIOSF")
        assert "EXAMPLE" not in result
        assert len(result) == 20

    def test_redact_short_secret(self):
        result = redact_secret("short")
        assert result == "*****"

    def test_redact_empty(self):
        assert redact_secret("") == ""


# ── SecretType Tests ───────────────────────────────────

class TestSecretType:
    def test_aws_mapping(self):
        assert SecretType.from_rule_id("aws-access-key-id") == SecretType.AWS_KEY

    def test_github_mapping(self):
        assert SecretType.from_rule_id("github-pat") == SecretType.GITHUB_TOKEN

    def test_password_mapping(self):
        assert SecretType.from_rule_id("generic-password") == SecretType.PASSWORD

    def test_private_key(self):
        assert SecretType.from_rule_id("private-key") == SecretType.PRIVATE_KEY

    def test_api_key(self):
        assert SecretType.from_rule_id("generic-api-key") == SecretType.API_KEY

    def test_unknown(self):
        assert SecretType.from_rule_id("completely-unknown-rule") == SecretType.OTHER


# ── Criticality Tests ──────────────────────────────────

class TestCriticality:
    def test_test_file_is_low(self):
        assert assess_criticality("tests/config.py", "", "") == Criticality.LOW
        assert assess_criticality("spec/test_auth.rb", "", "") == Criticality.LOW
        assert assess_criticality(".env.example", "", "") == Criticality.LOW
        assert assess_criticality("examples/demo.py", "", "") == Criticality.LOW

    def test_recent_commit_is_critical(self):
        recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        assert assess_criticality("src/main.py", recent, "") == Criticality.CRITICAL

    def test_90day_commit_is_high(self):
        age = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
        assert assess_criticality("src/main.py", age, "") == Criticality.HIGH

    def test_old_commit_is_medium(self):
        old = (datetime.now(timezone.utc) - timedelta(days=180)).isoformat()
        assert assess_criticality("src/main.py", old, "") == Criticality.MEDIUM

    def test_aws_key_always_high(self):
        old = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
        result = assess_criticality("config.py", old, "aws-access-key")
        assert result == Criticality.HIGH

    def test_private_key_always_high(self):
        assert assess_criticality("certs/key.pem", "", "private-key") == Criticality.HIGH


# ── Gitleaks Parser Tests ──────────────────────────────

class TestGitleaksParser:
    def test_parse_valid_output(self):
        gitleaks_json = json.dumps([
            {
                "RuleID": "aws-access-key-id",
                "Secret": "AKIAIOSFODNN7EXAMPLE",
                "File": "config/aws.py",
                "Commit": "abc1234567890",
                "Author": "dev@company.com",
                "Date": "2024-06-15T10:00:00Z",
                "StartLine": 42,
                "Description": "AWS Access Key ID",
                "Tags": ["aws", "key"],
            },
            {
                "RuleID": "generic-password",
                "Secret": "SuperSecretP@ss123",
                "File": "docker-compose.yml",
                "Commit": "def5678901234",
                "Author": "admin@company.com",
                "Date": "2024-01-01T00:00:00Z",
                "StartLine": 15,
                "Description": "Generic password",
                "Tags": [],
            },
        ])

        findings = _parse_gitleaks_output(gitleaks_json, "myrepo")
        assert len(findings) == 2

        f1 = findings[0]
        assert f1.rule_id == "aws-access-key-id"
        assert f1.secret_type == SecretType.AWS_KEY
        assert f1.file_path == "config/aws.py"
        assert f1.commit == "abc123456789"  # truncated to 12
        assert f1.match_redacted.startswith("AKIAIOSF")
        assert "EXAMPLE" not in f1.match_redacted
        assert f1.repository == "myrepo"

        f2 = findings[1]
        assert f2.secret_type == SecretType.PASSWORD
        assert "SuperSec" not in f2.match_redacted or f2.match_redacted.count("*") > 0

    def test_parse_empty_array(self):
        assert _parse_gitleaks_output("[]", "repo") == []

    def test_parse_invalid_json(self):
        assert _parse_gitleaks_output("not json", "repo") == []

    def test_parse_non_array(self):
        assert _parse_gitleaks_output('{"error": "oops"}', "repo") == []


# ── Main Run Tests ─────────────────────────────────────

class TestRun:
    @pytest.mark.asyncio
    async def test_run_no_repos(self):
        output = await run(SkillInput())
        assert output.success is False
        assert "dépôt" in output.error.lower()

    def test_finding_to_dict(self):
        f = SecretFinding(
            rule_id="test",
            secret_type=SecretType.AWS_KEY,
            file_path="f.py",
            commit="abc",
            author="dev",
            date="2024-01-01",
            line=1,
            match_redacted="AKIA****",
            repository="repo",
            criticality=Criticality.CRITICAL,
        )
        d = f.to_dict()
        assert d["secret_type"] == "aws_key"
        assert d["criticality"] == "critical"
