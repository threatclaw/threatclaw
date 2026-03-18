"""Tests for skill-darkweb."""

import pytest
from src.main import (
    Breach,
    BreachCriticality,
    SkillInput,
    anonymize_email,
    assess_breach_criticality,
    generate_recommendations,
    check_email_breaches,
    run,
)


# ── Anonymization Tests ───────────────────────────────

class TestAnonymizeEmail:
    def test_normal_email(self):
        result = anonymize_email("john.doe@company.com")
        assert result == "j***@company.com"

    def test_single_char_local(self):
        result = anonymize_email("j@company.com")
        assert result == "*@company.com"

    def test_no_at_sign(self):
        assert anonymize_email("notanemail") == "***"


# ── Criticality Tests ─────────────────────────────────

class TestBreachCriticality:
    def test_critical_recent_passwords(self):
        result = assess_breach_criticality(
            ["Passwords", "Email addresses"],
            "2026-01-01",
            True,
        )
        assert result == BreachCriticality.CRITICAL

    def test_high_old_passwords(self):
        result = assess_breach_criticality(
            ["Passwords", "Email addresses"],
            "2020-01-01",
            True,
        )
        assert result == BreachCriticality.HIGH

    def test_medium_sensitive_no_passwords(self):
        result = assess_breach_criticality(
            ["Credit cards", "Email addresses"],
            "2024-01-01",
            True,
        )
        assert result == BreachCriticality.MEDIUM

    def test_low_public_data(self):
        result = assess_breach_criticality(
            ["Email addresses", "Usernames"],
            "2024-01-01",
            True,
        )
        assert result == BreachCriticality.LOW

    def test_empty_data_classes(self):
        assert assess_breach_criticality([], "", False) == BreachCriticality.LOW


# ── Recommendations Tests ─────────────────────────────

class TestRecommendations:
    def test_critical_recommendations(self):
        breaches = [
            Breach(
                name="TestBreach",
                title="Test",
                domain="test.com",
                breach_date="2026-01-01",
                added_date="2026-01-15",
                affected_email="j***@test.com",
                data_classes=["Passwords"],
                criticality=BreachCriticality.CRITICAL,
            )
        ]
        recs = generate_recommendations(breaches)
        assert any("CRITIQUE" in r for r in recs)
        assert any("MFA" in r or "multi-facteur" in r for r in recs)

    def test_no_breaches(self):
        assert generate_recommendations([]) == []


# ── HIBP API Tests ────────────────────────────────────

class TestHIBPAPI:
    @pytest.mark.asyncio
    async def test_check_email_with_mock(self):
        async def mock_http_get(url):
            return [
                {
                    "Name": "LinkedIn",
                    "Title": "LinkedIn",
                    "Domain": "linkedin.com",
                    "BreachDate": "2021-06-22",
                    "AddedDate": "2021-06-23",
                    "PwnCount": 700000000,
                    "DataClasses": ["Email addresses", "Passwords"],
                    "IsVerified": True,
                    "IsSensitive": False,
                }
            ]

        breaches = await check_email_breaches(
            "test@company.com",
            http_get=mock_http_get,
        )
        assert len(breaches) == 1
        assert breaches[0].name == "LinkedIn"
        assert breaches[0].affected_email == "t***@company.com"
        assert "Passwords" in breaches[0].data_classes

    @pytest.mark.asyncio
    async def test_check_email_no_breaches(self):
        async def mock_empty(url):
            return None

        breaches = await check_email_breaches(
            "safe@company.com",
            http_get=mock_empty,
        )
        assert len(breaches) == 0

    @pytest.mark.asyncio
    async def test_check_email_api_error(self):
        async def mock_error(url):
            raise ConnectionError("API down")

        breaches = await check_email_breaches(
            "test@company.com",
            http_get=mock_error,
        )
        assert len(breaches) == 0


# ── Main Run Tests ─────────────────────────────────────

class TestRun:
    @pytest.mark.asyncio
    async def test_run_no_input(self):
        output = await run(SkillInput())
        assert output.success is False
        assert "email" in output.error.lower() or "domaine" in output.error.lower()

    def test_breach_to_dict(self):
        b = Breach(
            name="Test",
            title="Test",
            domain="test.com",
            breach_date="2024-01-01",
            added_date="2024-01-02",
            affected_email="t***@test.com",
            criticality=BreachCriticality.CRITICAL,
        )
        d = b.to_dict()
        assert d["criticality"] == "critical"
        assert d["affected_email"] == "t***@test.com"
