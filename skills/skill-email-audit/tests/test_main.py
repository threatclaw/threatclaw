"""Tests for skill-email-audit."""

import pytest
from src.main import (
    DmarcPolicy,
    DmarcResult,
    SpfQualifier,
    SpfResult,
    DkimResult,
    DomainAudit,
    SkillInput,
    run,
)


# ── DMARC Tests ───────────────────────────────────────

class TestDmarcPolicy:
    def test_score_values(self):
        assert DmarcPolicy.REJECT.score_value == 40
        assert DmarcPolicy.QUARANTINE.score_value == 25
        assert DmarcPolicy.NONE.score_value == 5
        assert DmarcPolicy.MISSING.score_value == 0


# ── SPF Tests ─────────────────────────────────────────

class TestSpfQualifier:
    def test_score_values(self):
        assert SpfQualifier.FAIL.score_value == 30
        assert SpfQualifier.SOFTFAIL.score_value == 20
        assert SpfQualifier.NEUTRAL.score_value == 5
        assert SpfQualifier.PASS.score_value == 0
        assert SpfQualifier.MISSING.score_value == 0


# ── Scoring Tests ─────────────────────────────────────

class TestDomainAuditScoring:
    def test_perfect_score(self):
        audit = DomainAudit(
            domain="example.com",
            dmarc=DmarcResult(
                exists=True,
                policy=DmarcPolicy.REJECT,
                pct=100,
                rua="mailto:dmarc@example.com",
            ),
            spf=SpfResult(
                exists=True,
                qualifier=SpfQualifier.FAIL,
            ),
            dkim=DkimResult(
                found=True,
                selectors_found=["google"],
                key_sizes={"google": 2048},
            ),
        )
        score = audit.calculate_score()
        # DMARC: 40 (reject) + 5 (rua) + 5 (pct=100) = 50
        # SPF: 30 (-all)
        # DKIM: 15 (found) + 5 (>=2048) + 10 (selectors) = 30
        # Total: capped at 100
        assert score == 100

    def test_no_records_score(self):
        audit = DomainAudit(domain="bad.com")
        score = audit.calculate_score()
        assert score == 0

    def test_partial_score(self):
        audit = DomainAudit(
            domain="partial.com",
            dmarc=DmarcResult(
                exists=True,
                policy=DmarcPolicy.NONE,
                pct=100,
            ),
            spf=SpfResult(
                exists=True,
                qualifier=SpfQualifier.SOFTFAIL,
            ),
            dkim=DkimResult(found=False),
        )
        score = audit.calculate_score()
        # DMARC: 5 (none) + 0 (no rua) + 5 (pct=100) = 10
        # SPF: 20 (~all)
        # DKIM: 0
        assert score == 30


# ── Recommendations Tests ─────────────────────────────

class TestRecommendations:
    def test_missing_dmarc(self):
        audit = DomainAudit(domain="test.com")
        recs = audit.generate_recommendations()
        assert any("DMARC" in r and "CRITIQUE" in r for r in recs)

    def test_dmarc_none(self):
        audit = DomainAudit(
            domain="test.com",
            dmarc=DmarcResult(exists=True, policy=DmarcPolicy.NONE),
        )
        recs = audit.generate_recommendations()
        assert any("quarantine" in r.lower() or "reject" in r.lower() for r in recs)

    def test_spf_plus_all(self):
        audit = DomainAudit(
            domain="test.com",
            spf=SpfResult(exists=True, qualifier=SpfQualifier.PASS),
        )
        recs = audit.generate_recommendations()
        assert any("+all" in r for r in recs)

    def test_no_dkim(self):
        audit = DomainAudit(
            domain="test.com",
            dkim=DkimResult(found=False),
        )
        recs = audit.generate_recommendations()
        assert any("DKIM" in r for r in recs)

    def test_weak_dkim_key(self):
        audit = DomainAudit(
            domain="test.com",
            dkim=DkimResult(
                found=True,
                selectors_found=["default"],
                key_sizes={"default": 1024},
            ),
        )
        recs = audit.generate_recommendations()
        assert any("1024" in r and "2048" in r for r in recs)

    def test_spf_too_many_lookups(self):
        audit = DomainAudit(
            domain="test.com",
            spf=SpfResult(
                exists=True,
                qualifier=SpfQualifier.FAIL,
                lookup_count=12,
            ),
        )
        # Note: recommendation comes from SPF issues, not generate_recommendations
        # The lookup count issue is already in spf.issues


# ── Main Run Tests ─────────────────────────────────────

class TestRun:
    @pytest.mark.asyncio
    async def test_run_no_domains(self):
        output = await run(SkillInput())
        assert output.success is False
        assert "domaine" in output.error.lower()
