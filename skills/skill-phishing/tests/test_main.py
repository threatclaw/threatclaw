"""Tests for skill-phishing."""

import pytest
from src.main import (
    TemplateType,
    CampaignStatus,
    CampaignResults,
    SkillInput,
    generate_template,
    run,
)


# ── Template Generation Tests ─────────────────────────

class TestTemplateGeneration:
    def test_generic_french(self):
        t = generate_template(TemplateType.GENERIC, "finance", "fr")
        assert t.language == "fr"
        assert t.sector == "finance"
        assert t.template_type == TemplateType.GENERIC
        assert "{{.FirstName}}" in t.html_body or "{{.URL}}" in t.html_body
        assert "{{.Tracker}}" in t.html_body
        assert t.subject != ""
        assert t.name.startswith("ThreatClaw-")

    def test_ceo_fraud(self):
        t = generate_template(TemplateType.CEO_FRAUD, "tech", "fr")
        assert "urgent" in t.subject.lower() or "aide" in t.subject.lower()

    def test_it_support(self):
        t = generate_template(TemplateType.IT_SUPPORT, "general", "fr")
        assert "IT" in t.subject or "Ticket" in t.subject

    def test_hr_notice(self):
        t = generate_template(TemplateType.HR_NOTICE, "general", "fr")
        assert "avantages" in t.subject.lower() or "modification" in t.subject.lower()

    def test_html_contains_url_placeholder(self):
        t = generate_template(TemplateType.GENERIC, "general", "fr")
        assert "{{.URL}}" in t.html_body
        assert "{{.URL}}" in t.text_body

    def test_html_contains_tracker(self):
        t = generate_template(TemplateType.GENERIC, "general", "fr")
        assert "{{.Tracker}}" in t.html_body


# ── Campaign Results Tests ────────────────────────────

class TestCampaignResults:
    def test_calculate_rates(self):
        results = CampaignResults(
            emails_sent=100,
            emails_opened=45,
            links_clicked=15,
            credentials_submitted=5,
        )
        results.calculate_rates()
        assert results.open_rate == 45.0
        assert results.click_rate == 15.0
        assert results.submission_rate == 5.0

    def test_calculate_rates_zero_sent(self):
        results = CampaignResults(emails_sent=0)
        results.calculate_rates()
        assert results.open_rate == 0.0

    def test_to_dict(self):
        results = CampaignResults(
            campaign_id=42,
            status=CampaignStatus.COMPLETED,
        )
        d = results.to_dict()
        assert d["status"] == "completed"
        assert d["campaign_id"] == 42


# ── Main Run Tests ─────────────────────────────────────

class TestRun:
    @pytest.mark.asyncio
    async def test_create_template(self):
        output = await run(SkillInput(
            action="create",
            template_type=TemplateType.GENERIC,
            sector="finance",
            language="fr",
        ))
        assert output.success is True
        assert output.template is not None
        assert output.status == CampaignStatus.PENDING_APPROVAL
        assert "validation" in output.message.lower() or "attente" in output.message.lower()

    @pytest.mark.asyncio
    async def test_launch_without_name(self):
        output = await run(SkillInput(action="launch"))
        assert output.success is False
        assert "nom" in output.error.lower()

    @pytest.mark.asyncio
    async def test_results_without_id(self):
        output = await run(SkillInput(action="results"))
        assert output.success is False
        assert "ID" in output.error

    @pytest.mark.asyncio
    async def test_unknown_action(self):
        output = await run(SkillInput(action="invalid"))
        assert output.success is False
        assert "inconnue" in output.error.lower()

    def test_output_to_dict(self):
        from src.main import SkillOutput, PhishingTemplate
        output = SkillOutput(
            success=True,
            campaign_id=1,
            status=CampaignStatus.PENDING_APPROVAL,
            message="test",
            template=PhishingTemplate(
                name="test",
                subject="test",
                html_body="<p>test</p>",
                text_body="test",
            ),
        )
        d = output.to_dict()
        assert d["success"] is True
        assert d["status"] == "pending_approval"
        assert d["template"]["template_type"] == "generic"
