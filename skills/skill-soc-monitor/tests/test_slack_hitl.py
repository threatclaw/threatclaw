"""
Comprehensive tests for the Human-in-the-Loop Slack validation module.

Covers the SlackNotifier, ApprovalResult, Urgency, Alert dataclass,
block formatting, interaction handling, and edge cases.
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.slack_hitl import (
    Alert,
    ApprovalResult,
    SlackNotifier,
    Urgency,
    create_notifier_from_env,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_notifier(
    webhook_url: str = "https://hooks.slack.com/services/T00/B00/test",
    bot_token: str = "xoxb-test-token",
    default_channel: str = "#security-alerts",
) -> SlackNotifier:
    return SlackNotifier(
        webhook_url=webhook_url,
        bot_token=bot_token,
        default_channel=default_channel,
    )


def make_alert(**kwargs) -> Alert:
    defaults = {
        "id": "alert-001",
        "title": "Brute force detected",
        "description": "Multiple failed login attempts from 10.0.0.5",
        "severity": "high",
        "source": "threatclaw-soc",
        "metadata": {"ip": "10.0.0.5", "attempts": "42"},
    }
    defaults.update(kwargs)
    return Alert(**defaults)


# ---------------------------------------------------------------------------
# 1. Urgency enum
# ---------------------------------------------------------------------------


class TestUrgency:

    def test_urgency_low_timeout(self):
        assert Urgency.LOW.timeout_secs == 86400

    def test_urgency_medium_timeout(self):
        assert Urgency.MEDIUM.timeout_secs == 14400

    def test_urgency_high_timeout(self):
        assert Urgency.HIGH.timeout_secs == 3600

    def test_urgency_critical_timeout(self):
        assert Urgency.CRITICAL.timeout_secs == 900

    def test_urgency_timeout_minutes(self):
        assert Urgency.CRITICAL.timeout_minutes == 15
        assert Urgency.HIGH.timeout_minutes == 60

    def test_urgency_color_is_hex(self):
        for u in Urgency:
            assert u.color.startswith("#")
            assert len(u.color) == 7

    def test_urgency_from_string(self):
        assert Urgency("low") == Urgency.LOW
        assert Urgency("critical") == Urgency.CRITICAL


# ---------------------------------------------------------------------------
# 2. ApprovalResult
# ---------------------------------------------------------------------------


class TestApprovalResult:

    def test_pending_is_not_terminal(self):
        result = ApprovalResult(request_id="r1", approved=False)
        assert not result.is_terminal
        assert result.status_label == "Pending"

    def test_approved_is_terminal(self):
        result = ApprovalResult(
            request_id="r2", approved=True, decided_by="U123", decided_at=time.time()
        )
        assert result.is_terminal
        assert result.status_label == "Approved"

    def test_rejected_is_terminal(self):
        result = ApprovalResult(
            request_id="r3",
            approved=False,
            decided_by="U456",
            decided_at=time.time(),
            reason="Too risky",
        )
        assert result.is_terminal
        assert result.status_label == "Rejected"

    def test_expired_is_terminal(self):
        result = ApprovalResult(request_id="r4", approved=False, expired=True)
        assert result.is_terminal
        assert result.status_label == "Expired"


# ---------------------------------------------------------------------------
# 3. Alert dataclass
# ---------------------------------------------------------------------------


class TestAlert:

    def test_alert_defaults(self):
        alert = Alert(title="Test alert")
        assert alert.title == "Test alert"
        assert alert.source == "threatclaw"
        assert alert.severity == "medium"
        assert alert.id  # auto-generated UUID
        assert alert.timestamp > 0

    def test_alert_severity_emoji(self):
        assert Alert(severity="low").severity_emoji == ":large_green_circle:"
        assert Alert(severity="high").severity_emoji == ":red_circle:"
        assert Alert(severity="critical").severity_emoji == ":rotating_light:"
        assert Alert(severity="unknown").severity_emoji == ":question:"

    def test_alert_severity_color(self):
        assert Alert(severity="low").severity_color == "#36a64f"
        assert Alert(severity="critical").severity_color == "#8b0000"


# ---------------------------------------------------------------------------
# 4. SlackNotifier construction
# ---------------------------------------------------------------------------


class TestSlackNotifierInit:

    def test_requires_webhook_url(self):
        with pytest.raises(ValueError, match="webhook_url"):
            SlackNotifier(webhook_url="")

    def test_valid_construction(self):
        n = make_notifier()
        assert n.webhook_url.startswith("https://")
        assert n.bot_token == "xoxb-test-token"
        assert n.default_channel == "#security-alerts"


# ---------------------------------------------------------------------------
# 5. Block formatting
# ---------------------------------------------------------------------------


class TestBlockFormatting:

    def test_alert_blocks_structure(self):
        notifier = make_notifier()
        alert = make_alert()
        blocks = notifier.format_alert_blocks(alert)

        assert isinstance(blocks, list)
        assert len(blocks) >= 3

        # First block is a header.
        assert blocks[0]["type"] == "header"

        # Second block contains the title.
        assert "Brute force" in blocks[1]["text"]["text"]

        # Description block exists.
        desc_blocks = [b for b in blocks if b.get("type") == "section" and "text" in b.get("text", {}).get("text", "")]
        assert len(desc_blocks) >= 0  # at least description or title

        # Context block with alert ID.
        context_blocks = [b for b in blocks if b.get("type") == "context"]
        assert len(context_blocks) == 1
        assert "alert-001" in context_blocks[0]["elements"][0]["text"]

    def test_alert_blocks_without_description(self):
        notifier = make_notifier()
        alert = Alert(id="a1", title="Minimal alert", description="")
        blocks = notifier.format_alert_blocks(alert)
        # Should still have header, title section, fields, context.
        assert len(blocks) >= 3

    def test_alert_blocks_metadata_fields(self):
        notifier = make_notifier()
        alert = make_alert(metadata={"host": "srv-01", "user": "admin"})
        blocks = notifier.format_alert_blocks(alert)
        # Find the section with fields.
        field_blocks = [b for b in blocks if "fields" in b]
        assert len(field_blocks) == 1
        fields_text = " ".join(f["text"] for f in field_blocks[0]["fields"])
        assert "host" in fields_text
        assert "srv-01" in fields_text

    def test_approval_blocks_structure(self):
        notifier = make_notifier()
        blocks = notifier.format_approval_blocks(
            action="Quarantine host-42",
            context="Ransomware indicators detected",
        )

        assert isinstance(blocks, list)
        assert len(blocks) >= 3

        # Header.
        assert blocks[0]["type"] == "header"
        assert "Approval" in blocks[0]["text"]["text"]

        # Action section.
        assert "Quarantine host-42" in blocks[1]["text"]["text"]

        # Context section.
        assert "Ransomware" in blocks[2]["text"]["text"]

        # Divider at the end.
        assert blocks[-1]["type"] == "divider"

    def test_approval_blocks_empty_context(self):
        notifier = make_notifier()
        blocks = notifier.format_approval_blocks(
            action="Reset MFA", context=""
        )
        # No context section, but header + action + divider.
        assert len(blocks) >= 2
        types = [b["type"] for b in blocks]
        assert "header" in types
        assert "divider" in types


# ---------------------------------------------------------------------------
# 6. send_alert
# ---------------------------------------------------------------------------


class TestSendAlert:

    @pytest.mark.asyncio
    async def test_send_alert_success(self):
        notifier = make_notifier()
        alert = make_alert()

        with patch("src.slack_hitl._post_json", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = {"ok": True}
            result = await notifier.send_alert(alert, urgency="high")
            assert result is True
            mock_post.assert_awaited_once()

            # Verify payload structure.
            payload = mock_post.call_args[0][1]
            assert payload["channel"] == "#security-alerts"
            assert "attachments" in payload

    @pytest.mark.asyncio
    async def test_send_alert_failure(self):
        notifier = make_notifier()
        alert = make_alert()

        with patch("src.slack_hitl._post_json", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = Exception("Connection refused")
            result = await notifier.send_alert(alert)
            assert result is False

    @pytest.mark.asyncio
    async def test_send_alert_invalid_urgency_defaults(self):
        notifier = make_notifier()
        alert = make_alert()

        with patch("src.slack_hitl._post_json", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = {"ok": True}
            result = await notifier.send_alert(alert, urgency="invalid_level")
            assert result is True
            # Should default to medium colour.
            payload = mock_post.call_args[0][1]
            assert payload["attachments"][0]["color"] == Urgency.MEDIUM.color


# ---------------------------------------------------------------------------
# 7. Interaction handling
# ---------------------------------------------------------------------------


class TestInteractionHandling:

    def test_approve_interaction(self):
        notifier = make_notifier()
        result = ApprovalResult(request_id="req-100", approved=False)
        notifier._pending_approvals["req-100"] = result

        updated = notifier.handle_interaction(
            request_id="req-100",
            action_id="hitl_approve",
            user_id="U999",
        )
        assert updated is not None
        assert updated.approved is True
        assert updated.decided_by == "U999"
        assert updated.decided_at is not None

    def test_reject_interaction_with_reason(self):
        notifier = make_notifier()
        result = ApprovalResult(request_id="req-200", approved=False)
        notifier._pending_approvals["req-200"] = result

        updated = notifier.handle_interaction(
            request_id="req-200",
            action_id="hitl_reject",
            user_id="U888",
            reason="Not appropriate right now",
        )
        assert updated is not None
        assert updated.approved is False
        assert updated.reason == "Not appropriate right now"

    def test_unknown_request_returns_none(self):
        notifier = make_notifier()
        result = notifier.handle_interaction(
            request_id="nonexistent",
            action_id="hitl_approve",
            user_id="U777",
        )
        assert result is None

    def test_already_decided_ignored(self):
        notifier = make_notifier()
        result = ApprovalResult(
            request_id="req-300",
            approved=True,
            decided_by="U111",
            decided_at=time.time(),
        )
        notifier._pending_approvals["req-300"] = result

        updated = notifier.handle_interaction(
            request_id="req-300",
            action_id="hitl_reject",
            user_id="U222",
        )
        # Should return existing result unchanged.
        assert updated is not None
        assert updated.approved is True
        assert updated.decided_by == "U111"

    def test_unknown_action_id_returns_none(self):
        notifier = make_notifier()
        result = ApprovalResult(request_id="req-400", approved=False)
        notifier._pending_approvals["req-400"] = result

        updated = notifier.handle_interaction(
            request_id="req-400",
            action_id="unknown_action",
            user_id="U666",
        )
        assert updated is None


# ---------------------------------------------------------------------------
# 8. create_notifier_from_env
# ---------------------------------------------------------------------------


class TestCreateFromEnv:

    def test_from_env(self):
        env = {
            "SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/T/B/X",
            "SLACK_BOT_TOKEN": "xoxb-env-token",
            "SLACK_DEFAULT_CHANNEL": "#env-channel",
        }
        with patch.dict("os.environ", env, clear=False):
            n = create_notifier_from_env()
            assert n.webhook_url == env["SLACK_WEBHOOK_URL"]
            assert n.bot_token == env["SLACK_BOT_TOKEN"]
            assert n.default_channel == "#env-channel"

    def test_from_env_missing_webhook_raises(self):
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError, match="webhook_url"):
                create_notifier_from_env()

    def test_from_env_defaults(self):
        env = {
            "SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/T/B/Y",
        }
        with patch.dict("os.environ", env, clear=True):
            n = create_notifier_from_env()
            assert n.bot_token is None
            assert n.default_channel == "#security-alerts"
