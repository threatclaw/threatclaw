"""
Human-in-the-Loop Slack validation for the ThreatClaw SOC Monitor skill.

Sends security alerts and approval requests to Slack using Block Kit,
then waits for human response through interactive message buttons.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enumerations & data classes
# ---------------------------------------------------------------------------


class Urgency(str, Enum):
    """Urgency level — determines the approval timeout."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def timeout_secs(self) -> int:
        """Return timeout in seconds for this urgency level."""
        return _URGENCY_TIMEOUTS[self]

    @property
    def timeout_minutes(self) -> int:
        """Return timeout in minutes for this urgency level."""
        return self.timeout_secs // 60

    @property
    def color(self) -> str:
        """Slack attachment colour bar."""
        return _URGENCY_COLORS[self]

    @property
    def emoji(self) -> str:
        """Slack emoji for this urgency."""
        return _URGENCY_EMOJIS[self]


_URGENCY_TIMEOUTS: dict[Urgency, int] = {
    Urgency.LOW: 86400,       # 24 h
    Urgency.MEDIUM: 14400,    # 4 h
    Urgency.HIGH: 3600,       # 1 h
    Urgency.CRITICAL: 900,    # 15 min
}

_URGENCY_COLORS: dict[Urgency, str] = {
    Urgency.LOW: "#36a64f",
    Urgency.MEDIUM: "#daa038",
    Urgency.HIGH: "#e01e5a",
    Urgency.CRITICAL: "#8b0000",
}

_URGENCY_EMOJIS: dict[Urgency, str] = {
    Urgency.LOW: ":large_green_circle:",
    Urgency.MEDIUM: ":large_yellow_circle:",
    Urgency.HIGH: ":red_circle:",
    Urgency.CRITICAL: ":rotating_light:",
}


@dataclass
class ApprovalResult:
    """Outcome of a human-in-the-loop approval request."""

    request_id: str
    approved: bool
    decided_by: Optional[str] = None
    decided_at: Optional[float] = None
    reason: Optional[str] = None
    expired: bool = False

    @property
    def is_terminal(self) -> bool:
        """Whether the result is final (approved, rejected, or expired)."""
        return self.approved or self.expired or (self.decided_by is not None)

    @property
    def status_label(self) -> str:
        if self.expired:
            return "Expired"
        if self.approved:
            return "Approved"
        if self.decided_by is not None:
            return "Rejected"
        return "Pending"


@dataclass
class Alert:
    """A security alert to be sent to Slack."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    severity: str = "medium"
    source: str = "threatclaw"
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def severity_emoji(self) -> str:
        return {
            "low": ":large_green_circle:",
            "medium": ":large_yellow_circle:",
            "high": ":red_circle:",
            "critical": ":rotating_light:",
        }.get(self.severity.lower(), ":question:")

    @property
    def severity_color(self) -> str:
        return {
            "low": "#36a64f",
            "medium": "#daa038",
            "high": "#e01e5a",
            "critical": "#8b0000",
        }.get(self.severity.lower(), "#cccccc")


# ---------------------------------------------------------------------------
# HTTP helper (thin wrapper to enable testing without real HTTP)
# ---------------------------------------------------------------------------


async def _post_json(url: str, payload: dict, headers: Optional[dict] = None) -> dict:
    """POST JSON to a URL. Uses aiohttp if available, falls back to urllib."""
    try:
        import aiohttp

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers) as resp:
                resp.raise_for_status()
                try:
                    return await resp.json()
                except Exception:
                    text = await resp.text()
                    return {"ok": resp.status < 400, "body": text}
    except ImportError:
        # Fallback: run synchronous urllib in executor
        import json
        import urllib.request

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={**(headers or {}), "Content-Type": "application/json"},
            method="POST",
        )
        loop = asyncio.get_event_loop()
        resp = await loop.run_in_executor(
            None, lambda: urllib.request.urlopen(req, timeout=30)
        )
        body = resp.read().decode("utf-8")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return {"ok": resp.status < 400, "body": body}


# ---------------------------------------------------------------------------
# SlackNotifier
# ---------------------------------------------------------------------------


class SlackNotifier:
    """Send security alerts and approval requests to Slack.

    Parameters
    ----------
    webhook_url:
        Slack incoming webhook URL for posting messages.
    bot_token:
        Slack bot token (xoxb-...) for interactive messages and updates.
        Required for approval requests; optional for simple alerts.
    default_channel:
        Default Slack channel for messages.
    """

    def __init__(
        self,
        webhook_url: str,
        bot_token: Optional[str] = None,
        default_channel: str = "#security-alerts",
    ) -> None:
        if not webhook_url:
            raise ValueError("webhook_url is required")
        self.webhook_url = webhook_url
        self.bot_token = bot_token
        self.default_channel = default_channel
        self._pending_approvals: dict[str, ApprovalResult] = {}

    # -- Public API ---------------------------------------------------------

    async def send_alert(self, alert: Alert, urgency: str = "medium") -> bool:
        """Send a security alert to Slack.

        Returns True on success, False on failure (errors are logged).
        """
        try:
            urgency_enum = Urgency(urgency.lower())
        except ValueError:
            urgency_enum = Urgency.MEDIUM

        blocks = self.format_alert_blocks(alert)
        payload = {
            "channel": self.default_channel,
            "text": f"{alert.severity_emoji} [{alert.severity.upper()}] {alert.title}",
            "attachments": [
                {
                    "color": urgency_enum.color,
                    "blocks": blocks,
                }
            ],
        }

        try:
            await _post_json(self.webhook_url, payload)
            logger.info("Alert %s sent to Slack", alert.id)
            return True
        except Exception:
            logger.exception("Failed to send alert %s to Slack", alert.id)
            return False

    async def request_approval(
        self,
        action: str,
        context: str,
        urgency: str = "medium",
        timeout_minutes: int = 60,
    ) -> ApprovalResult:
        """Request human approval via Slack interactive message.

        Sends a message with Approve/Reject buttons and waits for a
        response (or timeout).

        Parameters
        ----------
        action:
            Short description of the action requiring approval.
        context:
            Additional context for the approver.
        urgency:
            Urgency level string (low, medium, high, critical).
        timeout_minutes:
            Maximum time to wait for a response in minutes.

        Returns
        -------
        ApprovalResult with the decision.
        """
        try:
            urgency_enum = Urgency(urgency.lower())
        except ValueError:
            urgency_enum = Urgency.MEDIUM

        request_id = str(uuid.uuid4())
        effective_timeout = min(
            timeout_minutes * 60, urgency_enum.timeout_secs
        )

        blocks = self.format_approval_blocks(action, context)
        payload = {
            "channel": self.default_channel,
            "text": f"{urgency_enum.emoji} Approval required: {action}",
            "attachments": [
                {
                    "color": urgency_enum.color,
                    "blocks": blocks
                    + [
                        {
                            "type": "context",
                            "elements": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"Request ID: `{request_id}` | Timeout: {effective_timeout // 60} min",
                                }
                            ],
                        },
                        {
                            "type": "actions",
                            "elements": [
                                {
                                    "type": "button",
                                    "text": {
                                        "type": "plain_text",
                                        "text": "Approve",
                                        "emoji": True,
                                    },
                                    "style": "primary",
                                    "action_id": "hitl_approve",
                                    "value": request_id,
                                },
                                {
                                    "type": "button",
                                    "text": {
                                        "type": "plain_text",
                                        "text": "Reject",
                                        "emoji": True,
                                    },
                                    "style": "danger",
                                    "action_id": "hitl_reject",
                                    "value": request_id,
                                },
                            ],
                        },
                    ],
                }
            ],
        }

        result = ApprovalResult(request_id=request_id, approved=False)
        self._pending_approvals[request_id] = result

        try:
            await _post_json(self.webhook_url, payload)
            logger.info("Approval request %s sent to Slack", request_id)
        except Exception:
            logger.exception(
                "Failed to send approval request %s to Slack", request_id
            )
            # Return an unapproved result immediately on send failure.
            result.reason = "Failed to send Slack message"
            return result

        # Wait for the response (polling the internal state dict).
        deadline = time.monotonic() + effective_timeout
        while time.monotonic() < deadline:
            if result.is_terminal:
                break
            await asyncio.sleep(1)

        if not result.is_terminal:
            result.expired = True
            logger.warning(
                "Approval request %s expired after %d seconds",
                request_id,
                effective_timeout,
            )

        return result

    def handle_interaction(
        self,
        request_id: str,
        action_id: str,
        user_id: str,
        reason: Optional[str] = None,
    ) -> Optional[ApprovalResult]:
        """Process an interactive message callback from Slack.

        Call this from your webhook handler when Slack sends an interaction
        payload.

        Returns the updated ApprovalResult or None if the request_id is
        unknown.
        """
        result = self._pending_approvals.get(request_id)
        if result is None:
            logger.warning("Unknown approval request: %s", request_id)
            return None

        if result.is_terminal:
            logger.info("Request %s already decided, ignoring", request_id)
            return result

        result.decided_by = user_id
        result.decided_at = time.time()

        if action_id == "hitl_approve":
            result.approved = True
        elif action_id == "hitl_reject":
            result.approved = False
            result.reason = reason
        else:
            logger.warning("Unknown action_id: %s", action_id)
            return None

        logger.info(
            "Request %s %s by %s",
            request_id,
            "approved" if result.approved else "rejected",
            user_id,
        )
        return result

    # -- Block builders -----------------------------------------------------

    def format_alert_blocks(self, alert: Alert) -> list[dict[str, Any]]:
        """Build Slack Block Kit blocks for a security alert."""
        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{alert.severity_emoji} Security Alert",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{alert.title}*",
                },
            },
        ]

        if alert.description:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": alert.description,
                    },
                }
            )

        # Metadata fields
        meta_fields = [
            {"type": "mrkdwn", "text": f"*Severity:* {alert.severity.upper()}"},
            {"type": "mrkdwn", "text": f"*Source:* {alert.source}"},
        ]
        for key, value in alert.metadata.items():
            meta_fields.append(
                {"type": "mrkdwn", "text": f"*{key}:* {value}"}
            )
        blocks.append({"type": "section", "fields": meta_fields[:10]})

        # Footer with alert ID
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Alert ID: `{alert.id}`"}
                ],
            }
        )

        return blocks

    def format_approval_blocks(
        self, action: str, context: str
    ) -> list[dict[str, Any]]:
        """Build Slack Block Kit blocks for an approval request."""
        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": ":lock: Approval Required",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Action:* {action}",
                },
            },
        ]

        if context:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Context:*\n{context}",
                    },
                }
            )

        blocks.append({"type": "divider"})

        return blocks


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------


def create_notifier_from_env() -> SlackNotifier:
    """Create a SlackNotifier from environment variables.

    Expected variables:
        SLACK_WEBHOOK_URL — Incoming webhook URL (required).
        SLACK_BOT_TOKEN — Bot token for interactive messages (optional).
        SLACK_DEFAULT_CHANNEL — Default channel (default: #security-alerts).
    """
    import os

    webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "")
    bot_token = os.environ.get("SLACK_BOT_TOKEN")
    default_channel = os.environ.get("SLACK_DEFAULT_CHANNEL", "#security-alerts")

    return SlackNotifier(
        webhook_url=webhook_url,
        bot_token=bot_token,
        default_channel=default_channel,
    )
