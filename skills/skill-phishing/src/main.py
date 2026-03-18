"""
skill-phishing — Phishing simulation orchestrator
GoPhish REST API + LLM template generation

This module provides the business logic for phishing campaigns.
All send actions require RSSI approval (human-in-the-loop).
"""

import json
import asyncio
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
from datetime import datetime, timezone


# ── Constants ──────────────────────────────────────────────

GOPHISH_API_BASE = "http://gophish:3333/api"
GOPHISH_TIMEOUT = 30  # seconds


# ── Data Models ────────────────────────────────────────────

class TemplateType(Enum):
    GENERIC = "generic"
    SPEAR = "spear"
    CEO_FRAUD = "ceo_fraud"
    IT_SUPPORT = "it_support"
    HR_NOTICE = "hr_notice"


class CampaignStatus(Enum):
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    LAUNCHED = "launched"
    COMPLETED = "completed"


@dataclass
class PhishingTemplate:
    name: str
    subject: str
    html_body: str
    text_body: str
    template_type: TemplateType = TemplateType.GENERIC
    language: str = "fr"
    sector: str = "general"


@dataclass
class TargetGroup:
    name: str
    targets: list[dict] = field(default_factory=list)
    # Each target: {"first_name": "", "last_name": "", "email": "", "position": ""}


@dataclass
class CampaignResults:
    campaign_id: int = 0
    campaign_name: str = ""
    status: CampaignStatus = CampaignStatus.DRAFT
    total_targets: int = 0
    emails_sent: int = 0
    emails_opened: int = 0
    links_clicked: int = 0
    credentials_submitted: int = 0
    errors: int = 0
    open_rate: float = 0.0
    click_rate: float = 0.0
    submission_rate: float = 0.0
    timeline: list[dict] = field(default_factory=list)

    def calculate_rates(self):
        if self.emails_sent > 0:
            self.open_rate = round(self.emails_opened / self.emails_sent * 100, 1)
            self.click_rate = round(self.links_clicked / self.emails_sent * 100, 1)
            self.submission_rate = round(
                self.credentials_submitted / self.emails_sent * 100, 1
            )

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class SkillInput:
    action: str = "create"  # "create" | "launch" | "results" | "report"
    campaign_name: str = ""
    target_group_name: str = ""
    targets: list[dict] = field(default_factory=list)
    template_type: TemplateType = TemplateType.GENERIC
    sector: str = "general"
    language: str = "fr"
    campaign_id: Optional[int] = None  # for results/report actions
    smtp_profile_name: str = ""
    landing_page_url: str = ""


@dataclass
class SkillOutput:
    success: bool = False
    campaign_id: Optional[int] = None
    results: Optional[CampaignResults] = None
    template: Optional[PhishingTemplate] = None
    status: CampaignStatus = CampaignStatus.DRAFT
    message: str = ""
    error: Optional[str] = None

    def to_dict(self) -> dict:
        d = {
            "success": self.success,
            "campaign_id": self.campaign_id,
            "status": self.status.value,
            "message": self.message,
            "error": self.error,
        }
        if self.results:
            d["results"] = self.results.to_dict()
        if self.template:
            d["template"] = asdict(self.template)
            d["template"]["template_type"] = self.template.template_type.value
        return d


# ── Template Generation ───────────────────────────────────

# Pre-built template frameworks by type and sector
TEMPLATE_FRAMEWORKS = {
    "generic": {
        "fr": {
            "subject": "Action requise : Mise à jour de sécurité de votre compte",
            "body_intro": "Cher(e) {{.FirstName}},",
            "body_main": (
                "Dans le cadre de notre politique de sécurité, nous vous demandons "
                "de vérifier vos informations de connexion. Cette vérification est "
                "obligatoire et doit être effectuée dans les 24 heures."
            ),
            "body_cta": "Vérifier mon compte",
            "body_closing": "Cordialement,\nLe service informatique",
        },
    },
    "it_support": {
        "fr": {
            "subject": "Ticket IT #{RND} — Mise à jour requise",
            "body_intro": "Bonjour {{.FirstName}},",
            "body_main": (
                "Le service IT a détecté que votre poste de travail nécessite "
                "une mise à jour de sécurité critique. Veuillez vous connecter "
                "au portail IT pour appliquer la mise à jour."
            ),
            "body_cta": "Accéder au portail IT",
            "body_closing": "Support IT\nTicket #{RND}",
        },
    },
    "hr_notice": {
        "fr": {
            "subject": "Important : Modification de vos avantages sociaux",
            "body_intro": "Cher(e) {{.FirstName}},",
            "body_main": (
                "Suite à la mise à jour de notre politique d'avantages sociaux, "
                "nous vous informons que votre couverture a été modifiée. "
                "Veuillez consulter les détails et confirmer votre choix."
            ),
            "body_cta": "Consulter mes avantages",
            "body_closing": "Service des Ressources Humaines",
        },
    },
    "ceo_fraud": {
        "fr": {
            "subject": "Urgent — Besoin de votre aide",
            "body_intro": "Bonjour {{.FirstName}},",
            "body_main": (
                "Je suis actuellement en réunion et j'ai besoin que vous "
                "traitiez quelque chose rapidement pour moi. "
                "Pouvez-vous accéder au lien ci-dessous ?"
            ),
            "body_cta": "Accéder au document",
            "body_closing": "Envoyé depuis mon mobile",
        },
    },
}


def generate_template(
    template_type: TemplateType,
    sector: str,
    language: str,
) -> PhishingTemplate:
    """Generate a phishing email template.

    In production, this would call the LLM for contextualization.
    Here we use pre-built frameworks as a starting point.
    """
    type_key = template_type.value
    lang_key = language if language in ("fr", "en") else "fr"

    framework = TEMPLATE_FRAMEWORKS.get(type_key, TEMPLATE_FRAMEWORKS["generic"])
    content = framework.get(lang_key, framework.get("fr", {}))

    subject = content.get("subject", "Action requise")
    intro = content.get("body_intro", "Bonjour,")
    main = content.get("body_main", "")
    cta = content.get("body_cta", "Cliquer ici")
    closing = content.get("body_closing", "")

    html_body = f"""<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
  <div style="padding: 20px;">
    <p>{intro}</p>
    <p>{main}</p>
    <p style="text-align: center; margin: 30px 0;">
      <a href="{{{{.URL}}}}" style="background-color: #0066cc; color: white;
         padding: 12px 24px; text-decoration: none; border-radius: 4px;">
        {cta}
      </a>
    </p>
    <p>{closing.replace(chr(10), '<br>')}</p>
  </div>
  <div style="font-size: 11px; color: #666; padding: 10px 20px; border-top: 1px solid #eee;">
    <p>{{{{.Tracker}}}}</p>
  </div>
</body>
</html>"""

    text_body = f"{intro}\n\n{main}\n\n{cta}: {{{{.URL}}}}\n\n{closing}"

    return PhishingTemplate(
        name=f"ThreatClaw-{type_key}-{sector}-{lang_key}",
        subject=subject,
        html_body=html_body,
        text_body=text_body,
        template_type=template_type,
        language=language,
        sector=sector,
    )


# ── GoPhish API Client ────────────────────────────────────

async def _gophish_request(
    method: str,
    endpoint: str,
    data: dict | None = None,
    http_request=None,
) -> Optional[dict | list]:
    """Make a GoPhish API request."""
    url = f"{GOPHISH_API_BASE}{endpoint}"

    try:
        if http_request:
            return await http_request(method, url, data)

        cmd = ["curl", "-s", "-f", "-X", method, url]
        if data:
            cmd.extend([
                "-H", "Content-Type: application/json",
                "-d", json.dumps(data),
            ])

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(
            proc.communicate(), timeout=GOPHISH_TIMEOUT
        )
        output = stdout.decode("utf-8", errors="replace").strip()
        if not output:
            return None
        return json.loads(output)

    except Exception:
        return None


async def create_gophish_group(
    name: str,
    targets: list[dict],
    http_request=None,
) -> Optional[int]:
    """Create a target group in GoPhish."""
    data = {
        "name": name,
        "targets": [
            {
                "first_name": t.get("first_name", ""),
                "last_name": t.get("last_name", ""),
                "email": t.get("email", ""),
                "position": t.get("position", ""),
            }
            for t in targets
        ],
    }
    result = await _gophish_request("POST", "/groups/", data, http_request)
    if result and isinstance(result, dict):
        return result.get("id")
    return None


async def create_gophish_template(
    template: PhishingTemplate,
    http_request=None,
) -> Optional[int]:
    """Create an email template in GoPhish."""
    data = {
        "name": template.name,
        "subject": template.subject,
        "html": template.html_body,
        "text": template.text_body,
    }
    result = await _gophish_request("POST", "/templates/", data, http_request)
    if result and isinstance(result, dict):
        return result.get("id")
    return None


async def create_gophish_campaign(
    name: str,
    template_id: int,
    group_id: int,
    smtp_name: str,
    landing_page: str,
    http_request=None,
) -> Optional[int]:
    """Create a campaign in GoPhish (does NOT launch it)."""
    data = {
        "name": name,
        "template": {"id": template_id},
        "groups": [{"id": group_id}],
        "smtp": {"name": smtp_name},
        "page": {"name": landing_page},
    }
    result = await _gophish_request("POST", "/campaigns/", data, http_request)
    if result and isinstance(result, dict):
        return result.get("id")
    return None


async def get_campaign_results(
    campaign_id: int,
    http_request=None,
) -> Optional[CampaignResults]:
    """Fetch campaign results from GoPhish."""
    result = await _gophish_request(
        "GET", f"/campaigns/{campaign_id}/results", http_request=http_request
    )
    if not result or not isinstance(result, dict):
        return None

    results = CampaignResults(
        campaign_id=campaign_id,
        campaign_name=result.get("name", ""),
        status=CampaignStatus.COMPLETED,
        total_targets=len(result.get("results", [])),
    )

    for r in result.get("results", []):
        status = r.get("status", "")
        if status == "Email Sent":
            results.emails_sent += 1
        elif status == "Email Opened":
            results.emails_sent += 1
            results.emails_opened += 1
        elif status == "Clicked Link":
            results.emails_sent += 1
            results.emails_opened += 1
            results.links_clicked += 1
        elif status == "Submitted Data":
            results.emails_sent += 1
            results.emails_opened += 1
            results.links_clicked += 1
            results.credentials_submitted += 1
        elif status == "Error":
            results.errors += 1

    results.calculate_rates()
    return results


# ── Main Entry Point ───────────────────────────────────────

async def run(input: SkillInput) -> SkillOutput:
    """Main skill entry point."""

    if input.action == "create":
        # Step 1: Generate template
        template = generate_template(
            input.template_type, input.sector, input.language
        )

        return SkillOutput(
            success=True,
            template=template,
            status=CampaignStatus.PENDING_APPROVAL,
            message=(
                f"Template '{template.name}' généré. "
                "En attente de validation RSSI avant création de campagne."
            ),
        )

    elif input.action == "launch":
        # Step 2: Create campaign in GoPhish (requires prior approval)
        if not input.campaign_name:
            return SkillOutput(
                success=False,
                error="Nom de campagne requis pour le lancement.",
            )

        # Generate template
        template = generate_template(
            input.template_type, input.sector, input.language
        )

        # Create group
        group_id = await create_gophish_group(
            input.target_group_name or f"group-{input.campaign_name}",
            input.targets,
        )

        # Create template
        template_id = await create_gophish_template(template)

        if group_id and template_id:
            # Create campaign
            campaign_id = await create_gophish_campaign(
                input.campaign_name,
                template_id,
                group_id,
                input.smtp_profile_name,
                input.landing_page_url,
            )

            return SkillOutput(
                success=True,
                campaign_id=campaign_id,
                template=template,
                status=CampaignStatus.LAUNCHED,
                message=f"Campagne '{input.campaign_name}' lancée (ID: {campaign_id})",
            )
        else:
            return SkillOutput(
                success=False,
                error="Erreur lors de la création dans GoPhish. Vérifier que le service est accessible.",
            )

    elif input.action == "results":
        if not input.campaign_id:
            return SkillOutput(
                success=False,
                error="ID de campagne requis pour récupérer les résultats.",
            )

        results = await get_campaign_results(input.campaign_id)
        if results:
            return SkillOutput(
                success=True,
                campaign_id=input.campaign_id,
                results=results,
                status=CampaignStatus.COMPLETED,
                message=(
                    f"Résultats campagne #{input.campaign_id} : "
                    f"{results.open_rate}% ouverture, "
                    f"{results.click_rate}% clics, "
                    f"{results.submission_rate}% soumissions"
                ),
            )
        else:
            return SkillOutput(
                success=False,
                error=f"Impossible de récupérer les résultats de la campagne #{input.campaign_id}",
            )

    else:
        return SkillOutput(
            success=False,
            error=f"Action inconnue : {input.action}. Actions valides : create, launch, results",
        )
