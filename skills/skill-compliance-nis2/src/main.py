"""
skill-compliance-nis2 — NIS2 compliance mapping
Maps security findings to NIS2 Directive (EU) 2022/2555 articles
"""

from dataclasses import dataclass, field
from typing import Optional

# NIS2 Article 21 — security measures
NIS2_ARTICLES = {
    "art21_2a": "Politiques relatives à l'analyse des risques et à la sécurité des SI",
    "art21_2b": "Gestion des incidents",
    "art21_2c": "Continuité des activités et gestion de crise",
    "art21_2d": "Sécurité de la chaîne d'approvisionnement",
    "art21_2e": "Sécurité dans l'acquisition, le développement et la maintenance des SI",
    "art21_2f": "Politiques et procédures pour évaluer l'efficacité des mesures",
    "art21_2g": "Pratiques de base en matière de cyberhygiène et formation",
    "art21_2h": "Politiques relatives à l'utilisation de la cryptographie et du chiffrement",
    "art21_2i": "Sécurité des ressources humaines, politiques de contrôle d'accès",
    "art21_2j": "Utilisation de solutions d'authentification multi-facteur",
}


@dataclass
class ArticleScore:
    article_id: str
    article_title: str
    score: int  # 0-100
    findings_count: int = 0
    gaps: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class ComplianceReport:
    overall_score: int = 0
    article_scores: list[ArticleScore] = field(default_factory=list)
    total_findings: int = 0
    covered_articles: int = 0
    uncovered_articles: int = 0
    actions: list[str] = field(default_factory=list)


@dataclass
class SkillInput:
    findings_source: str = "all"
    period: str = "last_30d"
    include_recommendations: bool = True


@dataclass
class SkillOutput:
    success: bool = False
    report: Optional[ComplianceReport] = None
    error: Optional[str] = None


async def run(input: SkillInput) -> SkillOutput:
    """Main skill entry point."""
    try:
        # TODO: Fetch findings from PostgreSQL
        # TODO: Map findings to NIS2 articles
        # TODO: Calculate scores
        report = ComplianceReport(
            article_scores=[
                ArticleScore(
                    article_id=aid,
                    article_title=title,
                    score=0,
                )
                for aid, title in NIS2_ARTICLES.items()
            ],
            uncovered_articles=len(NIS2_ARTICLES),
        )
        return SkillOutput(success=True, report=report)
    except Exception as e:
        return SkillOutput(success=False, error=str(e))
