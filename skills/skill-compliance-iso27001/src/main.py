"""
skill-compliance-iso27001 — ISO 27001:2022 Annex A compliance mapping
Maps security findings to all 93 Annex A controls, calculates compliance
scores, maturity levels, and generates Statement of Applicability (SoA).
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ── Enums ─────────────────────────────────────────────────

class ControlCategory(Enum):
    ORGANIZATIONAL = "organizational"
    PEOPLE = "people"
    PHYSICAL = "physical"
    TECHNOLOGICAL = "technological"


class MaturityLevel(Enum):
    INITIAL = 1
    MANAGED = 2
    DEFINED = 3
    MEASURED = 4
    OPTIMIZED = 5


class ControlStatus(Enum):
    CONFORMING = "conforming"
    PARTIAL = "partial"
    NON_CONFORMING = "non_conforming"
    NOT_APPLICABLE = "not_applicable"


# ── Data Models ───────────────────────────────────────────

@dataclass
class ISO27001Control:
    id: str
    title_fr: str
    category: ControlCategory
    description_fr: str = ""
    mapping_keywords: list[str] = field(default_factory=list)


@dataclass
class ControlAssessment:
    control_id: str
    title: str
    status: ControlStatus = ControlStatus.NON_CONFORMING
    maturity: MaturityLevel = MaturityLevel.INITIAL
    evidence: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class SoAEntry:
    control_id: str
    title: str
    applicable: bool = True
    justification: str = ""
    status: ControlStatus = ControlStatus.NON_CONFORMING
    implementation_date: str = ""


@dataclass
class CategoryScore:
    category: ControlCategory
    control_count: int = 0
    controls_met: int = 0
    score: float = 0.0
    controls: list[str] = field(default_factory=list)


@dataclass
class SkillInput:
    scope: str = "full"
    category_filter: Optional[str] = None
    include_soa: bool = True
    include_recommendations: bool = True


@dataclass
class ComplianceResult:
    overall_score: float = 0.0
    maturity_level: MaturityLevel = MaturityLevel.INITIAL
    category_scores: list[CategoryScore] = field(default_factory=list)
    total_controls: int = 0
    conforming_count: int = 0
    partial_count: int = 0
    non_conforming_count: int = 0
    not_applicable_count: int = 0
    soa: Optional[list[SoAEntry]] = None
    action_plan: list[str] = field(default_factory=list)
    summary_fr: str = ""


@dataclass
class SkillOutput:
    success: bool = False
    result: Optional[ComplianceResult] = None
    error: Optional[str] = None


# ── ISO 27001:2022 Annex A Controls (all 93) ─────────────

ANNEX_A_CONTROLS: list[ISO27001Control] = [
    # ── A.5 Organizational controls (37 controls) ─────────
    ISO27001Control(
        id="A.5.1",
        title_fr="Politiques de securite de l'information",
        category=ControlCategory.ORGANIZATIONAL,
        description_fr="Des politiques de securite de l'information et des politiques specifiques doivent etre definies, approuvees, publiees et communiquees.",
        mapping_keywords=["policy", "politique", "governance", "gouvernance", "security policy"],
    ),
    ISO27001Control(
        id="A.5.2",
        title_fr="Roles et responsabilites en matiere de securite de l'information",
        category=ControlCategory.ORGANIZATIONAL,
        description_fr="Les roles et responsabilites en matiere de securite de l'information doivent etre definis et attribues.",
        mapping_keywords=["role", "responsibility", "responsabilite", "rbac", "governance"],
    ),
    ISO27001Control(
        id="A.5.3",
        title_fr="Separation des taches",
        category=ControlCategory.ORGANIZATIONAL,
        description_fr="Les taches et domaines de responsabilite en conflit doivent etre separes.",
        mapping_keywords=["separation of duties", "segregation", "sod", "privilege"],
    ),
    ISO27001Control(
        id="A.5.4",
        title_fr="Responsabilites de la direction",
        category=ControlCategory.ORGANIZATIONAL,
        mapping_keywords=["management", "direction", "leadership"],
    ),
    ISO27001Control(
        id="A.5.5",
        title_fr="Contact avec les autorites",
        category=ControlCategory.ORGANIZATIONAL,
        mapping_keywords=["authority", "autorite", "regulation", "regulateur"],
    ),
    ISO27001Control(
        id="A.5.6",
        title_fr="Contact avec des groupes d'interet specialises",
        category=ControlCategory.ORGANIZATIONAL,
        mapping_keywords=["threat intelligence", "isac", "cert", "community"],
    ),
    ISO27001Control(
        id="A.5.7",
        title_fr="Renseignement sur les menaces",
        category=ControlCategory.ORGANIZATIONAL,
        description_fr="Les informations relatives aux menaces pour la securite de l'information doivent etre collectees et analysees.",
        mapping_keywords=["threat intelligence", "menace", "ioc", "darkweb", "threat feed", "cti"],
    ),
    ISO27001Control(
        id="A.5.8",
        title_fr="Securite de l'information dans la gestion de projet",
        category=ControlCategory.ORGANIZATIONAL,
        mapping_keywords=["project", "projet", "sdlc"],
    ),
    ISO27001Control(
        id="A.5.9",
        title_fr="Inventaire des informations et autres actifs associes",
        category=ControlCategory.ORGANIZATIONAL,
        description_fr="Un inventaire des informations et autres actifs associes doit etre elabore et tenu a jour.",
        mapping_keywords=["asset", "inventory", "inventaire", "cmdb", "asset management"],
    ),
    ISO27001Control(
        id="A.5.10",
        title_fr="Utilisation acceptable des informations et autres actifs associes",
        category=ControlCategory.ORGANIZATIONAL,
        mapping_keywords=["acceptable use", "usage", "policy"],
    ),
    ISO27001Control(
        id="A.5.11",
        title_fr="Restitution des actifs",
        category=ControlCategory.ORGANIZATIONAL,
        mapping_keywords=["asset return", "offboarding"],
    ),
    ISO27001Control(
        id="A.5.12",
        title_fr="Classification des informations",
        category=ControlCategory.ORGANIZATIONAL,
        description_fr="Les informations doivent etre classifiees selon les besoins de l'organisation.",
        mapping_keywords=["classification", "data classification", "label", "sensitivity"],
    ),
    ISO27001Control(
        id="A.5.13",
        title_fr="Marquage des informations",
        category=ControlCategory.ORGANIZATIONAL,
        mapping_keywords=["labeling", "marking", "marquage", "classification"],
    ),
    ISO27001Control(
        id="A.5.14",
        title_fr="Transfert des informations",
        category=ControlCategory.ORGANIZATIONAL,
        description_fr="Des regles, procedures ou accords de transfert d'informations doivent etre mis en place.",
        mapping_keywords=["transfer", "data transfer", "email", "sharing", "transmission"],
    ),
    ISO27001Control(
        id="A.5.15",
        title_fr="Controle d'acces",
        category=ControlCategory.ORGANIZATIONAL,
        description_fr="Des regles de controle d'acces doivent etre etablies et mises en oeuvre.",
        mapping_keywords=["access control", "acl", "authorization", "autorisation", "controle d'acces", "iam"],
    ),
    ISO27001Control(
        id="A.5.16",
        title_fr="Gestion des identites",
        category=ControlCategory.ORGANIZATIONAL,
        description_fr="Le cycle de vie complet des identites doit etre gere.",
        mapping_keywords=["identity", "identite", "iam", "identity management", "provisioning"],
    ),
    ISO27001Control(
        id="A.5.17",
        title_fr="Informations d'authentification",
        category=ControlCategory.ORGANIZATIONAL,
        description_fr="L'attribution et la gestion des informations d'authentification doivent etre controlees.",
        mapping_keywords=["authentication", "password", "credential", "mot de passe", "secret", "api key"],
    ),
    ISO27001Control(
        id="A.5.18",
        title_fr="Droits d'acces",
        category=ControlCategory.ORGANIZATIONAL,
        description_fr="Les droits d'acces doivent etre provisionnes, revises et retires.",
        mapping_keywords=["access rights", "privilege", "permission", "droit d'acces"],
    ),
    ISO27001Control(
        id="A.5.19",
        title_fr="Securite de l'information dans les relations avec les fournisseurs",
        category=ControlCategory.ORGANIZATIONAL,
        mapping_keywords=["supplier", "fournisseur", "third party", "supply chain", "vendor"],
    ),
    ISO27001Control(
        id="A.5.20",
        title_fr="Prise en compte de la securite dans les accords avec les fournisseurs",
        category=ControlCategory.ORGANIZATIONAL,
        mapping_keywords=["supplier agreement", "contract", "sla", "vendor"],
    ),
    ISO27001Control(
        id="A.5.21",
        title_fr="Gestion de la securite de l'information dans la chaine TIC",
        category=ControlCategory.ORGANIZATIONAL,
        description_fr="Des processus doivent etre definis pour gerer les risques de securite lies a la chaine d'approvisionnement TIC.",
        mapping_keywords=["supply chain", "ict", "third party risk", "sbom", "dependency"],
    ),
    ISO27001Control(
        id="A.5.22",
        title_fr="Surveillance, revision et gestion des changements des services fournisseurs",
        category=ControlCategory.ORGANIZATIONAL,
        mapping_keywords=["supplier monitoring", "vendor review", "change management"],
    ),
    ISO27001Control(
        id="A.5.23",
        title_fr="Securite de l'information dans l'utilisation de services en nuage",
        category=ControlCategory.ORGANIZATIONAL,
        description_fr="Les processus d'acquisition, d'utilisation et de sortie des services en nuage doivent etre etablis.",
        mapping_keywords=["cloud", "cloud security", "saas", "iaas", "paas", "cloud posture", "cspm"],
    ),
    ISO27001Control(
        id="A.5.24",
        title_fr="Planification et preparation de la gestion des incidents",
        category=ControlCategory.ORGANIZATIONAL,
        description_fr="L'organisation doit planifier et preparer la gestion des incidents de securite de l'information.",
        mapping_keywords=["incident", "incident response", "soc", "siem", "playbook", "ir plan"],
    ),
    ISO27001Control(
        id="A.5.25",
        title_fr="Evaluation et prise de decision concernant les evenements de securite",
        category=ControlCategory.ORGANIZATIONAL,
        mapping_keywords=["event", "assessment", "triage", "alert", "soc"],
    ),
    ISO27001Control(
        id="A.5.26",
        title_fr="Reponse aux incidents de securite de l'information",
        category=ControlCategory.ORGANIZATIONAL,
        description_fr="Les incidents de securite de l'information doivent faire l'objet d'une reponse documentee.",
        mapping_keywords=["incident response", "reponse incident", "soc", "playbook"],
    ),
    ISO27001Control(
        id="A.5.27",
        title_fr="Apprentissage des incidents de securite de l'information",
        category=ControlCategory.ORGANIZATIONAL,
        mapping_keywords=["lessons learned", "post mortem", "retex", "incident review"],
    ),
    ISO27001Control(
        id="A.5.28",
        title_fr="Collecte de preuves",
        category=ControlCategory.ORGANIZATIONAL,
        mapping_keywords=["evidence", "forensic", "preuve", "log", "audit trail"],
    ),
    ISO27001Control(
        id="A.5.29",
        title_fr="Securite de l'information durant une perturbation",
        category=ControlCategory.ORGANIZATIONAL,
        mapping_keywords=["disruption", "continuity", "crisis", "bcp", "drp"],
    ),
    ISO27001Control(
        id="A.5.30",
        title_fr="Preparation des TIC pour la continuite d'activite",
        category=ControlCategory.ORGANIZATIONAL,
        description_fr="La disponibilite des TIC doit etre planifiee, mise en oeuvre et testee.",
        mapping_keywords=["business continuity", "disaster recovery", "backup", "bcp", "drp", "haute disponibilite"],
    ),
    ISO27001Control(
        id="A.5.31",
        title_fr="Exigences legales, statutaires, reglementaires et contractuelles",
        category=ControlCategory.ORGANIZATIONAL,
        mapping_keywords=["legal", "regulatory", "compliance", "rgpd", "gdpr", "nis2", "reglementaire"],
    ),
    ISO27001Control(
        id="A.5.32",
        title_fr="Droits de propriete intellectuelle",
        category=ControlCategory.ORGANIZATIONAL,
        mapping_keywords=["intellectual property", "license", "copyright"],
    ),
    ISO27001Control(
        id="A.5.33",
        title_fr="Protection des enregistrements",
        category=ControlCategory.ORGANIZATIONAL,
        description_fr="Les enregistrements doivent etre proteges contre la perte, la destruction, la falsification et l'acces non autorise.",
        mapping_keywords=["records", "enregistrement", "data protection", "retention", "secret", "secrets management"],
    ),
    ISO27001Control(
        id="A.5.34",
        title_fr="Vie privee et protection des DCP",
        category=ControlCategory.ORGANIZATIONAL,
        description_fr="La vie privee et la protection des donnees a caractere personnel doivent etre assurees.",
        mapping_keywords=["privacy", "personal data", "pii", "dcp", "rgpd", "gdpr"],
    ),
    ISO27001Control(
        id="A.5.35",
        title_fr="Revue independante de la securite de l'information",
        category=ControlCategory.ORGANIZATIONAL,
        mapping_keywords=["audit", "review", "independent review", "pentest"],
    ),
    ISO27001Control(
        id="A.5.36",
        title_fr="Conformite aux politiques, regles et normes de securite de l'information",
        category=ControlCategory.ORGANIZATIONAL,
        mapping_keywords=["compliance", "conformite", "policy compliance", "audit"],
    ),
    ISO27001Control(
        id="A.5.37",
        title_fr="Procedures d'exploitation documentees",
        category=ControlCategory.ORGANIZATIONAL,
        mapping_keywords=["procedure", "documentation", "runbook", "sop"],
    ),

    # ── A.6 People controls (8 controls) ──────────────────
    ISO27001Control(
        id="A.6.1",
        title_fr="Verification des antecedents",
        category=ControlCategory.PEOPLE,
        mapping_keywords=["background check", "screening", "verification"],
    ),
    ISO27001Control(
        id="A.6.2",
        title_fr="Conditions d'emploi",
        category=ControlCategory.PEOPLE,
        mapping_keywords=["employment", "contract", "nda", "confidentiality"],
    ),
    ISO27001Control(
        id="A.6.3",
        title_fr="Sensibilisation, education et formation a la securite de l'information",
        category=ControlCategory.PEOPLE,
        description_fr="Le personnel doit recevoir une sensibilisation, education et formation appropriees.",
        mapping_keywords=["awareness", "training", "formation", "sensibilisation", "phishing simulation", "cyberhygiene"],
    ),
    ISO27001Control(
        id="A.6.4",
        title_fr="Processus disciplinaire",
        category=ControlCategory.PEOPLE,
        mapping_keywords=["disciplinary", "sanction", "violation"],
    ),
    ISO27001Control(
        id="A.6.5",
        title_fr="Responsabilites apres la fin ou le changement d'emploi",
        category=ControlCategory.PEOPLE,
        mapping_keywords=["offboarding", "termination", "depart"],
    ),
    ISO27001Control(
        id="A.6.6",
        title_fr="Accords de confidentialite ou de non-divulgation",
        category=ControlCategory.PEOPLE,
        mapping_keywords=["nda", "confidentiality", "non-disclosure"],
    ),
    ISO27001Control(
        id="A.6.7",
        title_fr="Travail a distance",
        category=ControlCategory.PEOPLE,
        description_fr="Des mesures de securite doivent etre mises en oeuvre pour le travail a distance.",
        mapping_keywords=["remote work", "telework", "vpn", "teletravail"],
    ),
    ISO27001Control(
        id="A.6.8",
        title_fr="Signalement des evenements de securite de l'information",
        category=ControlCategory.PEOPLE,
        mapping_keywords=["reporting", "signalement", "incident reporting", "whistleblowing"],
    ),

    # ── A.7 Physical controls (14 controls) ───────────────
    ISO27001Control(
        id="A.7.1",
        title_fr="Perimetres de securite physique",
        category=ControlCategory.PHYSICAL,
        mapping_keywords=["physical perimeter", "perimetre", "datacenter", "physical security"],
    ),
    ISO27001Control(
        id="A.7.2",
        title_fr="Controles physiques des entrees",
        category=ControlCategory.PHYSICAL,
        mapping_keywords=["physical access", "badge", "entry control"],
    ),
    ISO27001Control(
        id="A.7.3",
        title_fr="Securisation des bureaux, des salles et des equipements",
        category=ControlCategory.PHYSICAL,
        mapping_keywords=["office security", "room", "facility"],
    ),
    ISO27001Control(
        id="A.7.4",
        title_fr="Surveillance de la securite physique",
        category=ControlCategory.PHYSICAL,
        mapping_keywords=["surveillance", "cctv", "monitoring", "camera"],
    ),
    ISO27001Control(
        id="A.7.5",
        title_fr="Protection contre les menaces physiques et environnementales",
        category=ControlCategory.PHYSICAL,
        mapping_keywords=["environmental", "fire", "flood", "disaster"],
    ),
    ISO27001Control(
        id="A.7.6",
        title_fr="Travail dans les zones securisees",
        category=ControlCategory.PHYSICAL,
        mapping_keywords=["secure area", "zone securisee", "restricted area"],
    ),
    ISO27001Control(
        id="A.7.7",
        title_fr="Bureau propre et ecran vide",
        category=ControlCategory.PHYSICAL,
        mapping_keywords=["clear desk", "clear screen", "bureau propre"],
    ),
    ISO27001Control(
        id="A.7.8",
        title_fr="Emplacement et protection du materiel",
        category=ControlCategory.PHYSICAL,
        mapping_keywords=["equipment", "placement", "protection materiel"],
    ),
    ISO27001Control(
        id="A.7.9",
        title_fr="Securite des actifs hors des locaux",
        category=ControlCategory.PHYSICAL,
        mapping_keywords=["offsite", "mobile device", "laptop", "hors site"],
    ),
    ISO27001Control(
        id="A.7.10",
        title_fr="Supports de stockage",
        category=ControlCategory.PHYSICAL,
        description_fr="Les supports de stockage doivent etre geres tout au long de leur cycle de vie.",
        mapping_keywords=["storage media", "usb", "disk", "media disposal", "support stockage"],
    ),
    ISO27001Control(
        id="A.7.11",
        title_fr="Services generaux",
        category=ControlCategory.PHYSICAL,
        mapping_keywords=["utilities", "power", "ups", "hvac"],
    ),
    ISO27001Control(
        id="A.7.12",
        title_fr="Securite du cablage",
        category=ControlCategory.PHYSICAL,
        mapping_keywords=["cabling", "network cable", "cablage"],
    ),
    ISO27001Control(
        id="A.7.13",
        title_fr="Maintenance du materiel",
        category=ControlCategory.PHYSICAL,
        mapping_keywords=["maintenance", "hardware maintenance", "materiel"],
    ),
    ISO27001Control(
        id="A.7.14",
        title_fr="Mise au rebut ou reutilisation securisee du materiel",
        category=ControlCategory.PHYSICAL,
        mapping_keywords=["disposal", "reuse", "sanitization", "decommission"],
    ),

    # ── A.8 Technological controls (34 controls) ──────────
    ISO27001Control(
        id="A.8.1",
        title_fr="Terminaux utilisateurs",
        category=ControlCategory.TECHNOLOGICAL,
        description_fr="Les informations stockees, traitees ou accessibles via les terminaux utilisateurs doivent etre protegees.",
        mapping_keywords=["endpoint", "device", "terminal", "edr", "endpoint security", "mdm"],
    ),
    ISO27001Control(
        id="A.8.2",
        title_fr="Droits d'acces a privileges",
        category=ControlCategory.TECHNOLOGICAL,
        description_fr="L'attribution et l'utilisation des droits d'acces a privileges doivent etre restreintes et gerees.",
        mapping_keywords=["privileged access", "admin", "root", "sudo", "pam", "privilege escalation"],
    ),
    ISO27001Control(
        id="A.8.3",
        title_fr="Restriction d'acces aux informations",
        category=ControlCategory.TECHNOLOGICAL,
        mapping_keywords=["access restriction", "data access", "need to know", "rbac"],
    ),
    ISO27001Control(
        id="A.8.4",
        title_fr="Acces au code source",
        category=ControlCategory.TECHNOLOGICAL,
        description_fr="L'acces en lecture et en ecriture au code source, aux outils de developpement et aux bibliotheques doit etre gere de maniere appropriee.",
        mapping_keywords=["source code", "repository", "git", "code access", "scm"],
    ),
    ISO27001Control(
        id="A.8.5",
        title_fr="Authentification securisee",
        category=ControlCategory.TECHNOLOGICAL,
        description_fr="Les technologies et procedures d'authentification securisees doivent etre mises en oeuvre.",
        mapping_keywords=["authentication", "mfa", "2fa", "sso", "oauth", "saml", "authentification"],
    ),
    ISO27001Control(
        id="A.8.6",
        title_fr="Dimensionnement",
        category=ControlCategory.TECHNOLOGICAL,
        mapping_keywords=["capacity", "dimensionnement", "scaling", "performance"],
    ),
    ISO27001Control(
        id="A.8.7",
        title_fr="Protection contre les programmes malveillants",
        category=ControlCategory.TECHNOLOGICAL,
        description_fr="La protection contre les programmes malveillants doit etre mise en oeuvre et soutenue par une sensibilisation appropriee.",
        mapping_keywords=["malware", "antivirus", "anti-malware", "edr", "xdr", "virus"],
    ),
    ISO27001Control(
        id="A.8.8",
        title_fr="Gestion des vulnerabilites techniques",
        category=ControlCategory.TECHNOLOGICAL,
        description_fr="Les informations sur les vulnerabilites techniques doivent etre obtenues, l'exposition evaluee et les mesures appropriees prises.",
        mapping_keywords=["vulnerability", "vulnerabilite", "cve", "patch", "vuln scan", "vulnerability management", "nuclei", "grype"],
    ),
    ISO27001Control(
        id="A.8.9",
        title_fr="Gestion de la configuration",
        category=ControlCategory.TECHNOLOGICAL,
        description_fr="Les configurations doivent etre etablies, documentees, mises en oeuvre, surveillees et revisees.",
        mapping_keywords=["configuration", "hardening", "baseline", "cis benchmark", "misconfiguration", "cloud posture"],
    ),
    ISO27001Control(
        id="A.8.10",
        title_fr="Suppression des informations",
        category=ControlCategory.TECHNOLOGICAL,
        mapping_keywords=["data deletion", "erasure", "suppression", "data lifecycle"],
    ),
    ISO27001Control(
        id="A.8.11",
        title_fr="Masquage des donnees",
        category=ControlCategory.TECHNOLOGICAL,
        mapping_keywords=["data masking", "anonymization", "pseudonymization", "masquage"],
    ),
    ISO27001Control(
        id="A.8.12",
        title_fr="Prevention de la fuite de donnees",
        category=ControlCategory.TECHNOLOGICAL,
        description_fr="Des mesures de prevention de la fuite de donnees doivent etre appliquees.",
        mapping_keywords=["dlp", "data leak", "data loss prevention", "exfiltration", "fuite de donnees"],
    ),
    ISO27001Control(
        id="A.8.13",
        title_fr="Sauvegarde des informations",
        category=ControlCategory.TECHNOLOGICAL,
        mapping_keywords=["backup", "sauvegarde", "restore", "recovery"],
    ),
    ISO27001Control(
        id="A.8.14",
        title_fr="Redondance des moyens de traitement de l'information",
        category=ControlCategory.TECHNOLOGICAL,
        mapping_keywords=["redundancy", "high availability", "failover", "redondance"],
    ),
    ISO27001Control(
        id="A.8.15",
        title_fr="Journalisation",
        category=ControlCategory.TECHNOLOGICAL,
        description_fr="Des journaux enregistrant les activites, exceptions, defaillances et autres evenements pertinents doivent etre produits, stockes, proteges et analyses.",
        mapping_keywords=["logging", "log", "journal", "siem", "audit log", "journalisation"],
    ),
    ISO27001Control(
        id="A.8.16",
        title_fr="Activites de surveillance",
        category=ControlCategory.TECHNOLOGICAL,
        description_fr="Les reseaux, systemes et applications doivent etre surveilles.",
        mapping_keywords=["monitoring", "surveillance", "soc", "detection", "alerting", "siem"],
    ),
    ISO27001Control(
        id="A.8.17",
        title_fr="Synchronisation des horloges",
        category=ControlCategory.TECHNOLOGICAL,
        mapping_keywords=["ntp", "time sync", "clock", "horloge"],
    ),
    ISO27001Control(
        id="A.8.18",
        title_fr="Utilisation de programmes utilitaires a privileges",
        category=ControlCategory.TECHNOLOGICAL,
        mapping_keywords=["utility", "privileged utility", "admin tool"],
    ),
    ISO27001Control(
        id="A.8.19",
        title_fr="Installation de logiciels sur les systemes en exploitation",
        category=ControlCategory.TECHNOLOGICAL,
        mapping_keywords=["software installation", "deployment", "package management"],
    ),
    ISO27001Control(
        id="A.8.20",
        title_fr="Securite des reseaux",
        category=ControlCategory.TECHNOLOGICAL,
        description_fr="Les reseaux et les dispositifs de reseau doivent etre securises, geres et controles.",
        mapping_keywords=["network security", "firewall", "ids", "ips", "network segmentation", "reseau"],
    ),
    ISO27001Control(
        id="A.8.21",
        title_fr="Securite des services reseau",
        category=ControlCategory.TECHNOLOGICAL,
        mapping_keywords=["network service", "dns", "dhcp", "proxy", "service reseau"],
    ),
    ISO27001Control(
        id="A.8.22",
        title_fr="Filtrage du trafic reseau",
        category=ControlCategory.TECHNOLOGICAL,
        mapping_keywords=["filtering", "firewall", "waf", "acl", "network filter", "filtrage"],
    ),
    ISO27001Control(
        id="A.8.23",
        title_fr="Filtrage web",
        category=ControlCategory.TECHNOLOGICAL,
        mapping_keywords=["web filtering", "proxy", "url filtering", "content filter"],
    ),
    ISO27001Control(
        id="A.8.24",
        title_fr="Utilisation de la cryptographie",
        category=ControlCategory.TECHNOLOGICAL,
        description_fr="Des regles pour l'utilisation efficace de la cryptographie, y compris la gestion des cles cryptographiques, doivent etre definies et mises en oeuvre.",
        mapping_keywords=["cryptography", "encryption", "chiffrement", "tls", "ssl", "certificate", "key management", "pki"],
    ),
    ISO27001Control(
        id="A.8.25",
        title_fr="Cycle de vie de developpement securise",
        category=ControlCategory.TECHNOLOGICAL,
        description_fr="Des regles pour le developpement securise de logiciels et de systemes doivent etre etablies et appliquees.",
        mapping_keywords=["sdlc", "secure development", "devsecops", "sast", "dast", "code review", "appsec"],
    ),
    ISO27001Control(
        id="A.8.26",
        title_fr="Exigences de securite des applications",
        category=ControlCategory.TECHNOLOGICAL,
        description_fr="Les exigences de securite de l'information doivent etre identifiees, specifiees et approuvees lors du developpement ou de l'acquisition d'applications.",
        mapping_keywords=["application security", "security requirements", "appsec", "owasp"],
    ),
    ISO27001Control(
        id="A.8.27",
        title_fr="Principes d'ingenierie et d'architecture de systemes securises",
        category=ControlCategory.TECHNOLOGICAL,
        mapping_keywords=["secure architecture", "security by design", "architecture", "zero trust"],
    ),
    ISO27001Control(
        id="A.8.28",
        title_fr="Codage securise",
        category=ControlCategory.TECHNOLOGICAL,
        description_fr="Des principes de codage securise doivent etre appliques au developpement de logiciels.",
        mapping_keywords=["secure coding", "sast", "code review", "owasp", "injection", "xss", "sqli"],
    ),
    ISO27001Control(
        id="A.8.29",
        title_fr="Tests de securite dans le developpement et l'acceptation",
        category=ControlCategory.TECHNOLOGICAL,
        mapping_keywords=["security testing", "pentest", "dast", "test securite", "penetration test"],
    ),
    ISO27001Control(
        id="A.8.30",
        title_fr="Developpement externalise",
        category=ControlCategory.TECHNOLOGICAL,
        mapping_keywords=["outsourced development", "third party development", "vendor code"],
    ),
    ISO27001Control(
        id="A.8.31",
        title_fr="Separation des environnements de developpement, de test et de production",
        category=ControlCategory.TECHNOLOGICAL,
        mapping_keywords=["environment separation", "dev", "staging", "production", "separation environnement"],
    ),
    ISO27001Control(
        id="A.8.32",
        title_fr="Gestion des changements",
        category=ControlCategory.TECHNOLOGICAL,
        mapping_keywords=["change management", "change control", "gestion changement"],
    ),
    ISO27001Control(
        id="A.8.33",
        title_fr="Informations de test",
        category=ControlCategory.TECHNOLOGICAL,
        mapping_keywords=["test data", "donnees de test", "data anonymization"],
    ),
    ISO27001Control(
        id="A.8.34",
        title_fr="Protection des systemes d'information au cours des tests d'audit",
        category=ControlCategory.TECHNOLOGICAL,
        mapping_keywords=["audit test", "pentest scope", "audit protection"],
    ),
]


# ── Derived indexes ───────────────────────────────────────

def _build_control_map() -> dict[str, ISO27001Control]:
    return {c.id: c for c in ANNEX_A_CONTROLS}


CONTROL_MAP: dict[str, ISO27001Control] = _build_control_map()


# Source-to-control mapping: finding sources to the most relevant control IDs
SOURCE_CONTROL_MAP: dict[str, list[str]] = {
    "nuclei": ["A.8.8", "A.8.20", "A.8.9"],
    "grype": ["A.8.8", "A.8.25", "A.5.21"],
    "vuln-scan": ["A.8.8", "A.8.9"],
    "secrets": ["A.5.17", "A.5.33", "A.8.4"],
    "cloud-posture": ["A.5.23", "A.8.9", "A.8.1"],
    "appsec": ["A.8.25", "A.8.26", "A.8.28"],
    "soc-monitor": ["A.5.24", "A.5.25", "A.5.26", "A.8.16"],
    "phishing": ["A.6.3", "A.5.14", "A.8.7"],
    "darkweb": ["A.5.7", "A.8.12"],
    "email-audit": ["A.5.14", "A.8.24", "A.8.5"],
}


# ── Finding Mapping ───────────────────────────────────────

def map_finding_to_controls(finding: dict) -> list[str]:
    """
    Map a security finding to ISO 27001 Annex A control IDs.

    Args:
        finding: dict with keys like 'source', 'title', 'description',
                 'category', 'severity', 'keywords' (any subset).

    Returns:
        List of control IDs (e.g. ["A.8.8", "A.5.17"]).
    """
    matched: set[str] = set()

    # 1) Source-based mapping
    source = finding.get("source", "").lower()
    for src_key, control_ids in SOURCE_CONTROL_MAP.items():
        if src_key in source:
            matched.update(control_ids)

    # 2) Keyword-based mapping
    text_fields = []
    for key in ("title", "description", "category", "template_id"):
        val = finding.get(key, "")
        if val:
            text_fields.append(val.lower())

    keyword_list = finding.get("keywords", [])
    if keyword_list:
        text_fields.extend([k.lower() for k in keyword_list])

    combined_text = " ".join(text_fields)

    for control in ANNEX_A_CONTROLS:
        if not control.mapping_keywords:
            continue
        for kw in control.mapping_keywords:
            if kw.lower() in combined_text:
                matched.add(control.id)
                break

    return sorted(matched)


# ── Maturity Assessment ───────────────────────────────────

def _determine_maturity(findings_for_control: list[dict]) -> MaturityLevel:
    """Determine maturity level based on findings associated with a control."""
    if not findings_for_control:
        return MaturityLevel.INITIAL

    severities = []
    for f in findings_for_control:
        sev = f.get("severity", "info").lower()
        severities.append(sev)

    critical_high = sum(1 for s in severities if s in ("critical", "high"))
    medium = sum(1 for s in severities if s == "medium")
    total = len(severities)

    if critical_high > 0:
        return MaturityLevel.INITIAL
    elif medium > total * 0.5:
        return MaturityLevel.MANAGED
    elif medium > 0:
        return MaturityLevel.DEFINED
    else:
        return MaturityLevel.MEASURED


def _determine_status(findings_for_control: list[dict]) -> ControlStatus:
    """Determine conformity status based on findings associated with a control."""
    if not findings_for_control:
        return ControlStatus.CONFORMING

    severities = []
    for f in findings_for_control:
        sev = f.get("severity", "info").lower()
        severities.append(sev)

    critical_high = sum(1 for s in severities if s in ("critical", "high"))

    if critical_high > 0:
        return ControlStatus.NON_CONFORMING
    else:
        return ControlStatus.PARTIAL


def assess_control(
    control: ISO27001Control,
    findings: list[dict],
) -> ControlAssessment:
    """
    Assess a single control against findings.

    Args:
        control: The ISO 27001 control to assess.
        findings: All findings; this function filters relevant ones.

    Returns:
        ControlAssessment with status, maturity, evidence, gaps, recommendations.
    """
    # Find findings related to this control
    related: list[dict] = []
    for f in findings:
        mapped_controls = map_finding_to_controls(f)
        if control.id in mapped_controls:
            related.append(f)

    status = _determine_status(related)
    maturity = _determine_maturity(related)

    evidence = []
    gaps = []
    recommendations = []

    if related:
        evidence = [
            f.get("title", f.get("cve_id", "Finding"))
            for f in related
        ]

    if status == ControlStatus.NON_CONFORMING:
        gaps.append(f"Controle {control.id} non conforme : {len(related)} finding(s) critique(s)/eleve(s)")
        recommendations.append(
            f"Remediez aux {len(related)} finding(s) affectant {control.id} ({control.title_fr})"
        )
    elif status == ControlStatus.PARTIAL:
        gaps.append(f"Controle {control.id} partiellement conforme : {len(related)} finding(s) de severite moyenne/basse")
        recommendations.append(
            f"Ameliorez la conformite de {control.id} en traitant les {len(related)} finding(s) restant(s)"
        )

    return ControlAssessment(
        control_id=control.id,
        title=control.title_fr,
        status=status,
        maturity=maturity,
        evidence=evidence,
        gaps=gaps,
        recommendations=recommendations,
    )


# ── Statement of Applicability (SoA) ─────────────────────

def generate_soa(assessments: list[ControlAssessment]) -> list[SoAEntry]:
    """
    Generate Statement of Applicability from control assessments.

    Args:
        assessments: List of ControlAssessment for each control.

    Returns:
        List of SoAEntry, one per control.
    """
    soa: list[SoAEntry] = []
    for a in assessments:
        applicable = a.status != ControlStatus.NOT_APPLICABLE
        justification = ""
        if not applicable:
            justification = "Controle juge non applicable au perimetre de l'organisation."
        elif a.status == ControlStatus.CONFORMING:
            justification = "Controle mis en oeuvre et conforme."
        elif a.status == ControlStatus.PARTIAL:
            justification = "Controle partiellement mis en oeuvre, amelioration necessaire."
        else:
            justification = "Controle non mis en oeuvre, action corrective requise."

        soa.append(SoAEntry(
            control_id=a.control_id,
            title=a.title,
            applicable=applicable,
            justification=justification,
            status=a.status,
        ))
    return soa


# ── Compliance Score ──────────────────────────────────────

def calculate_compliance_score(assessments: list[ControlAssessment]) -> float:
    """
    Calculate overall compliance score.

    Formula: (conforming + 0.5 * partial) / applicable * 100

    Args:
        assessments: List of ControlAssessment.

    Returns:
        Score from 0.0 to 100.0.
    """
    applicable = [a for a in assessments if a.status != ControlStatus.NOT_APPLICABLE]
    if not applicable:
        return 0.0

    conforming = sum(1 for a in applicable if a.status == ControlStatus.CONFORMING)
    partial = sum(1 for a in applicable if a.status == ControlStatus.PARTIAL)

    return round((conforming + 0.5 * partial) / len(applicable) * 100, 2)


def calculate_category_scores(
    assessments: list[ControlAssessment],
) -> list[CategoryScore]:
    """
    Calculate compliance score per control category.

    Args:
        assessments: List of ControlAssessment.

    Returns:
        List of CategoryScore, one per category.
    """
    # Group assessments by category
    category_assessments: dict[ControlCategory, list[ControlAssessment]] = {
        cat: [] for cat in ControlCategory
    }

    for a in assessments:
        control = CONTROL_MAP.get(a.control_id)
        if control:
            category_assessments[control.category].append(a)

    scores: list[CategoryScore] = []
    for cat in ControlCategory:
        cat_assessments = category_assessments[cat]
        applicable = [a for a in cat_assessments if a.status != ControlStatus.NOT_APPLICABLE]

        if not applicable:
            score_val = 0.0
        else:
            conforming = sum(1 for a in applicable if a.status == ControlStatus.CONFORMING)
            partial = sum(1 for a in applicable if a.status == ControlStatus.PARTIAL)
            score_val = round((conforming + 0.5 * partial) / len(applicable) * 100, 2)

        controls_met = sum(
            1 for a in cat_assessments if a.status == ControlStatus.CONFORMING
        )

        scores.append(CategoryScore(
            category=cat,
            control_count=len(cat_assessments),
            controls_met=controls_met,
            score=score_val,
            controls=[a.control_id for a in cat_assessments],
        ))

    return scores


# ── Overall Maturity ──────────────────────────────────────

def _overall_maturity(score: float) -> MaturityLevel:
    """Map overall compliance score to a maturity level."""
    if score >= 90:
        return MaturityLevel.OPTIMIZED
    elif score >= 70:
        return MaturityLevel.MEASURED
    elif score >= 50:
        return MaturityLevel.DEFINED
    elif score >= 25:
        return MaturityLevel.MANAGED
    else:
        return MaturityLevel.INITIAL


# ── Action Plan ───────────────────────────────────────────

def _build_action_plan(assessments: list[ControlAssessment]) -> list[str]:
    """Build prioritised action plan from non-conforming and partial controls."""
    actions: list[str] = []

    # Non-conforming first (priority)
    for a in assessments:
        if a.status == ControlStatus.NON_CONFORMING:
            for rec in a.recommendations:
                actions.append(f"[PRIORITAIRE] {rec}")

    # Then partial
    for a in assessments:
        if a.status == ControlStatus.PARTIAL:
            for rec in a.recommendations:
                actions.append(f"[AMELIORATION] {rec}")

    return actions


# ── Main Entry Point ──────────────────────────────────────

async def run(input: SkillInput) -> SkillOutput:
    """
    Main skill entry point.

    Args:
        input: SkillInput with scope, filters and options.

    Returns:
        SkillOutput with ComplianceResult or error.
    """
    try:
        # Determine which controls to assess
        controls = ANNEX_A_CONTROLS
        if input.scope == "category" and input.category_filter:
            prefix = input.category_filter
            controls = [c for c in ANNEX_A_CONTROLS if c.id.startswith(prefix)]
            if not controls:
                return SkillOutput(
                    success=False,
                    error=f"Aucun controle trouve pour le filtre : {prefix}",
                )

        # TODO: Fetch findings from PostgreSQL / other skills
        # For now, assess with empty findings (= all conforming baseline)
        findings: list[dict] = []

        # Assess each control
        assessments = [assess_control(c, findings) for c in controls]

        # Calculate scores
        overall_score = calculate_compliance_score(assessments)
        maturity = _overall_maturity(overall_score)
        category_scores = calculate_category_scores(assessments)

        # Counts
        conforming_count = sum(1 for a in assessments if a.status == ControlStatus.CONFORMING)
        partial_count = sum(1 for a in assessments if a.status == ControlStatus.PARTIAL)
        non_conforming_count = sum(1 for a in assessments if a.status == ControlStatus.NON_CONFORMING)
        not_applicable_count = sum(1 for a in assessments if a.status == ControlStatus.NOT_APPLICABLE)

        # SoA
        soa = None
        if input.include_soa:
            soa = generate_soa(assessments)

        # Action plan
        action_plan = _build_action_plan(assessments) if input.include_recommendations else []

        # Summary
        summary_fr = (
            f"Evaluation ISO 27001:2022 Annexe A — "
            f"Score global : {overall_score:.1f}% — "
            f"Maturite : {maturity.name} — "
            f"{conforming_count} conformes, {partial_count} partiels, "
            f"{non_conforming_count} non conformes, {not_applicable_count} non applicables "
            f"sur {len(assessments)} controles evalues."
        )

        result = ComplianceResult(
            overall_score=overall_score,
            maturity_level=maturity,
            category_scores=category_scores,
            total_controls=len(assessments),
            conforming_count=conforming_count,
            partial_count=partial_count,
            non_conforming_count=non_conforming_count,
            not_applicable_count=not_applicable_count,
            soa=soa,
            action_plan=action_plan,
            summary_fr=summary_fr,
        )

        return SkillOutput(success=True, result=result)

    except Exception as e:
        return SkillOutput(success=False, error=str(e))
