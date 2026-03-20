export interface Skill {
  id: string;
  name: string;
  version: string;
  author: string;
  description: string;
  longDescription: string;
  icon: string;
  tags: string[];
  trust: "official" | "verified" | "community";
  installed: boolean;
  hasUpdate?: boolean;
  stars: number;
  downloads: number;
  permissions: string[];
  changelog: string[];
}

export const skills: Skill[] = [
  // ── Installed (10 core skills) ──
  {
    id: "skill-vuln-scan",
    name: "Scan Vulnérabilités",
    version: "1.0.0",
    author: "ThreatClaw",
    description: "Scanner de vulnérabilités réseau avec Nuclei et Nmap",
    longDescription:
      "Analyse complète de votre infrastructure réseau. Détection de CVE, ports ouverts, services obsolètes. Intégration Nuclei pour les templates de détection et Nmap pour la découverte réseau. Rapports détaillés avec scoring CVSS.",
    icon: "Crosshair",
    tags: ["scanning", "réseau", "CVE"],
    trust: "official",
    installed: true,
    stars: 245,
    downloads: 1823,
    permissions: ["network_scan", "docker_exec", "db_write"],
    changelog: [
      "1.0.0 — Version initiale avec Nuclei + Nmap",
      "0.9.0 — Beta: templates Nuclei personnalisés",
    ],
  },
  {
    id: "skill-secrets-audit",
    name: "Audit Secrets",
    version: "1.0.0",
    author: "ThreatClaw",
    description: "Détection de secrets exposés (clés API, mots de passe, tokens)",
    longDescription:
      "Scanne vos dépôts Git, fichiers de configuration et variables d'environnement pour détecter les secrets exposés. Supporte plus de 150 types de secrets (AWS, GCP, GitHub, Slack, etc.). Alertes en temps réel.",
    icon: "KeyRound",
    tags: ["secrets", "git", "compliance"],
    trust: "official",
    installed: true,
    stars: 198,
    downloads: 1456,
    permissions: ["file_read", "git_access", "db_write"],
    changelog: [
      "1.0.0 — Version initiale, 150+ patterns",
      "0.8.0 — Support des regex personnalisés",
    ],
  },
  {
    id: "skill-email-audit",
    name: "Audit Email",
    version: "1.0.0",
    author: "ThreatClaw",
    description: "Audit sécurité email — SPF, DKIM, DMARC, BIMI",
    longDescription:
      "Vérifie la configuration de sécurité de vos domaines email. Analyse SPF, DKIM, DMARC et BIMI. Détection des misconfiguration courantes. Score de maturité email avec recommandations.",
    icon: "Mail",
    tags: ["email", "DNS", "compliance"],
    trust: "official",
    installed: true,
    stars: 167,
    downloads: 1234,
    permissions: ["dns_query", "db_write"],
    changelog: ["1.0.0 — Support complet SPF/DKIM/DMARC/BIMI"],
  },
  {
    id: "skill-darkweb-monitor",
    name: "Surveillance Dark Web",
    version: "1.0.0",
    author: "ThreatClaw",
    description: "Surveillance dark web et fuites de données",
    longDescription:
      "Monitore les forums, marketplaces et paste sites du dark web pour détecter les fuites de données liées à votre organisation. Alertes sur les identifiants compromis, documents exfiltrés et mentions de votre marque.",
    icon: "Eye",
    tags: ["darkweb", "monitoring", "fuites"],
    trust: "official",
    installed: true,
    stars: 312,
    downloads: 2105,
    permissions: ["network_scan", "db_write", "alert_send"],
    changelog: [
      "1.0.0 — Monitoring paste sites + forums",
      "0.7.0 — Alertes Slack intégrées",
    ],
  },
  {
    id: "skill-phishing-sim",
    name: "Simulation Phishing",
    version: "1.0.0",
    author: "ThreatClaw",
    description: "Campagnes de simulation phishing pour sensibiliser vos équipes",
    longDescription:
      "Créez et lancez des campagnes de phishing simulé. Templates réalistes, tracking des clics et ouvertures, rapports de sensibilisation par département. Conformité NIS2 Art.21 §2g.",
    icon: "Fish",
    tags: ["phishing", "sensibilisation", "NIS2"],
    trust: "official",
    installed: true,
    stars: 289,
    downloads: 1890,
    permissions: ["email_send", "db_write", "alert_send"],
    changelog: [
      "1.0.0 — Templates FR + tracking complet",
      "0.9.0 — Rapports par département",
    ],
  },
  {
    id: "skill-soc-monitor",
    name: "Monitoring SOC",
    version: "1.0.0",
    author: "ThreatClaw",
    description: "Monitoring SOC avec moteur Sigma et corrélation d'événements",
    longDescription:
      "Analyse en temps réel des logs avec un moteur de règles Sigma intégré. Corrélation d'événements multi-sources, détection d'anomalies, et alertes contextualisées. Compatible Fluent Bit, syslog, et Docker.",
    icon: "Monitor",
    tags: ["SOC", "Sigma", "logs", "SIEM"],
    trust: "official",
    installed: true,
    stars: 356,
    downloads: 2340,
    permissions: ["log_read", "db_write", "alert_send", "docker_exec"],
    changelog: [
      "1.0.0 — Moteur Sigma + Fluent Bit",
      "0.8.0 — Corrélation multi-sources",
    ],
  },
  {
    id: "skill-cloud-posture",
    name: "Audit Cloud",
    version: "1.0.0",
    author: "ThreatClaw",
    description: "Audit posture cloud — AWS, Azure, GCP avec Prowler",
    longDescription:
      "Évalue la posture de sécurité de vos environnements cloud. Intégration Prowler pour AWS/Azure/GCP. Mapping automatique NIS2 et ISO 27001. Score de conformité cloud avec recommandations priorisées.",
    icon: "Cloud",
    tags: ["cloud", "AWS", "Azure", "GCP", "compliance"],
    trust: "official",
    installed: true,
    stars: 278,
    downloads: 1678,
    permissions: ["cloud_api", "db_write", "alert_send"],
    changelog: [
      "1.0.0 — Support AWS/Azure/GCP",
      "0.9.0 — Mapping NIS2 automatique",
    ],
  },
  {
    id: "skill-report-gen",
    name: "Génération Rapports",
    version: "1.0.0",
    author: "ThreatClaw",
    description: "Génération de rapports PDF/HTML en français pour le RSSI",
    longDescription:
      "Génère des rapports de sécurité professionnels en français. Templates pour rapports mensuels, audits NIS2, briefs exécutifs. Export PDF et HTML. Graphiques et KPIs intégrés.",
    icon: "FileText",
    tags: ["rapports", "PDF", "RSSI"],
    trust: "official",
    installed: true,
    stars: 201,
    downloads: 1567,
    permissions: ["db_read", "file_write"],
    changelog: [
      "1.0.0 — Templates FR + export PDF/HTML",
      "0.9.0 — Graphiques Recharts intégrés",
    ],
  },
  {
    id: "skill-compliance-nis2",
    name: "Conformité NIS2",
    version: "1.0.0",
    author: "ThreatClaw",
    description: "Mapping conformité NIS2 — Directive 2022/2555 Art.21",
    longDescription:
      "Évalue votre conformité à la directive NIS2 (UE 2022/2555). Mapping des 10 mesures de l'Article 21. Scoring par article, identification des écarts, et plan de remédiation priorisé. Conforme aux exigences ANSSI.",
    icon: "ShieldCheck",
    tags: ["NIS2", "compliance", "ANSSI", "UE"],
    trust: "official",
    installed: true,
    stars: 334,
    downloads: 2456,
    permissions: ["db_read", "db_write"],
    changelog: [
      "1.0.0 — Mapping complet Art.21 §1-10",
      "0.9.0 — Scoring et plan de remédiation",
    ],
  },
  {
    id: "skill-compliance-iso27001",
    name: "Conformité ISO 27001",
    version: "1.0.0",
    author: "ThreatClaw",
    description: "Conformité ISO 27001:2022 — 93 contrôles Annexe A",
    longDescription:
      "Évalue votre conformité ISO 27001:2022. Couvre les 93 contrôles de l'Annexe A répartis en 4 catégories. Matrice de correspondance avec NIS2. Score de maturité et roadmap d'amélioration.",
    icon: "Award",
    tags: ["ISO27001", "compliance", "audit"],
    trust: "official",
    installed: true,
    stars: 298,
    downloads: 2123,
    permissions: ["db_read", "db_write"],
    changelog: [
      "1.0.0 — 93 contrôles Annexe A",
      "0.9.0 — Correspondance NIS2",
    ],
  },

  // ── Available (community/marketplace) ──
  {
    id: "skill-ad-audit",
    name: "Audit Active Directory",
    version: "0.3.1",
    author: "CyberDefense.fr",
    description: "Audit Active Directory — GPO, Kerberos, permissions NTFS",
    longDescription:
      "Analyse complète de votre Active Directory. Détection des mauvaises configurations GPO, vulnérabilités Kerberoasting/AS-REP Roasting, permissions NTFS excessives, comptes dormants et élévation de privilèges.",
    icon: "Users",
    tags: ["AD", "Kerberos", "Windows"],
    trust: "community",
    installed: false,
    stars: 89,
    downloads: 423,
    permissions: ["ldap_query", "network_scan", "db_write"],
    changelog: [
      "0.3.1 — Fix Kerberoasting detection",
      "0.3.0 — Support multi-domaines",
      "0.2.0 — Analyse GPO",
    ],
  },
  {
    id: "skill-wifi-audit",
    name: "Audit WiFi",
    version: "0.2.0",
    author: "WifiSec",
    description: "Audit sécurité WiFi — WPA3, rogue AP, Evil Twin",
    longDescription:
      "Scanne vos réseaux WiFi pour détecter les points d'accès non autorisés, vérifier la configuration WPA3, et identifier les vulnérabilités Evil Twin et KRACK.",
    icon: "Wifi",
    tags: ["WiFi", "réseau", "sans-fil"],
    trust: "community",
    installed: false,
    stars: 56,
    downloads: 234,
    permissions: ["network_scan", "db_write"],
    changelog: [
      "0.2.0 — Détection Evil Twin",
      "0.1.0 — Scan basique WPA/WPA2/WPA3",
    ],
  },
  {
    id: "skill-backup-check",
    name: "Vérification Sauvegardes",
    version: "1.1.0",
    author: "DataSafe",
    description: "Vérification des sauvegardes — règle 3-2-1, intégrité, RPO/RTO",
    longDescription:
      "Vérifie que vos sauvegardes respectent la règle 3-2-1 (3 copies, 2 supports, 1 hors-site). Teste l'intégrité des backups, mesure les RPO/RTO réels, et alerte en cas de non-conformité.",
    icon: "HardDrive",
    tags: ["backup", "PRA", "données"],
    trust: "verified",
    installed: false,
    stars: 134,
    downloads: 876,
    permissions: ["file_read", "cloud_api", "db_write", "alert_send"],
    changelog: [
      "1.1.0 — Support S3/Azure Blob",
      "1.0.0 — Vérification 3-2-1 + intégrité",
    ],
  },
  {
    id: "skill-cert-monitor",
    name: "Surveillance Certificats",
    version: "1.0.2",
    author: "CertWatch",
    description: "Surveillance expiration certificats SSL/TLS et Certificate Transparency",
    longDescription:
      "Monitore l'expiration de vos certificats SSL/TLS. Alertes 30/15/7 jours avant expiration. Surveillance Certificate Transparency pour détecter les certificats émis frauduleusement pour vos domaines.",
    icon: "Lock",
    tags: ["SSL", "TLS", "certificats"],
    trust: "verified",
    installed: false,
    stars: 167,
    downloads: 1023,
    permissions: ["network_scan", "dns_query", "db_write", "alert_send"],
    changelog: [
      "1.0.2 — Fix wildcard certificates",
      "1.0.1 — Alertes multi-canal",
      "1.0.0 — Monitoring SSL + CT logs",
    ],
  },
  {
    id: "skill-ransomware-sim",
    name: "Simulation Ransomware",
    version: "0.4.0",
    author: "RedTeam.eu",
    description: "Simulation ransomware safe — testez votre résilience sans risque",
    longDescription:
      "Simule le comportement d'un ransomware de manière totalement sûre (aucun chiffrement réel). Teste la détection EDR, les politiques de sauvegarde, et le temps de réponse incident. Rapport de résilience.",
    icon: "ShieldAlert",
    tags: ["ransomware", "simulation", "résilience"],
    trust: "community",
    installed: false,
    stars: 78,
    downloads: 345,
    permissions: ["file_read", "file_write", "db_write", "alert_send"],
    changelog: [
      "0.4.0 — Scénarios chiffrement simulé",
      "0.3.0 — Rapport de résilience",
    ],
  },
  {
    id: "skill-asset-discovery",
    name: "Découverte d'Actifs",
    version: "1.2.0",
    author: "NetMap",
    description: "Découverte automatique d'actifs réseau et cartographie",
    longDescription:
      "Découvre automatiquement tous les actifs de votre réseau. Cartographie interactive, classification par criticité, détection des shadow IT. Export CMDB compatible.",
    icon: "Network",
    tags: ["actifs", "réseau", "CMDB", "inventaire"],
    trust: "verified",
    installed: false,
    stars: 203,
    downloads: 1345,
    permissions: ["network_scan", "db_write"],
    changelog: [
      "1.2.0 — Export CMDB + API",
      "1.1.0 — Cartographie interactive",
      "1.0.0 — Découverte réseau L2/L3",
    ],
  },
  {
    id: "skill-password-audit",
    name: "Audit Mots de Passe",
    version: "0.5.0",
    author: "PassCheck",
    description: "Audit politique mots de passe et détection d'identifiants faibles",
    longDescription:
      "Vérifie la robustesse de vos politiques de mots de passe. Teste les identifiants contre les listes de fuites connues (HaveIBeenPwned). Scoring de la politique et recommandations ANSSI.",
    icon: "Key",
    tags: ["mots de passe", "identifiants", "ANSSI"],
    trust: "community",
    installed: false,
    stars: 92,
    downloads: 567,
    permissions: ["ldap_query", "db_write"],
    changelog: [
      "0.5.0 — Intégration HaveIBeenPwned",
      "0.4.0 — Scoring politique ANSSI",
    ],
  },
  {
    id: "skill-firewall-audit",
    name: "Audit Firewall",
    version: "0.9.0",
    author: "FireCheck",
    description: "Audit des règles firewall — détection de règles permissives",
    longDescription:
      "Analyse vos règles de firewall pour détecter les configurations trop permissives, les règles obsolètes, et les violations de la politique de segmentation. Support iptables, pf, et API cloud.",
    icon: "Flame",
    tags: ["firewall", "réseau", "segmentation"],
    trust: "verified",
    installed: false,
    stars: 145,
    downloads: 789,
    permissions: ["network_scan", "file_read", "db_write"],
    changelog: [
      "0.9.0 — Support cloud firewalls (AWS SG, Azure NSG)",
      "0.8.0 — Analyse iptables + pf",
    ],
  },
];
