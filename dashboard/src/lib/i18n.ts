/**
 * ThreatClaw Dashboard i18n — centralized translations.
 *
 * To add a new language:
 * 1. Add a new key to each entry (e.g., "de" for German)
 * 2. That's it — the hook reads from DB settings or localStorage
 */

export type Locale = "fr" | "en";

const T: Record<string, Record<Locale, string>> = {
  // ── General ──
  refresh: { fr: "Actualiser", en: "Refresh" },
  save: { fr: "Enregistrer", en: "Save" },
  cancel: { fr: "Annuler", en: "Cancel" },
  close: { fr: "Fermer", en: "Close" },
  search: { fr: "Rechercher...", en: "Search..." },
  loading: { fr: "Chargement...", en: "Loading..." },
  noData: { fr: "Aucune donnee", en: "No data" },

  // ── Skills ──
  skills: { fr: "Skills", en: "Skills" },
  mySkills: { fr: "My Skills", en: "My Skills" },
  catalog: { fr: "Catalog", en: "Catalog" },
  install: { fr: "Installer", en: "Install" },
  uninstall: { fr: "Desinstaller", en: "Uninstall" },
  installing: { fr: "Installation en cours...", en: "Installing..." },
  uninstalling: { fr: "Desinstallation en cours...", en: "Uninstalling..." },
  installed: { fr: "installe ! Configurez-le dans My Skills", en: "installed! Configure it in My Skills" },
  uninstalled: { fr: "desinstallee", en: "uninstalled" },
  noSkillsActive: { fr: "Aucune skill activee. Allez dans le Catalog pour en ajouter.", en: "No skills activated. Go to Catalog to add some." },
  allInstalled: { fr: "Toutes les skills sont installees", en: "All skills are installed" },
  noSkillFound: { fr: "Aucune skill trouvee", en: "No skill found" },
  comingSoon: { fr: "Bientot disponible", en: "Coming soon" },
  configuration: { fr: "Configuration", en: "Configuration" },
  searchCatalog: { fr: "Rechercher dans le catalogue...", en: "Search catalog..." },
  launch: { fr: "Lancer", en: "Run" },
  sync: { fr: "Sync", en: "Sync" },

  // ── Skills types ──
  tool: { fr: "OUTIL", en: "TOOL" },
  connector: { fr: "CONNECTEUR", en: "CONNECTOR" },
  enrichment: { fr: "ENRICHISSEMENT", en: "ENRICHMENT" },
  connectors: { fr: "Connecteurs", en: "Connectors" },
  intelligenceSkills: { fr: "Intelligence", en: "Intelligence" },
  actions: { fr: "Actions", en: "Actions" },
  allTypes: { fr: "Tous", en: "All" },
  communityBlocked: { fr: "Skills communautaires non autorisées dans cette section", en: "Community skills not allowed in this section" },
  verificationRequired: { fr: "Remédiation — vérification requise", en: "Remediation — verification required" },
  communityReadOnly: { fr: "Les skills communautaires ne peuvent pas exécuter d'actions. Demandez une vérification.", en: "Community skills cannot execute actions. Request verification." },
  onlyVerified: { fr: "Seuls les skills ThreatClaw et Vérifiés peuvent effectuer des actions de remédiation", en: "Only ThreatClaw and Verified skills can perform remediation actions" },
  inDevelopment: { fr: "En développement", en: "In development" },
  premium: { fr: "PREMIUM", en: "PREMIUM" },
  installed2: { fr: "Installés", en: "Installed" },
  catalogue: { fr: "Catalogue", en: "Catalogue" },
  collectData: { fr: "Collecte de données depuis votre infrastructure", en: "Collects data from your infrastructure" },
  ctiEnrichment: { fr: "Enrichissement CTI et réputation", en: "CTI enrichment and reputation" },
  remediationResponse: { fr: "Remédiation et réponse automatisée", en: "Remediation and automated response" },
  by: { fr: "Par", en: "By" },
  downloadModel: { fr: "Télécharger le modèle", en: "Download model" },
  modelInstalled: { fr: "Modèle installé", en: "Model installed" },
  modelNotFound: { fr: "Modèle non installé — téléchargement requis", en: "Model not installed — download required" },
  downloading: { fr: "Téléchargement en cours...", en: "Downloading..." },
  ollamaError: { fr: "Erreur — vérifiez la connexion Ollama", en: "Error — check Ollama connection" },

  // ── Auth ──
  login: { fr: "Connexion", en: "Login" },
  logout: { fr: "Déconnexion", en: "Logout" },
  initialSetup: { fr: "Configuration initiale", en: "Initial setup" },
  email: { fr: "Email", en: "Email" },
  password: { fr: "Mot de passe", en: "Password" },
  name: { fr: "Nom", en: "Name" },
  signIn: { fr: "Se connecter", en: "Sign in" },
  createAdmin: { fr: "Créer le compte administrateur", en: "Create admin account" },
  firstRunHint: { fr: "Premier démarrage — créez le compte administrateur.", en: "First start — create the admin account." },
  fullAccessHint: { fr: "Ce compte aura un accès complet au dashboard.", en: "This account will have full dashboard access." },
  minPassword: { fr: "8 caractères minimum", en: "8 characters minimum" },
  wrongCredentials: { fr: "Email ou mot de passe incorrect", en: "Wrong email or password" },
  accountLocked: { fr: "Compte verrouillé. Réessayez dans 15 minutes.", en: "Account locked. Try again in 15 minutes." },

  // ── Account ──
  myAccount: { fr: "Mon compte", en: "My account" },
  role: { fr: "Rôle", en: "Role" },
  changePassword: { fr: "Changer le mot de passe", en: "Change password" },
  currentPassword: { fr: "Mot de passe actuel", en: "Current password" },
  newPassword: { fr: "Nouveau mot de passe (8 car. min)", en: "New password (8 char. min)" },
  modify: { fr: "Modifier", en: "Modify" },
  passwordChanged: { fr: "Mot de passe modifié", en: "Password changed" },

  // ── Config IA ──
  aiOps: { fr: "ThreatClaw AI Ops", en: "ThreatClaw AI Ops" },
  aiOpsDesc: { fr: "Dialogue — conversation naturelle, tool calling", en: "Dialogue — natural conversation, tool calling" },
  source: { fr: "Source", en: "Source" },
  disabled: { fr: "Désactivé", en: "Disabled" },
  local: { fr: "Local", en: "Local" },
  cloud: { fr: "Cloud", en: "Cloud" },
  model: { fr: "Modèle", en: "Model" },
  nativeToolCalling: { fr: "Tool calling natif — meilleure qualité de dialogue", en: "Native tool calling — best dialogue quality" },
  promptToolCalling: { fr: "Tool calling via prompt — plus léger, compatible CPU", en: "Prompt-based tool calling — lighter, CPU compatible" },
  ramEstimated: { fr: "Mémoire estimée", en: "Estimated memory" },
  permanent: { fr: "permanent", en: "permanent" },
  peak: { fr: "pic", en: "peak" },
  swap: { fr: "swap", en: "swap" },
  onDemand: { fr: "à la demande", en: "on-demand" },
  anonymization: { fr: "Anonymisation", en: "Anonymization" },
  anonymizeOn: { fr: "IPs, hostnames, users anonymisés avant envoi", en: "IPs, hostnames, users anonymized before sending" },
  anonymizeOff: { fr: "Données brutes envoyées au cloud", en: "Raw data sent to cloud" },
  provider: { fr: "Provider", en: "Provider" },
  apiKey: { fr: "Clé API", en: "API Key" },

  // ── About ──
  instance: { fr: "Instance", en: "Instance" },
  noLimit: { fr: "aucune limite", en: "no limit" },
  freeUnlimited: { fr: "Community — Gratuit et illimité", en: "Community — Free and unlimited" },

  // ── Intelligence ──
  graphIntelligence: { fr: "Graph Intelligence", en: "Graph Intelligence" },
  realTimeAnalysis: { fr: "Analyse en temps reel depuis Apache AGE + STIX 2.1", en: "Real-time analysis from Apache AGE + STIX 2.1" },
  attackPaths: { fr: "Chemins d'attaque", en: "Attack Paths" },
  threatActors: { fr: "Acteurs de menace", en: "Threat Actors" },
  blastRadius: { fr: "Blast Radius", en: "Blast Radius" },
  lateralMovement: { fr: "Mouvement lateral", en: "Lateral Movement" },
  campaigns: { fr: "Campagnes detectees", en: "Detected Campaigns" },
  identityAnomalies: { fr: "Anomalies identite (UBA)", en: "Identity Anomalies (UBA)" },
  noAttackPaths: { fr: "Aucun chemin d'attaque detecte", en: "No attack paths detected" },
  noActors: { fr: "Aucun acteur profile", en: "No actors profiled" },
  noLateral: { fr: "Aucun mouvement lateral detecte", en: "No lateral movement detected" },
  noCampaigns: { fr: "Aucune campagne coordonnee", en: "No coordinated campaign" },
  noAnomalies: { fr: "aucune anomalie", en: "no anomalies" },
  assetIsolated: { fr: "Asset isole — pas d'impact collateral", en: "Isolated asset — no collateral impact" },
  recommendations: { fr: "RECOMMANDATIONS", en: "RECOMMENDATIONS" },
  calculate: { fr: "Calculer", en: "Calculate" },
  attacks: { fr: "attaques", en: "attacks" },
  detections_count: { fr: "detection(s)", en: "detection(s)" },
  usersTracked: { fr: "utilisateurs suivis", en: "users tracked" },
  actors: { fr: "Acteurs", en: "Actors" },
  matchesTo: { fr: "Correspond a", en: "Matches" },
  reportNis2: { fr: "Rapport NIS2 Article 21", en: "NIS2 Article 21 Report" },
  loadPlaybooks: { fr: "Charger playbooks MITRE", en: "Load MITRE Playbooks" },
  attackGraph: { fr: "Graphe d'attaque", en: "Attack Graph" },
  loadingGraph: { fr: "Chargement du graphe...", en: "Loading graph..." },
  noGraphData: { fr: "Aucune donnee dans le graphe. Lancez un test ou activez des connecteurs.", en: "No graph data. Run a test or activate connectors." },
  dragNodes: { fr: "Glissez les noeuds pour reorganiser", en: "Drag nodes to rearrange" },
  nodes: { fr: "noeuds", en: "nodes" },
  relations: { fr: "relations", en: "relations" },

  // ── Assets ──
  assets: { fr: "Assets", en: "Assets" },
  discovered: { fr: "Decouverts", en: "Discovered" },
  manual: { fr: "Manuels", en: "Manual" },
  noAssets: { fr: "Aucun asset decouvert", en: "No assets discovered" },
  activateSkills: { fr: "Activez un scan nmap, un connecteur AD ou pfSense dans Skills", en: "Activate a nmap scan, AD or pfSense connector in Skills" },
  lowConfidence: { fr: "Confiance faible — activez des sources supplementaires (AD, pfSense) dans Skills pour enrichir cet asset.", en: "Low confidence — activate additional sources (AD, pfSense) in Skills to enrich this asset." },
  seeInGraph: { fr: "Voir dans le graphe", en: "View in graph" },
  noManualTargets: { fr: "Aucune cible manuelle configuree", en: "No manual targets configured" },
  withMac: { fr: "Avec MAC", en: "With MAC" },
  withHostname: { fr: "Avec hostname", en: "With hostname" },
  coverage: { fr: "Couverture", en: "Coverage" },
  firstSeen: { fr: "Premier vu", en: "First seen" },
  lastSeen: { fr: "Dernier vu", en: "Last seen" },
  criticality: { fr: "Criticite", en: "Criticality" },
  confidence: { fr: "Confiance", en: "Confidence" },
  sources: { fr: "Sources", en: "Sources" },

  // ── Config tabs ──
  general: { fr: "General", en: "General" },
  about: { fr: "A propos", en: "About" },
  tests: { fr: "Tests", en: "Tests" },

  // ── Nav ──
  status: { fr: "Status", en: "Status" },
  detections: { fr: "Détections", en: "Detections" },
  exports: { fr: "Rapports", en: "Reports" },
  findings: { fr: "Findings", en: "Findings" },
  alerts: { fr: "Alertes", en: "Alerts" },
  intelligence: { fr: "Intelligence", en: "Intelligence" },
  agent: { fr: "Agent", en: "Agent" },
  config: { fr: "Config", en: "Config" },
  lightMode: { fr: "Mode clair", en: "Light mode" },
  darkMode: { fr: "Mode sombre", en: "Dark mode" },
};

/** Get a translated string. Falls back to French if key missing. */
export function t(key: string, locale: Locale): string {
  return T[key]?.[locale] || T[key]?.["fr"] || key;
}

/** Get all translations for a given locale (useful for debugging). */
export function allTranslations(locale: Locale): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, val] of Object.entries(T)) {
    result[key] = val[locale] || val["fr"] || key;
  }
  return result;
}

export default T;
