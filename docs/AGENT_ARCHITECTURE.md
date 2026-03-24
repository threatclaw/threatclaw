# ThreatClaw Agent — Architecture & Security Model

## Vision

ThreatClaw Agent est un binaire Rust leger (~5 MB) qui s'installe sur chaque serveur
(Linux, Windows, macOS) et collecte des metriques de securite en temps reel.

**Principe fondamental : l'agent est READ-ONLY.**

Il collecte et envoie — il ne recoit et n'execute aucune commande.

## Pourquoi un agent ?

| Sans agent (aujourd'hui) | Avec agent |
|--------------------------|------------|
| Connexion SSH/WinRM active | Connexion sortante (firewall-friendly) |
| Credentials necessaires | Token d'enrolement unique |
| Polling periodique | Temps reel (push) |
| Limite aux commandes distantes | Acces aux metriques locales profondes |
| Ne fonctionne pas derriere NAT | Fonctionne partout (outbound 443) |

## Architecture

```
Serveurs clients                    ThreatClaw Core
┌─────────────┐                     ┌─────────────────┐
│ Agent Linux │─── WebSocket ───┐   │                 │
│ (read-only) │    TLS mutuel   │   │  /ws/agent/{id} │
└─────────────┘                 ├──>│                 │
┌─────────────┐                 │   │  Intelligence   │
│ Agent Win   │─── WebSocket ───┤   │  Engine         │
│ (read-only) │    Port 443     │   │                 │
└─────────────┘                 │   │  Graph AGE      │
┌─────────────┐                 │   │                 │
│ Agent macOS │─── WebSocket ───┘   │  Dashboard      │
│ (read-only) │                     │                 │
└─────────────┘                     └─────────────────┘
```

## Ce que l'agent collecte

### Autorise (V1)
- CPU, RAM, disk usage (toutes les 30s)
- Connexions reseau actives (IP + port, pas le contenu)
- Processus en cours (nom + PID, pas les arguments complets)
- Tentatives d'authentification (succes/echec + timestamp)
- Changements de comptes utilisateurs
- Fichiers modifies dans les dossiers critiques (/etc, /system32)
- Score de hardening en continu (equivalent Lynis permanent)

### Filtre avant envoi
- Arguments de processus : supprime tout apres password=, token=, secret=, key=
- Logs : uniquement les evenements d'authentification, pas les logs applicatifs
- Variables d'environnement : JAMAIS envoyees

### Interdit (jamais implemente)
- Contenu des fichiers
- Donnees applicatives / bases de donnees
- Requetes SQL
- Secrets, mots de passe, cles API
- Acces aux /home des utilisateurs

## Modele de securite

### Menace : ThreatClaw Core compromis

**Question du RSSI : "Si votre serveur est hacke, mes serveurs sont en danger ?"**

**Reponse : Non.**

| Scenario | Avec remote execution (CrowdStrike) | ThreatClaw V1 (read-only) |
|----------|--------------------------------------|---------------------------|
| Core compromis | Attaquant execute des commandes sur tous les agents | Attaquant voit des metriques systeme |
| Impact | Tous les serveurs clients compromis | Serveurs clients inaccessibles |
| Pivot possible | OUI — game over | NON — aucune commande possible |
| Pire cas | Ransomware deploye partout (cf. CrowdStrike juillet 2024) | Fuite de metriques (CPU, connexions, processus) |

### Principe 1 : Agent READ-ONLY

```
L'agent NE PEUT PAS :
  - Executer des commandes recues du core
  - Lire des fichiers arbitraires
  - Se connecter a d'autres machines
  - Modifier quoi que ce soit sur le systeme
  - Acceder aux secrets ou mots de passe

La connexion WebSocket est UNIDIRECTIONNELLE :
  agent → core UNIQUEMENT

Si le core envoie un message a l'agent :
  → L'agent l'IGNORE completement
  → Log local : "unexpected message from core — ignored"
```

### Principe 2 : Authentification mutuelle TLS

- L'agent verifie le certificat du core (certificate pinning)
- Le core verifie le certificat de l'agent
- Un faux core ne peut pas se faire passer pour le vrai
- Meme si le DNS est detourne, la connexion echoue

### Principe 3 : Moindre privilege

```
Linux :
  Compte systeme : threatclaw-agent
  Shell : /sbin/nologin (pas de login interactif)
  Permissions : lecture /proc, /sys, /var/log/auth.log
  PAS d'acces : /home, /etc/shadow, /root, donnees applicatives

Windows :
  Service Account : ThreatClawAgent
  Groupes : Performance Monitor Users, Event Log Readers
  PAS admin local
  PAS d'acces aux partages reseau
```

### Principe 4 : Chiffrement

- Events chiffres TLS en transit
- Queue locale chiffree si deconnecte (AES-256-GCM)
- Pas de donnees sensibles en clair sur le disque

## Enrolement

```
1. Dashboard ThreatClaw → "Ajouter un agent"
   → Genere un token unique : TC-A3F7-KX92-M4PL (valable 24h)

2. Sur le serveur cible :
   curl -sSL https://get.threatclaw.io/agent | sh
   tc-agent enroll --core https://mon-threatclaw:8443 --token TC-A3F7KX92

3. Echange de certificat TLS mutuel automatique
   → Le token expire immediatement apres utilisation
   → Communication chiffree avec certificat propre

4. L'agent demarre en service (systemd / Windows Service)
   → Demarre automatiquement au boot
   → Reconnexion automatique si deconnecte
```

## Format des events

```json
{
  "type": "observed-data",
  "spec_version": "2.1",
  "agent_id": "agent--srv-prod-01",
  "first_observed": "2026-03-24T02:17:00Z",
  "objects": {
    "0": {
      "type": "network-traffic",
      "src_ref": "1",
      "dst_ref": "2",
      "dst_port": 4444,
      "protocols": ["tcp"]
    }
  }
}
```

Events STIX 2.1 envoyes par batch toutes les 10 secondes,
ou immediatement si evenement critique (nouvelle connexion suspecte, processus inconnu).

## Plateformes cibles

| Plateforme | Priorite | Status |
|-----------|----------|--------|
| Linux x86_64 | V2 | A faire |
| Windows x86_64 | V2 | A faire |
| Linux ARM64 (Raspberry Pi, serveurs ARM) | V3 | Planifie |
| macOS ARM64 (M1/M2/M3) | V3 | Planifie |
| Linux ARM (IoT) | V4 | Futur |

## Modele commercial

| Edition | Agents | Mode |
|---------|--------|------|
| Community | 3 max | Polling 5 min |
| Pro | Illimite | Temps reel (push) |
| Enterprise | Illimite | Temps reel + hardening continu + streaming logs |

## Ce qu'il ne faut JAMAIS implementer dans l'agent

**DANGER — Ces fonctionnalites transformeraient l'agent en vecteur d'attaque :**

- Remote shell / remote execution
- File upload / download
- Kill process a distance
- Run script a distance
- Modification de fichiers
- Acces aux credentials du systeme
- Connexion a d'autres machines depuis l'agent

**Si une de ces fonctionnalites est demandee, la reponse est NON.**
C'est un choix architectural delibere, pas une limitation.

CrowdStrike a remote execution → panne mondiale juillet 2024.
ThreatClaw Agent est read-only par conception → surface d'attaque minimale.

## Argument commercial

> "ThreatClaw Agent est read-only par conception.
> Meme dans le pire scenario — notre infrastructure compromise —
> vos serveurs restent inaccessibles.
> C'est un choix architectural delibere pour les environnements sensibles."

---

*Document interne — ne pas publier en l'etat. Adapter pour la documentation publique.*
