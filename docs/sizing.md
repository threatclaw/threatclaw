# Sizing Guide

Comment dimensionner le serveur qui fera tourner ThreatClaw chez votre client ou sur votre infrastructure.

Ce guide repose sur des mesures réelles effectuées sur deux profils de machine très différents (Ryzen 9 7940HS 2023 et Xeon E3-1245 v5 2015) avec les modèles de la stack par défaut.

---

## TL;DR — Recommandations express

| Usage | CPU minimum | RAM minimum | Mode LLM conseillé |
|---|---|---|---|
| Découverte / POC | 4 cœurs post-2020, AVX2 | 16 GB | Cloud L0 + L1 local |
| PME 5-50 postes | 6-8 cœurs post-2021 | 24 GB | Cloud L0 + L1/L2 local |
| PME NIS2 full-local | 8 cœurs Zen3+/Intel 12e gen+ | 32 GB | gemma4:e4b + L1 + L2 à la demande |
| PME confortable | 8-16 cœurs Zen3+/Raptor Lake | 48 GB | gemma4:26b + L1 + L2 + L2.5 |
| Enterprise / MSP | 16+ cœurs Zen4+/EPYC | 64+ GB | Mistral Small 24B full stack |

**Règle d'or** : CPU post-2020 avec AVX2 obligatoire, DDR4-3200 ou mieux. En dessous de ce seuil, le mode cloud L0 reste la seule expérience utilisable pour le chatbot conversationnel.

---

## 1. Ce que consomme la stack ThreatClaw hors LLM

ThreatClaw en lui-même est léger. La consommation de base (sans modèle chargé) est dominée par Ollama et PostgreSQL.

| Composant | RAM au repos | RAM en charge | CPU |
|---|---|---|---|
| Core Rust `threatclaw-core` | 174 MB | 400-600 MB | 1-2 threads |
| Dashboard Next.js | 55 MB | 100-200 MB | moins de 1 thread |
| PostgreSQL + pgvector + AGE + Timescale | 215 MB | 500 MB à 1 GB | 1-2 threads |
| ML engine Python | 130 MB | 400-800 MB pendant le retrain nocturne | 1-2 threads |
| Fluent-bit syslog | 25 MB | 50-100 MB | moins de 1 thread |
| Nginx reverse proxy | 12 MB | 30 MB | moins de 1 thread |
| Ollama daemon vide | 500 MB | plus le modèle chargé | selon modèle |
| Overhead Docker | ~500 MB | ~500 MB | - |
| **Total hors LLM** | **~1.6 GB** | **~3 GB** | **4-6 threads** |

Un serveur 8 GB sans LLM local pourrait faire tourner toute la stack ThreatClaw. Le vrai consommateur, c'est Ollama et les modèles qu'il charge en mémoire.

---

## 2. Consommation RAM par modèle

Mesures effectuées sur des GGUF quantifiés Q4_K_M avec une fenêtre de contexte de 8 K tokens.

| Modèle | RAM inference | RAM avec context plein | Rôle typique |
|---|---|---|---|
| `gemma4:e4b` | 3 GB | 3.5 GB | L0 léger ou L1 léger |
| `threatclaw-l1` (qwen3:8b) | 5.9 GB | 6.5 GB | L1 triage |
| `qwen3:14b` | 9.3 GB | 10 GB | L0 intermédiaire |
| `gemma4:26b` MoE | 10 GB | 11-12 GB | L0 confortable |
| `mistral-small:24b` | 14 GB | 15.5 GB | L0 premium |
| `threatclaw-l2` (Foundation-Sec Reasoning) | 8.5 GB | 9.5 GB | L2 forensic |
| `threatclaw-l3` (Foundation-Sec Instruct) | 5 GB | 5.5 GB | L2.5 playbooks et rapports |

**Le MoE change la donne** : `gemma4:26b` est un Mixture of Experts à 26 milliards de paramètres totaux mais seulement 3.8 milliards actifs par token. En pratique il se comporte comme un 4B en vitesse et comme un 24B en qualité, tout en occupant seulement 10 GB de RAM.

---

## 3. Vitesse d'inférence par CPU

Tests effectués avec un prompt SOC français "Résume en 2 phrases : un attaquant a brute-forcé SSH sur 192.168.1.50 depuis 185.220.101.42. Quelle sévérité MITRE ?"

| Modèle | Ryzen 9 7940HS (16 threads, 2023) | Xeon E3-1245 v5 (8 threads, 2015) |
|---|---|---|
| `gemma4:e4b` | 16.6 tok/s | ~6 tok/s |
| `gemma4:26b` MoE | **18.3 tok/s** | 7.2 tok/s |
| `qwen3:14b` | 6.4 tok/s | ~3 tok/s |
| `mistral-small:24b` | 4.0 tok/s | ~2 tok/s |

Le facteur 2.5× entre un CPU de 2015 et un CPU de 2023 est colossal. C'est la différence entre "chatbot utilisable" (15+ tok/s, le RSSI attend 3 secondes) et "chatbot frustrant" (6 tok/s, le RSSI attend 15-30 secondes et finit par ne plus l'utiliser).

**Pour un chatbot conversationnel, viser 12 tok/s minimum en génération.** En dessous, passer en cloud L0.

---

## 4. Les quatre profils de déploiement

### Profil 1 — Cloud L0 — pour TPE, budget serré, POC

Le plus petit setup viable. Le LLM conversationnel (L0) est hébergé chez Claude Haiku ou Mistral Small via API. Les données sensibles sont anonymisées avant envoi. La forensique reste locale.

| | Minimum | Recommandé |
|---|---|---|
| CPU | 4 cœurs modernes, AVX2 obligatoire | 6 cœurs modernes |
| RAM | **16 GB** | **24 GB** |
| Disque | 100 GB SSD | 200 GB SSD |
| Modèles locaux | L1 triage uniquement (`threatclaw-l1`, 6 GB) | L1 + L2 reasoning à la demande (~15 GB peak) |
| Coût cloud LLM | 5-15 € par mois (Claude Haiku / Mistral API) | 15-30 € par mois |
| Expérience RSSI | Chatbot instantané (cloud), forensique locale OK | Tout rapide |

**Cibles matérielles** : VPS Hetzner CX32 à CX42, OVH Advance-1, Scaleway DEV1-L, NAS Synology haut de gamme (DS1522+, DS923+), petit serveur dédié d'occasion.

---

### Profil 2 — Full local léger — pour PME sous NIS2 stricte

Tout en local, pas un octet qui sort. Pour les organisations avec des contraintes de souveraineté, les OIV, ou les clients qui veulent maîtriser totalement leur chaîne LLM.

| | Minimum | Recommandé |
|---|---|---|
| CPU | **8 cœurs modernes AVX2** (Zen3+, Alder Lake+ minimum) | 8-12 cœurs Zen4 ou Raptor Lake |
| RAM | **32 GB** | **32 GB** (confortable) |
| Disque | 200 GB SSD NVMe | 500 GB SSD NVMe |
| Modèles locaux | `gemma4:e4b` (L0) + `threatclaw-l1` + `threatclaw-l2` à la demande | Pareil + `threatclaw-l3` |
| RAM peak | 3 + 6 + 9 = **18 GB de modèles** + 3 GB base = 21 GB | Idem |
| Expérience RSSI | L0 rapide (10-15 tok/s), forensique L2 en ~30 s | Idem |

**Cibles matérielles** : Dell PowerEdge R240/R340, HP ProLiant ML30/DL20 Gen10, Intel NUC 12/13 Pro, Synology RS/XS haut de gamme, Proxmox sur mini PC Ryzen 7.

**À éviter absolument** : tout Xeon antérieur à 2018. Un Xeon E5-2680 v4 ou équivalent plafonne à 4 tok/s sur un 24B, ce n'est pas une expérience viable pour un chatbot. Les seuls Xeon acceptables sont les Xeon Gold 6*** 3e gen ou plus récents (Ice Lake+).

---

### Profil 3 — Full local confortable — sweet spot PME

Le meilleur ratio confort / coût pour une PME qui veut tout local et fluide, sans se poser de questions.

| | Recommandé |
|---|---|
| CPU | **Ryzen 9 5900X / 7900 / 9900** ou Intel i7-13700 / 14700 (8-16 cœurs Zen3+/Alder Lake+) |
| RAM | **48 GB** |
| Disque | 500 GB SSD NVMe (OS + modèles) + 2 TB HDD pour les logs |
| Modèles locaux | `gemma4:26b` MoE (L0) + `threatclaw-l1` + L2 + L2.5 à la demande |
| RAM peak | 10 + 6 + 9 = 25 GB + 4 GB base = **~29 GB** |
| Expérience RSSI | L0 conversationnel 15-20 tok/s, forensique 10 tok/s, tout fluide |

**Cibles matérielles** : Dell PowerEdge R350/R360, HP ProLiant DL325/DL345, serveur dédié sur mesure Ryzen 9, station de travail convertie en serveur.

---

### Profil 4 — Enterprise / MSP — pour RSSI en cabinet ou grosse PME

Pour les RSSI à temps partagé qui gèrent plusieurs clients, les MSP, ou les PME de 200+ postes avec un gros volume de logs.

| | Recommandé |
|---|---|
| CPU | **Ryzen 9 9950X** ou **EPYC 9354** (16-32 cœurs Zen4/Zen5) |
| RAM | **64-128 GB** |
| Disque | 1 TB NVMe (OS + modèles ML) + 4 TB SSD (PostgreSQL logs) |
| GPU optionnel | RTX 4060 Ti 16 GB ou RTX 5060 Ti 16 GB (×10 sur la vitesse L0/L1) |
| Modèles locaux | `mistral-small:24b` (L0) + `threatclaw-l1` + L2 + L2.5 + tests de modèles concurrents |
| RAM peak | 14 + 6 + 9 + 5 = 34 GB modèles + 8 GB buffer = **~42 GB** |
| Expérience RSSI | Tout rapide même sans GPU. Avec GPU, imbattable |

**Cibles matérielles** : baies Dell PowerEdge R750xs/R760xs, Supermicro 1U/2U Epyc, workstation ThreadRipper Pro, instances cloud GPU type g5.xlarge AWS.

---

## 5. Ce qui compte vraiment dans le CPU

Pour l'inference LLM locale, l'ordre de priorité des caractéristiques CPU est contre-intuitif :

| Importance | Critère | Pourquoi |
|---|---|---|
| **Critique** | Instructions AVX2 | Sans AVX2, Ollama tourne 5 à 10× plus lentement. C'est un hard requirement |
| **Critique** | Année du CPU (2020+) | L'IPC (performance par cycle) a progressé de 80 % en 8 ans. Un 8 cœurs récent bat un 16 cœurs de 2016 |
| **Important** | Bande passante mémoire | L'inference LLM est memory-bound, pas compute-bound. DDR5 bat DDR4, DDR4-3200 bat DDR4-2400 |
| **Important** | Cœurs physiques (8 à 12) | Au-delà de 12 cœurs, les gains sont marginaux en single-user |
| **Utile** | AVX-512 | +15 à 25 % sur les CPU qui l'ont (Zen4+, Sapphire Rapids, Ice Lake Server) |
| **Bonus** | Plus de 16 cœurs | Utile seulement pour du multi-utilisateur ou du batch (plusieurs investigations simultanées) |

### Le piège Xeon ancien

Un serveur d'occasion à 500 € avec un bi-Xeon E5-2680 v4 (14 cœurs × 2 = 28 cœurs, 128 GB RAM) **semble** idéal sur le papier. En réalité, son IPC est si bas qu'il fait à peine mieux qu'un Ryzen 5 5600 (6 cœurs, 2020) pour l'inference LLM. Pour un client qui veut "juste un serveur pas cher", ce type de machine peut sembler tentant mais l'expérience utilisateur sera mauvaise.

**Test simple avant achat** : lancer `ollama run gemma4:26b --verbose 'bonjour'` sur la machine cible. Si on n'obtient pas au moins 10 tok/s en génération, il faut soit changer de machine, soit passer en mode cloud L0.

---

## 6. Recommandations mémoire RAM

L'inference LLM est **extrêmement sensible à la bande passante mémoire**, plus qu'au compute. Un modèle de 10 GB lit l'équivalent de son poids en RAM à chaque token généré. Donc :

- DDR4-3200 minimum, DDR4-2666 acceptable, DDR4-2133 à éviter
- DDR5 apporte typiquement 30-50 % de tok/s en plus vs DDR4 équivalent
- ECC est recommandé en production mais pas obligatoire
- Ne pas sous-peupler les canaux (dual-channel minimum, quad-channel sur EPYC/Xeon Scalable)

**Règle** : si on a le choix entre 32 GB DDR4-3200 et 64 GB DDR4-2133, **prendre le 32 GB DDR4-3200**. La vitesse compte plus que la capacité pour nos modèles Q4 qui tiennent tous en moins de 32 GB.

---

## 7. Disque — pourquoi SSD NVMe

Le disque n'est critique que sur trois scénarios :

1. **Chargement initial du modèle** (première requête après boot ou après déchargement). Un NVMe charge un modèle 10 GB en ~5 secondes, un SSD SATA en ~30 secondes, un HDD en ~3 minutes.
2. **Téléchargement des modèles Ollama** au premier démarrage (via `entrypoint.sh`). 15-20 GB à télécharger puis à écrire.
3. **Stockage PostgreSQL des logs et sigma alerts**. Sur une PME moyenne, compter 50-200 MB par jour de logs bruts.

**Recommandation** : SSD NVMe pour OS + modèles Ollama. HDD acceptable pour la partition logs PostgreSQL si le volume est important et le budget serré, mais SSD reste préférable.

---

## 8. Contexte cloud — le cas des VPS et serveurs loués

| Fournisseur | Offre | CPU | RAM | Profil adapté |
|---|---|---|---|---|
| **Hetzner** | CX32 | 4 vCPU Intel Xeon | 16 GB | Profil 1 (Cloud L0) |
| **Hetzner** | CX42 | 8 vCPU | 32 GB | Profil 2 |
| **Hetzner** | CCX33 (dédié) | 8 vCPU AMD Epyc | 32 GB | Profil 2-3 |
| **OVH** | Advance-1 | Ryzen 5 Pro 3600 | 32 GB | Profil 2 |
| **OVH** | Rise-LE-1 | Ryzen 7 | 64 GB | Profil 3 |
| **Scaleway** | DEV1-L | 4 vCPU | 8 GB | POC seulement |
| **Scaleway** | PRO2-M | 8 vCPU | 32 GB | Profil 2 |

Les VPS mutualisés avec vCPU partagés sont généralement **décevants** pour l'inference LLM (jitter, throttling). Préférer des instances dédiées ou bare metal dès qu'on dépasse le POC.

---

## 9. Le cas air-gap et NIS2 strict

Pour les clients qui ne peuvent **rien** envoyer en cloud (OIV, défense, santé CSPN, administrations) :

- Le mode **Profil 2 full local** est obligatoire
- Budget serveur à prévoir : 2000-4000 € pour un Dell R340 Ryzen d'occasion récent ou un NUC 13 Pro avec 32 GB
- Prévoir le **bundle offline** téléchargé une fois par mois sur une machine avec internet puis transféré via USB (`scripts/download-offline-bundle.sh`)
- L'escalade L3 cloud est désactivée, toute l'analyse reste sur les modèles locaux L1/L2/L2.5

L'expérience conversationnelle sera **moins fluide** qu'en mode cloud (on ne peut pas faire mieux que ~15 tok/s sur un Ryzen 9 moderne), mais la forensique reste très bonne grâce à Foundation-Sec en local.

---

## 10. Calcul de la RAM — formule rapide

```
RAM requise = 3 GB (base stack)
            + RAM modèle L0 permanent
            + RAM modèle L1 permanent (threatclaw-l1 = 6 GB)
            + max(RAM L2, RAM L2.5) (l'un ou l'autre à la demande, jamais les deux)
            + 2 GB de buffer kernel et cache
```

Exemples concrets :

- Profil 1 (cloud L0) : 3 + 0 + 6 + 9 + 2 = **20 GB** → prendre 24 GB
- Profil 2 (gemma4:e4b L0) : 3 + 3 + 6 + 9 + 2 = **23 GB** → prendre 32 GB
- Profil 3 (gemma4:26b L0) : 3 + 10 + 6 + 9 + 2 = **30 GB** → prendre 48 GB
- Profil 4 (mistral 24b L0) : 3 + 14 + 6 + 9 + 2 = **34 GB** → prendre 64 GB

Le buffer kernel et cache de 2 GB est conservateur — Docker peut consommer plus selon le nombre de connecteurs actifs (Wazuh, Zeek, ML retrain, etc.). Toujours prévoir de la marge.

---

## 11. Installation sur une machine sous-dimensionnée

Si le client a déjà une machine qui ne correspond à aucun profil (ex : vieux Xeon, 16 GB, disque SATA), voici l'ordre des compromis à proposer :

1. **Activer le mode cloud L0** dans Config > IA. Le chatbot devient instantané quel que soit le CPU.
2. **Choisir `gemma4:e4b`** au lieu de `threatclaw-l1` pour le L1. 3 GB au lieu de 6 GB, ~3× plus rapide.
3. **Désactiver L2.5 (Instruct)** dans la config. Économie : 5 GB RAM. Les playbooks seront générés par L2 ou pas du tout.
4. **Désactiver le ML engine** dans `docker-compose.yml`. Économie : 400-800 MB de RAM. Les détections Sigma et Intelligence Engine continuent de fonctionner, seul le scoring ML disparaît.
5. **Réduire la cadence de l'IE** de 5 min à 15 min dans les settings. Moins de charge CPU moyenne.
6. **Dernier recours** : passer `threatclaw-l1` en cloud aussi. Tout ThreatClaw devient "thin client" et le serveur n'a plus qu'à faire tourner la stack de base.

Un serveur 8 GB sans aucun modèle local et tout en cloud tient sur **~4 GB utilisés**. Le coût cloud mensuel reste inférieur à 30 € dans 95 % des cas PME.

---

## 12. Résumé pour l'avant-vente

Questions à poser au client pour choisir le profil :

1. **Quel est votre CPU serveur et son année ?** → élimine les Profils 2-4 si CPU pré-2018
2. **Combien de RAM est disponible ou budgetable ?** → détermine le profil direct
3. **Avez-vous des contraintes de souveraineté des données (NIS2 stricte, OIV, santé) ?** → force Profil 2 minimum, bloque le cloud L0
4. **Combien de postes à surveiller ?** → affine le volume de logs donc le disque
5. **Le RSSI consultera-t-il le chatbot plusieurs fois par jour ?** → si oui, besoin d'un chatbot rapide (cloud L0 ou profil 3+)

La réponse à ces 5 questions donne le profil recommandé en 30 secondes.

---

## Annexe — Mesures brutes

Pour information, voici les deux machines de référence utilisées pour les mesures :

**DEV** : laptop AMD Ryzen 9 7940HS (8 cœurs / 16 threads, Zen 4, AVX-512), 30 GB DDR5-4800, SSD NVMe. Représentatif d'un bon Profil 3 en 2026.

**CASE** : serveur Intel Xeon E3-1245 v5 (4 cœurs / 8 threads, Skylake, AVX2 mais pas AVX-512, 2015), 32 GB DDR4-2133, SSD SATA. Représentatif d'un serveur d'occasion "pas cher" typique — en dessous du seuil acceptable pour le chatbot conversationnel, mais acceptable pour la partie batch (L1, L2 on-demand).

Les mesures datent d'avril 2026 avec Ollama 0.20.4 et les modèles GGUF Q4_K_M standard du registry Ollama.
