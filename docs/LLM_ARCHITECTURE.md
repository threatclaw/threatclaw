# ThreatClaw — Architecture LLM Souveraine

> Migration Ollama → llama.cpp server embarqué
> Planifié pour v2.5 — ne pas implémenter avant InCyber

---

## Situation actuelle (v2.0)

```
┌─────────────────┐     HTTP      ┌─────────────────┐
│  Core Rust      │ ────────────▶ │  Ollama (Go)    │
│  (container 1)  │  :11434       │  (container 2)  │
│                 │               │                 │
│  call_ollama()  │               │  llama.cpp      │
│                 │               │  + Modelfiles   │
└─────────────────┘               └─────────────────┘
                                         │
                                    Pull modèles
                                    depuis ollama.com
```

**Problèmes :**
- 1.2GB d'image Docker pour un wrapper Go autour de llama.cpp
- Dépendance au registry ollama.com (si down → install échoue)
- Pas de contrôle sur le moteur d'inférence (c'est du Go tiers)
- Overhead : Go HTTP server → llama.cpp subprocess → modèle
- En air-gap : impossible de `ollama pull`

---

## Architecture cible (v2.5)

```
┌──────────────────────────────────────────┐
│  Core Rust (container unique)            │
│                                          │
│  ┌──────────────────┐  HTTP :8081        │
│  │  llama-server    │◀── call_llm_l1()   │
│  │  L1 permanent    │   (cycle 5min)     │
│  │  threatclaw-l1   │                    │
│  └──────────────────┘                    │
│                                          │
│  ┌──────────────────┐  HTTP :8082        │
│  │  llama-server    │◀── call_llm_l2()   │
│  │  L2/L2.5 swap    │   (à la demande)   │
│  │  (chargé/déchargé│                    │
│  │   dynamiquement) │                    │
│  └──────────────────┘                    │
│                                          │
│  models/                                 │
│  ├── threatclaw-l1.gguf  (6.5GB)        │
│  ├── threatclaw-l2.gguf  (8.5GB)        │
│  └── threatclaw-l25.gguf (4.9GB)        │
└──────────────────────────────────────────┘
```

---

## Détail des 2 instances

### Instance L1 — Permanente (port 8081)

```bash
llama-server \
  --model models/threatclaw-l1.gguf \
  --host 127.0.0.1 \
  --port 8081 \
  --ctx-size 4096 \
  --threads 4 \
  --n-predict 2048 \
  --system-prompt-file prompts/l1-triage.txt \
  --log-disable
```

- **Toujours en mémoire** — jamais déchargé
- Cycle toutes les 5 minutes par l'Intelligence Engine
- Latence : ~2-5s par requête (CPU), ~0.5-1s (GPU)
- RAM : ~6GB pour le modèle + ~1GB pour le contexte

### Instance L2 — À la demande (port 8082)

```bash
# Démarrage dynamique quand nécessaire
llama-server \
  --model models/threatclaw-l2.gguf \
  --host 127.0.0.1 \
  --port 8082 \
  --ctx-size 8192 \
  --threads 4 \
  --n-predict 4096 \
  --log-disable
```

- **Chargé uniquement** quand un incident Critical/High est détecté
- Swap entre L2 et L2.5 : kill process → relaunch avec l'autre modèle (~2-3s)
- Après 5 minutes d'inactivité → arrêté pour libérer la RAM
- RAM : ~8GB (L2 Q8) ou ~5GB (L2.5 Q4_K_M)

### Gestionnaire de swap (Rust)

```rust
// Nouveau fichier : src/llm/llama_manager.rs

pub struct LlamaManager {
    l1_process: Child,           // Toujours vivant
    l2_process: Option<Child>,   // Dynamique
    l2_current_model: Option<String>,
    l2_last_used: Instant,
    models_dir: PathBuf,
}

impl LlamaManager {
    /// Démarrer L1 au boot
    pub async fn start_l1(&mut self) -> Result<()>;

    /// Charger L2 ou L2.5 à la demande
    pub async fn ensure_l2(&mut self, model: &str) -> Result<()>;

    /// Swap L2 vers un autre modèle
    async fn swap_l2(&mut self, model: &str) -> Result<()>;

    /// Arrêter L2 après timeout d'inactivité
    pub async fn idle_check(&mut self);

    /// Health check
    pub async fn health(&self) -> LlamaHealth;
}
```

---

## Changements dans le code existant

### Fichiers à modifier

| Fichier | Changement |
|---------|-----------|
| `src/agent/react_runner.rs` | `call_ollama()` → `call_llama()` (même API OpenAI, URL change) |
| `src/config/llm.rs` | URLs `http://127.0.0.1:8081` et `:8082` au lieu de `:11434` |
| `src/config/channels.rs` | Supprimer `OLLAMA_BASE_URL` |
| `docker/Dockerfile` | Ajouter `llama-server` binaire (~50MB) |
| `docker/entrypoint.sh` | Télécharger GGUF depuis CDN au lieu de `ollama pull` |
| `docker/docker-compose.yml` | Supprimer le service `ollama` |

### Ce qui ne change PAS

- L'API appelée est OpenAI compatible (`/v1/chat/completions`) — llama-server la supporte nativement
- Le format des requêtes/réponses JSON reste identique
- Le dashboard ne voit aucun changement (il ne parle pas à Ollama directement)
- Le L3 Cloud (Mistral/Anthropic) n'est pas affecté

### Migration de `call_ollama` → `call_llama`

```rust
// Avant (react_runner.rs)
let url = format!("{}/api/chat", base_url);  // Ollama API

// Après
let url = format!("{}/v1/chat/completions", base_url);  // OpenAI API
// Le body est quasi identique, juste le format de réponse change :
// Ollama:  response.message.content
// OpenAI:  response.choices[0].message.content
```

---

## CDN models.threatclaw.io

### Hébergement

- **CloudFlare R2** (S3 compatible, pas de frais d'egress)
- ~20GB de modèles au total
- Coût : ~0.015$/GB/mois stockage = ~0.30$/mois

### Structure

```
https://models.threatclaw.io/
  v2.5/
    threatclaw-l1-9b-q4km.gguf     (6.5GB)
    threatclaw-l1-9b-q4km.sha256
    threatclaw-l2-8b-q8.gguf       (8.5GB)
    threatclaw-l2-8b-q8.sha256
    threatclaw-l25-8b-q4km.gguf    (4.9GB)
    threatclaw-l25-8b-q4km.sha256
    manifest.json                    (versions, checksums, tailles)
```

### Téléchargement dans entrypoint.sh

```bash
MODELS_URL="https://models.threatclaw.io/v2.5"
MODELS_DIR="/app/models"

download_model() {
  local name=$1
  local file="${MODELS_DIR}/${name}"

  if [ -f "$file" ]; then
    # Vérifie intégrité SHA-256
    expected=$(curl -sf "${MODELS_URL}/${name}.sha256")
    actual=$(sha256sum "$file" | cut -d' ' -f1)
    if [ "$expected" = "$actual" ]; then
      echo "Model $name already present and verified"
      return 0
    fi
  fi

  echo "Downloading $name..."
  curl -L --progress-bar "${MODELS_URL}/${name}" -o "$file"

  # Vérifie après téléchargement
  expected=$(curl -sf "${MODELS_URL}/${name}.sha256")
  actual=$(sha256sum "$file" | cut -d' ' -f1)
  if [ "$expected" != "$actual" ]; then
    echo "ERROR: SHA-256 mismatch for $name"
    rm -f "$file"
    return 1
  fi
}

download_model "threatclaw-l1-9b-q4km.gguf"
download_model "threatclaw-l2-8b-q8.gguf"
download_model "threatclaw-l25-8b-q4km.gguf"
```

### Mode air-gap

```bash
# Sur une machine avec internet :
./scripts/download-models.sh /path/to/usb/

# Chez le client (sans internet) :
cp /path/to/usb/models/* /srv/threatclaw/models/
docker compose up -d  # Les modèles sont déjà là, pas de download
```

---

## Compilation llama.cpp

### Pour l'image Docker (x86_64 Linux)

```dockerfile
# Dans Dockerfile — stage dédié
FROM ubuntu:22.04 AS llama-builder
RUN apt-get update && apt-get install -y cmake g++ git
RUN git clone https://github.com/ggerganov/llama.cpp.git /llama.cpp
WORKDIR /llama.cpp
RUN cmake -B build -DLLAMA_CURL=OFF -DLLAMA_SERVER=ON \
    && cmake --build build --target llama-server -j$(nproc)
# Résultat : build/bin/llama-server (~50MB)
```

### Variantes GPU

| Target | Flag CMake | Taille |
|--------|-----------|--------|
| CPU only | (défaut) | ~50MB |
| CUDA (NVIDIA) | `-DGGML_CUDA=ON` | ~80MB |
| ROCm (AMD) | `-DGGML_HIPBLAS=ON` | ~90MB |
| Vulkan (universel) | `-DGGML_VULKAN=ON` | ~60MB |

Pour la v2.5 : CPU par défaut, CUDA en option (image séparée `threatclaw/core:latest-cuda`).

---

## RAM requise

| Configuration | L1 seul | L1 + L2 | L1 + L2.5 |
|--------------|---------|---------|-----------|
| Modèles | 6.5GB | 15GB | 11.4GB |
| Runtime + contexte | 2GB | 3GB | 3GB |
| **Total minimum** | **8GB** | **18GB** | **14GB** |

**Recommandation client :**
- 16GB RAM : L1 permanent, L2/L2.5 swap (pas simultanés)
- 32GB RAM : L1 + L2 simultanés, L2.5 swap
- GPU NVIDIA 8GB+ : tout en VRAM, CPU libre

---

## Timeline d'implémentation

1. **Préparer les GGUF** — extraire les modèles du format Ollama vers GGUF pur
2. **Monter le CDN** — CloudFlare R2 + script upload + manifest.json
3. **Écrire `llama_manager.rs`** — gestion des 2 instances + swap + health
4. **Modifier les callers** — `call_ollama()` → `call_llama()` (format OpenAI)
5. **Modifier le Dockerfile** — compiler llama-server, supprimer ollama
6. **Modifier entrypoint.sh** — download depuis CDN au lieu de `ollama pull`
7. **Tester** — CPU, GPU CUDA, air-gap, swap L2/L2.5, RAM limitée
8. **Mettre à jour le dashboard** — le statut "ThreatClaw AI" ne check plus Ollama

---

## Ce qu'on ne fait PAS

- **Pas de candle (Rust natif)** pour le moment — pas assez mature
- **Pas de vLLM** — Python + GPU only, overkill
- **Pas de modèles custom fine-tunés** dans cette version — on garde les mêmes modèles
- **Pas de quantification on-the-fly** — les GGUF sont pré-quantifiés

---

*Document créé le 26/03/2026*
*À implémenter en v2.5 — après InCyber et après l'auth (v2.1)*
