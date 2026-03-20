# ThreatClaw — Guide de développement de Skills

## Deux types de skills

| Type | Langage | Runtime | Sécurité | Pour qui |
|------|---------|---------|----------|----------|
| **Officiel** | Rust → WASM | Sandbox WASM IronClaw | Maximum (fuel metered, 10MB RAM, pas de filesystem) | CyberConsulting maintient |
| **Communautaire** | Python | Container Docker isolé | Forte (network:none, mem 256MB, read-only, timeout 5min) | Contributeurs externes |

---

## Développer un skill communautaire (Python)

### Structure minimale

```
my-skill/
├── main.py              # Point d'entrée
├── requirements.txt     # Dépendances Python
├── Dockerfile           # Container isolé
├── skill.json           # Metadata
└── SKILL.md             # Documentation
```

### skill.json

```json
{
  "id": "skill-my-scanner",
  "name": "Mon Scanner",
  "version": "0.1.0",
  "description": "Description courte du skill",
  "author": "Votre nom",
  "trust": "community",
  "category": "scanning",
  "runtime": "docker",
  "requires_network": false,
  "timeout_seconds": 300,
  "memory_mb": 256,
  "api_key_required": false,
  "config_fields": [
    { "key": "target", "label": "Cible", "type": "text", "default": "" }
  ]
}
```

### main.py

```python
#!/usr/bin/env python3
"""Mon skill ThreatClaw."""

import os
import sys
sys.path.insert(0, "/sdk")
from threatclaw_sdk import ThreatClawClient, Finding, Severity

def main():
    client = ThreatClawClient()

    # Lire la config du skill
    config = client.get_config("skill-my-scanner")
    target = config.get("target", "")

    if not target:
        print("Erreur: aucune cible configurée")
        sys.exit(1)

    # Votre logique de scan ici
    # ...

    # Soumettre un finding
    client.report_finding(Finding(
        skill_id="skill-my-scanner",
        title="Vulnérabilité détectée",
        severity=Severity.HIGH,
        asset=target,
        source="my-scanner",
        description="Description détaillée",
    ))

if __name__ == "__main__":
    main()
```

### Dockerfile

```dockerfile
FROM python:3.12-slim
WORKDIR /app

# Sécurité : user non-root
RUN useradd -m -s /bin/sh skilluser

# Installer les dépendances
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier le SDK ThreatClaw
COPY --from=threatclaw/sdk:latest /sdk /sdk

# Copier le code du skill
COPY main.py .
COPY skill.json .

USER skilluser
CMD ["python3", "main.py"]
```

### Contraintes de sécurité (non négociables)

Le container tourne avec ces restrictions :

```yaml
network_mode: "none"          # Pas d'accès réseau direct
mem_limit: 256m               # 256 MB max
cpu_shares: 512               # CPU limité
read_only: true               # Filesystem read-only
tmpfs:
  - /tmp:size=64m             # Seul /tmp est writable (64MB)
security_opt:
  - no-new-privileges:true    # Pas d'escalade de privilèges
```

**Comment le skill communique :**
- Le SDK Python utilise une **socket Unix** montée dans le container
- La socket est connectée au Core API ThreatClaw
- Le skill ne peut QUE :
  - Lire sa config (`client.get_config()`)
  - Soumettre des findings (`client.report_finding()`)
  - Lire les findings existants (`client.list_findings()`)

**Le skill ne peut PAS :**
- Accéder au réseau
- Accéder au filesystem hôte
- Accéder à la base de données directement
- Modifier la config d'autres skills
- Modifier le comportement de l'agent

### Soumettre un skill

1. Fork le repo ThreatClaw
2. Créer un dossier `community-skills/skill-votre-nom/`
3. Ajouter `main.py`, `Dockerfile`, `skill.json`, `SKILL.md`
4. Ouvrir une Pull Request
5. L'équipe ThreatClaw review le code
6. Si approuvé → merge + publication dans le marketplace

### Review checklist

Votre PR sera vérifiée pour :
- [ ] Pas d'accès réseau dans le code (pas de `requests`, `urllib`, `socket`)
- [ ] Pas de `os.system()`, `subprocess.call()`, `exec()`, `eval()`
- [ ] Pas de lecture de fichiers hors de `/app/` et `/tmp/`
- [ ] `skill.json` complet avec tous les champs requis
- [ ] `SKILL.md` avec description, prérequis, exemples
- [ ] `Dockerfile` basé sur `python:3.12-slim` (pas de custom base)
- [ ] Tests unitaires (au moins 3)
- [ ] Pas de dépendances lourdes (max 50MB d'image)

---

## Développer un skill officiel (Rust/WASM)

### Structure

```
skills-src/skill-name/
├── Cargo.toml
├── src/
│   └── lib.rs            # Code du skill
└── skill.json            # Metadata
```

### Cargo.toml

```toml
[package]
name = "skill-name"
version = "1.0.0"
edition = "2021"
license = "Apache-2.0"

[lib]
crate-type = ["cdylib"]

[dependencies]
wit-bindgen = "0.36"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

[profile.release]
opt-level = "s"
lto = true
strip = true
codegen-units = 1

[workspace]
```

### lib.rs minimal

```rust
wit_bindgen::generate!({ world: "sandboxed-tool", path: "../../wit" });

use exports::near::agent::tool::{Guest, Request, Response};
use near::agent::host;

struct MySkill;
export!(MySkill);

impl Guest for MySkill {
    fn execute(req: Request) -> Response {
        host::log(host::LogLevel::Info, "my-skill: starting");

        // Parse params
        let params: serde_json::Value = serde_json::from_str(&req.params).unwrap_or_default();

        // Your logic here...

        // Submit finding via HTTP
        let finding = serde_json::json!({
            "skill_id": "my-skill",
            "title": "Something detected",
            "severity": "medium",
            "asset": "target",
            "source": "my-skill",
        });
        let body = serde_json::to_vec(&finding).unwrap_or_default();
        let _ = host::http_request("POST", "http://localhost:3000/api/tc/findings", "{}", Some(&body), Some(10000));

        Response { output: Some("done".to_string()), error: None }
    }

    fn schema() -> String {
        serde_json::json!({ "type": "object", "properties": {} }).to_string()
    }

    fn description() -> String {
        "Description of what this skill does.".to_string()
    }
}
```

### Compiler

```bash
cargo build --release --target wasm32-wasip2
# Output: target/wasm32-wasip2/release/skill_name.wasm
```

### Host functions disponibles

| Fonction | Description | Limite |
|----------|-------------|--------|
| `host::log(level, msg)` | Logger un message | 1000 entries, 4KB/msg |
| `host::now_millis()` | Timestamp Unix ms | Illimité |
| `host::workspace_read(path)` | Lire un fichier workspace | Paths relatifs only |
| `host::http_request(method, url, headers, body, timeout)` | Requête HTTP | Allowlist, rate limited |
| `host::tool_invoke(alias, params)` | Appeler un autre tool | Aliases only |
| `host::secret_exists(name)` | Vérifier si un secret existe | Jamais la valeur |

### Sécurité WASM

- **Fuel metering** : max 1.2B opérations
- **Memory** : max 10MB
- **Epoch interruption** : 500ms ticks
- **Pas de filesystem** : uniquement `workspace_read` avec paths validés
- **HTTP allowlist** : seuls les endpoints déclarés dans `skill.json` sont autorisés
- **Credentials** : injectés par le host au boundary HTTP, jamais exposés au WASM
- **Leak detection** : scan des requêtes/réponses pour les secrets

---

## Capabilities (skill.json)

```json
{
  "capabilities": {
    "http_allowed": true,
    "http_allowlist": [
      "https://api.example.com/*",
      "http://localhost:3000/api/tc/*"
    ],
    "workspace_read": false,
    "secrets": ["my_api_key"]
  }
}
```

Les skills WASM ne peuvent accéder qu'aux endpoints déclarés. Tout le reste est bloqué par le host.
