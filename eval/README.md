# ThreatClaw Hallucination Evaluation Suite

> Phase 6 de la roadmap v1.1.0-beta (voir `internal/roadmap-avril-mai.md`).
>
> Cette suite sera exécutée à chaque release pour mesurer le taux d'hallucination
> LLM et détecter les régressions sur les 5 métriques cibles ci-dessous.

## Structure

- `hallucination_suite_v1.json` — index des cas de test (seedé depuis `src/agent/test_scenarios.rs`)
- `run_eval.rs` — **à écrire en Phase 6** : runner qui exécute la suite contre une instance ThreatClaw et produit un rapport JSON

## Métriques cibles (Phase 6)

| Métrique | Cible v1.1.0 | Définition |
|----------|--------------|------------|
| **Structural validity rate** | > 95% | % de verdicts dont tous les MITRE/CVE/hashes cités existent réellement |
| **Evidence grounding rate** | > 90% | % de claims `Confirmed` avec au moins 1 citation vérifiée en DB |
| **Inconclusive precision** | — | Des verdicts `Inconclusive`, combien étaient vraiment ambigus vs classés incertains à tort |
| **Verdict accuracy** | > baseline | % de matchs verdict produit vs ground truth annotée |
| **Reconciliation impact** | — | % de verdicts modifiés par `reconcile_verdict()`, décomposition des raisons |

## Statut

**Phase 0 (avril 2026) — seedé uniquement**.
- Pas de runner
- Pas de ground truth annotée
- Les 9 cas proviennent de scénarios existants dans `src/agent/test_scenarios.rs`

**Phase 6 — expansion** (mai 2026) :
- Ajout de ~30 cas "vrai positif" annotés (ground truth depuis lab TARS)
- Ajout de ~30 cas "vrai négatif" (trafic légitime labellé)
- Ajout de ~20 cas "adversariaux" (alertes sous-spécifiées, IoCs ambigus)
- Ajout de ~20 cas "pièges hallucination" (contexte induisant en erreur)
- Implémentation de `run_eval.rs`
- Intégration CI hebdomadaire

## Exécution (post-Phase 6)

```bash
# Lance la suite complète contre une instance ThreatClaw
cargo run --bin run_eval -- --config eval/hallucination_suite_v1.json \
    --endpoint http://localhost:18789 \
    --output reports/eval-$(date +%Y-%m-%d).json

# Compare deux rapports pour détecter régressions
cargo run --bin run_eval -- --compare reports/eval-2026-05-30.json \
    reports/eval-2026-04-19-baseline.json
```
