"""DGA Detection — Dual backend: Random Forest (12 features) + LSTM ONNX.

See ADR-004, SESSION_2026-04-07.

Two backends available:
- random_forest (default): Fast, lightweight, 90% accuracy. No extra deps.
- onnx_lstm: Character-level LSTM via ONNX Runtime. 96% accuracy, 50MB dep.

Backend selection: DB setting 'ml_config' / 'dga_backend' or env DGA_BACKEND.
Both models are pre-trained and shipped in the Docker image.
The client never trains these — Isolation Forest (behavioral) trains nightly.
"""

import json
import math
import os
import pickle
import logging
import string
from collections import defaultdict
from pathlib import Path

import numpy as np

from . import db
from .features import extract_dns_features

logger = logging.getLogger("ml.dga")

MODEL_DIR = Path(os.environ.get("ML_MODEL_DIR", "/tmp/ml-models"))

# 12-feature column order (must match training script)
FEATURE_COLS = [
    "length", "entropy", "consonant_ratio", "digit_ratio",
    "unique_ratio", "hyphen_count", "bigram_ratio", "trigram_ratio",
    "vc_transition_ratio", "max_consec_consonants", "max_consec_digits",
    "gini_impurity",
]

# Legacy 7-feature columns (for backward compat with v1 models)
LEGACY_FEATURE_COLS = [
    "length", "entropy", "consonant_ratio", "digit_ratio",
    "unique_ratio", "hyphen_count", "common_bigram_ratio",
]

COMMON_BIGRAMS = frozenset({
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
    "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
    "st", "to", "nt", "ng", "se", "ha", "le", "ou", "io", "ge",
})

COMMON_TRIGRAMS = frozenset({
    "the", "and", "ing", "ion", "tio", "ent", "ati", "for", "her",
    "ter", "hat", "tha", "ere", "ate", "his", "con", "res", "ver",
    "all", "ons", "nce", "men", "ith", "ted", "ers", "pro", "com",
})

VOWELS = frozenset("aeiouy")
CONSONANTS = frozenset("bcdfghjklmnpqrstvwxz")


# ── Feature Extraction (12 features, v2) ──

def compute_features_v2(domain):
    """Compute 12 linguistic features for DGA detection (v2)."""
    if len(domain) < 3:
        return None

    n = len(domain)
    lower = domain.lower()

    freq = defaultdict(int)
    for c in lower:
        freq[c] += 1
    entropy = -sum((cnt / n) * math.log2(cnt / n) for cnt in freq.values()) if n > 0 else 0

    consonant_count = sum(1 for c in lower if c in CONSONANTS)
    digit_count = sum(1 for c in lower if c.isdigit())

    bigrams = [lower[i:i+2] for i in range(n - 1)]
    bigram_ratio = sum(1 for b in bigrams if b in COMMON_BIGRAMS) / max(len(bigrams), 1)

    trigrams_list = [lower[i:i+3] for i in range(n - 2)]
    trigram_ratio = sum(1 for t in trigrams_list if t in COMMON_TRIGRAMS) / max(len(trigrams_list), 1)

    transitions = 0
    for i in range(1, n):
        pv = lower[i-1] in VOWELS
        cv = lower[i] in VOWELS
        pc = lower[i-1] in CONSONANTS
        cc = lower[i] in CONSONANTS
        if (pv and cc) or (pc and cv):
            transitions += 1

    max_cc = 0
    run = 0
    for c in lower:
        if c in CONSONANTS:
            run += 1
            max_cc = max(max_cc, run)
        else:
            run = 0

    max_cd = 0
    run = 0
    for c in lower:
        if c.isdigit():
            run += 1
            max_cd = max(max_cd, run)
        else:
            run = 0

    total = sum(freq.values())
    gini = 1.0 - sum((cnt / total) ** 2 for cnt in freq.values()) if total > 0 else 0

    return {
        "length": n,
        "entropy": round(entropy, 4),
        "consonant_ratio": round(consonant_count / n, 4),
        "digit_ratio": round(digit_count / n, 4),
        "unique_ratio": round(len(set(lower)) / n, 4),
        "hyphen_count": lower.count("-"),
        "bigram_ratio": round(bigram_ratio, 4),
        "trigram_ratio": round(trigram_ratio, 4),
        "vc_transition_ratio": round(transitions / max(n - 1, 1), 4),
        "max_consec_consonants": max_cc,
        "max_consec_digits": max_cd,
        "gini_impurity": round(gini, 4),
        # Legacy compat alias
        "common_bigram_ratio": round(bigram_ratio, 4),
    }


# ── Backend: Random Forest ──

_rf_model = None

def _load_rf():
    global _rf_model
    if _rf_model is not None:
        return _rf_model

    model_path = MODEL_DIR / "dga_random_forest.pkl"
    if not model_path.exists():
        logger.warning("No RF model found at %s", model_path)
        return None

    with open(model_path, "rb") as f:  # nosec B301 — trusted model file shipped in Docker image
        data = pickle.load(f)  # nosec B301

    if isinstance(data, dict) and "model" in data:
        _rf_model = data
        logger.info("RF DGA model loaded (v%d, %d features)",
                    data.get("version", 1), len(data.get("features", [])))
    else:
        # Legacy v1 model (bare RandomForestClassifier)
        _rf_model = {"model": data, "features": LEGACY_FEATURE_COLS, "version": 1}
        logger.info("RF DGA model loaded (legacy v1, 7 features)")

    return _rf_model


def _score_rf(domain):
    """Score a domain using Random Forest. Returns DGA probability 0-1."""
    rf = _load_rf()
    if rf is None:
        return 0.0

    feats = compute_features_v2(domain)
    if feats is None:
        return 0.0

    cols = rf.get("features", FEATURE_COLS)
    vector = np.array([[feats.get(col, 0) for col in cols]], dtype=np.float64)
    proba = rf["model"].predict_proba(vector)[0]
    return float(proba[1]) if len(proba) > 1 else 0.0


# ── Backend: LSTM ONNX ──

_onnx_session = None
_onnx_meta = None

def _load_onnx():
    global _onnx_session, _onnx_meta
    if _onnx_session is not None:
        return _onnx_session, _onnx_meta

    onnx_path = MODEL_DIR / "dga_lstm.onnx"
    meta_path = MODEL_DIR / "dga_lstm_meta.json"

    if not onnx_path.exists() or not meta_path.exists():
        logger.warning("LSTM ONNX model not found at %s", onnx_path)
        return None, None

    try:
        import onnxruntime as ort
        _onnx_session = ort.InferenceSession(str(onnx_path))
        with open(meta_path) as f:
            _onnx_meta = json.load(f)
        logger.info("LSTM ONNX DGA model loaded (%s)", onnx_path)
        return _onnx_session, _onnx_meta
    except ImportError:
        logger.warning("onnxruntime not installed. Install with: pip install onnxruntime")
        return None, None
    except Exception as e:
        logger.warning("Failed to load ONNX model: %s", e)
        return None, None


def _score_onnx(domain):
    """Score a domain using LSTM ONNX. Returns DGA probability 0-1."""
    session, meta = _load_onnx()
    if session is None or meta is None:
        return _score_rf(domain)  # fallback to RF

    char_to_idx = meta["char_to_idx"]
    max_len = meta["max_len"]

    encoded = [char_to_idx.get(c, 0) for c in domain.lower()[:max_len]]
    encoded += [0] * (max_len - len(encoded))

    input_arr = np.array([encoded], dtype=np.int64)
    logit = session.run(None, {"domain_encoded": input_arr})[0][0]

    # Sigmoid to probability
    prob = 1.0 / (1.0 + math.exp(-float(logit)))
    return prob


# ── Unified API ──

def _get_backend():
    """Determine which DGA backend to use."""
    # Priority: env var > DB setting > auto-detect
    backend = os.environ.get("DGA_BACKEND", "").lower()
    if backend in ("onnx_lstm", "lstm", "onnx"):
        return "onnx_lstm"
    if backend in ("random_forest", "rf"):
        return "random_forest"

    # Try DB setting
    try:
        setting = db.get_setting("ml_config", "dga_backend")
        if setting:
            val = setting.lower() if isinstance(setting, str) else str(setting).lower()
            if val in ("onnx_lstm", "lstm", "onnx"):
                return "onnx_lstm"
    except Exception:
        pass

    # Auto-detect: use ONNX if model + runtime available, else RF
    onnx_path = MODEL_DIR / "dga_lstm.onnx"
    if onnx_path.exists():
        try:
            import onnxruntime  # noqa: F401
            return "onnx_lstm"
        except ImportError:
            pass

    return "random_forest"


def score_domain(domain):
    """Score a single domain. Returns DGA probability 0-1."""
    backend = _get_backend()
    if backend == "onnx_lstm":
        return _score_onnx(domain)
    return _score_rf(domain)


def train():
    """Train DGA model (Random Forest only — LSTM is pre-trained and shipped).

    Uses real dataset if available, otherwise falls back to synthetic.
    """
    logger.info("Training DGA detection model...")

    dataset_path = MODEL_DIR / "dga_dataset.json"
    if dataset_path.exists():
        return _train_from_dataset(dataset_path)
    return _train_synthetic()


def _train_from_dataset(dataset_path):
    """Train RF from the real dataset (47K+ samples, 12 features)."""
    with open(dataset_path) as f:
        data = json.load(f)

    train_samples = data["train"]
    X, y = [], []
    for s in train_samples:
        feats = compute_features_v2(s["domain"])
        if feats:
            X.append([feats.get(col, 0) for col in FEATURE_COLS])
            y.append(s["label"])

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_leaf=5,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(np.array(X), np.array(y))

    model_path = MODEL_DIR / "dga_random_forest.pkl"
    with open(model_path, "wb") as f:  # nosec B301
        pickle.dump({"model": model, "features": FEATURE_COLS, "version": 2}, f)

    logger.info("DGA RF trained on %d real samples (v2). Saved to %s", len(X), model_path)

    global _rf_model
    _rf_model = None
    return True


def _train_synthetic():
    """Fallback: train from synthetic data (legacy, if no dataset shipped)."""
    import random

    legit = ["google", "facebook", "amazon", "microsoft", "apple", "netflix",
             "youtube", "twitter", "instagram", "linkedin", "github"]
    words = ["shop", "tech", "web", "cloud", "data", "info", "blog", "news",
             "mail", "app", "dev", "code", "host", "site"]
    for _ in range(200):
        legit.append(f"{random.choice(words)}{random.choice(words)}")

    dga = []
    for _ in range(300):
        length = random.randint(8, 20)
        dga.append("".join(random.choices(string.ascii_lowercase + string.digits, k=length)))

    X, y = [], []
    for d in legit:
        feats = compute_features_v2(d)
        if feats:
            X.append([feats.get(col, 0) for col in FEATURE_COLS])
            y.append(0)
    for d in dga:
        feats = compute_features_v2(d)
        if feats:
            X.append([feats.get(col, 0) for col in FEATURE_COLS])
            y.append(1)

    model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)
    model.fit(np.array(X), np.array(y))

    model_path = MODEL_DIR / "dga_random_forest.pkl"
    with open(model_path, "wb") as f:  # nosec B301
        pickle.dump({"model": model, "features": FEATURE_COLS, "version": 2}, f)

    logger.info("DGA RF trained on %d synthetic samples (fallback). Saved to %s", len(X), model_path)

    global _rf_model
    _rf_model = None
    return True


def score_domains():
    """Score recent DNS queries for DGA likelihood.

    Returns: list of { domain, dga_score, is_dga, backend }
    """
    backend = _get_backend()
    logger.info("DGA scoring with backend: %s", backend)

    dns_features = extract_dns_features()
    if not dns_features:
        return []

    results = []
    for item in dns_features:
        domain = item["domain"]

        # Extract SLD for analysis
        parts = domain.split(".")
        sld = parts[-2] if len(parts) >= 2 else domain

        if len(sld) < 3:
            continue

        dga_score = score_domain(sld)

        results.append({
            "domain": domain,
            "sld": sld,
            "dga_score": round(dga_score, 3),
            "is_dga": dga_score > 0.7,
            "backend": backend,
            "features": item.get("features", {}),
        })

    results.sort(key=lambda r: r["dga_score"], reverse=True)

    suspicious = [r for r in results if r["is_dga"]]
    if suspicious:
        logger.warning("DGA: %d suspicious domains out of %d (backend=%s)",
                      len(suspicious), len(results), backend)

    return results


def create_findings_for_dga(scores):
    """Create findings for detected DGA domains."""
    findings_created = 0

    for item in scores:
        if not item["is_dga"]:
            continue

        backend_label = item.get("backend", "rf")

        db.write_finding(
            skill_id="ml-dga-detector",
            title=f"DGA suspect: {item['domain']} (score {item['dga_score']:.2f} [{backend_label}])",
            description=(
                f"Le domaine '{item['domain']}' a les caracteristiques d'un nom genere "
                f"algorithmiquement (DGA).\n"
                f"SLD analyse: {item.get('sld', '?')}\n"
                f"Score DGA: {item['dga_score']:.2f} (seuil: 0.70)\n"
                f"Backend: {backend_label}\n\n"
                f"Les DGA sont utilises par les botnets et ransomwares pour generer des "
                f"domaines C2 differents chaque jour, rendant le blocage par liste noire "
                f"impossible.\n\n"
                f"Action recommandee: verifier la machine qui resout ce domaine, "
                f"analyser le trafic reseau, bloquer si confirme."
            ),
            severity="HIGH",
            category="ml-dga",
            asset=None,
            source=f"ML DGA Detector ({backend_label})",
            metadata={
                "dga_score": item["dga_score"],
                "domain": item["domain"],
                "sld": item.get("sld"),
                "backend": backend_label,
                "features": item.get("features", {}),
                "mitre": ["T1568.002"],
            },
        )
        findings_created += 1

    return findings_created
