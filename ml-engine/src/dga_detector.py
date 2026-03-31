"""DGA Detection — Random Forest classifier for domain names.

Detects algorithmically-generated domain names used by malware for C2.
Features: entropy, length, consonant ratio, digit ratio, bigram frequency.
Trained on a mix of legitimate domains + known DGA samples.
"""

import os
import pickle
import logging
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from . import db
from .features import extract_dns_features

logger = logging.getLogger("ml.dga")

MODEL_DIR = Path(os.environ.get("ML_MODEL_DIR", "/tmp/ml-models"))
DGA_FEATURE_COLS = ["length", "entropy", "consonant_ratio", "digit_ratio",
                     "unique_ratio", "hyphen_count", "common_bigram_ratio"]


def _generate_training_data():
    """Generate synthetic training data for DGA detection.

    Legitimate domains: common patterns (words, brands, short names).
    DGA domains: random character sequences.
    """
    import random
    import string
    import math
    from collections import defaultdict

    legit_samples = [
        "google", "facebook", "amazon", "microsoft", "apple", "netflix",
        "youtube", "twitter", "instagram", "linkedin", "github", "stackoverflow",
        "wordpress", "wikipedia", "reddit", "cloudflare", "mozilla", "firefox",
        "chrome", "android", "samsung", "intel", "nvidia", "tesla", "shopify",
        "stripe", "paypal", "ebay", "alibaba", "tencent", "baidu",
        "ovhcloud", "scaleway", "orange", "bouygues", "free", "sfr",
        "laposte", "impots", "ameli", "caf", "pole-emploi", "service-public",
        "banque-france", "credit-agricole", "societe-generale", "bnp",
        "carrefour", "leclerc", "auchan", "decathlon", "leroy-merlin",
    ]

    # Generate more legitimate-looking domains
    words = ["shop", "tech", "web", "cloud", "data", "info", "blog", "news",
             "mail", "app", "dev", "code", "host", "site", "page", "home",
             "secure", "fast", "smart", "pro", "plus", "max", "hub", "lab"]
    for _ in range(200):
        w1 = random.choice(words)
        w2 = random.choice(words)
        legit_samples.append(f"{w1}{w2}")
        legit_samples.append(f"{w1}-{w2}")
        legit_samples.append(f"my{random.choice(words)}")

    # Generate DGA-like domains
    dga_samples = []
    for _ in range(300):
        length = random.randint(8, 20)
        # Pure random
        dga_samples.append("".join(random.choices(string.ascii_lowercase + string.digits, k=length)))
        # Consonant-heavy
        consonants = "bcdfghjklmnpqrstvwxyz"
        dga_samples.append("".join(random.choices(consonants + string.digits, k=random.randint(10, 18))))
        # Hex-like
        dga_samples.append("".join(random.choices("0123456789abcdef", k=random.randint(12, 24))))

    def compute_features(sld):
        if len(sld) < 3:
            return None
        length = len(sld)
        freq = defaultdict(int)
        for c in sld:
            freq[c] += 1
        entropy = -sum((cnt / length) * math.log2(cnt / length) for cnt in freq.values())
        vowels = set("aeiou")
        consonants = sum(1 for c in sld.lower() if c in string.ascii_lowercase and c not in vowels)
        digits = sum(1 for c in sld if c.isdigit())
        common_bigrams = {"th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
                          "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar"}
        bigrams = [sld[i:i+2].lower() for i in range(len(sld) - 1)]
        return {
            "length": length,
            "entropy": round(entropy, 3),
            "consonant_ratio": round(consonants / max(length, 1), 3),
            "digit_ratio": round(digits / max(length, 1), 3),
            "unique_ratio": round(len(set(sld)) / max(length, 1), 3),
            "hyphen_count": sld.count("-"),
            "common_bigram_ratio": round(sum(1 for b in bigrams if b in common_bigrams) / max(len(bigrams), 1), 3),
        }

    X = []
    y = []

    for domain in legit_samples:
        feats = compute_features(domain)
        if feats:
            X.append([feats[col] for col in DGA_FEATURE_COLS])
            y.append(0)  # Legitimate

    for domain in dga_samples:
        feats = compute_features(domain)
        if feats:
            X.append([feats[col] for col in DGA_FEATURE_COLS])
            y.append(1)  # DGA

    return np.array(X), np.array(y)


def train():
    """Train DGA detection model (Random Forest)."""
    logger.info("Training DGA detection model...")

    X, y = _generate_training_data()

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X, y)

    model_path = MODEL_DIR / "dga_random_forest.pkl"
    with open(model_path, "wb") as f:
        pickle.dump(model, f)

    # Evaluate
    from sklearn.metrics import accuracy_score
    preds = model.predict(X)
    acc = accuracy_score(y, preds)

    logger.info("DGA model trained. Accuracy: %.1f%%. Saved to %s", acc * 100, model_path)
    return True


def score_domains():
    """Score recent DNS queries for DGA likelihood.

    Returns: list of { domain, dga_score, is_dga }
    """
    model_path = MODEL_DIR / "dga_random_forest.pkl"
    if not model_path.exists():
        logger.warning("No DGA model found. Run train() first.")
        return []

    with open(model_path, "rb") as f:
        model = pickle.load(f)

    dns_features = extract_dns_features()
    if not dns_features:
        return []

    results = []
    for item in dns_features:
        feats = item["features"]
        vector = np.array([[feats[col] for col in DGA_FEATURE_COLS]], dtype=np.float64)

        proba = model.predict_proba(vector)[0]
        dga_score = float(proba[1]) if len(proba) > 1 else 0.0

        results.append({
            "domain": item["domain"],
            "dga_score": round(dga_score, 3),
            "is_dga": dga_score > 0.7,
            "features": feats,
        })

    # Sort by score (most suspicious first)
    results.sort(key=lambda r: r["dga_score"], reverse=True)

    suspicious = [r for r in results if r["is_dga"]]
    if suspicious:
        logger.warning("DGA: %d suspicious domains out of %d", len(suspicious), len(results))

    return results


def create_findings_for_dga(scores):
    """Create findings for detected DGA domains."""
    findings_created = 0

    for item in scores:
        if not item["is_dga"]:
            continue

        db.write_finding(
            skill_id="ml-dga-detector",
            title=f"Suspected DGA domain: {item['domain']} (score {item['dga_score']:.2f})",
            description=f"Domain '{item['domain']}' has characteristics of algorithmically-generated names.\n"
                        f"Entropy: {item['features']['entropy']}, Digit ratio: {item['features']['digit_ratio']}, "
                        f"Common bigram ratio: {item['features']['common_bigram_ratio']}",
            severity="HIGH",
            category="ml-dga",
            asset=None,
            source="ML DGA Detector",
            metadata={
                "dga_score": item["dga_score"],
                "domain": item["domain"],
                "features": item["features"],
            },
        )
        findings_created += 1

    return findings_created
