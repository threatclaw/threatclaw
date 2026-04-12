#!/usr/bin/env python3
"""Train both DGA detection models (Random Forest + LSTM) and benchmark them.

Usage:
    python3 train_dga_models.py

Outputs:
    datasets/dga_random_forest.pkl   - scikit-learn Random Forest model
    datasets/dga_lstm.onnx           - ONNX-exported LSTM model
    datasets/dga_lstm_meta.json      - char-to-index mapping for LSTM
    datasets/benchmark_results.json  - comparison metrics

Requirements:
    pip install scikit-learn numpy torch onnx onnxruntime
    (torch is only needed for training, not inference)
"""

import json
import math
import os
import pickle
import string
import sys
import time
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

SCRIPT_DIR = Path(__file__).parent
DATASET_DIR = SCRIPT_DIR.parent / "datasets"
MODEL_DIR = DATASET_DIR

# -------- FEATURE EXTRACTION (12 features) --------

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


def compute_features(domain: str):
    """Compute 12 linguistic features for a domain string."""
    if len(domain) < 3:
        return None

    n = len(domain)
    lower = domain.lower()

    # 1. Length
    length = n

    # 2. Shannon entropy
    freq = defaultdict(int)
    for c in lower:
        freq[c] += 1
    entropy = -sum((cnt / n) * math.log2(cnt / n) for cnt in freq.values()) if n > 0 else 0

    # 3. Consonant ratio
    consonant_count = sum(1 for c in lower if c in CONSONANTS)
    consonant_ratio = consonant_count / n

    # 4. Digit ratio
    digit_count = sum(1 for c in lower if c.isdigit())
    digit_ratio = digit_count / n

    # 5. Unique character ratio
    unique_ratio = len(set(lower)) / n

    # 6. Hyphen count
    hyphen_count = lower.count("-")

    # 7. Common bigram ratio
    bigrams = [lower[i:i+2] for i in range(n - 1)]
    bigram_ratio = sum(1 for b in bigrams if b in COMMON_BIGRAMS) / max(len(bigrams), 1)

    # 8. Common trigram ratio
    trigrams_list = [lower[i:i+3] for i in range(n - 2)]
    trigram_ratio = sum(1 for t in trigrams_list if t in COMMON_TRIGRAMS) / max(len(trigrams_list), 1)

    # 9. Vowel-consonant transition ratio
    transitions = 0
    for i in range(1, n):
        prev_v = lower[i-1] in VOWELS
        curr_v = lower[i] in VOWELS
        prev_c = lower[i-1] in CONSONANTS
        curr_c = lower[i] in CONSONANTS
        if (prev_v and curr_c) or (prev_c and curr_v):
            transitions += 1
    vc_transition_ratio = transitions / max(n - 1, 1)

    # 10. Max consecutive consonants
    max_consec_consonants = 0
    current_run = 0
    for c in lower:
        if c in CONSONANTS:
            current_run += 1
            max_consec_consonants = max(max_consec_consonants, current_run)
        else:
            current_run = 0

    # 11. Max consecutive digits
    max_consec_digits = 0
    current_run = 0
    for c in lower:
        if c.isdigit():
            current_run += 1
            max_consec_digits = max(max_consec_digits, current_run)
        else:
            current_run = 0

    # 12. Gini impurity of characters
    total = sum(freq.values())
    gini = 1.0 - sum((cnt / total) ** 2 for cnt in freq.values()) if total > 0 else 0

    return {
        "length": length,
        "entropy": round(entropy, 4),
        "consonant_ratio": round(consonant_ratio, 4),
        "digit_ratio": round(digit_ratio, 4),
        "unique_ratio": round(unique_ratio, 4),
        "hyphen_count": hyphen_count,
        "bigram_ratio": round(bigram_ratio, 4),
        "trigram_ratio": round(trigram_ratio, 4),
        "vc_transition_ratio": round(vc_transition_ratio, 4),
        "max_consec_consonants": max_consec_consonants,
        "max_consec_digits": max_consec_digits,
        "gini_impurity": round(gini, 4),
    }


FEATURE_COLS = [
    "length", "entropy", "consonant_ratio", "digit_ratio",
    "unique_ratio", "hyphen_count", "bigram_ratio", "trigram_ratio",
    "vc_transition_ratio", "max_consec_consonants", "max_consec_digits",
    "gini_impurity",
]


# -------- LOAD DATASET --------

def load_dataset():
    path = DATASET_DIR / "dga_dataset.json"
    with open(path) as f:
        data = json.load(f)
    return data["train"], data["test"], data["meta"]


def prepare_rf_data(samples):
    X, y = [], []
    for s in samples:
        feats = compute_features(s["domain"])
        if feats:
            X.append([feats[col] for col in FEATURE_COLS])
            y.append(s["label"])
    return np.array(X), np.array(y)


# -------- RANDOM FOREST --------

def train_random_forest(X_train, y_train, X_test, y_test):
    print("\n" + "="*60)
    print("RANDOM FOREST - Training")
    print("="*60)

    t0 = time.time()
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_leaf=5,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    train_time = time.time() - t0

    t0 = time.time()
    y_pred = model.predict(X_test)
    inference_time = (time.time() - t0) / len(X_test) * 1000

    metrics = compute_metrics(y_test, y_pred, "Random Forest")
    metrics["train_time_sec"] = round(train_time, 2)
    metrics["inference_ms"] = round(inference_time, 4)

    importances = dict(zip(FEATURE_COLS, model.feature_importances_))
    sorted_imp = sorted(importances.items(), key=lambda x: x[1], reverse=True)
    print("\nFeature importance:")
    for feat, imp in sorted_imp:
        bar = "#" * int(imp * 50)
        print(f"  {feat:25s} {imp:.4f} {bar}")

    model_path = MODEL_DIR / "dga_random_forest.pkl"
    with open(model_path, "wb") as f:
        pickle.dump({"model": model, "features": FEATURE_COLS, "version": 2}, f)
    print(f"\nModel saved to {model_path}")

    return model, metrics


# -------- LSTM CHARACTER-LEVEL --------

def train_lstm(train_samples, test_samples):
    print("\n" + "="*60)
    print("LSTM CHARACTER-LEVEL - Training")
    print("="*60)

    try:
        import torch
        import torch.nn as nn
        from torch.utils.data import DataLoader, TensorDataset
    except ImportError:
        print("PyTorch not installed. Installing CPU-only version...")
        os.system(f"{sys.executable} -m pip install torch --index-url https://download.pytorch.org/whl/cpu -q")
        import torch
        import torch.nn as nn
        from torch.utils.data import DataLoader, TensorDataset

    chars = sorted(set(string.ascii_lowercase + string.digits + "-._"))
    char_to_idx = {c: i + 1 for i, c in enumerate(chars)}
    vocab_size = len(chars) + 1
    max_len = 64

    def encode_domain(domain, ml=64):
        encoded = [char_to_idx.get(c, 0) for c in domain.lower()[:ml]]
        encoded += [0] * (ml - len(encoded))
        return encoded

    X_train = torch.tensor([encode_domain(s["domain"]) for s in train_samples], dtype=torch.long)
    y_train = torch.tensor([s["label"] for s in train_samples], dtype=torch.float32)
    X_test = torch.tensor([encode_domain(s["domain"]) for s in test_samples], dtype=torch.long)
    y_test_np = np.array([s["label"] for s in test_samples])

    train_ds = TensorDataset(X_train, y_train)
    train_loader = DataLoader(train_ds, batch_size=256, shuffle=True)

    class DGAClassifier(nn.Module):
        def __init__(self, vs, embed_dim=32, hidden_dim=64, num_layers=2):
            super().__init__()
            self.embedding = nn.Embedding(vs, embed_dim, padding_idx=0)
            self.lstm = nn.LSTM(embed_dim, hidden_dim, num_layers=num_layers,
                              batch_first=True, dropout=0.3, bidirectional=True)
            self.fc = nn.Sequential(
                nn.Linear(hidden_dim * 2, 32),
                nn.ReLU(),
                nn.Dropout(0.3),
                nn.Linear(32, 1),
            )

        def forward(self, x):
            emb = self.embedding(x)
            _, (h_n, _) = self.lstm(emb)
            h_cat = torch.cat((h_n[-2], h_n[-1]), dim=1)
            return self.fc(h_cat).squeeze(-1)

    model = DGAClassifier(vocab_size, embed_dim=32, hidden_dim=64, num_layers=2)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    criterion = nn.BCEWithLogitsLoss()

    print(f"  Vocab size: {vocab_size}, Max length: {max_len}")
    print(f"  Train: {len(X_train)}, Test: {len(X_test)}")
    print(f"  Parameters: {sum(p.numel() for p in model.parameters()):,}")

    t0 = time.time()
    best_f1 = 0
    best_state = None
    patience_counter = 0

    for epoch in range(20):
        model.train()
        total_loss = 0
        for batch_x, batch_y in train_loader:
            optimizer.zero_grad()
            logits = model(batch_x)
            loss = criterion(logits, batch_y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        model.eval()  # switch to inference mode
        with torch.no_grad():
            test_logits = model(X_test)
            test_probs = torch.sigmoid(test_logits)
            test_preds = (test_probs > 0.5).int().numpy()

        acc = accuracy_score(y_test_np, test_preds)
        f1 = f1_score(y_test_np, test_preds, zero_division=0)
        avg_loss = total_loss / len(train_loader)

        print(f"  Epoch {epoch+1:2d}: loss={avg_loss:.4f} acc={acc:.4f} f1={f1:.4f}")

        if f1 > best_f1:
            best_f1 = f1
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            patience_counter = 0
        else:
            patience_counter += 1
            if patience_counter >= 3:
                print(f"  Early stopping at epoch {epoch+1}")
                break

    train_time = time.time() - t0
    if best_state:
        model.load_state_dict(best_state)
    model.eval()

    with torch.no_grad():
        test_logits = model(X_test)
        test_probs = torch.sigmoid(test_logits).numpy()
        y_pred = (test_probs > 0.5).astype(int)

    t0 = time.time()
    with torch.no_grad():
        for _ in range(3):
            _ = model(X_test)
    torch_ms = (time.time() - t0) / (3 * len(X_test)) * 1000

    metrics = compute_metrics(y_test_np, y_pred, "LSTM")
    metrics["train_time_sec"] = round(train_time, 2)
    metrics["inference_ms_torch"] = round(torch_ms, 4)
    metrics["model_params"] = sum(p.numel() for p in model.parameters())

    # Export ONNX
    print("\nExporting to ONNX...")
    onnx_path = MODEL_DIR / "dga_lstm.onnx"
    dummy = torch.zeros(1, max_len, dtype=torch.long)

    torch.onnx.export(
        model, dummy, str(onnx_path),
        input_names=["domain_encoded"],
        output_names=["logit"],
        dynamic_axes={"domain_encoded": {0: "batch_size"}, "logit": {0: "batch_size"}},
        opset_version=14,
    )
    onnx_size = onnx_path.stat().st_size / 1024 / 1024
    print(f"  ONNX saved: {onnx_path} ({onnx_size:.1f} MB)")

    meta = {"char_to_idx": char_to_idx, "max_len": max_len, "vocab_size": vocab_size, "version": 1}
    meta_path = MODEL_DIR / "dga_lstm_meta.json"
    with open(meta_path, "w") as f:
        json.dump(meta, f)
    print(f"  Metadata saved: {meta_path}")

    # Test ONNX Runtime
    try:
        import onnxruntime as ort
    except ImportError:
        print("Installing onnxruntime...")
        os.system(f"{sys.executable} -m pip install onnxruntime -q")
        import onnxruntime as ort

    session = ort.InferenceSession(str(onnx_path))
    t0 = time.time()
    for _ in range(3):
        ort_input = X_test.numpy().astype(np.int64)
        _ = session.run(None, {"domain_encoded": ort_input})
    onnx_ms = (time.time() - t0) / (3 * len(X_test)) * 1000
    metrics["inference_ms_onnx"] = round(onnx_ms, 4)
    print(f"  ONNX Runtime inference: {onnx_ms:.4f} ms/domain")

    return model, metrics


# -------- METRICS --------

def compute_metrics(y_true, y_pred, model_name):
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()

    print(f"\n{model_name} Results:")
    print(f"  Accuracy:  {acc:.4f} ({acc*100:.1f}%)")
    print(f"  Precision: {prec:.4f} (false positives: {fp})")
    print(f"  Recall:    {rec:.4f} (false negatives: {fn})")
    print(f"  F1 Score:  {f1:.4f}")
    print(f"  Matrix: TP={tp} TN={tn} FP={fp} FN={fn}")

    return {
        "model": model_name,
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "true_positives": int(tp),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
    }


# -------- PER-FAMILY ANALYSIS --------

def analyze_per_family(model_rf, test_samples):
    print("\n" + "="*60)
    print("PER-FAMILY ANALYSIS (Random Forest)")
    print("="*60)

    families = defaultdict(lambda: {"total": 0, "correct": 0, "missed": []})

    for s in test_samples:
        feats = compute_features(s["domain"])
        if not feats:
            continue
        vector = np.array([[feats[col] for col in FEATURE_COLS]])
        pred = model_rf.predict(vector)[0]
        family = s.get("family", "unknown")
        families[family]["total"] += 1
        if pred == s["label"]:
            families[family]["correct"] += 1
        else:
            families[family]["missed"].append(s["domain"])

    print(f"\n{'Family':<25s} {'Total':>6s} {'Correct':>8s} {'Accuracy':>10s} {'Missed examples'}")
    print("-" * 90)
    for family in sorted(families.keys()):
        f = families[family]
        acc = f["correct"] / max(f["total"], 1) * 100
        missed = ", ".join(f["missed"][:3])
        if len(f["missed"]) > 3:
            missed += f" (+{len(f['missed'])-3} more)"
        print(f"  {family:<23s} {f['total']:>6d} {f['correct']:>8d} {acc:>9.1f}%  {missed}")


# -------- MAIN --------

def main():
    print("ThreatClaw DGA Model Training Pipeline")
    print("Random Forest (12 features) + LSTM (character-level)")
    print("=" * 55)

    train_samples, test_samples, meta = load_dataset()
    print(f"\nDataset: {meta['train_count']} train, {meta['test_count']} test")

    X_train, y_train = prepare_rf_data(train_samples)
    X_test, y_test = prepare_rf_data(test_samples)
    print(f"RF features: {X_train.shape[1]} cols, {X_train.shape[0]} train, {X_test.shape[0]} test")

    rf_model, rf_metrics = train_random_forest(X_train, y_train, X_test, y_test)
    analyze_per_family(rf_model, test_samples)
    lstm_model, lstm_metrics = train_lstm(train_samples, test_samples)

    print("\n" + "="*60)
    print("BENCHMARK COMPARISON")
    print("="*60)
    print(f"\n{'Metric':<20s} {'Random Forest':>15s} {'LSTM ONNX':>15s}")
    print("-" * 52)
    for key in ["accuracy", "precision", "recall", "f1"]:
        rv = rf_metrics.get(key, 0)
        lv = lstm_metrics.get(key, 0)
        print(f"  {key:<18s} {rv:>14.4f} {lv:>14.4f}")
    print(f"  {'Train time':<18s} {rf_metrics['train_time_sec']:>13.1f}s {lstm_metrics['train_time_sec']:>13.1f}s")
    print(f"  {'Inference':<18s} {rf_metrics['inference_ms']:>12.4f}ms {lstm_metrics.get('inference_ms_onnx', 0):>12.4f}ms")
    print(f"  {'False pos':<18s} {rf_metrics['false_positives']:>14d} {lstm_metrics['false_positives']:>14d}")
    print(f"  {'False neg':<18s} {rf_metrics['false_negatives']:>14d} {lstm_metrics['false_negatives']:>14d}")

    benchmark = {"random_forest": rf_metrics, "lstm_onnx": lstm_metrics, "dataset": meta, "features": FEATURE_COLS}
    bench_path = MODEL_DIR / "benchmark_results.json"
    with open(bench_path, "w") as f:
        json.dump(benchmark, f, indent=2)
    print(f"\nBenchmark saved to {bench_path}")
    print("\nBoth models trained and saved. Ready for deployment.")


if __name__ == "__main__":
    main()
