# ──────────────────────────────────────────────────────────────────────────────
# ml-engine — DGA detection (Random Forest + LSTM/ONNX) + clustering + anomaly
#
# Two-stage build:
#   1. trainer  — fetches public training corpora (Tranco, optional OpenPhish)
#                 and runs build_dga_dataset.py + train_dga_models.py to
#                 produce the .pkl / .onnx model files. No customer data is
#                 ever read; the inputs are public CC-BY lists and synthetic
#                 DGA domains generated algorithmically inside the script.
#   2. runtime  — slim image with the inference deps + the trained models
#                 copied from the trainer stage. torch is intentionally NOT
#                 installed at runtime (training-only dep).
# ──────────────────────────────────────────────────────────────────────────────

# ── Stage 1: train the models ────────────────────────────────────────────────
FROM python:3.11-slim AS trainer

WORKDIR /build

# Build deps that don't ship in slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

# Training requires the runtime numerics + torch + onnx. We install in two
# steps so PyPI handles sklearn/numpy/pandas/onnx normally and the PyTorch CPU
# wheel index is only used for torch (otherwise pip can't resolve the others).
RUN pip install --no-cache-dir \
        scikit-learn==1.6.1 \
        numpy==2.2.3 \
        pandas==2.2.3 \
        onnx==1.17.0
RUN pip install --no-cache-dir \
        --index-url https://download.pytorch.org/whl/cpu \
        torch==2.5.1

# Bring the training scripts and the committed fallback corpus.
COPY scripts/ ./scripts/
COPY data/ ./data/

# Try to fetch a fresh Tranco list at build time. Tranco publishes daily lists
# at stable URLs; we fall back to the committed `top-100k.csv` when the live
# endpoint is unreachable (e.g. air-gapped client build, network hiccup, GitHub
# Actions transient failure). Never fails the build because of a missing
# upstream — the fallback is always sufficient to train a usable model.
RUN mkdir -p datasets \
    && (curl -fSL --max-time 30 \
            "https://tranco-list.eu/top/D/full" \
            -o datasets/top-1m.csv \
        && echo "Tranco fetched fresh ($(wc -l < datasets/top-1m.csv) rows)") \
       || (echo "Tranco unreachable — falling back to committed top-100k snapshot" \
           && cp data/top-100k.csv datasets/top-1m.csv)

# Generate the dataset (deterministic given the input list) and train both
# models. Outputs end up in datasets/.
RUN python scripts/build_dga_dataset.py
RUN python scripts/train_dga_models.py

# Provenance sidecar so a runtime can prove what produced the bundled models.
RUN python -c "import json, hashlib, datetime, pathlib; \
    f=lambda p: hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest(); \
    json.dump({ \
        'trained_at': datetime.datetime.utcnow().isoformat()+'Z', \
        'tranco_sha256': f('datasets/top-1m.csv'), \
        'dataset_sha256': f('datasets/dga_dataset.json'), \
        'lstm_sha256': f('datasets/dga_lstm.onnx'), \
        'forest_sha256': f('datasets/dga_random_forest.pkl'), \
    }, open('datasets/MODEL_PROVENANCE.json', 'w'), indent=2)"

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python:3.11-slim

# Link the published GHCR package back to its source repo. Without this
# label the GitHub Container Registry refuses to auto-create the package
# for the workflow's GITHUB_TOKEN ("denied: permission_denied: write_package").
LABEL org.opencontainers.image.source="https://github.com/threatclaw/threatclaw" \
      org.opencontainers.image.title="ThreatClaw ML Engine" \
      org.opencontainers.image.description="Behavioural anomaly + clustering + DGA detection (read-only inference)" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# Pull only the trained models from the trainer stage. No torch, no scripts,
# no raw training data in the runtime image.
COPY --from=trainer /build/datasets/dga_lstm.onnx \
                    /build/datasets/dga_lstm_meta.json \
                    /build/datasets/dga_dataset.json \
                    /build/datasets/dga_random_forest.pkl \
                    /build/datasets/MODEL_PROVENANCE.json \
                    /models/

ENV DATABASE_URL=postgres://threatclaw:threatclaw@threatclaw-db:5432/threatclaw
ENV ML_MODEL_DIR=/models

VOLUME /models

HEALTHCHECK --interval=60s --timeout=5s --retries=3 \
    CMD python -c "import psycopg2; psycopg2.connect('${DATABASE_URL}')" || exit 1

CMD ["python", "-m", "src.main", "daemon"]
