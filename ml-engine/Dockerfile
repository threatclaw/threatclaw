FROM python:3.11-slim

WORKDIR /app

# Install deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY src/ ./src/

# Copy pre-trained DGA models (LSTM ONNX + dataset for RF retraining)
COPY datasets/dga_lstm.onnx datasets/dga_lstm_meta.json datasets/dga_dataset.json /models/

# Config (overridable via docker-compose environment)
ENV DATABASE_URL=postgres://threatclaw:threatclaw@threatclaw-db:5432/threatclaw
ENV ML_MODEL_DIR=/models

VOLUME /models

# Health check — verify Python + DB connectivity
HEALTHCHECK --interval=60s --timeout=5s --retries=3 \
    CMD python -c "import psycopg2; psycopg2.connect('${DATABASE_URL}')" || exit 1

CMD ["python", "-m", "src.main", "daemon"]
