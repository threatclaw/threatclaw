FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

ENV DATABASE_URL=postgres://threatclaw:threatclaw@host.docker.internal:5432/threatclaw
ENV RETRAIN_SCHEDULE=0 3 * * *
ENV ML_MODEL_DIR=/models

VOLUME /models

CMD ["python", "-m", "src.main"]
