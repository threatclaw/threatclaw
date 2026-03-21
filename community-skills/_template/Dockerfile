FROM python:3.12-slim
WORKDIR /app

# Security: non-root user
RUN useradd -m -s /bin/sh skilluser

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || true

# Copy skill
COPY main.py skill.json ./

USER skilluser
CMD ["python3", "main.py"]
