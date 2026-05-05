# Dockerfile for ASM Platform (FastAPI + Celery)
FROM python:3.11-slim

WORKDIR /app

# Install git for pip to install from git URLs
RUN apt-get update && apt-get install -y git whois && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
# ensure docker-entrypoint script is executable
RUN chmod +x /app/docker-entrypoint.sh || true

# Expose FastAPI port
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
