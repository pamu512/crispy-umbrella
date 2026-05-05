FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    docker.io \
    docker-compose \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Playwright browsers: fixed path so installs are reproducible in the image
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
# Install Chromium and OS deps; fall back if --with-deps fails on minimal images
RUN playwright install --with-deps chromium || \
    (playwright install chromium && (playwright install-deps chromium || true))

# Copy application files
COPY *.py ./
COPY *.json ./
COPY playwright ./playwright

# Create directories for output and logs
RUN mkdir -p /app/output /app/logs

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONIOENCODING=utf-8

# Default command (can be overridden in docker-compose)
CMD ["python", "main.py"]

