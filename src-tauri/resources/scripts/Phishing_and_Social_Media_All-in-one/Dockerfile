FROM mcr.microsoft.com/playwright/python:v1.57.0-jammy

# Install Docker CLI and Daemon
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    iptables \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    && apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin fuse-overlayfs \
    && rm -rf /var/lib/apt/lists/*

# Expose Docker socket volume for DinD performance and compatibility
VOLUME /var/lib/docker

# Set working directory
WORKDIR /workdir

# Copy project files
COPY requirements.txt /app/requirements.txt
COPY social_media /app/social_media
COPY screenshots /app/screenshots
COPY brand_scout.py /app/brand_scout.py
COPY entrypoint.sh /app/entrypoint.sh

# Install Python dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

# Entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
