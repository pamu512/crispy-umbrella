#!/bin/bash
set -e

# Start Docker daemon in background
# echo "Starting Docker daemon..."
dockerd > /var/log/dockerd.log 2>&1 &
DOCKER_PID=$!

# Wait for Docker to be ready
# echo "Waiting for Docker daemon to be ready..."
timeout=30
while ! docker info >/dev/null 2>&1; do
    if [ "$timeout" -le 0 ]; then
        echo "Timeout waiting for Docker daemon"
        cat /var/log/dockerd.log
        exit 1
    fi
    timeout=$((timeout - 1))
    sleep 1
done
# echo "Docker daemon is ready."

# Run the main application
# echo "Starting Brand Scout..."
# Pass all arguments to the python script
python3 /app/brand_scout.py "$@"
EXIT_CODE=$?

# Fix ownership of created files to match the owner of /workdir
HOST_UID=$(stat -c "%u" /workdir)
HOST_GID=$(stat -c "%g" /workdir)
chown -R $HOST_UID:$HOST_GID /workdir

exit $EXIT_CODE
