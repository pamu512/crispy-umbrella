#!/bin/bash
# Docker Compose startup script
# Usage: ./docker-run.sh <target_name> [output_path] [start_time] [end_time]
# Compatible with Docker Compose V1 and V2

TARGET_NAME=${1:-}
OUTPUT_PATH=${2:-./output}
START_TIME=${3:-}
END_TIME=${4:-}

if [ -z "$TARGET_NAME" ]; then
    echo "Usage: $0 <target_name> [output_path] [start_time] [end_time]"
    echo "Example: $0 Test /home/client/Desktop 2026-01-01 2026-01-31"
    exit 1
fi

# Convert relative path to absolute path
if [ ! "${OUTPUT_PATH:0:1}" = "/" ]; then
    OUTPUT_PATH=$(cd "$(dirname "$OUTPUT_PATH")" && pwd)/$(basename "$OUTPUT_PATH")
fi

# Ensure output directory exists
mkdir -p "$OUTPUT_PATH"

# Check directory permissions
if [ ! -w "$OUTPUT_PATH" ]; then
    echo "Warning: Output directory '$OUTPUT_PATH' is not writable"
    echo "Attempting to modify permissions..."
    chmod 755 "$OUTPUT_PATH" 2>/dev/null || echo "Cannot modify permissions, please set manually"
fi

echo "Starting Docker Compose..."
echo "Target: $TARGET_NAME"
echo "Output: $OUTPUT_PATH (mapped to /app/output in container)"
if [ -n "$START_TIME" ]; then
    echo "Start Time: $START_TIME"
fi
if [ -n "$END_TIME" ]; then
    echo "End Time: $END_TIME"
fi
echo "Output directory permissions: $(ls -ld "$OUTPUT_PATH" 2>/dev/null | awk '{print $1, $3, $4}')"

# Detect available Docker Compose command and define execution function
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    # Docker Compose V2 (as Docker CLI plugin)
    echo "Using Docker Compose V2..."
    compose_cmd() {
        docker compose "$@"
    }
elif command -v docker-compose >/dev/null 2>&1; then
    # Docker Compose V1 (standalone command)
    echo "Using Docker Compose V1..."
    compose_cmd() {
        docker-compose "$@"
    }
else
    echo "Error: Docker Compose not found. Please install Docker Compose V1 or V2."
    exit 1
fi

# Start Tor service first (run in background)
echo "Starting Tor service..."
compose_cmd up -d tor_docker

# Wait for Tor service health check to pass
echo "Waiting for Tor service to be ready..."
timeout=60
elapsed=0
while [ $elapsed -lt $timeout ]; do
    if compose_cmd ps tor_docker 2>/dev/null | grep -q "healthy"; then
        echo "Tor service is ready"
        break
    fi
    sleep 2
    elapsed=$((elapsed + 2))
done

if [ $elapsed -ge $timeout ]; then
    echo "Warning: Tor service health check timeout, but continuing..."
fi

# Run main container with dynamic volume mapping
echo "Running main program..."
HOST_OUTPUT_PATH="$OUTPUT_PATH"  # Save host path
echo "Volume mapping: $HOST_OUTPUT_PATH -> /app/output"
export TARGET_NAME="$TARGET_NAME"
export OUTPUT_PATH="/app/output"  # Container path
if [ -n "$START_TIME" ]; then
    export START_TIME="$START_TIME"
fi
if [ -n "$END_TIME" ]; then
    export END_TIME="$END_TIME"
fi
compose_cmd run --rm --volume "$HOST_OUTPUT_PATH:/app/output" main

# Verify files have been saved
echo ""
echo "Checking output files..."
if [ -d "$HOST_OUTPUT_PATH/$TARGET_NAME" ]; then
    echo "✓ Found output directory: $HOST_OUTPUT_PATH/$TARGET_NAME"
    file_count=$(find "$HOST_OUTPUT_PATH/$TARGET_NAME" -name "*.csv" 2>/dev/null | wc -l)
    echo "✓ Found $file_count CSV file(s)"
    ls -lh "$HOST_OUTPUT_PATH/$TARGET_NAME" 2>/dev/null || echo "Cannot list files (may be a permission issue)"
else
    echo "✗ Output directory not found: $HOST_OUTPUT_PATH/$TARGET_NAME"
    echo "Please check container logs for more information"
    echo "Attempting to list output directory contents:"
    ls -la "$HOST_OUTPUT_PATH" 2>/dev/null || echo "Cannot access output directory"
fi

# Cleanup: Stop and remove Tor container
echo "Cleaning up Tor service..."
compose_cmd stop tor_docker 2>/dev/null || true
compose_cmd rm -f tor_docker 2>/dev/null || true

echo "Done!"
