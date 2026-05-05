#!/bin/bash
# Run Playwright screenshots (uses Docker by default, fallback to local Python if available)
# Usage: ./run-screenshots.sh <target_name> [output_path] [max_rows]
# Example: ./run-screenshots.sh Jack ./output 10

TARGET_NAME=${1:-}
OUTPUT_PATH=${2:-./output}
MAX_ROWS=${3:-10}

if [ -z "$TARGET_NAME" ]; then
    echo "Usage: $0 <target_name> [output_path] [max_rows]"
    echo "Example: $0 Jack ./output 10"
    echo ""
    echo "Target name = folder under output_path containing CSV files"
    echo "Expected CSV pattern: <target>_<platform>.csv (e.g. Jack_facebook.csv)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Resolve output path (relative to cwd)
if [ "${OUTPUT_PATH:0:1}" != "/" ]; then
    INPUT_ROOT="$(cd "$(dirname "$OUTPUT_PATH")" && pwd)/$(basename "$OUTPUT_PATH")"
else
    INPUT_ROOT="$OUTPUT_PATH"
fi
OUTPUT_DIR="$(dirname "$INPUT_ROOT")/output_screenshot_${TARGET_NAME}"

echo "Input (CSV): $INPUT_ROOT"
echo "Target: $TARGET_NAME"
echo "Screenshots: $OUTPUT_DIR"
echo "Max rows per platform: $MAX_ROWS"
echo ""

mkdir -p "$OUTPUT_DIR"
cd "$SCRIPT_DIR"

# Try Docker first (recommended - has Playwright + Chromium)
if command -v docker >/dev/null 2>&1; then
    echo "Using Docker..."
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        COMPOSE="docker compose"
    else
        COMPOSE="docker-compose"
    fi
    $COMPOSE build main 2>/dev/null || true
    $COMPOSE run --rm --no-deps \
      -v "$INPUT_ROOT:/app/output" \
      -v "$OUTPUT_DIR:/app/output_screenshot" \
      main python playwright/main.py \
        --input-root /app/output \
        --target "$TARGET_NAME" \
        --output-dir /app/output_screenshot \
        --max-rows "$MAX_ROWS"
else
    # Fallback: local Python (requires: pip install playwright && playwright install chromium)
    echo "Using local Python (Docker not found)..."
    python3 playwright/main.py \
      --input-root "$INPUT_ROOT" \
      --target "$TARGET_NAME" \
      --output-dir "$OUTPUT_DIR" \
      --max-rows "$MAX_ROWS"
fi

echo ""
echo "Done! Screenshots saved to: $OUTPUT_DIR"
