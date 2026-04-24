#!/usr/bin/env bash
# ── Project Glasswing Demo — Docker runner ─────────────────────────────────
#
# Builds the Docker image and runs the container, injecting the API key from
# the host environment. Run from the repo root:
#
#   export ANTHROPIC_API_KEY=sk-ant-...
#   bash docker/run.sh
#
# The image is rebuilt every run so local edits to orchestrator.py or target/
# are always picked up. For faster iteration, pass --no-rebuild:
#   SKIP_BUILD=1 bash docker/run.sh

set -euo pipefail

IMAGE_NAME="glasswing-demo"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# ── Verify API key is present in the host environment ──────────────────────
if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo ""
  echo "[ERROR] ANTHROPIC_API_KEY is not set in your environment."
  echo ""
  echo "  Set it first:"
  echo "    export ANTHROPIC_API_KEY=sk-ant-..."
  echo "  Or load from .env:"
  echo "    source .env && bash docker/run.sh"
  echo ""
  exit 1
fi

# ── Build the Docker image (unless skipped) ─────────────────────────────────
if [[ "${SKIP_BUILD:-}" != "1" ]]; then
  echo "Building Docker image '${IMAGE_NAME}'…"
  docker build -t "${IMAGE_NAME}" -f "${SCRIPT_DIR}/Dockerfile" "${REPO_ROOT}"
  echo ""
fi

# ── Run the container ────────────────────────────────────────────────────────
echo "Starting Project Glasswing pipeline inside Docker…"
echo ""
docker run --rm \
  -e ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}" \
  "${IMAGE_NAME}"
