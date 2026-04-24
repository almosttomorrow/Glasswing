# ── Project Glasswing Demo — Docker image ──────────────────────────────────
#
# Builds a minimal, self-contained environment to run orchestrator.py.
# The Anthropic API key is injected at runtime via the -e flag (see run.sh).
# Never bake secrets into the image.

FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Copy the synthetic target codebase
COPY target/ ./target/

# Copy the pipeline orchestrator
COPY orchestrator.py ./

# Install the official Anthropic Python SDK (only dependency)
RUN pip install --no-cache-dir anthropic

# The ANTHROPIC_API_KEY must be passed in at runtime:
#   docker run -e ANTHROPIC_API_KEY=sk-... glasswing-demo
# It is intentionally not set here — setting secrets in ENV is a bad practice.

# Run the pipeline when the container starts
ENTRYPOINT ["python3", "orchestrator.py"]
