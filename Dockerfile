# ==============================================================================
# ASCP Autonomous Control Plane Agent - Container Image
# Multi-stage / secure non-root Python deployment
# Target: Python 3.12-slim
# ==============================================================================

FROM python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered standard I/O
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ASCP_ENV=production \
    PORT=8085 \
    HOST=0.0.0.0

WORKDIR /app

# Install security patches and runtime utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install pinned Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application modules and web assets
COPY ascp_agent/ ascp_agent/
COPY web/ web/
COPY config/ config/
COPY deploy/ deploy/
COPY pyproject.toml .

# Create non-root dedicated system user and secure directories
RUN useradd -u 10001 -m -s /bin/sh appuser \
    && mkdir -p /app/logs /run/secrets \
    && chown -R appuser:appuser /app /run/secrets

USER appuser

EXPOSE 8085

# Container healthcheck querying REST API status endpoint
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:8085/api/status || exit 1

ENTRYPOINT ["python", "web/server.py"]
CMD ["8085", "0.0.0.0"]
