FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# System deps: build-essential for any wheel builds, ffmpeg for video validation
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ffmpeg \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first (better Docker layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source (includes bundled frontend/ folder)
COPY . .

# Data directory for any local SQLite fallback (not used in Turso mode)
RUN mkdir -p /app/data

# Defaults — Render overrides via env vars
ENV ENV=production \
    WORKER_ID=0 \
    HOST=0.0.0.0 \
    PORT=10000

EXPOSE 10000

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:${PORT}/healthz || exit 1

# Single worker because: background threads (bot polling, expiry scheduler) must run only once.
# Scale by adding instances, not workers.
CMD gunicorn main:app \
    -k uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:${PORT} \
    --workers 1 \
    --timeout 120 \
    --access-logfile - \
    --error-logfile - \
    --log-level info
