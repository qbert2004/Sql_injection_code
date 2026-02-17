# ============================================================
# SQL Injection Protector AI Agent — Production Dockerfile
# ============================================================
# Multi-stage build: deps → runtime (minimizes image size)
#
# Build:  docker build -t sqli-protector .
# Run:    docker run -p 5000:5000 --env-file .env sqli-protector
# ============================================================

# --- Stage 1: Base with dependencies ---
FROM python:3.13-slim AS base

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install system dependencies (for scipy, scikit-learn builds)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        libgomp1 && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements first (layer caching for deps)
COPY requirements.txt .

# Install Python dependencies
# NOTE: torch CPU-only variant to reduce image size (~200MB vs ~2GB)
RUN pip install --no-cache-dir \
    torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir -r requirements.txt

# --- Stage 2: Application ---
FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=production

WORKDIR /app

# Copy installed packages from base stage
COPY --from=base /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=base /usr/local/bin /usr/local/bin

# Runtime system dependency (OpenMP for scikit-learn)
RUN apt-get update && \
    apt-get install -y --no-install-recommends libgomp1 && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

# Copy application code
COPY sql_injection_detector.py .
COPY api_server.py .
COPY incident_logger.py .
COPY config.py .
COPY logger.py .
COPY metrics.py .

# Copy ML models and data
COPY rf_sql_model.pkl .
COPY tfidf_vectorizer.pkl .
COPY models/ ./models/

# Create data directory for SQLite (writable by appuser)
RUN mkdir -p /app/data && chown -R appuser:appuser /app

USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/health')" || exit 1

EXPOSE 5000

# Run with uvicorn — production settings
# Workers = 1 for SQLite compatibility (no concurrent writes)
# For PostgreSQL, use --workers $(nproc)
CMD ["uvicorn", "api_server:app", \
     "--host", "0.0.0.0", \
     "--port", "5000", \
     "--workers", "1", \
     "--access-log", \
     "--log-level", "info"]
