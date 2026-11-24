# ==============================================================================
# OWASP Sentinel - Production Multi-Stage Container Image
# ==============================================================================

# Stage 1: Build React + TypeScript Frontend
FROM node:22-alpine AS frontend-builder
WORKDIR /build/frontend

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# Stage 2: Python 3.13 Backend & Unified Serving Runtime
FROM python:3.13-slim AS production

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install system dependencies for networking and PostgreSQL connectivity
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    libc6-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application codebase (including app, scripts, scanners, and configuration)
COPY . .

# Copy compiled frontend single-page application from Stage 1
COPY --from=frontend-builder /build/frontend/dist ./frontend/dist

# Expose standard HTTP port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Launch FastAPI web application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

