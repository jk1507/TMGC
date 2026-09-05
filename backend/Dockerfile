# ============================================
# RETRO_INTEL Backend — Docker Image
# ============================================
FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    dnsutils \
    whois \
    netcat-openbsd \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (layer caching)
COPY requirements.txt .

# Install Python dependencies
# Install PyTorch first so PyTorch Geometric extensions can build/install correctly
RUN pip install --no-cache-dir "torch==2.5.1"

# Install remaining Python dependencies
RUN pip install --no-cache-dir \
    --find-links https://data.pyg.org/whl/torch-2.5.1+cpu.html \
    -r requirements.txt

# Install Playwright browsers (for browser automation)
RUN python -m playwright install chromium --with-deps || true

# Copy backend source code
COPY *.py ./
COPY *.pkl ./
COPY *.onnx ./
COPY *.csv ./

# Copy .env if it exists (will be overridden by docker-compose)
COPY .env* ./

# Create non-root user
RUN useradd --create-home --shell /bin/bash appuser
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1
