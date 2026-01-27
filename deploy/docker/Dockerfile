# =============================================================================
# RedOPS Docker Image
# Multi-stage build for optimized production image
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Builder
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -e ".[all]"

# -----------------------------------------------------------------------------
# Stage 2: Runtime
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

# Labels
LABEL maintainer="RedOPS Team"
LABEL version="1.5.0"
LABEL description="RedOPS Security Assessment Framework"

# Create non-root user
RUN groupadd -r redops && useradd -r -g redops redops

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    dnsutils \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY --chown=redops:redops src/ ./src/
COPY --chown=redops:redops pyproject.toml README.md ./

# Create data directories
RUN mkdir -p /app/data /app/logs && \
    chown -R redops:redops /app

# Install the package
RUN pip install --no-cache-dir -e .

# Switch to non-root user
USER redops

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV REDOPS_ENV=production
ENV LOG_LEVEL=INFO

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command
CMD ["python", "-m", "redops.web.app"]

# Expose ports
EXPOSE 8000
