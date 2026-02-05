# RedOPS Docker Image
# Multi-stage build for smaller final image

# Build stage
FROM python:3.12-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip to latest
RUN pip install --no-cache-dir --upgrade pip

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install package with all dependencies, upgrade protobuf for CVE fix
RUN pip install --no-cache-dir --upgrade protobuf && \
    pip install --no-cache-dir --target=/app/deps .[all]

# Runtime stage
FROM python:3.12-slim

# Upgrade pip in runtime image for security
RUN pip install --no-cache-dir --upgrade pip

LABEL org.opencontainers.image.title="RedOPS"
LABEL org.opencontainers.image.description="Professional Cybersecurity Intelligence & Attack Surface Management Platform"
LABEL org.opencontainers.image.source="https://github.com/AreteDriver/RedOPS"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash redops

# Copy installed dependencies from builder
COPY --from=builder /app/deps /usr/local/lib/python3.12/site-packages/

# Copy application code
COPY --from=builder /app/src /app/src
COPY config/ /app/config/

# Set Python path
ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

# Create output directory
RUN mkdir -p /app/output && chown -R redops:redops /app

# Switch to non-root user
USER redops

# Default command
ENTRYPOINT ["python", "-m", "redops.main"]
CMD ["--help"]
