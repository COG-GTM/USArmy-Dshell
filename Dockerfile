# Dshell Network Forensic Analysis Framework
# Security-hardened multi-stage Docker build
# Following DevSecOps best practices

# Build stage
FROM python:3.11-alpine AS builder

# Security: Pin base image version for reproducibility
# Vulnerability scanning: Run `trivy image python:3.11-alpine` before building

COPY . /src

WORKDIR /src

ARG OUI_SRC="http://standards-oui.ieee.org/oui/oui.txt"

ENV VIRTUAL_ENV="/opt/venv"

# Install build dependencies with --no-cache to reduce image size
# Security: Minimize attack surface by only installing required packages
RUN apk add --no-cache \
        cargo \
        curl \
        g++ \
        gcc \
        rust \
        libpcap-dev \
        libffi-dev \
    && python3 -m venv "${VIRTUAL_ENV}" \
    && curl --location --silent --output "/src/dshell/data/oui.txt" "${OUI_SRC}"

ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

# Install Python dependencies with --no-cache-dir to reduce image size
# Security: Use requirements.txt with pinned versions
COPY requirements.txt /src/
RUN pip install --no-cache-dir --upgrade pip wheel \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir .

# Production stage
FROM python:3.11-alpine

# Security labels for container metadata
LABEL maintainer="USArmyResearchLab" \
      version="3.2.3" \
      description="Dshell - Network Forensic Analysis Framework" \
      security.scan="trivy" \
      org.opencontainers.image.source="https://github.com/USArmyResearchLab/Dshell"

ENV VIRTUAL_ENV="/opt/venv"

# Copy virtual environment from builder
COPY --from=builder "${VIRTUAL_ENV}/" "${VIRTUAL_ENV}/"

# Install runtime dependencies with --no-cache
RUN apk add --no-cache \
        bash \
        libstdc++ \
        libpcap \
        tini \
    # Security: Create non-root user for running the application
    && addgroup -g 1000 -S dshell \
    && adduser -u 1000 -S -G dshell -s /bin/sh -h /home/dshell dshell \
    # Security: Create data directory with proper permissions
    && mkdir -p /data \
    && chown -R dshell:dshell /data

# Security: Set restrictive file permissions
RUN chmod -R 755 "${VIRTUAL_ENV}"

VOLUME ["/data"]

WORKDIR "/data"

ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

# Security: Run as non-root user
USER dshell

# Health check for container orchestration
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import dshell; print('healthy')" || exit 1

# Security: Use tini as init system to handle signals properly
ENTRYPOINT ["/sbin/tini", "--", "dshell"]

# Default command shows help
CMD ["--help"]
