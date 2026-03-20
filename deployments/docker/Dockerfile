# =============================================================
# MCP-SCT - Security Code Testing
# Multi-stage build: Go + Python AI Bridge
# =============================================================

# Stage 1: Build Go binary
FROM golang:1.24-alpine AS go-builder

RUN apk add --no-cache git gcc musl-dev

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build \
    -o mcp-sct \
    -ldflags "-s -w -X main.version=0.6.0" \
    ./cmd/mcp-sct/

# Stage 2: Install Python dependencies
FROM python:3.12-slim AS python-builder

WORKDIR /build
COPY python/pyproject.toml python/pyproject.toml
COPY python/src python/src
RUN pip install --no-cache-dir --prefix=/python-install ./python[all] 2>/dev/null || \
    pip install --no-cache-dir --prefix=/python-install ./python

# Stage 3: Final image
FROM alpine:3.20

# Runtime deps: PostgreSQL client (psql, pg_isready) para migrations
RUN apk add --no-cache \
    ca-certificates \
    python3 \
    postgresql-client \
    && rm -rf /var/cache/apk/*

# Copy Go binary
COPY --from=go-builder /build/mcp-sct /usr/local/bin/mcp-sct
RUN chmod +x /usr/local/bin/mcp-sct

# Copy Python AI bridge
COPY --from=python-builder /python-install /usr/local
COPY python/src/mcp_sct_ai /usr/lib/python3/mcp_sct_ai

# Copy migrations
COPY migrations /app/migrations

# Copy entrypoint
COPY scripts/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Create non-root user
RUN addgroup -g 1000 -S mcp && \
    adduser -u 1000 -S mcp -G mcp && \
    mkdir -p /home/mcp/.mcp-sct && \
    chown -R mcp:mcp /home/mcp /app

USER mcp
WORKDIR /home/mcp

# Default environment
ENV MCP_SCT_MODE=cloud \
    MCP_SCT_ADDR=:8080 \
    MCP_SCT_AI_ENABLED=false \
    MCP_SCT_LOG_LEVEL=info \
    PYTHONPATH=/usr/lib/python3 \
    TZ=America/Sao_Paulo

EXPOSE 8080

HEALTHCHECK NONE

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["--mode", "cloud"]
