# Build stage
FROM golang:1.25.4-alpine AS builder

# Install build dependencies for CGO (SQLite requires CGO)
RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build with CGO enabled for SQLite support
ARG VERSION=dev
RUN CGO_ENABLED=1 go build -ldflags="-s -w -X main.Version=${VERSION}" -o /app/tailscale-acl-manager ./cmd/server

# Runtime stage
FROM alpine:3.20

# Install runtime dependencies
RUN apk add --no-cache sqlite-libs ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 appgroup && \
    adduser -u 1000 -G appgroup -h /app -D appuser

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/tailscale-acl-manager /app/tailscale-acl-manager

# Create data directory for SQLite
RUN mkdir -p /data && chown appuser:appgroup /data

# Set default environment variables
ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=8080
ENV DATABASE_DRIVER=sqlite3
ENV DATABASE_DSN=/data/tailscale-acl-manager.db
ENV SYNC_DEBOUNCE=5s
ENV SYNC_AUTO_SYNC=true

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Volume for persistent data
VOLUME ["/data"]

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the application
ENTRYPOINT ["/app/tailscale-acl-manager"]
