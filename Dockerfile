# Stage 1: Build the vlt-sync binary
FROM golang:alpine AS builder

WORKDIR /src

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Build
COPY . .
RUN CGO_ENABLED=0 go build -o /vlt-sync ./cmd/vlt-sync/

# Stage 2: Minimal runtime image
FROM alpine:3.21

# Install ca-certificates for TLS and curl for health checks
RUN apk add --no-cache ca-certificates curl

# Default port for sync server
EXPOSE 8443

# Copy binary from builder
COPY --from=builder /vlt-sync /usr/local/bin/vlt-sync

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -k -f https://localhost:8443/healthz || curl -f http://localhost:8443/healthz || exit 1

# Create non-root user and prepare data directory
RUN adduser -D -u 1000 vlt && \
    mkdir -p /data && \
    chown -R vlt:vlt /data
USER vlt

# Default data directory (mount as volume)
VOLUME ["/data"]

ENTRYPOINT ["vlt-sync"]
