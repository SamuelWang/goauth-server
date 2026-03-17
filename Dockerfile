# ─── Build Stage ─────────────────────────────────────────────────────────────
FROM golang:1.25.5-alpine AS builder

# Install git and CA certificates required during the build
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Download dependencies first so this layer is cached independently of source changes
COPY go.mod go.sum ./
RUN go mod download

# Copy source and compile a statically-linked binary (no CGO) with debug info stripped
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" -o auth-service ./cmd/auth-server

# ─── Runtime Stage ───────────────────────────────────────────────────────────
FROM alpine:3.21

# Install CA certificates (required for HTTPS calls to OAuth providers) and wget
# (used by the HEALTHCHECK probe). tzdata provides accurate timezone handling.
RUN apk add --no-cache ca-certificates tzdata wget \
    && addgroup -S appgroup \
    && adduser -S appuser -G appgroup

WORKDIR /app

# Copy the compiled binary from the build stage
COPY --from=builder /build/auth-service .

# Run as a non-root user
USER appuser

# Expose the default server port; override with the PORT environment variable
EXPOSE 8080

# Liveness probe – polls the ops health endpoint.
# The shell form is used so that ${PORT:-8080} is expanded by /bin/sh.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -q --spider http://localhost:${PORT:-8080}/ops/health || exit 1

ENTRYPOINT ["/app/auth-service"]
