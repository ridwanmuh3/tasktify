# =========================
# 1. Builder Stage
# =========================
FROM golang:1.25.7-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Copy shared pkg module
COPY pkg/ ./pkg/

# Copy gateway module (with vendored dependencies)
COPY gateway/ ./gateway/
WORKDIR /build/gateway

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -mod=vendor -o app ./cmd/app/main.go

# =========================
# 2. Runtime Stage
# =========================
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata su-exec

WORKDIR /app

COPY --from=builder /build/gateway/app /app/app

EXPOSE 3000

RUN adduser -D appuser && \
    mkdir -p /app/logs /app/keys && \
    chown -R appuser:appuser /app

COPY gateway/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]

HEALTHCHECK --interval=2m --timeout=5s \
  CMD wget -qO- http://localhost:3000/health || exit 1
