# =========================
# 1. Builder Stage
# =========================
FROM golang:1.25.8-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Copy shared pkg module
COPY pkg/ ./pkg/

# Copy auth-service module (with vendored dependencies)
COPY auth-service/ ./auth-service/
WORKDIR /build/auth-service

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -mod=vendor -o app ./cmd/app/main.go

# =========================
# 2. Runtime Stage
# =========================
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /build/auth-service/app /app/app

EXPOSE 3001

RUN adduser -D appuser && \
    mkdir -p /app/logs /app/keys && \
    chown -R appuser:appuser /app

USER appuser

ENTRYPOINT ["/app/app"]
