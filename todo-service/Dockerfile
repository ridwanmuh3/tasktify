# =========================
# 1. Builder Stage
# =========================
FROM golang:1.25.7-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Copy todo-service module (with vendored dependencies)
COPY todo-service/ ./todo-service/
WORKDIR /build/todo-service

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -mod=vendor -o app ./cmd/app/main.go

# =========================
# 2. Runtime Stage
# =========================
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /build/todo-service/app /app/app

EXPOSE 3002

RUN adduser -D appuser && \
    mkdir -p /app/logs && \
    chown -R appuser:appuser /app

USER appuser

ENTRYPOINT ["/app/app"]
