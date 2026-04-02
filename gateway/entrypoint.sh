#!/bin/sh
# Tunggu auth service gRPC siap (parse dari AUTH_SERVICE_ADDR=host:port)
AUTH_HOST="${AUTH_SERVICE_ADDR%:*}"
AUTH_PORT="${AUTH_SERVICE_ADDR##*:}"
until nc -z "${AUTH_HOST:-localhost}" "${AUTH_PORT:-3001}" 2>/dev/null; do
  echo "Menunggu auth service ${AUTH_HOST}:${AUTH_PORT}..."
  sleep 2
done

# Fix ownership of mounted keys volume
chown -R appuser:appuser /app/keys 2>/dev/null || true
exec su-exec appuser /app/app
