#!/bin/sh
# Tunggu postgres menerima koneksi TCP (nc tersedia di Alpine/busybox)
until nc -z "${DB_HOST:-localhost}" "${DB_PORT:-5432}" 2>/dev/null; do
  echo "Menunggu database ${DB_HOST}:${DB_PORT}..."
  sleep 2
done
sleep 1

# Fix ownership of mounted keys volume
chown -R appuser:appuser /app/keys 2>/dev/null || true
exec su-exec appuser /app/app
