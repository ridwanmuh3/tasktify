#!/bin/sh
# Fix ownership of mounted keys volume
chown -R appuser:appuser /app/keys 2>/dev/null || true
exec su-exec appuser /app/app
