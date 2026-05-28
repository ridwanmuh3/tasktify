# Tasktify Frontend

Svelte client for Tasktify gateway.

## Run

Run full local stack from repo root:

```bash
make dev
```

Or run API services in one terminal:

```bash
make dev-api
```

Then run client in this folder:

```bash
npm install
npm run dev
```

Default dev server proxies `/api` and `/health` to `http://localhost:3000`. If Vite prints `ECONNREFUSED`, gateway is not running.

Override gateway target:

```bash
VITE_PROXY_TARGET=http://localhost:3000 npm run dev
```

For deployed builds that call a remote gateway directly:

```bash
VITE_API_BASE_URL=https://poc-ridwanmuh3.my.id npm run build
```

## Production Caddy

Build static assets:

```bash
npm install
npm run build
```

Then run the full stack from `backend/`:

```bash
make up-build
```

Caddy serves `frontend/dist`, proxies `/api` and `/health` to `gateway:3000`, blocks framing, sets a restrictive CSP, and allows 64 KB request headers for large PQC JWTs.
