# Tasktify

Tasktify is a Go microservice task API with post-quantum JWT signing. It exposes HTTP/JSON through a Fiber gateway, uses gRPC between services, and stores data in PostgreSQL.

> **Branch scope.** This is the `service/tasktify-backend` branch: deployable backend services only. The benchmark harness, k6 scenarios, statistical scripts, article figures, and thesis documentation live on `research/pqc-jwt-benchmark`. The two branches are parallel deliverables — do not merge this one into the research branch (its deletions would remove the research artifacts); cherry-pick shared fixes instead.

Two FN-DSA signer profiles are supported:

| Profile | JWS `alg` | Meaning |
| ------- | --------- | ------- |
| `FN-DSA-Precomputed-512` | `FN-DSA-512` | FN-DSA-512 signer with precomputed LDL tree (production default) |
| `FN-DSA-512` | `FN-DSA-512` | FN-DSA-512 original signer |

`FN-DSA-Precomputed-512` is a signer profile, not a JOSE algorithm value. Tokens from both profiles carry `FN-DSA-512` in the header; precomputation is implementation state recorded in config only.

## Architecture

```text
Client
  -> Caddy
  -> Gateway (:3000, HTTP/Fiber)
      -> Auth service (:3001, gRPC)
      -> Todo service (:3002, gRPC)
          -> PostgreSQL
```

## Components

| Component | Path | Responsibility |
| --------- | ---- | -------------- |
| Gateway | `backend/gateway/` | Public HTTP API, JWT verification, gRPC clients |
| Auth service | `backend/auth-service/` | User registration, sign-in, refresh token flow, bcrypt, JWT signing |
| Todo service | `backend/todo-service/` | Task CRUD scoped by authenticated user |
| Shared package | `backend/pkg/` | JWT implementation, FN-DSA signing methods, key loaders, precomputed signer |
| Key generator | `backend/cmd/keygen/` | Generate JWT signing keys |
| API specs | `backend/api/`, `backend/gateway/api/`, service `api/` folders | OpenAPI and service contracts |

## Runtime Flows

Registration:

```text
POST /api/auth/register
Gateway -> Auth UserService.Create -> PostgreSQL users table
```

Sign-in:

```text
POST /api/auth/signin
Gateway -> AuthService.SignIn
Auth service -> PostgreSQL user lookup -> bcrypt check -> JWT access + refresh signing
Gateway -> HTTP response with token payload
```

Protected request:

```text
GET /api/profile or /api/tasks/*
Gateway AuthMiddleware -> parse JWT -> validate alg, typ, issuer, signature, token_use
Gateway -> service request with user id metadata
```

## API Routes

Default gateway URL is `http://localhost:3000` in local service mode.

### Public

| Method | Path | Body | Result |
| ------ | ---- | ---- | ------ |
| `GET` | `/` | none | `"API OK"` |
| `GET` | `/health` | none | `{"status":"ok"}` |
| `POST` | `/api/auth/register` | `name`, `email`, `password` | Create user |
| `POST` | `/api/auth/signin` | `email`, `password`, optional `algorithm` | Access and refresh token pair |
| `POST` | `/api/auth/refresh` | `refresh_token` | New access and refresh token pair |

### Protected

Protected routes require:

```http
Authorization: Bearer <access_token>
```

| Method | Path | Body | Result |
| ------ | ---- | ---- | ------ |
| `GET` | `/api/profile` | none | Current user profile |
| `POST` | `/api/tasks/` | `title`, `status`, optional `description`, optional `due_date` Unix ms | Create task |
| `GET` | `/api/tasks/` | none | List current user tasks |
| `GET` | `/api/tasks/:id` | none | Get one current user task |
| `PUT` | `/api/tasks/:id` | `title`, `status`, optional `description`, optional `due_date` Unix ms | Update task |
| `DELETE` | `/api/tasks/:id` | none | Delete task |

## Requirements

| Tool | Version / note |
| ---- | -------------- |
| Go | `1.25.7` in Go modules |
| Docker Compose | Required for the Compose stack |
| PostgreSQL | `postgres:18-alpine` in Compose |
| Protocol Buffers | `protoc`, `protoc-gen-go`, `protoc-gen-go-grpc` for proto regeneration |

Go modules:

| Module | Purpose |
| ------ | ------- |
| `backend/gateway` | HTTP gateway and gRPC clients |
| `backend/auth-service` | Auth/user gRPC server |
| `backend/todo-service` | Task gRPC server |
| `backend/pkg` | Shared JWT and FN-DSA code |
| `backend/cmd/keygen` | Key generation CLI |

## Configuration

Main environment variables:

| Variable | Used by | Meaning |
| -------- | ------- | ------- |
| `APP_MODE` | all services | `dev` reads `.env`; `production` reads process environment |
| `APP_PORT` | gateway | HTTP listen port |
| `GRPC_PORT` | auth/todo | gRPC listen port |
| `AUTH_SERVICE_ADDR` | gateway | Auth gRPC address |
| `TODO_SERVICE_ADDR` | gateway | Todo gRPC address |
| `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_HOST`, `DB_PORT`, `DB_SSL_MODE` | auth/todo | PostgreSQL connection |
| `DB_POOL_IDLE`, `DB_MAX_POOL`, `DB_MAX_LIFETIME` | auth/todo | Database pool settings |
| `JWT_DEFAULT_ALG` | gateway/auth | Default signing profile |
| `JWT_ALLOWED_ALGS` | gateway/auth | Comma-separated profile allowlist |
| `JWT_ISSUER` | gateway/auth | Expected issuer |
| `JWT_AUDIENCE` | gateway/auth | Expected audience; must match on both sides, empty disables the claim |
| `JWT_TOKEN_DURATION` | gateway/auth | Token lifetime in minutes |
| `KEYS_DIR` | gateway/auth | PEM key directory |

`JWT_ALLOWED_ALGS` narrows the algorithms a process loads. When unset, both services fall back to the FN-DSA profiles only; production pins `FN-DSA-Precomputed-512`.

## Keys

```bash
cd backend
make keygen
```

Writes the key pair into `auth-service/keys/` and copies it to `gateway/keys/`:

```text
FNDSA-512_pk.pem
FNDSA-512_sk.pem
```

Keys are gitignored (`**/keys/*.pem`). Generate them per environment.

## Build And Run

Production-like Compose stack:

```bash
cd backend
cp .env.example .env
make keygen
make vendor
make up-build
curl http://localhost/health
```

Stop stack:

```bash
make down
```

Remove volumes:

```bash
make clean
```

Local service mode (PostgreSQL in Docker, three Go processes on the host):

```bash
make dev
```

Regenerate protobuf code:

```bash
make compile-proto
```

## Validation

```bash
cd backend
make test    # all four modules, then the race detector on pkg
make build   # gateway, auth-service, todo-service binaries into bin/
make check   # validate production and dev Compose configs
```

## Make Targets

Run from `backend/` (the workspace `Makefile` proxies the same names from the repo root).

| Target | Action |
| ------ | ------ |
| `make env` | Create `.env` from `.env.example` when missing |
| `make keygen` | Generate keys into `auth-service/keys` and copy to `gateway/keys` |
| `make compile-proto` | Regenerate protobuf files |
| `make dev` | Start PostgreSQL in Docker, run all three services locally |
| `make dev-db` / `make dev-down` | Start / stop the local PostgreSQL only |
| `make up` / `make up-build` | Start (and optionally build) the Compose stack |
| `make down` / `make clean` | Stop the stack, optionally removing volumes |
| `make ps` / `make logs` / `make logs-gateway` | Compose status and log following |
| `make vendor` | Vendor dependencies for Docker builds |
| `make tidy` | Run `go mod tidy` across the Go modules |
| `make build` | Build the three service binaries into `bin/` |
| `make test` | Run all Go tests plus the race detector on `pkg` |
| `make check` | Validate production and dev Compose configs |
| `make fndsa-kat` | FN-DSA dynamic and precomputed KAT |
| `make adversarial-kat` | KAT plus adversarial attack-rejection gate |
| `make fndsa-check` | Full correctness/security gate and Compose config |

## Related Documentation

| File | Purpose |
| ---- | ------- |
| `backend/api/api-spec.yml` | API specification |
| `backend/pkg/jwt/SECURITY.md` | Security notes for the JWT package |
| `research/pqc-jwt-benchmark` branch | Benchmark harness, k6 scenarios, statistical analysis, figures, thesis documentation |
