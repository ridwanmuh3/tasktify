# Tasktify

Tasktify is a task management API built as a set of Go microservices. It also
doubles as a research testbed for benchmarking post-quantum (FN-DSA) JWT
signing against a precomputed-signer variant.

A public HTTP/JSON gateway (Fiber) fronts internal auth and todo services
over gRPC, backed by PostgreSQL.

## Tech Stack

| Layer | Technology |
| ----- | ---------- |
| Language | Go 1.25 |
| HTTP gateway | [Fiber v3](https://github.com/gofiber/fiber) |
| Internal service transport | gRPC |
| Database | PostgreSQL 18 |
| Reverse proxy (production) | Caddy |
| Containerization | Docker Compose |
| Load testing | k6 |
| JWT signing | [golang-jwt/jwt](https://github.com/golang-jwt/jwt), forked in `backend/pkg/jwt` with FN-DSA support |

## Project Structure

| Path | Responsibility |
| ---- | -------------- |
| `backend/gateway/` | Public HTTP API, JWT verification, gRPC clients |
| `backend/auth-service/` | Registration, sign-in, refresh tokens, JWT signing |
| `backend/todo-service/` | Task CRUD scoped to the authenticated user |
| `backend/pkg/` | Shared JWT/FN-DSA signing code |
| `backend/cmd/keygen/` | Key generation CLI |
| `backend/k6/` | Load and benchmark test scripts |
| `docs/` | Benchmark methodology, gRPC contracts, and test scenarios |

## How to Run

### Docker Compose (production-like stack)

```bash
cd backend
cp .env.example .env
make keygen
make vendor
make up-build
curl http://localhost/health
```

Stop the stack with `make down`, or `make clean` to also remove volumes.

### Local services (no Docker)

```bash
cd backend
make dev
```

Runs Postgres in Docker while the Go services run locally.

## API

Default gateway URL is `http://localhost:3000`.

| Method | Path | Description |
| ------ | ---- | ----------- |
| `POST` | `/api/auth/register` | Create a user |
| `POST` | `/api/auth/signin` | Get an access/refresh token pair |
| `POST` | `/api/auth/refresh` | Rotate a token pair |
| `GET` | `/api/profile` | Current user profile (auth required) |
| `GET`/`POST`/`PUT`/`DELETE` | `/api/tasks/*` | Task CRUD (auth required) |

Protected routes expect `Authorization: Bearer <access_token>`. Full request/response
shapes are in `backend/api/api-spec.yml`.

## Configuration

Key environment variables (see `backend/.env.example` for the full list):

| Variable | Meaning |
| -------- | ------- |
| `APP_MODE` | `dev` reads `.env`; `production` reads process environment |
| `APP_PORT` / `GRPC_PORT` | Gateway HTTP port / service gRPC ports |
| `DB_*` | PostgreSQL connection and pool settings |
| `JWT_DEFAULT_ALG` / `JWT_ALLOWED_ALGS` | Signing profile allowlist |
| `JWT_TOKEN_DURATION` | Token lifetime in minutes |
| `KEYS_DIR` | PEM key directory |

## Benchmarking

The repo includes a k6-driven benchmark comparing two FN-DSA signer profiles
(a precomputed-tree variant against the original signer) across isolated
signing, stress, and adversarial scenarios.

```bash
cd backend
make bench-sign     # run the local benchmark stack + k6 workflow
make bench-down     # tear it down
```

Run `make help` in `backend/` for the full list of targets (key generation,
proto regen, KAT/correctness checks, remote benchmarking, etc.).

Benchmark methodology, metric definitions, and results live in `docs/`:

| Doc | Covers |
| --- | ------ |
| `docs/skenario-pengujian.md` | k6 scenario design, metrics, thresholds |
| `docs/pengujian-kat-dan-adversarial-fndsa.md` | FN-DSA known-answer and adversarial tests |
| `docs/grpc-implementation.md` | Internal gRPC contracts and metadata |
| `docs/hasil-benchmark-agregat-20-run.md` | Aggregate results across benchmark runs |
