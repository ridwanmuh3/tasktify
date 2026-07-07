# Tasktify

Tasktify is a Go microservice task API with post-quantum JWT signing. It exposes HTTP/JSON through a Fiber gateway, uses gRPC between services, stores data in PostgreSQL, and benchmarks Falcon/FN-DSA JWT generation with k6.

Current research scope is limited to two Falcon signer profiles:

| Profile | JWS `alg` | Benchmark port | Meaning |
| ------- | --------- | -------------- | ------- |
| `Falcon-Precomputed-512` | `FN-DSA-512` | `5001` | FN-DSA-512 signer with precomputed LDL tree |
| `Falcon-512` | `FN-DSA-512` | `5002` | FN-DSA-512 original signer |

`Falcon-Precomputed-512` is a benchmark profile, not a JOSE algorithm value. Tokens from both profiles use `FN-DSA-512`; precomputation is implementation state recorded in config, metadata, and benchmark output.

## Recent Updates

| Area | Change | Result |
| ---- | ------ | ------ |
| Benchmark scope | Removed unrelated benchmark algorithms from benchmark flow | Compose, keygen, gateway config, and k6 focus on `Falcon-Precomputed-512` and `Falcon-512` |
| JWS algorithm | Kept `FN-DSA-512` as the token `alg` for both Falcon profiles | Avoids using `Falcon-Precomputed-512` as a fake JOSE algorithm |
| JWT issuance | Added `POST /api/benchmark/jwt-issuance` | Measures JWT claims, serialization, Base64URL, signing, and compact token assembly without DB, bcrypt, auth-service, or gRPC |
| Pure signing | Added `POST /api/benchmark/pure-signing` | Measures `SigningMethod.Sign(fixedMessage)` only, without JWT serialization, Base64URL, or compact assembly |
| k6 workflow | Isolated k6 phase now runs JWT issuance and pure signing | `benchmark_sign_result.json` includes pure signing, JWT issuance, and JWT-over-pure overhead ratio |
| Stress metadata | Added stage duration, ramp-up, steady state, ramp-down, request count, think time, load model, timeout, connection reuse, TLS, error rate, pool, and quota metadata | Load is no longer described by VU count only |
| Security tests | Expanded JWT parser and claim tests | Covers malformed tokens, duplicate header/claim, invalid Base64URL, oversized token, `kid`, `typ`, token-use confusion, unsigned/signature-empty tokens, and claim validation |
| Falcon correctness | Added dynamic and precomputed FN-DSA KAT coverage | `TestFNDSA_Precomputed_KAT` validates precomputed signing against known-answer behavior |
| Automation | Added `make falcon-kat`, `make falcon-check`, `make wait-bench`, and simplified benchmark targets | Validation and benchmark startup use fewer manual steps |
| Documentation | Cleaned README and benchmark docs | Metric scope and interpretation are explicit |

## Architecture

Production runtime:

```text
Client
  -> Caddy
  -> Gateway (:3000, HTTP/Fiber)
      -> Auth service (:3001, gRPC)
      -> Todo service (:3002, gRPC)
          -> PostgreSQL
```

Benchmark runtime:

```text
k6 client
  -> Gateway Falcon-Precomputed-512 (:5001)
  -> Gateway Falcon-512 (:5002)
      -> shared benchmark PostgreSQL and todo service
```

Each benchmark profile gets an isolated gateway/auth process pair. This avoids cross-profile signer state and runtime contention inside one process.

## Components

| Component | Path | Responsibility |
| --------- | ---- | -------------- |
| Gateway | `backend/gateway/` | Public HTTP API, JWT verification, benchmark endpoints, gRPC clients |
| Auth service | `backend/auth-service/` | User registration, sign-in, refresh token flow, bcrypt, JWT signing |
| Todo service | `backend/todo-service/` | Task CRUD scoped by authenticated user |
| Shared package | `backend/pkg/` | JWT implementation, Falcon/FN-DSA signing methods, key loaders, precomputed signer |
| Key generator | `backend/cmd/keygen/` | Generate production and benchmark keys |
| k6 scripts | `backend/k6/` | Isolated, stress, refresh, and adversarial JWT scenarios |
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
Gateway <- gRPC trailers with signing/runtime metrics
Gateway -> HTTP response headers + token payload
```

Protected request:

```text
GET /api/profile or /api/tasks/*
Gateway AuthMiddleware -> parse JWT -> validate alg, typ, issuer, signature, token_use
Gateway -> service request with user id metadata
```

Benchmark endpoints:

```text
POST /api/benchmark/pure-signing
Gateway -> SigningMethod.Sign(fixedMessage)

POST /api/benchmark/jwt-issuance
Gateway -> JWT claims -> JSON/Base64URL -> signing -> compact JWT

POST /api/benchmark/token
Gateway -> one access JWT plus signing-time headers
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
| `POST` | `/api/benchmark/pure-signing` | `algorithm`, `iterations`, `warmup_iterations`, `email` | Isolated pure signing stats |
| `POST` | `/api/benchmark/jwt-issuance` | `algorithm`, `iterations`, `warmup_iterations`, `email` | Isolated JWT issuance stats |
| `POST` | `/api/benchmark/sign` | `algorithm`, `iterations`, `warmup_iterations`, `email` | Backward-compatible alias for JWT issuance |
| `POST` | `/api/benchmark/token` | `algorithm`, `email` | One benchmark token plus signing-time headers |

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
| Docker Compose | Required for production and benchmark stacks |
| PostgreSQL | `postgres:18-alpine` in Compose |
| k6 | `0.50+` recommended |
| Protocol Buffers | `protoc`, `protoc-gen-go`, `protoc-gen-go-grpc` for proto regeneration |

Go modules:

| Module | Purpose |
| ------ | ------- |
| `backend/gateway` | HTTP gateway and gRPC clients |
| `backend/auth-service` | Auth/user gRPC server |
| `backend/todo-service` | Task gRPC server |
| `backend/pkg` | Shared JWT and Falcon/FN-DSA code |
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
| `JWT_TOKEN_DURATION` | gateway/auth | Token lifetime in minutes |
| `KEYS_DIR` | gateway/auth | PEM key directory |

Benchmark metadata can also record `RATE_LIMIT`, `CPU_QUOTA`, and `MEMORY_QUOTA` when those values are provided to k6 or the runtime environment.

## Keys

Production keys:

```bash
cd backend
make keygen
```

Benchmark keys:

```bash
cd backend
make keygen-all
```

Benchmark key filenames:

```text
FNDSA-512_pk.pem
FNDSA-512_sk.pem
```

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

Local service mode:

```bash
make dev
```

Regenerate protobuf code:

```bash
make compile-proto
```

## Benchmark Workflow

Validate Falcon/FN-DSA code and benchmark config:

```bash
cd backend
make falcon-check
```

Run local benchmark stack and k6 workflow:

```bash
cd backend
make bench-sign
make bench-down
```

Run against one remote gateway:

```bash
cd backend
make client-k6 BASE_URL=https://example.com
```

Remote single-gateway runs must load every benchmarked signing profile in
`JWT_ALLOWED_ALGS`, for example `Falcon-Precomputed-512,Falcon-512`.
Otherwise the unconfigured profile fails instead of being silently measured with
the wrong signer.

Useful k6 flags:

| Variable | Meaning |
| -------- | ------- |
| `BASE_URL` | Single gateway base URL |
| `BENCH_HOST` | Multi-gateway host; k6 adds profile ports |
| `ITERATIONS` | Isolated server-side iterations, default `100` |
| `ISOLATED_WARMUP` | Warmup iterations, default `20` |
| `ISOLATED_ONLY=true` | Run isolated phase only |
| `STRESS_ONLY=true` | Run stress phase only |
| `ATTACK_ONLY=true` | Run adversarial phase only |
| `ATTACK_ITERATIONS` | Attack attempts per profile, default `25` |

Benchmark artifacts are written under `backend/`:

| File | Purpose |
| ---- | ------- |
| `benchmark_sign_result.json` | Academic summary grouped by signer profile |
| `benchmark_sign_raw.json` | Full k6 metric dump |
| `benchmark_sign_samples.ndjson` | Per-sample k6 output for statistical tests |
| `result.txt` | Human-readable k6 output |
| `benchmark_stats.md` | Statistical summary |
| `benchmark_welch.md` | Pairwise comparison summary |
| `fndsa_precompute_ablation.csv` | FN-DSA precompute ablation output |

## Benchmark Metrics

Use these metric names consistently:

| Metric | Scope | Use |
| ------ | ----- | --- |
| `isolated.pure_signing_gc_free_ms` | Direct Falcon/FN-DSA signing over fixed message, GC-free | Pure signing baseline |
| `isolated.token_generation_gc_free_ms` | Access JWT generation from benchmark payload, GC-free | Primary JWT issuance metric |
| `isolated.refresh_token_generation_gc_free_ms` | Refresh JWT generation from benchmark payload, GC-free | Secondary JWT issuance metric |
| `stress.token_generation_ms` | Access JWT generation under concurrent VUs | Signing under load |
| `stress.refresh_token_generation_ms` | New JWT generation during refresh flow under concurrent VUs | Refresh signing under load |
| `stress.login_ms` | Full `/api/auth/signin` round trip | Real login workflow impact |
| `stress.refresh_ms` | Full `/api/auth/refresh` round trip | Real refresh workflow impact |
| `stress.e2e_ms` | Full `/api/benchmark/token` k6 round trip | Benchmark endpoint overhead check |

Interpretation rules:

- Do not call `isolated.token_generation_gc_free_ms` login latency.
- Do not call `isolated.token_generation_gc_free_ms` network latency.
- Do not call `isolated.token_generation_gc_free_ms` pure cryptographic signing.
- Use `isolated.pure_signing_gc_free_ms` for pure Falcon/FN-DSA signing.
- Use `isolated.token_generation_gc_free_ms` for server-side JWT issuance from benchmark payload.
- Use `stress.login_ms` for login latency with JWT signing, because it includes DB lookup, bcrypt, transport, and response serialization.
- Use `stress.refresh_ms` for refresh latency with token verification and JWT rotation.

Stress runs also emit:

| Metadata | Meaning |
| -------- | ------- |
| `stress_stage_model` | executor, closed-loop model, ramp-up, steady state, ramp-down, think time |
| `stress_transport` | timeout, connection reuse, protocol note, TLS flag |
| `stress_environment` | database pool, rate limit, CPU quota, memory quota when provided |
| per-scenario request counts | success/failure totals for benchmark token, login, and refresh paths |

VU count alone is not enough to describe load. Report stage model, request count, error rate, transport, and resource quota with every stress result.

## Security And Correctness

JWT security tests cover:

| Category | Status |
| -------- | ------ |
| Signature tampering and unsigned/signature-empty compact token | Covered |
| Algorithm confusion and algorithm case variation | Covered |
| Malformed JSON, invalid Base64URL, duplicate header, duplicate claim | Covered |
| Invalid or missing issuer, invalid subject, invalid `nbf`, illogical `iat` | Covered |
| Oversized token, unknown `kid`, `kid` traversal attempt | Covered |
| `typ` alteration and access/refresh token-use confusion | Covered |
| Audience validation | Gap until app config defines audience |
| Refresh token replay/reuse | Gap until stateful refresh-token store or JTI blacklist exists |
| Key revocation/rotation | Gap until key registry and operational rotation exist |

Falcon/FN-DSA correctness tests cover:

| Property | Location |
| -------- | -------- |
| Dynamic and precomputed KAT | `backend/pkg/fndsa/fndsa_test.go` |
| Signature verification, bit-flip signature failure, bit-flip message failure | `backend/pkg/jwt/falcon_correctness_test.go`, `backend/pkg/fndsa/*_test.go` |
| Dynamic and precomputed verifier interoperability | `backend/pkg/jwt/falcon_optimize_test.go` |
| Concurrent verification/signing behavior | `backend/pkg/jwt/falcon_correctness_test.go` |

Run:

```bash
cd backend
make falcon-kat
make falcon-check
```

## Statistical Analysis

Run after benchmark artifacts exist:

```bash
python3 scripts/benchmark_stat_tests.py
```

Common variants:

```bash
python3 scripts/benchmark_stat_tests.py --metric isolated.pure_signing_gc_free_ms
python3 scripts/benchmark_stat_tests.py --metric isolated.refresh_token_generation_gc_free_ms
python3 scripts/benchmark_stat_tests.py --baseline Falcon-Precomputed-512
python3 scripts/benchmark_stat_tests.py --format csv
```

`benchmark_sign_samples.ndjson` enables normality checks and Mann-Whitney U tests. Without samples, the script falls back to summary statistics from `benchmark_sign_result.json`.

## FN-DSA Precompute Ablation

Run:

```bash
python3 scripts/fndsa_precompute_ablation.py
python3 scripts/fndsa_precompute_ablation.py --format csv
```

Direct Go benchmark:

```bash
cd backend/pkg
go test ./fndsa -run '^$' -bench '^BenchmarkFalconPrecomputeAblation512/' -benchmem
```

The ablation compares original runtime signing against detached precomputation stages. `Significance %` in that output means relative runtime reduction from A0, not statistical significance.

## Validation

Recent validation commands:

```bash
cd backend/gateway
env GOCACHE=/tmp/go-build-cache go test ./internal/delivery/http/handler ./internal/delivery/http/route
env GOCACHE=/tmp/go-build-cache go test ./internal/config

cd ../pkg
env GOCACHE=/tmp/go-build-cache go test ./utils/jwtutils ./jwt ./fndsa

cd ..
k6 inspect k6/benchmark_sign.js
make falcon-check
```

## Make Targets

Run from `backend/`.

| Target | Action |
| ------ | ------ |
| `make keygen` | Generate production keys into `auth-service/keys` and copy to `gateway/keys` |
| `make keygen-all` | Generate benchmark keys into `keys/` |
| `make compile-proto` | Regenerate protobuf files |
| `make up` | Start production Compose stack |
| `make up-build` | Build and start production Compose stack |
| `make down` | Stop production stack |
| `make clean` | Stop production stack and remove volumes |
| `make vendor` | Vendor dependencies for Docker builds |
| `make tidy` | Run `go mod tidy` in Go modules |
| `make build` | Build gateway, auth-service, and todo-service binaries into `bin/` |
| `make falcon-kat` | Run FN-DSA dynamic and precomputed KAT |
| `make falcon-check` | Run Falcon KAT/tests plus Compose and k6 script checks |
| `make bench-up` | Build and start benchmark Compose stack |
| `make wait-bench` | Wait for benchmark gateways on ports `5001` and `5002` |
| `make bench-down` | Stop benchmark stack and remove volumes |
| `make bench-sign` | Run local benchmark workflow and write `result.txt` |
| `make bench-sign-remote` | Run remote benchmark against configured URL |
| `make attack-adversarial` | Run adversarial JWT test |

## Related Documentation

| File | Purpose |
| ---- | ------- |
| `docs/grpc-implementation.md` | gRPC contracts, metadata, trailers, keep-alive, and benchmark bias controls |
| `docs/skenario-pengujian.md` | k6 scenario design, isolated/stress/attack phases, metrics, thresholds, and output files |
| `backend/api/api-spec.yml` | API specification |
