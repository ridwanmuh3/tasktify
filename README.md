# Tasktify

Tasktify is Go microservice task API with post-quantum JWT signing. System exposes HTTP/JSON through Fiber gateway, uses gRPC between services, stores users and tasks in PostgreSQL, and benchmarks JWT generation latency across multiple signing algorithms with k6.

Primary research path measures server-side JWT generation from benchmark payloads for signer profiles:

| Algorithm                | Category                                  | Benchmark port |
| ------------------------ | ----------------------------------------- | -------------- |
| `Falcon-Precomputed-512` | PQC, FN-DSA-512 with precomputed LDL tree | `5001`         |
| `Falcon-512`             | PQC, FN-DSA-512 original signer           | `5002`         |
| `ML-DSA-44`              | PQC, FIPS 204 / Dilithium2 class          | `5003`         |
| `SLH-DSA-SHA2-128f`      | PQC, FIPS 205 / SPHINCS+ fast variant     | `5004`         |
| `SLH-DSA-SHA2-128s`      | PQC, FIPS 205 / SPHINCS+ small variant    | `5005`         |

`Falcon-Precomputed-512` and `Falcon-512` are benchmark profiles, not distinct JWS algorithms. Tokens from both profiles use experimental JWS `alg` value `FN-DSA-512`; precomputation is signer implementation state recorded in config and benchmark metadata.

## System Architecture

Production topology:

```text
Client / k6
    |
    | HTTP/JSON
    v
Caddy reverse proxy (:80, :443)
    |
    | HTTP/JSON
    v
Gateway service (:3000, Fiber)
    |                         |
    | gRPC                    | gRPC
    v                         v
Auth service (:3001)          Todo service (:3002)
UserService + AuthService     TaskService
    |                         |
    | PostgreSQL              | PostgreSQL
    v                         v
tasktify database             tasktify database
```

Benchmark topology in `backend/docker-compose.benchmark.yml` starts one auth-service plus one gateway per algorithm. Shared `bench-todo` and `bench-postgres` keep task/database infrastructure constant while each algorithm gets isolated gateway/auth process pair.

| Component      | Path                                                               | Responsibility                                                                       |
| -------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------ |
| Frontend       | `frontend/`                                                        | Svelte client, built to static assets and served by Caddy in production              |
| Gateway        | `backend/gateway/`                                                 | Public HTTP API, JWT verification, route dispatch, benchmark endpoints, gRPC clients |
| Auth service   | `backend/auth-service/`                                            | User CRUD, sign-in, refresh token, bcrypt password check, JWT signing                |
| Todo service   | `backend/todo-service/`                                            | Task CRUD, user scoping through `x-user-id` gRPC metadata                            |
| Shared package | `backend/pkg/`                                                     | JWT implementation, PQC signing methods, key loaders, Falcon precompute code         |
| Key generator  | `backend/cmd/keygen/`                                              | Generate algorithm keys for production and benchmark runs                            |
| k6 scripts     | `backend/k6/`                                                      | Isolated signing, stress, refresh, and tampered-token benchmark scenarios            |
| API specs      | `backend/api/`, `backend/gateway/api/`, and service `api/` folders | OpenAPI specifications                                                               |
| Technical docs | `docs/`                                                            | gRPC implementation notes and benchmark scenario methodology                         |

### Runtime Flow

Register flow:

```text
POST /api/auth/register
Gateway -> Auth UserService.Create -> PostgreSQL users table
```

Sign-in flow:

```text
POST /api/auth/signin
Gateway -> AuthService.SignIn
Auth service -> PostgreSQL user lookup -> bcrypt check -> JWT access + refresh signing
Auth service -> gRPC trailers with signing/runtime metrics
Gateway -> HTTP response headers + token payload
```

Protected API flow:

```text
GET /api/profile or /api/tasks/*
Gateway AuthMiddleware -> parse JWT -> validate alg/typ/issuer/signature/token_use -> set user locals
Task routes -> gRPC metadata x-user-id -> Todo AuthInterceptor -> task service
```

Benchmark flow:

```text
POST /api/benchmark/sign
Gateway generates JWTs in-process from benchmark payloads, skips DB/bcrypt/auth-service path, and returns batch timing stats.
Use this for isolated JWT generation experiments. Request controls iterations and warmup_iterations.
Each measured iteration generates one access token and one refresh token, then returns raw timings,
p50/p95/p99 summaries, GC-free samples, CPU, CPU time, memory metrics, and canonical JWS `alg`.

POST /api/benchmark/token
Gateway generates one access token in-process, skips DB/bcrypt/auth-service path, and returns token payload.
Use this for stress tests that need one usable Bearer token per request.
Response includes X-Sign-Time-Ms and X-Token-Generation-Time-Ms headers.
```

### Data Ownership

| Data             | Owner                             | Storage                                                                              |
| ---------------- | --------------------------------- | ------------------------------------------------------------------------------------ |
| Users            | `auth-service`                    | `users` table, `backend/auth-service/internal/entity/user_entity.go`                 |
| Tasks            | `todo-service`                    | `tasks` table, `backend/todo-service/internal/entity/task_entity.go`                 |
| JWT keys         | `backend/cmd/keygen` output       | `backend/auth-service/keys`, `backend/gateway/keys`, or `backend/keys` for benchmark |
| JWT verification | `gateway`                         | Public keys loaded from `KEYS_DIR`                                                   |
| JWT signing      | `auth-service`, benchmark handler | Private keys loaded from `KEYS_DIR`                                                  |

## Routes

Default production base URL is gateway HTTP port `http://localhost:3000`. Caddy publishes same gateway through HTTPS domain configured in `backend/Caddyfile`.

Response envelope:

```json
{
  "status": 200,
  "message": "success",
  "data": {}
}
```

### Public Routes

| Method | Path                   | Body                                                    | Result                                                |
| ------ | ---------------------- | ------------------------------------------------------- | ----------------------------------------------------- |
| `GET`  | `/`                    | none                                                    | `"API OK"`                                            |
| `GET`  | `/health`              | none                                                    | `{"status":"ok"}`                                     |
| `POST` | `/api/auth/register`   | `name`, `email`, `password`                             | Creates user, returns `201`                           |
| `POST` | `/api/auth/signin`     | `email`, `password`, optional `algorithm`               | Returns `token_type`, `access_token`, `refresh_token` |
| `POST` | `/api/auth/refresh`    | `refresh_token`, optional `user_id`                     | Returns new access and refresh tokens                 |
| `POST` | `/api/benchmark/sign`  | `algorithm`, `iterations`, `warmup_iterations`, `email` | Isolated signing stats                                |
| `POST` | `/api/benchmark/token` | `algorithm`, `email`                                    | One benchmark token plus signing-time headers         |

Sign-in and refresh response headers:

| Header                               | Meaning                                |
| ------------------------------------ | -------------------------------------- |
| `X-Sign-Time-Ms`                     | Token signing time in milliseconds     |
| `X-Access-Token-Generation-Time-Ms`  | Access-token generation time           |
| `X-Refresh-Token-Generation-Time-Ms` | Refresh-token generation time          |
| `X-Token-Generation-Time-Ms`         | Total or current token generation time |
| `X-Auth-CPU-Pct`                     | Auth-service CPU sample                |
| `X-Auth-Mem-Alloc-MB`                | Auth-service allocated heap sample     |
| `X-Auth-Mem-Sys-MB`                  | Auth-service system memory sample      |

### Protected Routes

Protected routes require:

```http
Authorization: Bearer <access_token>
```

Gateway rejects missing headers, non-Bearer format, invalid/expired signatures, and refresh tokens used as access tokens.

| Method   | Path             | Body                                                                   | Result                     |
| -------- | ---------------- | ---------------------------------------------------------------------- | -------------------------- |
| `GET`    | `/api/profile`   | none                                                                   | Current user profile       |
| `POST`   | `/api/tasks/`    | `title`, `status`, optional `description`, optional `due_date` Unix ms | Creates task               |
| `GET`    | `/api/tasks/`    | none                                                                   | Lists current user tasks   |
| `GET`    | `/api/tasks/:id` | none                                                                   | Gets one current user task |
| `PUT`    | `/api/tasks/:id` | `title`, `status`, optional `description`, optional `due_date` Unix ms | Updates task               |
| `DELETE` | `/api/tasks/:id` | none                                                                   | Deletes task               |

gRPC error mapping in gateway:

| gRPC code         | HTTP status |
| ----------------- | ----------- |
| `InvalidArgument` | `400`       |
| `Unauthenticated` | `401`       |
| `NotFound`        | `404`       |
| Other errors      | `500`       |

## Implementation Requirements

### Toolchain

| Requirement      | Version / note                                                         |
| ---------------- | ---------------------------------------------------------------------- |
| Go               | `1.25.7` in all Go modules                                             |
| Docker Compose   | Needed for production and benchmark stacks                             |
| PostgreSQL       | `postgres:18-alpine` in Compose                                        |
| k6               | `0.50+` recommended by benchmark docs                                  |
| Protocol Buffers | `protoc`, `protoc-gen-go`, `protoc-gen-go-grpc` for proto regeneration |
| Caddy            | `caddy:2-alpine` in production Compose                                 |

### Go Modules

| Module               | Purpose                            |
| -------------------- | ---------------------------------- |
| `gateway`            | Fiber HTTP server and gRPC clients |
| `auth-service`       | gRPC auth/user server              |
| `todo-service`       | gRPC task server                   |
| `pkg`                | JWT/PQC shared library             |
| `backend/cmd/keygen` | Key generation CLI                 |

Core dependencies include `gofiber/fiber/v3`, `google.golang.org/grpc`, `gorm.io/gorm`, `gorm.io/driver/postgres`, `go-playground/validator/v10`, `spf13/viper`, `zap`, `bcrypt`, `cloudflare/circl`, and local `backend/pkg/jwt` plus `backend/pkg/fndsa`.

### Environment Variables

| Variable             | Used by            | Required meaning                                           |
| -------------------- | ------------------ | ---------------------------------------------------------- |
| `APP_MODE`           | all services       | `dev` reads `.env`; `production` reads process environment |
| `APP_PORT`           | gateway            | HTTP listen port, default Compose value `3000`             |
| `APP_PREFORK`        | gateway            | Fiber prefork flag                                         |
| `GRPC_PORT`          | auth/todo          | gRPC listen port, `3001` or `3002`                         |
| `AUTH_SERVICE_ADDR`  | gateway            | Auth gRPC address, e.g. `auth-service:3001`                |
| `TODO_SERVICE_ADDR`  | gateway            | Todo gRPC address, e.g. `todo-service:3002`                |
| `DB_USER`            | auth/todo/postgres | PostgreSQL user                                            |
| `DB_PASSWORD`        | auth/todo/postgres | PostgreSQL password                                        |
| `DB_NAME`            | auth/todo/postgres | PostgreSQL database                                        |
| `DB_HOST`            | auth/todo          | PostgreSQL host                                            |
| `DB_PORT`            | auth/todo          | PostgreSQL port                                            |
| `DB_SSL_MODE`        | auth/todo          | Usually `disable` in Compose                               |
| `DB_POOL_IDLE`       | auth/todo          | GORM idle connection pool size                             |
| `DB_MAX_POOL`        | auth/todo          | GORM max open connections                                  |
| `DB_MAX_LIFETIME`    | auth/todo          | Connection lifetime seconds                                |
| `JWT_DEFAULT_ALG`    | gateway/auth       | Default signing algorithm                                  |
| `JWT_ALLOWED_ALGS`   | gateway/auth       | Comma-separated algorithm allowlist                        |
| `JWT_ISSUER`         | gateway/auth       | Expected JWT issuer, Compose value `tasktify`              |
| `JWT_TOKEN_DURATION` | gateway/auth       | Token lifetime in minutes                                  |
| `KEYS_DIR`           | gateway/auth       | Directory containing PEM keys                              |

Production `JWT_ALLOWED_ALGS` must match between gateway and auth-service. Benchmark Compose narrows this list to one algorithm per gateway/auth pair.

### Key Files

Production keys:

```bash
cd backend
make keygen
```

Command generates keys into `backend/auth-service/keys` and copies them to `backend/gateway/keys`.

Benchmark keys:

```bash
cd backend
make keygen-all
```

Command generates shared keys into `backend/keys/`, mounted by all benchmark containers.

Expected key filenames come from `backend/pkg/utils/jwtutils/loader.go`, including `FNDSA-512_pk.pem`, `FNDSA-512_sk.pem`, `ML-DSA-44_pk.pem`, `ML-DSA-44_sk.pem`, `SLH-DSA-SHA2-128f_pk.pem`, and matching private-key files.

### Build And Run

Production-like stack:

```bash
cd backend
cp .env.example .env
make keygen
make vendor
make up-build
curl http://localhost/health
```

Production HTTP flow is `Caddy TLS/static frontend -> /api proxy -> gateway`. Caddy serves `frontend/dist`, applies hardened browser headers, and keeps 64 KB request-header buffers for PQC JWT Authorization headers.

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

Frontend already running:

```bash
make dev-api
```

Proto regeneration:

```bash
cd backend
make compile-proto
```

Benchmark stack:

```bash
cd backend
make keygen-all
make vendor
make bench-up
k6 run --out json=benchmark_sign_samples.ndjson -e BENCH_HOST=localhost k6/benchmark_sign.js
```

Remote benchmark:

```bash
cd backend
make client-k6 BASE_URL=https://poc-ridwanmuh3.my.id
```

Split client/VPS Hostinger flow:

```bash
cd backend

# Start benchmark stack on VPS.
make hostinger-bench-up VPS_SSH=user@hostinger-host VPS_REPO=/home/user/tasktify

# Run k6 from client, upload artifacts, calculate stats on VPS, fetch reports.
make hostinger-bench \
  VPS_SSH=user@hostinger-host \
  VPS_REPO=/home/user/tasktify \
  BASE_URL=https://poc-ridwanmuh3.my.id
```

Useful split targets:

| Target | Runs on | Purpose |
| ------ | ------- | ------- |
| `make client-k6 BASE_URL=...` | Client | Run full k6 benchmark against VPS HTTP endpoint |
| `make client-k6-isolated BASE_URL=...` | Client | Run isolated phase only |
| `make client-k6-stress BASE_URL=...` | Client | Run stress phase only |
| `make client-k6-attack BASE_URL=...` | Client | Run attack block-rate only |
| `make hostinger-upload VPS_SSH=...` | Client -> VPS | Copy k6 artifacts to VPS backend directory |
| `make hostinger-calc VPS_SSH=...` | VPS | Run statistical calculation scripts on Hostinger |
| `make hostinger-fetch VPS_SSH=...` | VPS -> Client | Fetch generated calculation outputs |

## Benchmark JSON Results

Current benchmark targets write these files under `backend/`:

| File                            | Purpose                                        |
| ------------------------------- | ---------------------------------------------- |
| `benchmark_sign_result.json`    | Academic summary grouped by algorithm          |
| `benchmark_sign_raw.json`       | Full k6 raw metric dump                        |
| `benchmark_sign_samples.ndjson` | Per-iteration k6 samples for statistical tests |
| `result.txt`                    | Human-readable k6 stdout                       |
| `benchmark_stats.md`            | Statistical summary generated on VPS           |
| `benchmark_welch.md`            | Welch pairwise comparison generated on VPS      |
| `fndsa_precompute_ablation.csv` | FN-DSA precompute ablation generated on VPS     |

Run metadata from `benchmark_sign_result.json`:

| Field                        | Value                             |
| ---------------------------- | --------------------------------- |
| `generated_at`               | `2026-05-21T03:34:25.259Z`        |
| `endpoint`                   | `https://poc-ridwanmuh3.my.id`    |
| `mode`                       | `Isolated + Stress + Attack`      |
| `primary_metric`             | `isolated_gc_free_token_generation` |
| `isolated_iterations`        | `100`                             |
| `isolated_warmup_iterations` | `20`                              |
| `stress_duration_seconds`    | `30`                              |
| `concurrency_levels`         | `10`, `30`, `50`                  |

Primary academic metric is `isolated.token_generation_gc_free_ms`, not k6 round-trip latency. It measures server-side JWT generation from the benchmark payload and removes iterations where Go GC ran during generation.

Metric scope:

| Metric | Scope | Use |
| ------ | ----- | --- |
| `isolated.token_generation_gc_free_ms` | Access JWT generation from benchmark payload, GC-free, server-side timer | Primary signing metric |
| `isolated.refresh_token_generation_gc_free_ms` | Refresh JWT generation from benchmark payload, GC-free, server-side timer | Secondary signing metric |
| `stress.token_generation_ms` | Access JWT generation under concurrent VUs, from `X-Token-Generation-Time-Ms` | Signing under load |
| `stress.refresh_token_generation_ms` | New refresh-path JWT generation under concurrent VUs, from server timing header | Refresh signing under load |
| `stress.login_ms` | Full `/api/auth/signin` round-trip: DB lookup + bcrypt + access/refresh JWT signing + transport | Real login workflow impact, includes signing |
| `stress.refresh_ms` | Full `/api/auth/refresh` round-trip: refresh-token verification + JWT rotation/signing + transport | Real refresh workflow impact, includes signing and verification |
| `stress.e2e_ms` | Full `/api/benchmark/token` k6 round-trip | Benchmark endpoint overhead check |

Signing relevance:

- `isolated.token_generation_gc_free_ms` is the cleanest signing-time metric because it isolates backend JWT generation and removes GC-contaminated samples.
- `stress.token_generation_ms` and `stress.refresh_token_generation_ms` still measure direct token generation, but under concurrent load.
- `stress.login_ms` and `stress.refresh_ms` are relevant because both workflows invoke JWT signing directly. They are not pure signing-time metrics because they also include DB, bcrypt, verification, service/transport, and response overhead.
- `stress.e2e_ms` is not a signing-time metric. It is endpoint round-trip latency for `/api/benchmark/token`.

### Seminar Hasil Metric Definition

Untuk seminar hasil, istilah resmi yang dipakai:

| Level | Metric | Definisi | Dipakai untuk |
| ----- | ------ | -------- | ------------- |
| Primer | `isolated.token_generation_gc_free_ms` | Latensi server-side generasi access JWT dari payload benchmark; sampel yang terkena Go GC dibuang | Perbandingan utama algoritma |
| Sekunder isolated | `isolated.refresh_token_generation_gc_free_ms` | Latensi server-side generasi refresh JWT dari payload benchmark; sampel GC dibuang | Validasi konsistensi access vs refresh token |
| Pendukung stress | `stress.token_generation_ms` | Latensi generasi access JWT saat VU konkuren, dari header `X-Token-Generation-Time-Ms` | Dampak beban konkuren terhadap generasi JWT |
| Signing refresh | `stress.refresh_token_generation_ms` | Latensi generasi JWT baru pada flow refresh saat VU konkuren | Dampak signing di refresh token rotation |
| Auth nyata login | `stress.login_ms` | Round-trip penuh `/api/auth/signin`: DB lookup + bcrypt + access/refresh JWT signing + transport | Dampak algoritma pada workflow login nyata, bukan signing murni |
| Auth nyata refresh | `stress.refresh_ms` | Round-trip penuh `/api/auth/refresh`: refresh-token verification + JWT rotation/signing + transport | Dampak algoritma pada workflow refresh nyata, bukan signing murni |
| Pendukung sistem | `stress.e2e_ms` | Round-trip penuh k6 ke `/api/benchmark/token` | Overhead handler, antrean, dan transport |

Kalimat siap pakai:

> Metrik utama penelitian adalah `isolated.token_generation_gc_free_ms`, yaitu latensi generasi access JWT dari payload benchmark yang diukur langsung di sisi server. Metrik ini mengecualikan round-trip k6, HTTP client overhead, DB query, bcrypt, auth-service, gRPC, dan sampel yang terkontaminasi Go GC. Karena itu, angka ini merepresentasikan biaya generasi token JWT pada masing-masing algoritma, bukan latensi login penuh dan bukan operasi kriptografi mentah saja.

> Metrik `stress.login_ms` dan `stress.refresh_ms` tetap dilaporkan karena keduanya memanggil proses signing JWT secara langsung pada workflow autentikasi nyata. Namun, keduanya dikategorikan sebagai metrik dampak workflow, bukan metrik signing murni, karena ikut memuat DB lookup, bcrypt atau verifikasi refresh token, transport, antrean, dan serialisasi response.

Batas interpretasi:

- Jangan sebut metric primer sebagai "latensi login".
- Jangan sebut metric primer sebagai "network latency".
- Jangan sebut metric primer sebagai "pure cryptographic primitive".
- Sebut sebagai "server-side JWT generation latency from benchmark payload".
- Sebut `stress.login_ms` sebagai "login latency with JWT signing", bukan "signing latency".
- Sebut `stress.refresh_ms` sebagai "refresh latency with token verification and JWT signing", bukan "signing latency".

### Statistical Testing

`scripts/benchmark_stat_tests.py` calculates normality, pairwise significance, effect size, and percentage improvement from benchmark output.

Run from repo root after benchmark:

```bash
python3 scripts/benchmark_stat_tests.py
```

Default comparison uses:

| Field       | Value                                   |
| ----------- | --------------------------------------- |
| Metric      | `isolated.token_generation_gc_free_ms`  |
| Baseline    | `Falcon-512`                            |
| Sample file | `backend/benchmark_sign_samples.ndjson` |

Test selection:

| Data condition | Test                              | Effect size   |
| -------------- | --------------------------------- | ------------- |
| Normal         | Welch independent t-test          | Cohen's d     |
| Not normal     | Mann-Whitney U                    | rank-biserial |
| Summary only   | Welch independent t-test fallback | Cohen's d     |

`benchmark_sign_samples.ndjson` is required for real normality and Mann-Whitney U testing. Without that file, script falls back to mean/sd/n from `benchmark_sign_result.json` and reports normality as unavailable.

Useful commands:

```bash
python3 scripts/benchmark_stat_tests.py --metric isolated.refresh_token_generation_gc_free_ms
python3 scripts/benchmark_stat_tests.py --baseline Falcon-Precomputed-512
python3 scripts/benchmark_stat_tests.py --format csv
```

### FN-DSA Precompute Ablation

`backend/pkg/fndsa/precompute_ablation_test.go` measures Falcon-512 from original runtime signing to detached precomputed LDL tree. Each variant uses the same seeded signing path, so RNG cost is excluded.

| Variant | Detached component                                                                                        |
| ------- | --------------------------------------------------------------------------------------------------------- |
| A0      | Original signer: decode private key, recompute `G`/hash, FFT basis, Gram matrix, and LDL tree during sign |
| A1      | A0 + detach private-key decode, `G` recomputation, verifying-key hash                                     |
| A2      | A1 + detach FFT basis `b00`, `b01`, `b10`, `b11`                                                          |
| A3      | A2 + detach Gram matrix                                                                                   |
| A4      | A3 + detach LDL tree                                                                                      |
| A5      | A1-A4 combined through production `PrecomputedSigner` runtime path                                        |

`Significance %` means relative runtime reduction from A0, not statistical significance:

```text
(A0 ns/op - Ai ns/op) / A0 ns/op * 100
```

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

### Isolated Results

Values below come from `benchmark_sign_result.json`. Units are milliseconds unless column name says otherwise.

| Algorithm                | Iter | GC contaminated | Access avg | Access p95 | Access stdev | Refresh avg | Refresh p95 | CPU avg % | Heap alloc MB | Alloc delta MB |
| ------------------------ | ---: | --------------: | ---------: | ---------: | -----------: | ----------: | ----------: | --------: | ------------: | -------------: |
| `Falcon-Precomputed-512` |  100 |               5 |      0.284 |      0.344 |        0.050 |       0.295 |       0.415 |   120.895 |         2.698 |          0.091 |
| `Falcon-512`             |  100 |               6 |      0.341 |      0.422 |        0.043 |       0.354 |       0.452 |   104.484 |         2.798 |          0.114 |
| `ML-DSA-44`              |  100 |               2 |      0.098 |      0.244 |        0.070 |       0.109 |       0.243 |   115.447 |         2.721 |          0.043 |
| `SLH-DSA-SHA2-128f`      |  100 |              10 |     12.046 |     12.462 |        0.301 |      12.044 |      12.429 |    59.081 |         2.836 |          0.211 |
| `SLH-DSA-SHA2-128s`      |  100 |               5 |    248.870 |    263.372 |        8.111 |     247.588 |     258.625 |    50.164 |         3.053 |          0.126 |

Result reading:

- `ML-DSA-44` has lowest isolated access-token generation average at `0.098 ms`.
- `Falcon-Precomputed-512` generates access tokens faster than `Falcon-512` in isolated average, `0.284 ms` vs `0.341 ms`.
- `SLH-DSA-SHA2-128s` is slowest isolated access-token generator, with `248.870 ms` average and `263.372 ms` p95.
- Heap allocation columns are runtime process/allocation samples, not persistent expanded-key memory. Use `PrecomputedSigner.PersistentBytes()` and `BenchmarkBuildPrecomputedSigner512` for expanded-key memory/startup cost.
- CPU avg % is utilization, not CPU cost per token. New benchmark output also includes `cpu_time_ms` and `cpu_time_per_token_ms`.

### Stress Results

Stress phase uses `/api/benchmark/token`, `/api/auth/signin`, and `/api/auth/refresh` at 10, 30, and 50 VUs. Access avg/p95 comes from server-side JWT generation header; E2E/login/refresh values are k6 round-trip metrics. Values come from `benchmark_sign_result.json`; all error-rate values are `0`.

| Algorithm                | VUs | Access avg | Access p95 |  E2E p95 | Login p95 | Refresh p95 | Token ok/s |
| ------------------------ | --: | ---------: | ---------: | -------: | --------: | ----------: | ---------: |
| `Falcon-Precomputed-512` |  10 |    0.418 |    0.742 |  117.627 |   275.370 |     188.308 |           26.83 |
| `Falcon-Precomputed-512` |  30 |    0.415 |    0.654 |   68.819 |  1395.385 |    1219.381 |           22.33 |
| `Falcon-Precomputed-512` |  50 |    0.413 |    0.748 |   76.032 |  2174.233 |    2137.003 |           22.83 |
| `Falcon-512`             |  10 |    0.523 |    0.956 |   84.491 |   309.218 |     203.734 |           25.53 |
| `Falcon-512`             |  30 |    0.504 |    0.899 |  124.337 |   906.812 |     593.971 |           27.67 |
| `Falcon-512`             |  50 |    0.511 |    0.758 |  132.346 |  2429.321 |    2220.635 |           21.70 |
| `ML-DSA-44`              |  10 |    0.194 |    0.394 |   81.170 |   290.151 |     210.904 |           26.10 |
| `ML-DSA-44`              |  30 |    0.230 |    0.486 |   90.315 |  1311.638 |    1374.570 |           21.60 |
| `ML-DSA-44`              |  50 |    0.266 |    0.520 |  107.458 |  2284.412 |    2436.186 |           21.33 |
| `SLH-DSA-SHA2-128f`      |  10 |   20.377 |   39.474 |  389.473 |   782.439 |     918.115 |           10.90 |
| `SLH-DSA-SHA2-128f`      |  30 |   31.899 |   85.706 |  942.078 |  2160.787 |    2512.400 |           11.40 |
| `SLH-DSA-SHA2-128f`      |  50 |   19.162 |   36.419 |  751.799 |  4151.146 |    3699.200 |           13.17 |
| `SLH-DSA-SHA2-128s`      |  10 |  786.799 | 1552.408 | 1624.340 |  3515.741 |    3242.158 |            1.67 |
| `SLH-DSA-SHA2-128s`      |  30 | 2842.993 | 3814.459 | 4067.915 |  9250.730 |    9967.187 |            2.00 |
| `SLH-DSA-SHA2-128s`      |  50 | 4257.338 | 6628.612 | 6814.575 | 19911.388 |   23039.505 |            2.43 |

Stress thresholds in `benchmark_sign_raw.json` all pass. `stress_error_rate` is `0`, and `stress_refresh_error_rate` is `0`.

At 30 VU, `Falcon-Precomputed-512` has worse login/refresh tail latency and lower throughput than `Falcon-512` in this run. Treat that as a load-test anomaly requiring repeated independent runs, not proof that precomputation improves end-to-end performance under every load.

### Attack Results

`benchmark_sign_result.json` has `attack: null` per algorithm, but `benchmark_sign_raw.json` contains attack metrics. Tampered-token block rate is `100%` overall and `100%` for every algorithm.

| Metric                                          | Passes | Fails |  Rate | Threshold           |
| ----------------------------------------------- | -----: | ----: | ----: | ------------------- |
| `attack_block_rate`                             |    125 |     0 | 1.000 | `rate>0.99`, passed |
| `attack_block_rate{alg:Falcon-Precomputed-512}` |     25 |     0 | 1.000 | `rate>0.99`, passed |
| `attack_block_rate{alg:Falcon-512}`             |     25 |     0 | 1.000 | `rate>0.99`, passed |
| `attack_block_rate{alg:ML-DSA-44}`              |     25 |     0 | 1.000 | `rate>0.99`, passed |
| `attack_block_rate{alg:SLH-DSA-SHA2-128f}`      |     25 |     0 | 1.000 | `rate>0.99`, passed |
| `attack_block_rate{alg:SLH-DSA-SHA2-128s}`      |     25 |     0 | 1.000 | `rate>0.99`, passed |

Raw aggregate `http_req_failed` is `0.5308%` because k6 counts intentional `401` responses from tampered-token attacks as failed HTTP requests. Custom attack checks confirm those `401` responses are expected blocks.

### Raw k6 Summary

From `benchmark_sign_raw.json`:

| Metric                      |                             Value |
| --------------------------- | --------------------------------: |
| Test duration               |                  `1133026.708 ms` |
| `checks`                    |         `31003` passes, `0` fails |
| `http_reqs`                 |  `23549` requests, `20.784 req/s` |
| `iterations`                | `7839` iterations, `6.919 iter/s` |
| `stress_error_rate`         |                               `0` |
| `stress_refresh_error_rate` |                               `0` |
| Threshold checks            |       `329` evaluated, `0` failed |

## Testing Result

Commands run with `GOCACHE=/tmp/go-build-cache` on current workspace:

| Command                                 | Result                                                                                                                                                           |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `go test ./...` in `pkg`                | Passed. `backend/pkg/fndsa` `99.369s`, `backend/pkg/jwt` `100.513s`, `backend/pkg/jwt/request` `0.027s`, `backend/pkg/utils/jwtutils` `0.007s [no tests to run]` |
| `go test ./...` in `gateway`            | Passed. `backend/gateway/test` `0.005s`; other packages reported `[no test files]`                                                                               |
| `go test ./...` in `auth-service`       | Passed. `backend/auth-service/test` `0.012s`; other packages reported `[no test files]`                                                                          |
| `go test ./...` in `todo-service`       | Passed. `backend/todo-service/cmd/app` `0.035s`, `backend/todo-service/test` `0.015s`; other packages reported `[no test files]`                                 |
| `go test ./...` in `backend/cmd/keygen` | Passed. Package reported `[no test files]`                                                                                                                       |

No failing Go tests were observed in this run.

## Make Targets

Run these from `backend/`.

| Target                    | Action                                                                    |
| ------------------------- | ------------------------------------------------------------------------- |
| `make keygen`             | Generate production keys into `auth-service/keys`, copy to `gateway/keys` |
| `make keygen-all`         | Generate benchmark keys into `keys/`                                      |
| `make compile-proto`      | Regenerate service and gateway Go protobuf files                          |
| `make up`                 | Start production Compose stack                                            |
| `make up-build`           | Build and start production Compose stack                                  |
| `make down`               | Stop production stack                                                     |
| `make clean`              | Stop production stack and remove volumes                                  |
| `make vendor`             | Vendor dependencies for Docker builds                                     |
| `make tidy`               | Run `go mod tidy` in Go modules                                           |
| `make build`              | Build gateway, auth-service, and todo-service binaries into `bin/`        |
| `make bench-up`           | Build and start benchmark Compose stack                                   |
| `make bench-down`         | Stop benchmark stack and remove volumes                                   |
| `make bench-sign`         | Run local benchmark and write `result.txt`                                |
| `make bench-sign-remote`  | Run remote benchmark against `https://poc-ridwanmuh3.my.id`               |
| `make attack-adversarial` | Run adversarial JWT test against configurable base URL                    |

## Related Documentation

- `docs/grpc-implementation.md` explains gRPC contracts, metadata, trailers, keep-alive, and benchmark bias controls.
- `docs/skenario-pengujian.md` explains k6 scenario design, isolated/stress/attack phases, metrics, thresholds, and output files.
- `backend/api/api-spec.yml` and service `backend/api/spec.yaml` files contain OpenAPI-level API specifications.
