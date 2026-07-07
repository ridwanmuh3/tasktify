# Research System Architecture

Mermaid diagrams for Tasktify research architecture. Scope: production runtime, benchmark topology, request flows, and research artifact pipeline.

## Paper-Style System Architecture

```mermaid
flowchart LR
  %% Section order follows paper flow: input -> service/data -> JWT -> optimization -> evaluation.

  subgraph sec31["SECTION 3.1<br/>API ENTRY"]
    direction TB
    client["Browser / k6"]
    caddy["Caddy<br/>Static + API proxy"]
    gateway["Gateway<br/>HTTP to gRPC"]
    client --> caddy
    caddy --> gateway
  end

  subgraph sec32["SECTION 3.2<br/>SERVICE + DATA"]
    direction TB
    route_type{"Route type"}
    auth_svc["Auth service<br/>register, signin,<br/>refresh, profile"]
    todo_svc["Todo service<br/>task CRUD"]
    users_db[("users<br/>id, email,<br/>password_hash")]
    tasks_db[("tasks<br/>id, user_id,<br/>status, due_date")]

    route_type -->|"auth / profile"| auth_svc
    route_type -->|"tasks + x-user-id"| todo_svc
    auth_svc --> users_db
    todo_svc --> tasks_db
  end

  subgraph sec33["SECTION 3.3<br/>PQC JWT"]
    direction TB
    claims["JWT claims<br/>jti, user_id, email,<br/>token_use, iss, iat, exp"]
    alg_policy["Alg policy<br/>default + allowlist"]
    signer["PQC signer<br/>Falcon, ML-DSA, SLH-DSA"]
    token_pair["Token pair<br/>access + refresh"]
    verifier["Verifier<br/>alg, issuer, exp,<br/>signature, token_use"]

    claims --> alg_policy
    alg_policy --> signer
    signer --> token_pair
    token_pair --> verifier
  end

  subgraph sec34["SECTION 3.4<br/>OPTIMIZED METHOD"]
    direction TB
    key_load["Load FNDSA-512 keys"]
    precompute["Startup precompute<br/>decode f,g,F<br/>derive G,h"]
    cache["Cache<br/>hashedVK, FFT basis,<br/>LDL tree"]
    runtime_sign["Runtime sign<br/>reuse cache"]
    signature["Falcon signature"]

    key_load --> precompute
    precompute --> cache
    cache --> runtime_sign
    runtime_sign --> signature
  end

  subgraph sec35["SECTION 3.5<br/>EVALUATION"]
    direction TB
    bench_api["Benchmark API<br/>sign + token"]
    k6_phases["k6 phases<br/>isolated, stress,<br/>attack block-rate"]
    metrics["Metrics<br/>raw, GC-free,<br/>CPU/mem, p95"]
    artifacts["Artifacts<br/>JSON, tests,<br/>figures, docs"]

    bench_api --> k6_phases
    k6_phases --> metrics
    metrics --> artifacts
  end

  gateway --> route_type
  gateway --> bench_api
  auth_svc -->|"signin / refresh"| claims
  signer -->|"Falcon-Precomputed-512"| key_load
  signer -->|"JWT generation endpoint"| bench_api
  signer -->|"latency samples"| metrics

  classDef entry fill:#dbeafe,stroke:#2563eb,color:#111827
  classDef service fill:#dcfce7,stroke:#16a34a,color:#111827
  classDef data fill:#fef9c3,stroke:#ca8a04,color:#111827
  classDef crypto fill:#ede9fe,stroke:#7c3aed,color:#111827
  classDef opt fill:#ffedd5,stroke:#ea580c,color:#111827
  classDef output fill:#e0f2fe,stroke:#0284c7,color:#111827

  class client,caddy,gateway entry
  class route_type,auth_svc,todo_svc service
  class users_db,tasks_db,claims,metrics data
  class alg_policy,signer,token_pair,verifier crypto
  class key_load,precompute,cache,runtime_sign,signature opt
  class bench_api,k6_phases,artifacts output

  style sec31 fill:#f8fafc,stroke:#64748b,stroke-dasharray: 5 5
  style sec32 fill:#f8fafc,stroke:#64748b,stroke-dasharray: 5 5
  style sec33 fill:#f8fafc,stroke:#64748b,stroke-dasharray: 5 5
  style sec34 fill:#f8fafc,stroke:#64748b,stroke-dasharray: 5 5
  style sec35 fill:#f8fafc,stroke:#64748b,stroke-dasharray: 5 5
```

Diagram reading:

- 3.1: request masuk lewat Caddy, lalu Gateway.
- 3.2: Gateway dispatch ke Auth/Todo; data inti ada di `users` dan `tasks`.
- 3.3: Auth/benchmark membentuk JWT, signer PQC menandatangani, Gateway memverifikasi.
- 3.4: Falcon-Precomputed memindahkan decode, FFT basis, dan LDL tree ke startup cache.
- 3.5: k6 mengukur generasi JWT, stress, attack block-rate; output jadi JSON, statistik, figure, docs.

## Production Runtime

```mermaid
flowchart LR
  browser["Browser / API client"]
  k6["k6 runner"]

  subgraph edge["Edge"]
    caddy["Caddy<br/>static frontend + /api reverse proxy<br/>:80 / :443"]
  end

  subgraph gateway_layer["Gateway"]
    gateway["Gateway service<br/>Go Fiber HTTP API<br/>:3000"]
    auth_mw["Auth middleware<br/>JWT issuer / alg / signature / token_use check"]
    bench_handler["Benchmark handler<br/>/api/benchmark/sign<br/>/api/benchmark/token"]
  end

  subgraph services["gRPC services"]
    auth_svc["Auth service<br/>AuthService + UserService<br/>:3001"]
    todo_svc["Todo service<br/>TaskService<br/>:3002"]
    todo_interceptor["Todo gRPC auth interceptor<br/>requires x-user-id metadata"]
  end

  subgraph crypto["PQC JWT library"]
    jwtutils["pkg/utils/jwtutils<br/>Sign / Parse facade"]
    jwtpkg["pkg/jwt<br/>JWT parser + signing methods"]
    fndsa["pkg/fndsa<br/>Falcon / FN-DSA implementation"]
    keygen["cmd/keygen<br/>algorithm key generation"]
    keys["KEYS_DIR<br/>private + public keys"]
  end

  postgres[("PostgreSQL<br/>tasktify database")]
  frontend["frontend/dist<br/>Svelte static app"]

  browser -->|"HTTP/JSON"| caddy
  k6 -->|"HTTP/JSON"| caddy
  caddy -->|"serves static files"| frontend
  caddy -->|"API and health routes"| gateway

  gateway -->|"public routes<br/>register / signin / refresh"| auth_svc
  gateway -->|"protected /profile"| auth_svc
  gateway -->|"public /benchmark routes"| bench_handler
  gateway --> auth_mw
  auth_mw -->|"verified user_id"| gateway
  gateway -->|"protected /tasks<br/>gRPC metadata x-user-id"| todo_interceptor
  todo_interceptor --> todo_svc

  auth_svc -->|"users table"| postgres
  todo_svc -->|"tasks table"| postgres

  gateway -->|"verify JWT"| jwtutils
  auth_svc -->|"sign + parse JWT"| jwtutils
  bench_handler -->|"in-process JWT generation"| jwtutils
  jwtutils --> jwtpkg
  jwtpkg --> fndsa
  keygen --> keys
  keys --> gateway
  keys --> auth_svc
```

## Data Structure

```mermaid
erDiagram
  USERS ||--o{ TASKS : owns
  USERS ||--o{ JWT_CLAIMS : subject

  USERS {
    uuid id PK
    string name
    string email UK
    string password_hash
    int64 created_at
    int64 updated_at
  }

  TASKS {
    uuid id PK
    uuid user_id FK
    string title
    string description
    string status
    int64 due_date
    int64 created_at
    int64 updated_at
  }

  JWT_CLAIMS {
    string jti
    uuid user_id FK
    string email
    string token_use
    string issuer
    int64 issued_at
    int64 expires_at
  }
```

```mermaid
classDiagram
  class ResponseEnvelope {
    int status
    string message
    object data
  }

  class SignInRequest {
    string email
    string password
    string algorithm
  }

  class AuthResponse {
    string token_type
    string access_token
    string refresh_token
  }

  class TaskRequest {
    string title
    string description
    string status
    int64 due_date
  }

  class BenchmarkSignRequest {
    string algorithm
    int iterations
    int warmup_iterations
    string email
    string payload_note
  }

  class BenchmarkSignResult {
    string algorithm
    int success_count
    int gc_contaminated_count
    float_array sign_timings_ms
    float_array token_generation_gc_free_timings_ms
    float_array refresh_token_generation_timings_ms
    float_array auth_cpu_pct
    float_array auth_memory_alloc_mb
    object stats
  }

  class TimingStats {
    float min_ms
    float avg_ms
    float p50_ms
    float p95_ms
    float p99_ms
    float max_ms
    float stdev_ms
  }

  SignInRequest --> AuthResponse : returns
  TaskRequest --> ResponseEnvelope : wrapped
  BenchmarkSignRequest --> BenchmarkSignResult : returns
  BenchmarkSignResult --> TimingStats : summarizes
```

Data structure rules:

- Persistent data split by owner: Auth service owns `users`; Todo service owns `tasks`.
- `users.email` is unique. Password stored as bcrypt hash, never plaintext.
- `tasks.user_id` links task rows to authenticated user. API and repository scope task reads/writes by that user.
- JWT payload carries `sub`, `user_id`, `email`, `token_use`, `iss`, `iat`, `exp`, and `jti`.
- Token header carries `alg` and `typ`; gateway parser accepts only configured algorithms and validates token type against `token_use`.
- `Falcon-Precomputed-512` is a signer profile. JWT header `alg` remains `FN-DSA-512` for both dynamic and precomputed Falcon profiles.
- gRPC contracts use protobuf messages. HTTP handlers map JSON DTOs to protobuf requests.
- Benchmark output keeps raw samples plus summary stats so research can audit p50/p95/p99 and GC-free timing.

## Benchmark Topology

```mermaid
flowchart LR
  k6["k6 benchmark scripts<br/>backend/k6/benchmark_sign.js<br/>backend/k6/adversarial_jwt.js"]

  subgraph gateways["One gateway per algorithm"]
    gw1["bench-gw-fnp512<br/>Falcon-Precomputed-512<br/>localhost:5001"]
    gw2["bench-gw-fn512<br/>Falcon-512<br/>localhost:5002"]
    gw3["bench-gw-mldsa44<br/>ML-DSA-44<br/>localhost:5003"]
    gw4["bench-gw-slhdsa128f<br/>SLH-DSA-SHA2-128f<br/>localhost:5004"]
    gw5["bench-gw-slhdsa128s<br/>SLH-DSA-SHA2-128s<br/>localhost:5005"]
  end

  subgraph auth_pairs["Matching auth service per algorithm"]
    a1["bench-auth-fnp512<br/>JWT_DEFAULT_ALG=Falcon-Precomputed-512"]
    a2["bench-auth-fn512<br/>JWT_DEFAULT_ALG=Falcon-512"]
    a3["bench-auth-mldsa44<br/>JWT_DEFAULT_ALG=ML-DSA-44"]
    a4["bench-auth-slhdsa128f<br/>JWT_DEFAULT_ALG=SLH-DSA-SHA2-128f"]
    a5["bench-auth-slhdsa128s<br/>JWT_DEFAULT_ALG=SLH-DSA-SHA2-128s"]
  end

  bench_todo["bench-todo<br/>shared TaskService"]
  bench_db[("bench-postgres<br/>tasktify_bench")]
  bench_keys["backend/keys<br/>shared benchmark keys"]

  k6 -->|"HTTP benchmark traffic"| gw1
  k6 -->|"HTTP benchmark traffic"| gw2
  k6 -->|"HTTP benchmark traffic"| gw3
  k6 -->|"HTTP benchmark traffic"| gw4
  k6 -->|"HTTP benchmark traffic"| gw5

  gw1 -->|"gRPC signin / refresh / profile"| a1
  gw2 -->|"gRPC signin / refresh / profile"| a2
  gw3 -->|"gRPC signin / refresh / profile"| a3
  gw4 -->|"gRPC signin / refresh / profile"| a4
  gw5 -->|"gRPC signin / refresh / profile"| a5

  gw1 -->|"gRPC tasks"| bench_todo
  gw2 -->|"gRPC tasks"| bench_todo
  gw3 -->|"gRPC tasks"| bench_todo
  gw4 -->|"gRPC tasks"| bench_todo
  gw5 -->|"gRPC tasks"| bench_todo

  a1 --> bench_db
  a2 --> bench_db
  a3 --> bench_db
  a4 --> bench_db
  a5 --> bench_db
  bench_todo --> bench_db

  bench_keys --> gw1
  bench_keys --> gw2
  bench_keys --> gw3
  bench_keys --> gw4
  bench_keys --> gw5
  bench_keys --> a1
  bench_keys --> a2
  bench_keys --> a3
  bench_keys --> a4
  bench_keys --> a5
```

## Request Flows

```mermaid
sequenceDiagram
  autonumber
  participant Client as Browser / k6
  participant Gateway as Gateway HTTP API
  participant Auth as Auth service
  participant Todo as Todo service
  participant DB as PostgreSQL
  participant JWT as PQC JWT package

  rect rgb(240, 248, 255)
    Client->>Gateway: POST /api/auth/signin
    Gateway->>Auth: SignIn(email, password, algorithm)
    Auth->>DB: lookup user
    DB-->>Auth: user row
    Auth->>Auth: bcrypt password check
    Auth->>JWT: sign access token + refresh token
    JWT-->>Auth: signed JWT pair
    Auth-->>Gateway: AuthResponse + timing metadata
    Gateway-->>Client: token payload + X-*-Time-Ms headers
  end

  rect rgb(245, 255, 245)
    Client->>Gateway: GET /api/tasks with Bearer token
    Gateway->>JWT: parse + verify signature
    JWT-->>Gateway: claims with user_id
    Gateway->>Todo: Task RPC with x-user-id metadata
    Todo->>Todo: interceptor validates x-user-id UUID
    Todo->>DB: query tasks by user_id
    DB-->>Todo: task rows
    Todo-->>Gateway: task response
    Gateway-->>Client: HTTP JSON response
  end

  rect rgb(255, 250, 240)
    Client->>Gateway: POST /api/benchmark/sign
    Gateway->>JWT: sign N access + refresh tokens in-process
    JWT-->>Gateway: per-iteration timings
    Gateway-->>Client: raw samples + p50 / p95 / p99 + CPU / memory
  end
```

## Optimized Method Used

```mermaid
flowchart TD
  sk["FNDSA-512 private key<br/>FNDSA-512_sk.pem"]
  pk["FNDSA-512 public key<br/>FNDSA-512_pk.pem"]
  loader["LoadAlgConfig(signMode=true)"]
  precompute["fndsa.NewPrecomputedSigner"]
  decode["Decode f, g, F<br/>recompute G and public h"]
  vkhash["Hash verifying key<br/>SHAKE256"]
  fft["Precompute FFT basis<br/>b00, b01, b10, b11"]
  gram["Build Gram matrix"]
  ldl["Precompute LDL tree"]
  method["SigningMethodFalconPrecomputed<br/>signer embedded in method"]
  runtime["Runtime Sign()"]
  hash_msg["Hash JWT signing string to lattice point"]
  sample["Sample with precomputed LDL tree"]
  map_back["Map sample back through precomputed basis"]
  encode["Encode Falcon signature"]
  verify["Gateway Verify()<br/>public key + SHA3-256"]

  sk --> loader --> precompute
  pk --> loader
  precompute --> decode --> vkhash --> fft --> gram --> ldl --> method
  method --> runtime
  runtime --> hash_msg --> sample --> map_back --> encode
  encode --> verify
  pk --> verify
```

Optimization logic:

- Baseline `Falcon-512` signs with `fndsa.Sign`, which decodes private key and recomputes key-dependent lattice data during signing.
- Optimized `Falcon-Precomputed-512` builds `PrecomputedSigner` once at service startup.
- Startup precompute stores `hashedVK`, FFT basis arrays `b00`, `b01`, `b10`, `b11`, and LDL tree.
- Runtime signing reuses stored basis and LDL tree, so each JWT sign avoids repeated private-key decode, `G` recomputation, FFT basis generation, Gram matrix construction, and LDL tree construction.
- Verification unchanged at cryptographic level: gateway verifies `FN-DSA-512` signature with public key, algorithm allowlist, `typ`, issuer, subject, token_use, issued-at, and expiry checks.
- Benchmark measures effect through `/api/benchmark/sign`: warmup, forced GC, per-iteration access/refresh JWT generation, GC-contaminated count, CPU, memory, and timing stats.

## Research Artifact Pipeline

```mermaid
flowchart LR
  compose["docker-compose.benchmark.yml<br/>isolated gateway/auth pairs"]
  k6scripts["k6 scenarios<br/>isolated JWT generation<br/>stress test<br/>attack block-rate"]
  raw["benchmark_sign_raw.json<br/>adversarial_raw.json"]
  stats["scripts/benchmark_stat_tests.py<br/>statistical checks"]
  graphics["scripts/generate_article_graphics*.py<br/>figure generation"]
  figures["figures/article*<br/>PNG figures + CSV data + captions"]
  docs["README.md<br/>docs/skenario-pengujian.md<br/>docs/grpc-implementation.md"]

  compose --> k6scripts
  k6scripts --> raw
  raw --> stats
  raw --> graphics
  stats --> figures
  graphics --> figures
  figures --> docs
```
