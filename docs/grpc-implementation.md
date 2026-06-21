# Implementasi gRPC pada Arsitektur Microservices Tasktify

**Dokumen:** Penjelasan Teknis Implementasi gRPC  
**Bahasa implementasi:** Go  
**Library:** `google.golang.org/grpc`

---

## 1. Gambaran Arsitektur

```
Client (Browser/k6)
       │  HTTP/JSON
       ▼
┌─────────────────┐
│    Gateway      │  :8080  (Fiber HTTP server)
│  (HTTP Server)  │
└──────┬──────────┘
       │
       ├── gRPC ──────────────────▶ Auth Service  :3001
       │                            (UserService + AuthService)
       │
       └── gRPC ──────────────────▶ Todo Service  :3002
                                    (TaskService)
```

Gateway adalah satu-satunya titik masuk (_single entry point_) yang menerima HTTP dari klien, lalu meneruskan ke service backend menggunakan gRPC. Klien tidak pernah berbicara langsung ke service backend.

---

## 2. Protocol Buffers — Kontrak Antar Service

### Apa itu Protocol Buffers?

Protocol Buffers (Protobuf) adalah bahasa definisi antarmuka (_Interface Definition Language_/IDL) milik Google. File `.proto` mendefinisikan:

- **Struktur data** (messages) yang dikirim dan diterima
- **Layanan** (services) berisi daftar fungsi RPC yang tersedia

Dari satu file `.proto`, `protoc` menghasilkan kode Go secara otomatis — termasuk struct, interface server, dan implementasi klien.

### File Proto yang Digunakan

**`backend/auth-service/proto/auth.proto`** — Layanan autentikasi:

```protobuf
service AuthService {
    rpc SignIn(SignInRequest) returns (AuthResponse);
    rpc RefreshToken(RefreshTokenRequest) returns (AuthResponse);
    rpc Verify(VerifyRequest) returns (google.protobuf.Empty);
}
```

**`backend/auth-service/proto/user.proto`** — Manajemen pengguna:

```protobuf
service UserService {
    rpc Create(CreateUserRequest) returns (google.protobuf.Empty);
    rpc Update(UpdateUserRequest) returns (google.protobuf.Empty);
    rpc Delete(DeleteUserRequest) returns (google.protobuf.Empty);
    rpc Get(GetUserRequest) returns (UserResponse);
    rpc GetAll(google.protobuf.Empty) returns (ListUserResponse);
}
```

**`backend/todo-service/proto/task.proto`** — Manajemen tugas:

```protobuf
service TaskService {
    rpc Create(CreateTaskRequest) returns (google.protobuf.Empty);
    rpc Update(UpdateTaskRequest) returns (google.protobuf.Empty);
    rpc Delete(DeleteTaskRequest) returns (google.protobuf.Empty);
    rpc Get(GetTaskRequest) returns (TaskResponse);
    rpc GetAll(GetAllTaskRequest) returns (ListTaskResponse);
}
```

### Teknik Proto yang Digunakan

| Teknik                      | Contoh                                   | Keterangan                                            |
| --------------------------- | ---------------------------------------- | ----------------------------------------------------- |
| `google.protobuf.Empty`     | `returns (google.protobuf.Empty)`        | Pengganti `void` — RPC tidak perlu mengembalikan data |
| `google.protobuf.Timestamp` | field `created_at`, `due_date`           | Format waktu standar cross-language                   |
| `repeated`                  | `repeated Task tasks = 1`                | Setara array/slice untuk respons list                 |
| `enum`                      | `enum TaskStatus { PENDING=0; ... }`     | Tipe data terbatas dengan nilai yang pasti            |
| `option go_package`         | `option go_package = "./internal/model"` | Menentukan path package Go hasil generate             |

---

## 3. Pola Unary RPC

Semua RPC dalam sistem ini menggunakan pola **Unary RPC** — satu permintaan, satu respons. Ini adalah pola paling sederhana dan setara dengan pemanggilan fungsi biasa melalui jaringan.

```
Client ──── Request ────▶ Server
Client ◀─── Response ─── Server
```

> Tidak ada streaming RPC (client streaming / server streaming / bidirectional) karena operasi CRUD dan autentikasi tidak membutuhkannya.

---

## 4. Implementasi Server gRPC

### 4.1 Mendaftarkan Server

**Auth Service** (`backend/auth-service/cmd/app/main.go`):

```go
srv := grpc.NewServer(
    grpc.KeepaliveParams(keepalive.ServerParameters{
        Time:    30 * time.Second,
        Timeout: 10 * time.Second,
    }),
    grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
        MinTime:             5 * time.Second,
        PermitWithoutStream: true,
    }),
)
```

**Todo Service** (`backend/todo-service/cmd/app/main.go`):

```go
srv := grpc.NewServer(grpc.UnaryInterceptor(interceptor.AuthInterceptor))
```

Perbedaan utama: Auth Service menggunakan keep-alive (karena menerima beban berat dari benchmark), sedangkan Todo Service menggunakan interceptor untuk autentikasi setiap permintaan.

### 4.2 Pola `UnimplementedXxxServiceServer`

Setiap struct server meng-embed tipe yang dihasilkan oleh protoc:

```go
type AuthServer struct {
    model.UnimplementedAuthServiceServer  // ← ini
    log         *zap.SugaredLogger
    authService *service.AuthService
}
```

**Mengapa dibutuhkan?**  
Ini adalah pola _forward compatibility_ dari gRPC-Go. Jika di masa depan proto menambahkan method RPC baru, server yang belum mengimplementasikan method tersebut tidak akan langsung compile error — melainkan method tersebut akan mengembalikan `codes.Unimplemented` secara default dari embed.

### 4.3 Implementasi Method RPC

Setiap method RPC menerima `context.Context` dan pointer ke struct request, lalu mengembalikan pointer ke struct respons dan `error`:

```go
func (s *AuthServer) SignIn(ctx context.Context, request *model.SignInRequest) (*model.AuthResponse, error) {
    accessToken, refreshToken, tokenGenerationMs, runtimeStats, err := s.authService.SignIn(
        ctx,
        request.Email,
        request.Password,
        request.Algorithm,
    )
    if err != nil {
        return nil, err  // error langsung dikembalikan sebagai gRPC status error
    }
    // ...
    return &model.AuthResponse{Auth: &model.Auth{...}}, nil
}
```

---

## 5. gRPC Status Error

gRPC memiliki sistem kode error sendiri (berbeda dari HTTP status code). Konversi error dilakukan dengan `status.Error(codes.X, "pesan")`.

### Di Sisi Server (Auth Service)

```go
// User tidak ditemukan → Unauthenticated (bukan NotFound, untuk keamanan)
return "", "", 0, RuntimeStats{}, status.Error(codes.Unauthenticated, "invalid email or password")

// Password salah → sama, tidak dibedakan (mencegah user enumeration attack)
return "", "", 0, RuntimeStats{}, status.Error(codes.Unauthenticated, "invalid email or password")

// Error internal
return "", "", 0, RuntimeStats{}, status.Error(codes.Internal, "failed to generate token")
```

### Di Sisi Gateway (Konversi ke HTTP)

```go
func grpcToHTTPError(err error) *fiber.Error {
    st, ok := status.FromError(err)
    if !ok {
        return fiber.NewError(500, "internal server error")
    }
    switch st.Code() {
    case 3:  // codes.InvalidArgument → HTTP 400
        return fiber.NewError(400, st.Message())
    case 5:  // codes.NotFound → HTTP 404
        return fiber.NewError(404, st.Message())
    case 16: // codes.Unauthenticated → HTTP 401
        return fiber.NewError(401, st.Message())
    default:
        return fiber.NewError(500, st.Message())
    }
}
```

Tabel pemetaan kode error yang digunakan:

| gRPC Code               | Nilai | HTTP Equivalent | Kapan Digunakan                |
| ----------------------- | ----- | --------------- | ------------------------------ |
| `codes.Unauthenticated` | 16    | 401             | Login gagal, token tidak valid |
| `codes.NotFound`        | 5     | 404             | Data tidak ditemukan           |
| `codes.InvalidArgument` | 3     | 400             | Input tidak valid              |
| `codes.Internal`        | 13    | 500             | Error server internal          |
| `codes.Unimplemented`   | 12    | —               | Method belum diimplementasikan |

---

## 6. gRPC Metadata — Meneruskan Data Antar Layar

Metadata di gRPC setara dengan HTTP headers — pasangan key-value yang dikirim bersama setiap RPC call, di luar body utama.

### 6.1 Outgoing Metadata: Gateway → Todo Service

Ketika klien sudah login dan mengirim permintaan ke endpoint tugas, gateway perlu meneruskan identitas pengguna ke Todo Service. Ini dilakukan lewat metadata:

```go
// backend/gateway/internal/delivery/http/handler/task_handler.go
func forwardContext(c fiber.Ctx) context.Context {
    userID := c.Locals("user_id").(string)  // diambil dari JWT yang sudah diverifikasi
    md := metadata.Pairs("x-user-id", userID)
    return metadata.NewOutgoingContext(c.Context(), md)
}
```

Setiap RPC call ke Todo Service menggunakan context ini:

```go
ctx := forwardContext(c)
h.taskClient.Create(ctx, grpcReq)  // x-user-id terkirim dalam metadata
```

### 6.2 Incoming Metadata: Server Membaca x-user-id

Di Todo Service, interceptor membaca `x-user-id` dari metadata masuk:

```go
// backend/todo-service/internal/delivery/grpc/interceptor/auth_interceptor.go
md, ok := metadata.FromIncomingContext(ctx)
userIDs := md.Get("x-user-id")
// → inject ke context
authCtx := context.WithValue(ctx, server.AuthContextKey, userIDs[0])
return handler(authCtx, req)  // teruskan ke handler dengan context baru
```

Server kemudian membaca dari context:

```go
// backend/todo-service/internal/delivery/grpc/server/task_server.go
func getUserID(ctx context.Context) (string, error) {
    userID, ok := ctx.Value(AuthContextKey).(string)
    // ...
    return userID, nil
}
```

### 6.3 Trailing Metadata: Auth Service → Gateway (Arah Balik)

Trailing metadata dikirim di akhir respons (setelah body) — digunakan untuk mengirimkan data observabilitas dari auth-service ke gateway:

```go
// backend/auth-service/internal/delivery/grpc/server/auth_server.go
grpc.SetTrailer(ctx, metadata.Pairs(
    "x-sign-time-ms",             fmt.Sprintf("%.3f", tokenGenerationMs),
    "x-token-generation-time-ms", fmt.Sprintf("%.3f", tokenGenerationMs),
    "x-auth-cpu-pct",             fmt.Sprintf("%.3f", runtimeStats.CPUPct),
    "x-auth-mem-alloc-mb",        fmt.Sprintf("%.3f", runtimeStats.MemoryAllocMB),
    "x-auth-mem-sys-mb",          fmt.Sprintf("%.3f", runtimeStats.MemorySysMB),
))
```

Gateway menangkap trailer ini dan meneruskannya ke klien sebagai HTTP response header:

```go
// backend/gateway/internal/delivery/http/handler/auth_handler.go
var trailer metadata.MD
resp, err := h.authClient.SignIn(ctx, req, grpc.Trailer(&trailer))

for trailerKey, headerKey := range map[string]string{
    "x-sign-time-ms":             "X-Sign-Time-Ms",
    "x-token-generation-time-ms": "X-Token-Generation-Time-Ms",
    // ...
} {
    if vals := trailer.Get(trailerKey); len(vals) > 0 {
        c.Set(headerKey, vals[0])
    }
}
```

Alur lengkap data latensi:

```
Auth Service (ukur sign time)
    → kirim via gRPC Trailer
        → Gateway terima
            → forward sebagai HTTP Response Header
                → k6 baca dari header → catat sebagai metrik
```

---

## 7. Unary Server Interceptor — Autentikasi di Todo Service

Interceptor di gRPC setara dengan middleware di HTTP. Interceptor berjalan **sebelum** setiap handler RPC dipanggil.

```go
// backend/todo-service/cmd/app/main.go
srv := grpc.NewServer(grpc.UnaryInterceptor(interceptor.AuthInterceptor))
```

```go
// Signature interceptor standar gRPC-Go
func AuthInterceptor(
    ctx context.Context,
    req any,
    info *grpc.UnaryServerInfo,  // berisi nama method yang dipanggil
    handler grpc.UnaryHandler,   // handler asli
) (any, error) {
    // 1. Baca metadata
    md, ok := metadata.FromIncomingContext(ctx)
    if !ok {
        return nil, status.Errorf(codes.Unauthenticated, "metadata not provided")
    }

    // 2. Validasi kehadiran x-user-id
    userIDs := md.Get("x-user-id")
    if len(userIDs) == 0 {
        return nil, status.Errorf(codes.Unauthenticated, "x-user-id not provided")
    }

    // 3. Inject user ID ke context → diteruskan ke handler
    authCtx := context.WithValue(ctx, server.AuthContextKey, userIDs[0])
    return handler(authCtx, req)
}
```

**Kenapa tidak verifikasi JWT di Todo Service?**  
JWT sudah diverifikasi oleh gateway (menggunakan public key PQC secara lokal). Todo Service hanya perlu `user_id` yang sudah diekstrak — tidak perlu memiliki kunci kriptografi, mengurangi coupling antar service.

---

## 8. Keep-Alive — Menjaga Koneksi HTTP/2 Tetap Hidup

gRPC berjalan di atas HTTP/2, yang menggunakan **satu koneksi TCP yang di-multiplex** untuk banyak RPC secara bersamaan. Tanpa keep-alive, koneksi idle bisa ditutup oleh firewall atau load balancer.

### Konfigurasi Client (Gateway)

```go
// backend/gateway/internal/config/grpc.go
grpc.WithKeepaliveParams(keepalive.ClientParameters{
    Time:                20 * time.Second,  // kirim ping setiap 20 detik jika tidak ada aktivitas
    Timeout:             10 * time.Second,  // tunggu 10 detik untuk ack ping
    PermitWithoutStream: true,              // kirim ping meski tidak ada RPC aktif
})
```

### Konfigurasi Server (Auth Service)

```go
// backend/auth-service/cmd/app/main.go
grpc.KeepaliveParams(keepalive.ServerParameters{
    Time:    30 * time.Second,
    Timeout: 10 * time.Second,
}),
grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
    MinTime:             5 * time.Second,   // toleransi ping dari klien minimal 5 detik sekali
    PermitWithoutStream: true,
}),
```

**Kenapa ini penting untuk benchmark?**  
Skenario stress test mengirim 10–50 permintaan konkuren selama 30 detik, diselingi jeda. Tanpa keep-alive, koneksi yang terbuka saat jeda bisa dianggap stale dan ditutup, menyebabkan latensi spike saat koneksi baru dibuat.

---

## 9. gRPC Connection — Client di Gateway

Gateway membuat satu koneksi gRPC per service (bukan per permintaan):

```go
// backend/gateway/internal/config/grpc.go
func NewAuthServiceConn(config *viper.Viper, log *zap.SugaredLogger) *grpc.ClientConn {
    addr := config.GetString("AUTH_SERVICE_ADDR")  // default: localhost:3001
    conn, err := grpc.NewClient(addr, grpcClientOpts...)
    // ...
    return conn
}
```

Koneksi ini dibuat sekali saat startup dan digunakan bersama (_shared_) oleh semua goroutine yang menangani HTTP request secara konkuren. HTTP/2 multiplexing memungkinkan banyak RPC berjalan bersamaan di atas satu koneksi TCP ini tanpa blocking.

---

## 10. Alur Lengkap: Login Pengguna

Berikut alur teknis end-to-end dari login hingga akses resource:

```
1. Klien → POST /api/auth/signin {email, password, algorithm}
           ↓ HTTP/JSON
2. Gateway: parse request, buat gRPC call
           ↓ gRPC (metadata kosong)
3. Auth Service: AuthServer.SignIn()
    a. UserRepository.GetByEmail() → query database
    b. bcrypt.CompareHashAndPassword() → verifikasi password
    c. jwtUtil.Sign(payload) → tanda tangan PQC ← diukur waktunya
    d. grpc.SetTrailer() → sisipkan x-sign-time-ms ke trailer
           ↑ gRPC Response {access_token} + Trailer {x-sign-time-ms}
4. Gateway: terima response + trailer
    - forward trailer sebagai HTTP header
    - kembalikan JSON {access_token}
           ↑ HTTP Response + X-Sign-Time-Ms header
5. Klien: simpan access_token

--- Akses resource (contoh: buat task) ---

6. Klien → POST /api/tasks {title, ...} + Authorization: Bearer <token>
           ↓ HTTP/JSON
7. Gateway: Auth Middleware
    - Parse JWT → verifikasi tanda tangan PQC secara lokal
    - Ekstrak user_id dari claims
    - c.Locals("user_id", userID)
           ↓
8. Gateway: TaskHandler.Create()
    - forwardContext() → buat metadata {x-user-id: <userID>}
           ↓ gRPC (metadata: x-user-id)
9. Todo Service: AuthInterceptor (sebelum handler)
    - Baca x-user-id dari metadata
    - Inject ke context
           ↓
10. Todo Service: TaskServer.Create()
    - getUserID(ctx) → ambil dari context
    - taskService.Create() → simpan ke database
           ↑ gRPC Response (Empty)
11. Gateway → HTTP 201 Created
           ↑
12. Klien: menerima respons
```

---

## 11. Teknik Reduksi Bias pada Pengujian Benchmarking

Bagian ini menjelaskan perubahan teknis spesifik yang diterapkan **di dalam lapisan gRPC dan server** untuk memastikan hasil benchmark mencerminkan performa algoritma kriptografi secara murni — bukan artefak dari infrastruktur atau runtime Go.

### 11.1 Pengukuran Terisolasi dari Jalur gRPC

**Masalah:** Jika latensi tanda tangan diukur dari sisi klien (k6), angka yang diperoleh mencakup: serialisasi Protobuf, overhead gRPC, latensi jaringan TCP, dan deserialisasi — bukan hanya operasi kriptografi.

**Solusi:** Timer diletakkan **di dalam proses server**, mengelilingi hanya pemanggilan `Sign()`:

```go
// backend/auth-service/internal/service/auth_service.go
signStart := time.Now()
accessToken, err := s.jwtUtil.Sign(&jwtutils.JWTPayload{...})
signTimeMs := float64(time.Since(signStart).Microseconds()) / 1000.0
```

Seluruh overhead gRPC (marshal/unmarshal, network, bcrypt, DB query) terjadi di **luar** interval timer ini. Hasil `signTimeMs` lalu dikirim ke klien melalui **gRPC Trailing Metadata** — bukan dihitung dari sisi klien.

**Dampak pada bias:** Mengeliminasi ±0.5–5 ms overhead jaringan dan serialisasi dari setiap pengukuran.

---

### 11.2 Endpoint Benchmark Khusus — Membypass Auth Pipeline

**Masalah:** Login nyata (`/api/auth/signin`) melibatkan: query database (PostgreSQL), `bcrypt.CompareHashAndPassword()` (~100–300 ms), dan overhead gRPC. Ini mendominasi latensi dan mengaburkan performa tanda tangan.

**Solusi:** Dibuat dua endpoint benchmark khusus yang mem-bypass semua lapisan tersebut:

| Endpoint                    | Jalur                                     | Digunakan untuk |
| --------------------------- | ----------------------------------------- | --------------- |
| `POST /api/benchmark/sign`  | Gateway → langsung ke fungsi `Sign()`     | Fase 1 Isolated |
| `POST /api/benchmark/token` | Gateway → fungsi `Sign()` tanpa DB/bcrypt | Fase 2 Stress   |

Endpoint ini tidak melalui auth-service, tidak ada DB query, tidak ada bcrypt. Payload JWT dibuat dari email yang disuplai dan UUID deterministik (`uuid.NewSHA1`).

**Dampak pada bias:** Mengisolasi variabel bebas (algoritma kriptografi) dari variabel pengganggu (latensi DB, bcrypt cost).

---

### 11.3 Warmup Iterasi — Menghilangkan Bias Cold-Start

**Masalah:** Iterasi pertama selalu lebih lambat karena:

- **Cold path/branch prediction miss** — jalur kode dan prediktor cabang belum stabil
- **CPU cache miss** — instruksi dan data kriptografi belum ada di cache L1/L2
- **Heap belum terbentuk** — alokasi pertama lebih lambat karena Go harus meminta memori dari OS

**Solusi:** 20 iterasi warmup dijalankan sebelum pengukuran dimulai, hasilnya dibuang:

```go
// backend/gateway/internal/delivery/http/handler/benchmark_handler.go
for i := 0; i < warmupIterations; i++ {
    h.signBenchmarkToken(req.Algorithm, req.Email, false)  // hasil tidak disimpan
}
```

**Dampak pada bias:** Iterasi yang diukur dimulai dalam kondisi "warm" — distribusi latensi menjadi stasioner, tidak ada outlier dari cold-start yang menggelembungkan rata-rata atau stdev.

---

### 11.4 GC Cleanup Setelah Warmup

**Masalah:** Warmup menyebabkan alokasi heap. Jika Garbage Collector (GC) Go berjalan di tengah iterasi pengukuran, ia menyebabkan jeda **Stop-The-World (STW)** — seluruh goroutine dihentikan sementara GC bekerja. Ini menggelembungkan latensi iterasi tersebut secara artifisial.

**Solusi:** Dua siklus GC paksa dijalankan tepat setelah warmup selesai:

```go
// Force GC twice after warmup so measurement starts with a clean heap.
// First call triggers collection; second ensures finalizers have run.
runtime.GC()
runtime.GC()
```

Dua kali pemanggilan: pertama men-trigger koleksi, kedua memastikan semua finalizer telah selesai. Pengukuran dimulai dari heap yang bersih sehingga GC tidak akan terpicu di awal sesi pengukuran.

**Dampak pada bias:** Mengurangi kemungkinan GC berjalan selama pengukuran, terutama pada iterasi-iterasi awal.

---

### 11.5 Deteksi dan Pemisahan Iterasi yang Terkontaminasi GC

**Masalah:** Meski sudah ada GC cleanup, GC tetap bisa berjalan di tengah iterasi pengukuran (terutama untuk algoritma yang mengalokasikan memori besar seperti Falcon). Iterasi tersebut memiliki latensi yang **tidak representatif** karena mencakup jeda STW.

**Solusi:** Setiap iterasi mendeteksi apakah GC berjalan selama `Sign()` dengan membandingkan `runtime.MemStats.NumGC` sebelum dan sesudah:

```go
// backend/gateway/internal/delivery/http/handler/benchmark_handler.go
stats := BenchmarkRuntimeStats{
    GCOccurred: memAfter.NumGC > memBefore.NumGC,  // true jika ada ≥1 siklus GC
}
```

Iterasi yang terkontaminasi dipisah dari yang bersih:

```go
if stats.GCOccurred {
    gcContaminatedCount++
} else {
    gcFreeSignTimings = append(gcFreeSignTimings, signMs)  // sampel bersih
}
```

Hasil akhir melaporkan **dua set statistik**:

- `token_generation_ms` — generasi JWT access token dari payload benchmark, semua iterasi (referensi)
- `token_generation_gc_free_ms` — generasi JWT access token dari payload benchmark, hanya iterasi bersih ← gunakan ini di skripsi

**Dampak pada bias:** Memungkinkan analisis dengan dan tanpa kontaminasi GC. `gc_free` mencerminkan performa generasi JWT dari payload benchmark tanpa artefak GC.

---

### 11.6 Pengukuran Memori Di Luar Timer

**Masalah:** `runtime.ReadMemStats()` adalah operasi yang melakukan STW (Stop-The-World) kecil untuk membaca statistik memori secara konsisten. Jika dipanggil di dalam interval timer, ia menambahkan overhead ke pengukuran latensi.

**Solusi:** `ReadMemStats` dipanggil **sebelum** dan **sesudah** Sign, namun **di luar** interval timer:

```goS
// ReadMemStats dipanggil di luar timer — STW-nya tidak masuk ke pengukuran latensi
var memBefore, memAfter runtime.MemStats
runtime.ReadMemStats(&memBefore)   // ← sebelum timer

t0 := time.Now()
token, err := h.benchmarkJWT.Sign(payload)  // ← hanya ini yang diukur
signMs := float64(time.Since(t0).Microseconds()) / 1000.0

runtime.ReadMemStats(&memAfter)    // ← sesudah timer
```

**Dampak pada bias:** Overhead STW dari `ReadMemStats` tidak masuk ke nilai `signMs`.

---

### 11.7 Metrik CPU Per-Operasi vs Monitor Latar Belakang

**Masalah:** CPU usage sulit diukur untuk operasi sub-milidetik. Monitor latar belakang (sampling `/proc/self/stat` tiap 100ms) menghasilkan rata-rata yang terlalu kasar untuk satu operasi Sign yang berlangsung < 1ms.

**Solusi:** Dua mode pengukuran CPU dengan parameter `usePerOpCPU`:

| Mode          | `usePerOpCPU` | Cara ukur                               | Digunakan pada         |
| ------------- | ------------- | --------------------------------------- | ---------------------- |
| Per-operasi   | `true`        | Delta tick CPU sebelum-sesudah Sign     | Fase 1 Isolated        |
| Monitor latar | `false`       | Nilai rata-rata dari background sampler | Fase 2 Stress (warmup) |

```go
if usePerOpCPU {
    // Delta tick CPU hanya selama Sign — akurat untuk operasi < 1ms
    cpuPct = float64(cpuDelta) * 1_000_000.0 / float64(wallUs) / float64(runtime.GOMAXPROCS(0))
} else {
    // Background monitor — lebih representatif di bawah beban konkuren
    cpuMonitor.mu.RLock()
    cpuPct = cpuMonitor.pct
    cpuMonitor.mu.RUnlock()
}
```

**Dampak pada bias:** Mode per-operasi tidak mencampur CPU workload dari goroutine lain yang berjalan bersamaan, menghasilkan angka yang lebih akurat untuk pengujian isolated.

---

### Ringkasan Sumber Bias dan Mitigasinya

| Sumber Bias                 | Dampak                   | Teknik Mitigasi                                |
| --------------------------- | ------------------------ | ---------------------------------------------- |
| Latensi jaringan & gRPC     | +0.5–5 ms per iterasi    | Timer di sisi server, trailing metadata        |
| DB query + bcrypt           | +100–300 ms              | Endpoint benchmark khusus bypass auth pipeline |
| Cold-start path/cache miss  | Outlier iterasi awal     | 20 iterasi warmup yang dibuang                 |
| GC Stop-The-World           | Spike latensi artifisial | GC paksa post-warmup + deteksi per-iterasi     |
| ReadMemStats STW            | +overhead kecil ke timer | ReadMemStats di luar interval timer            |
| CPU coarse-grained sampling | Tidak akurat untuk < 1ms | Per-op tick delta untuk fase isolated          |

---

## 12. Ringkasan Teknik yang Digunakan

| Teknik                          | Lokasi                   | Tujuan                                |
| ------------------------------- | ------------------------ | ------------------------------------- |
| **Protocol Buffers (proto3)**   | `*/proto/*.proto`        | Mendefinisikan kontrak data dan RPC   |
| **Unary RPC**                   | Semua service            | Pola request-response sederhana       |
| **`UnimplementedXxxServer`**    | Semua server             | Forward compatibility                 |
| **`google.protobuf.Empty`**     | Semua CRUD               | Return void tanpa payload             |
| **`google.protobuf.Timestamp`** | User, Task               | Representasi waktu lintas bahasa      |
| **`repeated`**                  | GetAll responses         | Slice/array dalam proto               |
| **gRPC Status + Error Codes**   | Semua service            | Error handling terstandarisasi        |
| **Outgoing Metadata**           | Gateway → Todo Service   | Propagasi user_id antar service       |
| **Incoming Metadata**           | Todo Service interceptor | Membaca x-user-id dari gateway        |
| **Trailing Metadata**           | Auth Service → Gateway   | Kirim metrik latensi setelah respons  |
| **Unary Server Interceptor**    | Todo Service             | Autentikasi setiap RPC call           |
| **Keep-Alive (client)**         | Gateway                  | Pertahankan koneksi HTTP/2            |
| **Keep-Alive (server)**         | Auth Service             | Toleransi ping dari gateway           |
| **Shared gRPC Connection**      | Gateway                  | Satu koneksi, banyak goroutine        |
| **`grpc.Trailer(&trailer)`**    | Gateway auth handler     | Tangkap trailing metadata dari server |

---

_Dokumen ini dibuat berdasarkan kode sumber di direktori `backend/auth-service/`, `backend/todo-service/`, dan `backend/gateway/`._
