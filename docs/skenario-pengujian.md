# Skenario Pengujian Performa Tanda Tangan Digital Post-Quantum

**Dokumen:** Metodologi & Skenario Pengujian  
**Berkas Skrip:** `backend/k6/benchmark_sign.js`  
**Alat Pengujian:** k6 v0.50+ (Grafana Labs)  
**Tanggal:** Mei 2026

---

## 1. Gambaran Umum

Pengujian performa dilaksanakan menggunakan **k6**, sebuah alat *load testing* berbasis Go yang dijalankan dari sisi klien (*client-side*). k6 mensimulasikan pengguna virtual (VU — *Virtual User*) yang mengirimkan permintaan HTTP ke server secara bersamaan, kemudian mengumpulkan statistik latensi, throughput, dan tingkat kesalahan.

Pengujian dirancang dalam **tiga fase berurutan** yang dieksekusi dalam satu sesi pengujian tunggal:

| Fase | Nama | Tujuan |
|------|------|---------|
| 1 | Isolated Benchmark | Mengukur latensi generasi JWT dari payload benchmark tanpa gangguan (*noise*) eksternal |
| 2 | Stress Test | Mengukur degradasi performa di bawah beban konkuren |
| 3 | Attack Block-Rate | Memverifikasi integritas token — sistem harus menolak token yang dimanipulasi |

---

## 2. Arsitektur Sistem Benchmark

```
┌─────────────┐         HTTP          ┌──────────────────────────────┐
│   k6 Client │ ─────────────────────▶│ Gateway Service              │
│  (1 mesin)  │                       │  /api/benchmark/jwt-issuance │
│             │                       │  /api/benchmark/pure-signing │
└─────────────┘                       │  /api/benchmark/token (Ph.2) │
                                      │  /api/auth/signin     (Ph.2) │
                                      │  /api/profile         (Ph.3) │
                                      └──────────┬───────────────────┘
                                                 │ gRPC
                                      ┌──────────▼───────────┐
                                      │  Auth Service         │
                                      │  (bcrypt + DB + JWT)  │
                                      └──────────────────────┘
```

### Mode Deployment

| Mode | Variabel Lingkungan | Keterangan |
|------|---------------------|------------|
| **Single Gateway** | `BASE_URL=https://...` | Satu gateway melayani semua algoritma |
| **Multi Gateway** | `BENCH_HOST=localhost` | Satu gateway per profil FN-DSA, port berbeda (5001-5002) |

Pada mode multi-gateway, setiap profil FN-DSA mendapatkan proses gateway terpisah sehingga tidak ada kontestasi sumber daya antar profil selama pengujian.

---

## 3. Profil Signer yang Diuji

| ID Internal | Profil Benchmark | JWS `alg` | Kategori | Port (Multi-GW) |
|-------------|-------------------|-----------|----------|-----------------|
| `FNP512` | FN-DSA-Precomputed-512 | FN-DSA-512 | PQC (proposed/optimized) | 5001 |
| `FN512` | FN-DSA-512 | FN-DSA-512 | PQC (baseline / historically "Falcon-512") | 5002 |
| `HS256` | HS256 | HS256 | Classical (symmetric) | 5003 |
| `RS256` | RS256 | RS256 | Classical (RSA) | 5004 |
| `ES256` | ES256 | ES256 | Classical (ECDSA P-256) | 5005 |
| `EdDSA` | EdDSA | EdDSA | Classical (Ed25519) | 5006 |

Kolom **Profil Benchmark** adalah konfigurasi signer internal untuk eksperimen. Untuk FN-DSA, token JWT tetap memakai JWS `alg` eksperimental `FN-DSA-512`; profil `FN-DSA-Precomputed-512` tidak muncul sebagai nilai `alg` karena precomputation hanya teknik implementasi signer. FN-DSA-512 adalah basis FN-DSA-512, sedangkan profil JOSE/FIPS final masih harus mengikuti spesifikasi resmi terbaru ketika tersedia.

`Falcon-512`/`Falcon-Precomputed-512` di `supportedAlgorithms` adalah alias lama untuk profil FN-DSA yang sama (lihat commit "rewrite falcon to fndsa") — bukan implementasi terpisah. Ketika skripsi menyebut perbandingan terhadap "Falcon", baris `FN512` (FN-DSA-512, tanpa precomputation) adalah baris yang dimaksud: secara matematis identik dengan Falcon-512, hanya penamaan mengikuti standardisasi FIPS 206 [7].

HS256, RS256, ES256, dan EdDSA adalah baseline klasik yang ditambahkan agar perbandingan performa dan ketahanan adversarial mencakup algoritma tanda tangan pra-kuantum yang umum dipakai di JWT produksi saat ini. Setiap profil memakai kunci masing-masing (`HS256_secret.pem`, `RS256_{sk,pk}.pem`, `ES256_{sk,pk}.pem`, `EdDSA_{sk,pk}.pem`) yang dibuat oleh `cmd/keygen` bersamaan dengan kunci FN-DSA-512.

---

## 4. Fase 1 — Isolated Benchmark (Metrik Utama Skripsi)

### 4.1 Tujuan

Mengukur **latensi generasi token JWT dari payload benchmark** pada kondisi terkendali: 1 VU, tidak ada beban konkuren, tidak ada operasi basis data, dan tidak ada bcrypt. Angka dari fase ini adalah yang digunakan sebagai **hasil utama dalam skripsi**.

### 4.2 Endpoint

```
POST /api/benchmark/jwt-issuance
```

Endpoint ini menjalankan loop generasi token langsung di dalam proses gateway. Jalur ini memanggil `Sign(payload)` tanpa melalui basis data, bcrypt, auth-service, atau gRPC. Endpoint lama `/api/benchmark/sign` tetap tersedia sebagai alias kompatibilitas.

```
POST /api/benchmark/pure-signing
```

Endpoint ini menjalankan loop `SigningMethod.Sign()` terhadap pesan tetap. Jalur ini tidak membuat klaim JWT, tidak melakukan serialisasi JSON, tidak melakukan Base64URL, dan tidak melakukan assembly compact JWS. Metrik ini dipakai sebagai baseline pure FN-DSA/FN-DSA signing di workflow k6.

### 4.3 Konfigurasi

| Parameter | Nilai Default | Variabel Lingkungan | Keterangan |
|-----------|--------------|---------------------|------------|
| Jumlah iterasi | 100 | `ITERATIONS` | Jumlah generasi token yang diukur per profil |
| Iterasi warmup | 20 | `ISOLATED_WARMUP` | Iterasi yang dibuang sebelum pengukuran dimulai |
| VU (pengguna virtual) | 1 | — | Selalu 1, tidak dapat diubah |
| Timeout per skenario | ≥ 60 detik | — | Dihitung otomatis: `max(60, ceil(N×0.01)+30)` detik |

**Minimum 100 iterasi** ditetapkan sebagai standar minimum untuk validitas akademik — memberikan sampel statistik yang cukup untuk menghitung persentil P95 dan P99 yang representatif.

### 4.4 Mekanisme Warmup

Sebelum iterasi yang diukur dimulai, server menjalankan **20 iterasi warmup** yang hasilnya dibuang. Tujuannya:

1. **Pemanasan jalur kode** — branch predictor dan fungsi hot path mulai stabil
2. **Pemanasan cache CPU** — instruksi dan data kriptografi masuk ke cache L1/L2
3. **Alokasi memori awal** — Go runtime melakukan alokasi heap awal

Setelah warmup, **dua siklus GC paksa** (`runtime.GC()` dipanggil dua kali) dijalankan untuk memastikan pengukuran dimulai dari kondisi heap yang bersih.

### 4.5 Pengukuran Latensi di Sisi Server

Latensi diukur **di dalam proses server** (bukan dari sisi k6) menggunakan `time.Now()` tepat sebelum dan sesudah pemanggilan fungsi `Sign()`. Ini mengeliminasi latensi jaringan dan overhead HTTP dari pengukuran.

```
[timerStart] → Sign(payload) → [timerStop]
signMs = (timerStop - timerStart) dalam milidetik
```

Cakupan timer:

| Masuk timer | Tidak masuk timer |
|-------------|-------------------|
| Pembuatan klaim JWT dari payload benchmark | k6 round-trip |
| JSON marshal dan base64url header/payload | HTTP request parsing |
| Pembuatan signing string | DB query |
| Operasi tanda tangan algoritma | bcrypt |
| Penggabungan JWT compact (`header.payload.signature`) | auth-service/gRPC |

Dengan demikian, metrik ini mengukur **generasi JWT dari payload benchmark**, bukan hanya primitif kriptografi mentah.

Endpoint `/api/benchmark/pure-signing` memakai timer terpisah:

```
[timerStart] → SigningMethod.Sign(fixedMessage) → [timerStop]
```

Metrik ini mengukur primitive signing saja, bukan JWT issuance.

### 4.6 Deteksi Kontaminasi GC

Selama setiap iterasi, sistem memantau apakah *Garbage Collector* (GC) Go berjalan selama pemanggilan `Sign()` menggunakan `runtime.ReadMemStats().NumGC`. Iterasi yang terkena GC ditandai sebagai **GC-contaminated** karena GC menyebabkan jeda STW (*Stop-The-World*) yang dapat menggelembungkan latensi pengukuran.

Dua set statistik dilaporkan:

| Set | Keterangan |
|-----|------------|
| `pure_signing_ms` | Primitive FN-DSA/FN-DSA signing, semua iterasi |
| `pure_signing_gc_free_ms` | Primitive FN-DSA/FN-DSA signing, hanya iterasi bersih |
| `token_generation_ms` | Access-token generation, semua iterasi, termasuk yang terkena GC |
| `token_generation_gc_free_ms` | Access-token generation, hanya iterasi bersih (GC tidak terjadi) — **gunakan ini sebagai hasil primer skripsi** |
| `refresh_token_generation_ms` | Refresh-token generation, semua iterasi |
| `refresh_token_generation_gc_free_ms` | Refresh-token generation, hanya iterasi bersih |
| `total_ms` | Access-token generation + refresh-token generation |

### 4.7 Statistik yang Dilaporkan

Untuk setiap set waktu (dalam milidetik):

| Statistik | Simbol | Keterangan |
|-----------|--------|------------|
| Minimum | min | Latensi terkecil yang diamati |
| Rata-rata | avg | Mean aritmetika |
| Median | p50 | Persentil ke-50 |
| Persentil 95 | p95 | 95% permintaan selesai di bawah nilai ini |
| Persentil 99 | p99 | 99% permintaan selesai di bawah nilai ini |
| Maksimum | max | Latensi terbesar yang diamati |
| Standar Deviasi | stdev | Dispersi distribusi latensi |

---

## 5. Fase 2 — Stress Test (Metrik Pendukung)

### 5.1 Tujuan

Mengukur **degradasi performa dan throughput** ketika banyak pengguna mengakses sistem secara bersamaan (*concurrent*). Fase ini menggunakan endpoint benchmark dan endpoint autentikasi nyata dalam satu iterasi VU:

1. `/api/benchmark/token` — Generasi JWT dari payload benchmark (tanpa bcrypt/DB)
2. `/api/auth/signin` — Login lengkap (bcrypt verifikasi password + query DB + generasi JWT)
3. `/api/auth/refresh` — Rotasi access token dan refresh token

### 5.2 Konfigurasi

| Parameter | Nilai | Keterangan |
|-----------|-------|------------|
| Level konkurensi | 10, 30, 50 VU | Tiga skenario per profil |
| Executor k6 | `constant-vus` | Model beban **closed-loop**; VU berikutnya mulai iterasi baru setelah respons selesai dan think time lewat |
| Ramp-up | 0 detik | k6 langsung menjalankan jumlah VU target pada awal skenario |
| Steady state | 30 detik | Setiap level VU berjalan selama 30 detik |
| Ramp-down | 0 detik | Tidak ada penurunan bertahap; `gracefulStop` 15 detik hanya memberi waktu iterasi aktif selesai |
| Jeda antar skenario | 20 detik | Memberi waktu server pulih sebelum level VU berikutnya |
| Jeda antar fase | 30 detik | Jeda antara Fase 1 dan Fase 2 |
| Warmup per VU | 3 permintaan | Setiap VU mengirim 3 permintaan di iterasi pertama untuk memanaskan connection pool |
| Jeda per iterasi | 50 ms | `sleep(0.05)` setelah setiap iterasi |
| Jumlah request | Tercatat di `benchmark_sign_result.json` | `benchmark_token_success`, `benchmark_token_failed`, `login_total`, `refresh_success`, `refresh_failed` |
| Timeout request | Default k6 kecuali override per request | Registrasi setup memakai 10 detik; isolated/attack memakai `maxDuration` skenario |
| Connection reuse | Aktif | `noConnectionReuse=false`, `noVUConnectionReuse=false` |
| HTTP protocol | Negosiasi k6/server | HTTP/1.1 atau HTTP/2 bergantung endpoint dan server; lihat raw k6 output bila protocol tag tersedia |
| TLS | Bergantung URL | `https://` berarti TLS aktif; `http://` berarti tidak aktif |
| Error rate | `stress_error_rate`, `stress_refresh_error_rate` | Threshold overall `<1%`, per skenario benchmark-token `<5%`, refresh `<10%` |
| Database pool | Harus dicatat dari env server | Gunakan `DB_POOL_IDLE`/`DB_POOL_OPEN` saat run; k6 tidak bisa menebak nilai server |
| Rate limit | Harus dicatat dari konfigurasi deployment | Isi `RATE_LIMIT` saat run jika ada; jika tidak ada, tulis `not configured` |
| CPU quota | Harus dicatat dari container/VPS | Isi `CPU_QUOTA` saat run; jangan infer dari jumlah core host |
| Memory quota | Harus dicatat dari container/VPS | Isi `MEMORY_QUOTA` saat run; jangan pakai heap Go sebagai quota |

Catatan: jumlah VU saja tidak mendeskripsikan beban. Laporan stress harus memuat model beban, stage, durasi, think time, request count, error rate, transport, dan batas resource server.

### 5.3 Urutan Eksekusi per Iterasi VU

```
Iterasi VU ke-N:
├── [Hanya iterasi pertama] 3x warmup request ke /api/benchmark/token
├── POST /api/benchmark/token  → ukur: sign_actual, dirty, clean, network
├── POST /api/auth/signin       → ukur: login_dirty (terpisah, tidak campur dengan signing)
└── POST /api/auth/refresh      → ukur: refresh_dirty + refresh_token_generation_clean
```

Panggilan login dan refresh dieksekusi **di luar grup pengukuran benchmark token** agar tidak mengkontaminasi metrik `stress_token_generation_clean`.

### 5.4 Anggaran Latensi per Algoritma

Ambang batas (*threshold*) p95 yang ditetapkan untuk setiap profil:

| Algoritma | p95 Dirty (ms) | p95 Actual (ms) |
|-----------|---------------|-----------------|
| FN-DSA-Precomputed-512 | 5.000 | 500 |
| FN-DSA-512 | 10.000 | 1.000 |
| HS256 | 3.000 | 100 |
| RS256 | 3.000 | 200 |
| ES256 | 3.000 | 100 |
| EdDSA | 3.000 | 100 |

Pengujian dinyatakan **gagal** (exit code non-zero) apabila nilai p95 melampaui anggaran yang ditetapkan.

### 5.5 Metrik yang Dikumpulkan (Fase 2)

#### Metrik Generasi JWT Benchmark (`/api/benchmark/token`)

| Nama Metrik k6 | Sumber | Cakupan | Keterangan |
|----------------|--------|---------|------------|
| `stress_token_generation_clean` | Header `X-Token-Generation-Time-Ms` | `Sign(payload)` di server | Generasi JWT dari payload benchmark; tanpa DB, bcrypt, auth-service, dan round-trip k6 |
| `stress_sign_clean` | `timings.waiting` | Server wait/TTFB | Waktu tunggu sampai byte respons pertama; mencakup antrean handler dan proses server |
| `stress_sign_dirty` | `timings.duration` | Client round-trip | Total waktu dari k6 mengirim request sampai response selesai |
| `stress_sign_network` | `dirty - clean` | Estimasi network/client overhead | Selisih antara round-trip penuh dan TTFB |

#### Metrik Login Penuh (`/api/auth/signin`)

| Nama Metrik k6 | Sumber | Cakupan | Keterangan |
|----------------|--------|---------|------------|
| `stress_login_dirty` | `timings.duration` | Full login round-trip | bcrypt verify + DB lookup + generasi access/refresh JWT + HTTP round-trip |

#### Metrik Refresh (`/api/auth/refresh`)

| Nama Metrik k6 | Sumber | Cakupan | Keterangan |
|----------------|--------|---------|------------|
| `stress_refresh_token_generation_clean` | Header `X-Refresh-Token-Generation-Time-Ms` | Generasi token baru di server | Waktu server-side untuk generasi token saat refresh |
| `stress_refresh_dirty` | `timings.duration` | Full refresh round-trip | Verifikasi refresh token + rotasi token + HTTP round-trip |
| `stress_refresh_error_rate` | Rate | Kegagalan refresh | Proporsi refresh gagal per skenario |

#### Metrik Keberhasilan

| Nama Metrik k6 | Tipe | Keterangan |
|----------------|------|------------|
| `stress_req_success` | Counter | Jumlah permintaan berhasil (HTTP 200 + ada token) |
| `stress_req_failed` | Counter | Jumlah permintaan gagal |
| `stress_error_rate` | Rate | Proporsi permintaan gagal; gagal jika > 5% per skenario |

---

## 6. Fase 3 — Attack Block-Rate

### 6.1 Tujuan

Memverifikasi bahwa sistem **menolak token JWT yang telah dimanipulasi**. Ini menguji integritas verifikasi tanda tangan dari sisi server.

### 6.2 Mekanisme

Setiap iterasi melakukan empat langkah:

1. **Dapatkan token valid** — `POST /api/benchmark/token` → token JWT asli
2. **Manipulasi token** — header, payload, signature, atau bentuk compact JWS diubah sesuai vektor serangan
3. **Kirim token palsu** — `GET /api/profile` dengan header `Authorization: Bearer <token_palsu>`
4. **Catat hasil** — HTTP 401/403 = diblokir ✓, HTTP 200 = lolos ✗

### 6.3 Konfigurasi

| Parameter | Nilai Default | Variabel Lingkungan |
|-----------|--------------|---------------------|
| Jumlah iterasi | 25 | `ATTACK_ITERATIONS` |
| VU | 1 | — |
| Timeout | 120 detik | — |

### 6.4 Ambang Batas

```
attack_block_rate > 99%
```

Sistem harus memblokir setidaknya 99% dari token yang dimanipulasi. Kegagalan memblokir menunjukkan kelemahan kritis pada implementasi verifikasi tanda tangan.

### 6.5 Cakupan Vektor Keamanan

`backend/k6/adversarial_jwt.js` adalah pengujian black-box dari sisi HTTP. Vektor yang membutuhkan token bertanda tangan valid dengan klaim khusus diuji di unit test Go, karena k6 tidak memiliki private key dan tidak boleh membuat token valid arbitrer.

Setiap baris di bawah dipetakan ke bagian spesifik RFC 7519 [1] (JSON Web Token), RFC 7515 [8] (JSON Web Signature — mendefinisikan struktur compact serialization, header parameter `alg`, dan prosedur validasi tanda tangan yang dipakai JWT), dan/atau RFC 8725 [2] (JWT Best Current Practices) — bukan vektor yang dibuat ad hoc. RFC 7519 mendefinisikan *claims* JWT; JWT sendiri adalah JWS (atau JWE) menurut RFC 7515 dengan *claims set* JSON sebagai payload — sehingga vektor yang menyerang struktur token, header `alg`, atau proses validasi tanda tangan berpijak pada RFC 7515, bukan RFC 7519. Baris yang tidak berpijak pada RFC-RFC tersebut ditandai jujur dengan referensi lain (RFC 8259 [3] untuk ambiguitas JSON) atau ditandai sebagai *gap* yang belum ditutup oleh RFC manapun.

| Vektor | Status | Lokasi | Referensi RFC |
|--------|--------|--------|----------------|
| Signature tampering | Covered | k6 (#1) + `pkg/jwt` | RFC 7515 [8] §5.2 (validation MUST fail if signature invalid); RFC 8725 [2] §3.3 |
| Token forgery | Covered | k6 (#2) + `pkg/jwt` | RFC 7515 [8] §5.2; RFC 8725 [2] §3.1, §3.3 |
| Algorithm confusion | Covered | k6 (#3) + `pkg/jwt` | RFC 7515 [8] §4.1.1 "alg" Header Parameter; RFC 8725 [2] §3.1 |
| None algorithm | Covered | k6 (#4) + `pkg/jwt` | RFC 7519 [1] §6; RFC 7515 [8] §4.1.1, §5.2; RFC 8725 [2] §3.1, §3.2 |
| Payload manipulation tanpa re-sign | Covered | k6 (#5) + `pkg/jwt` | RFC 7515 [8] §5.2; RFC 8725 [2] §3.3, §3.10 |
| Expired token | Covered | k6 (#6) payload-tamper; signed case di `pkg/jwt` | RFC 7519 [1] §4.1.4 |
| Unsigned compact token / signature kosong | Covered | k6 (#7) + `pkg/jwt` | RFC 7515 [8] §7.1 (compact serialization), §5.2; RFC 7519 [1] §6; RFC 8725 [2] §3.1, §3.3 |
| Cross-algorithm injection | Covered | k6 (#8) + `pkg/jwt` | RFC 7515 [8] §4.1.1; RFC 8725 [2] §3.1 |
| RS256→HS256 key confusion (kunci publik dipakai sebagai HMAC secret) | Covered | k6 (#9) + `pkg/utils/jwtutils` (`TestAttack_RS256ToHS256KeyConfusion`) | RFC 7515 [8] §4.1.1; RFC 8725 [2] §3.1 (contoh literal di teks RFC) |
| Issuer tidak valid / missing issuer | Covered | `pkg/utils/jwtutils` | RFC 7519 [1] §4.1.1; RFC 8725 [2] §3.8 |
| Audience tidak valid / missing audience | Covered | `pkg/utils/jwtutils` menerbitkan `aud` (`JWT_AUDIENCE`) dan memvalidasinya; `TestJWTUtilsValidatesAudience` | RFC 7519 [1] §4.1.3; RFC 8725 [2] §3.9 |
| Header pembawa/rujukan kunci (`jku`/`jwk`/`x5u`/`x5c`/`x5t`) | Covered | `pkg/utils/jwtutils` menolak header pembawa kunci; `TestJWTUtilsRejectsUnsupportedJOSEHeaders` | RFC 7515 [8] §4.1.4–§4.1.8; RFC 8725 [2] §3.10 Do Not Trust Received Public Keys |
| Subject kosong/tidak valid | Covered | `pkg/utils/jwtutils` | RFC 7519 [1] §4.1.2 |
| `nbf` di masa depan | Covered | `pkg/utils/jwtutils` | RFC 7519 [1] §4.1.5 |
| `iat` tidak logis | Covered | `pkg/utils/jwtutils` | RFC 7519 [1] §4.1.6; RFC 8725 [2] §3.10 |
| Duplicate claim / duplicate header | Covered | `pkg/jwt` parser | RFC 8259 [3] §4 (bukan RFC 7519 [1]/RFC 7515 [8]/RFC 8725 [2] — lihat catatan di `parser_security_test.go`) |
| Invalid Base64URL / malformed JSON | Covered | `pkg/jwt` parser | RFC 7515 [8] §7.1 (compact serialization format); RFC 8259 [3] (JSON) |
| Oversized token | Covered | `pkg/utils/jwtutils` | RFC 8725 [2] §3.2 (implementation hardening; tidak ada batas ukuran eksplisit di RFC) |
| Unknown `kid` / `kid` path traversal | Covered | `pkg/utils/jwtutils`, `kid` ditolak karena key-id belum didukung | RFC 7515 [8] §4.1.4 "kid" Header Parameter; RFC 8725 [2] §3.10 Do Not Trust Received Claims |
| Token type confusion / altered `typ` | Covered | `pkg/utils/jwtutils`, middleware, auth-service refresh path | RFC 7515 [8] §4.1.9 "typ" Header Parameter; RFC 8725 [2] §3.11, §3.12 |
| Access token dipakai sebagai refresh token | Covered | Auth-service refresh path memerlukan `token_use=refresh` | RFC 8725 [2] §3.12 Mutually Exclusive Validation Rules |
| Refresh token dipakai sebagai access token | Covered | Gateway middleware memerlukan `token_use=access` | RFC 8725 [2] §3.12 |
| Replay refresh token / refresh token reuse | Gap | Butuh stateful refresh-token store atau JTI blacklist | RFC 7519 [1] §4.1.7 (gap belum ditutup; RFC 8725 [2] tidak punya bagian replay) |
| Revoked key / rotated key | Gap | Butuh key registry, `kid`, dan rotasi kunci operasional | Tidak dibahas eksplisit di RFC 7519 [1], RFC 7515 [8], dan RFC 8725 [2] (gap belum ditutup) |
| Algorithm case variation | Covered | `pkg/utils/jwtutils` | RFC 7515 [8] §4.1.1 (nilai `alg` case-sensitive); RFC 8725 [2] §3.1 |
| Invalid `crit` | Covered | `pkg/utils/jwtutils`, `crit` ditolak | RFC 7515 [8] §4.1.11 "crit" Header Parameter; RFC 8725 [2] §3.3 (unvalidated header extension = unvalidated cryptographic operation) |
| Signature valid tetapi konteks salah | Partially covered | `typ`, `token_use`, `sub=user_id`, issuer; audience/konteks resource belum ada | RFC 8725 [2] §3.9, §3.12 |

Istilah **Missing Signature Verification** tidak dipakai sebagai vektor input. Vektor input yang diuji adalah **unsigned compact token atau JWS dengan bagian signature kosong**. Missing signature verification adalah kelas kelemahan implementasi bila token tersebut diterima.

### 6.6 Vektor Adversarial terhadap Primitif Tanda Tangan FN-DSA (bukan JWT)

Tabel 6.5 di atas seluruhnya menguji lapisan JOSE/JWT — header `alg`, klaim, dan compact serialization — berpijak pada RFC 7519 [1] dan RFC 8725 [2]. RFC tersebut tidak menyatakan apa pun tentang apakah skema tanda tangan FN-DSA sendiri tahan forgery; itu properti primitif kriptografi, bukan format token yang membungkusnya. Pengujian yang hanya memalsukan header JWT membuktikan kebenaran kode parsing envelope — bukan klaim keamanan atas FN-DSA itu sendiri. Karena itu ada suite terpisah yang memanggil `fndsa.Sign`/`fndsa.Verify` langsung, melewati `pkg/jwt`, JSON, dan base64url sepenuhnya: `backend/pkg/fndsa/fndsa_adversarial_test.go`.

Referensi untuk suite ini bukan RFC 7519 [1] dan RFC 8725 [2] (di luar cakupan keduanya), melainkan:

- Fouque, Hoffstein, Kirchner, Lyubashevsky, Pornin, Prest, Ricosset, Seiler, Whyte, Zhang [4] — mendefinisikan algoritma Verify: signature `(s1, s2)` diterima hanya jika berhasil didekode DAN `||(s1, s2)|| ≤ β` (norm bound). Implementasi repo ini menegakkan pemeriksaan itu lewat `mqpoly_sqnorm_is_acceptable()` terhadap tabel `sqbeta[]` (`mq.go`, `vrfy.go`).
- Goldwasser, Micali, Rivest [5] — mendefinisikan EUF-CMA, tujuan keamanan formal yang harus dipenuhi skema tanda tangan digital manapun (termasuk FN-DSA), independen dari format transport/envelope apa pun.
- NIST FIPS 204 [6] — konstruksi context-string/Mu yang jadi rujukan gaya domain-separation FN-DSA.
- NIST FIPS 206 [7] (FN-DSA/Falcon) — standardisasi masih berjalan; per penulisan dokumen ini, Initial Public Draft belum dipublikasikan ke URL publik yang stabil (status update forum PQC NIST, akhir 2025: draft masih dalam proses clearance NIST/Departemen Perdagangan AS). Spesifikasi Falcon Round-3 [4] di atas adalah sumber otoritatif yang jadi target pengujian ini; begitu FIPS 206 [7] terbit, bagian algoritma Verify-nya harus dikutip juga.

Empat dari lima vektor dijalankan sebagai subtest berpasangan lewat helper `signerVariants()`: setiap vektor diuji sekali terhadap **Falcon** (`FN-DSA-512`, signer asli/dinamis — baseline) dan sekali terhadap **Falcon Precomputed** (`FN-DSA-Precomputed-512` — metode yang diusulkan), dengan kunci dan pesan yang identik, supaya hasil PROTECTED/VULNERABLE langsung bisa dibandingkan antar keduanya. Norm-bound rejection tidak dipasangkan karena pemeriksaannya ada di sisi `Verify()` (murni fungsi `mqpoly_sqnorm_is_acceptable`), identik untuk signature dari signer manapun — precomputation hanya mengubah persiapan trapdoor/basis saat signing, bukan kriteria penerimaan verifikasi.

| Vektor | Status | Dibandingkan: Falcon vs Precomputed | Referensi |
|--------|--------|--------------------------------------|-----------|
| Signature norm-bound rejection (forged over-norm signature) | Covered | Tidak — cek di sisi Verify(), identik untuk kedua signer | `TestAttack_SignatureNormBoundRejection` — Falcon spec [4], algoritma Verify (norm bound β) |
| Cross-key forgery | Covered | Ya — subtest `Falcon (FN-DSA-512 original/dynamic)` + `Falcon Precomputed (FN-DSA-Precomputed-512)` | `TestAttack_CrossKeyForgery` — EUF-CMA [5] |
| Domain-separation context confusion | Covered | Ya (idem) | `TestAttack_DomainContextConfusion` — context-string construction (gaya FIPS 204 [6] §5.4 Mu, diwariskan ke FN-DSA) |
| Pre-hash identifier confusion (raw vs pre-hashed) | Covered | Ya (idem) | `TestAttack_PreHashIdentifierConfusion` — Falcon spec [4] |
| Truncated/malformed signature encoding | Covered | Ya (idem) | `TestAttack_TruncatedSignatureRejected` — Falcon spec [4] (compact encoding) |
| Bit-flip signature / bit-flip message | Covered | Ya — `TestAttack_BitFlipTampering` (dua signer); `TestPrecomputedSignRejectsTampering` (`pkg/fndsa/sign_precomputed_test.go`) tetap ada sebagai pengujian precomputed-only tambahan | Falcon spec [4], algoritma Verify; EUF-CMA [5] |

---

## 7. Variabel Kontrol

Variabel kontrol adalah parameter yang dijaga konstan selama pengujian untuk memastikan perbandingan antar algoritma bersifat adil (*fair comparison*).

### 7.1 Variabel Tetap (Tidak Berubah Antar Algoritma)

| Variabel | Nilai | Justifikasi |
|----------|-------|-------------|
| Jumlah iterasi isolated | 100 | Sama untuk semua algoritma |
| Iterasi warmup | 20 | Menghilangkan bias cold-start yang sama |
| Payload benchmark | `userID`, `email`, `algorithm`, `token_use` | Struktur klaim sama; `jti`, `iat`, dan `exp` berubah per token |
| Akun pengguna | 1 akun benchmark dibuat di `setup()` | Mengeliminasi variabilitas dari pembuatan akun berbeda |
| Infrastruktur server | Proses gateway identik | Dikompilasi dari kode base yang sama |
| Metode pengukuran | `time.Now()` Go di dalam proses | Konsisten untuk semua algoritma |
| Pembersihan GC | 2x `runtime.GC()` setelah warmup | Kondisi heap awal yang sama |

### 7.2 Variabel Bebas (Berbeda Antar Algoritma)

| Variabel | Keterangan |
|----------|------------|
| Profil signer | FN-DSA-Precomputed-512, FN-DSA-512, HS256, RS256, ES256, EdDSA |
| Kategori algoritma | PQC (FN-DSA) vs klasik (HS256/RS256/ES256/EdDSA) |
| JWS `alg` | `FN-DSA-512` untuk kedua profil FN-DSA; sama dengan nama profil untuk profil klasik |
| State signer | Original FN-DSA signer vs precomputed LDL tree vs signer klasik stateless |
| Kompleksitas penandatanganan runtime | Berbeda karena precomputation (FN-DSA) dan karena keluarga algoritma (lattice vs RSA vs ECDSA vs EdDSA vs HMAC) |
| Ukuran kunci dan tanda tangan | Berbeda per keluarga algoritma; dicatat dari `token` size di hasil benchmark |

### 7.3 Variabel Terikat (Diukur)

| Variabel | Satuan | Fase |
|----------|--------|------|
| Latensi generasi JWT dari payload benchmark (avg, p95, p99, stdev) | milidetik | 1 |
| Jumlah iterasi terkontaminasi GC | integer | 1 |
| Latensi generasi JWT di bawah beban (avg, p95) | milidetik | 2 |
| Latensi login penuh di bawah beban (avg, p95) | milidetik | 2 |
| Throughput benchmark-token sukses | req/detik | 2 |
| Tingkat kesalahan | persen | 2 |
| Tingkat pemblokiran token palsu | persen | 3 |
| CPU time per token | milidetik | 1 |
| Memori persisten expanded key | byte | Go benchmark |
| Startup cost precomputed signer | ns/op, B/op, allocs/op | Go benchmark |

---

## 8. Taksonomi Latensi

Pengujian ini membedakan beberapa lapisan latensi dengan istilah spesifik:

```
┌─────────────────────────────────────────────────────────────┐
│                    dirty (k6 timings.duration)               │
│  ┌──────────────────────────────┐  ┌────────────────────┐   │
│  │  clean (timings.waiting)     │  │  network overhead  │   │
│  │  ┌───────────────────────┐  │  └────────────────────┘   │
│  │  │ token_generation_clean │  │                           │
│  │  │ (X-Token-Generation-  │  │                           │
│  │  │  Time-Ms header)      │  │                           │
│  │  └───────────────────────┘  │                           │
│  └──────────────────────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

| Istilah | Sumber | Mencakup | Tidak mencakup | Pemakaian |
|---------|--------|----------|----------------|----------|
| `pure_signing_gc_free_ms` | `/api/benchmark/pure-signing` | Primitive FN-DSA/FN-DSA signing atas pesan tetap | JWT serialization, Base64URL, compact assembly, DB, bcrypt, HTTP round-trip | Baseline pure signing |
| `token_generation_clean` | Header HTTP dari server | Generasi JWT dari payload benchmark: klaim, signing string, signature, compact token | DB, bcrypt, auth-service, HTTP round-trip | Metrik utama skripsi saat isolated; metrik pendukung saat stress |
| `clean` | `timings.waiting` k6 | Waktu tunggu sampai TTFB | Download body penuh | Diagnosa antrean/server |
| `network` | `dirty - clean` | Estimasi overhead client/network | Server-side token timer | Diagnosa transport |
| `dirty` | `timings.duration` k6 | Total round-trip dari k6 | Pemisahan komponen internal | E2E endpoint |
| `login_dirty` | `timings.duration` k6 | Login penuh: bcrypt + DB + JWT + HTTP round-trip | Isolasi signing | Performa autentikasi nyata |
| `refresh_dirty` | `timings.duration` k6 | Refresh penuh: verifikasi refresh token + rotasi JWT + HTTP round-trip | Isolasi signing | Performa refresh nyata |

---

## 9. Urutan Waktu Eksekusi Pengujian Penuh

```
t=0s       Fase 1 — Isolated FN-DSA-Precomputed-512 (≤ 60 detik)
t=65s      Fase 1 — Isolated FN-DSA-512             (≤ 60 detik)
t=130s     [Jeda 30 detik antar fase]
t=160s     Fase 2 — Stress FNP512 @ 10 VU (30 detik)
t=210s     Fase 2 — Stress FNP512 @ 30 VU (30 detik)
t=260s     Fase 2 — Stress FNP512 @ 50 VU (30 detik)
...        [ulangi untuk FN512]
t=N        Fase 3 — Attack per profil (25 iterasi masing-masing)
```

Jeda antar skenario stress (20 detik) dan antar fase (30 detik) memberi waktu server untuk memulihkan antrian koneksi dan melakukan GC sebelum skenario berikutnya dimulai.

---

## 10. Keluaran Pengujian

k6 menghasilkan tiga berkas keluaran di akhir pengujian:

| Berkas | Isi |
|--------|-----|
| `stdout` | Tabel ringkasan terformat untuk dibaca manusia |
| `benchmark_sign_result.json` | Hasil akademik terstruktur per profil (isolated + stress + attack) |
| `benchmark_sign_raw.json` | Seluruh metrik mentah k6 (untuk analisis lanjutan) |

### 10.1 Struktur `benchmark_sign_result.json`

```json
{
  "algorithms": [
    {
      "algorithm": "FN-DSA-Precomputed-512",
      "jws_alg": "FN-DSA-512",
      "isolated": {
        "iterations": 100,
        "gc_contaminated_count": 3,
        "token_generation_ms": { "avg": ..., "p95": ..., "p99": ..., "sd": ... },
        "token_generation_gc_free_ms": { "avg": ..., "p95": ..., "p99": ..., "sd": ... }
      },
      "stress": [
        {
          "vus": 10,
          "token_generation_ms": { "avg": ..., "p95": ... },
          "refresh_token_generation_ms": { "avg": ..., "p95": ... },
          "refresh_ms": { "avg": ..., "p95": ... },
          "e2e_ms": { "avg": ..., "p95": ... },
          "login_ms": { "avg": ..., "p95": ... },
          "throughput_ok_per_s": ...,
          "error_rate_pct": ...
        }
      ],
      "attack": {
        "tampered_token_block_rate_pct": 100.0
      }
    }
  ]
}
```

---

## 11. Cara Membaca Hasil untuk Skripsi

### 11.1 Metrik Primer (Fase 1)

Gunakan `isolated.token_generation_gc_free_ms` sebagai **angka utama yang dikutip dalam skripsi**:

- **avg** — latensi rata-rata generasi access JWT dari payload benchmark (milidetik)
- **p95** — 95% token selesai dalam waktu ini; metrik yang umum digunakan dalam SLA
- **stdev** — konsistensi latensi; stdev kecil berarti algoritma berperilaku prediktabel

Kalimat aman: metrik ini mengukur generasi JWT server-side dari payload benchmark, bukan round-trip k6 dan bukan operasi kriptografi mentah saja.

### 11.2 Metrik Pendukung (Fase 2)

- **token_generation_ms avg @ 10/30/50 VU** — latensi generasi JWT dari payload benchmark di bawah beban
- **refresh_token_generation_ms avg @ 10/30/50 VU** — latensi generasi token baru pada endpoint refresh
- **login_ms avg @ 10/30/50 VU** — waktu respons login pengguna nyata (termasuk bcrypt + DB + JWT)
- **refresh_ms avg @ 10/30/50 VU** — waktu respons refresh penuh
- **throughput_ok_per_s** — jumlah `/api/benchmark/token` sukses per detik

### 11.3 Validasi Keamanan (Fase 3)

- **tampered_token_block_rate_pct = 100%** — seluruh kasus negatif yang diuji ditolak oleh gateway. Angka ini bukan bukti keamanan sistem secara menyeluruh.

### 11.4 Perbandingan FN-DSA-Precomputed vs FN-DSA-512

FN-DSA-Precomputed-512 menggunakan pohon LDL yang dihitung satu kali saat inisialisasi dan disimpan di memori. Kedua profil FN-DSA tetap menghasilkan JWT dengan JWS `alg` `FN-DSA-512`; perbedaan precomputed hanya tercatat pada konfigurasi signer, metadata benchmark, dan hasil eksperimen. Perbandingan `avg_ms` keduanya pada Fase 1 menunjukkan **tradeoff waktu-memori** (*time-memory tradeoff*): penggunaan memori persisten lebih tinggi pada Precomputed sebagai imbalan latensi penandatanganan runtime yang lebih rendah.

### 11.5 Studi Ablasi FN-DSA FN-DSA Precomputed

Studi ablasi berada di `backend/pkg/fndsa/precompute_ablation_test.go` dan memakai seeded signing path, sehingga biaya RNG tidak masuk pengukuran. Varian bergerak dari original menuju komponen detached:

| Varian | Komponen detached |
| ------ | ----------------- |
| A0 | Original signer: decode private key, hitung `G`/hash, FFT basis, Gram matrix, dan LDL tree saat signing |
| A1 | A0 + private-key decode, rekalkulasi `G`, dan verifying-key hash detached |
| A2 | A1 + FFT basis `b00`, `b01`, `b10`, `b11` detached |
| A3 | A2 + Gram matrix detached |
| A4 | A3 + LDL tree detached |
| A5 | A1-A4 digabung lewat runtime production `PrecomputedSigner` |

Persentase signifikansi di sini berarti reduksi runtime relatif dari A0, bukan p-value dan bukan effect size:

```text
(A0 ns/op - Ai ns/op) / A0 ns/op * 100
```

Jalankan dari root repositori:

```bash
python3 scripts/fndsa_precompute_ablation.py
python3 scripts/fndsa_precompute_ablation.py --format csv
```

Benchmark Go langsung:

```bash
cd backend/pkg
go test ./fndsa -run '^$' -bench '^BenchmarkFN-DSAPrecomputeAblation512/' -benchmem
```

---

## 12. Correctness Test FN-DSA/FN-DSA

Correctness tidak dinilai dari latensi. Jalankan test terpisah untuk memastikan dynamic signer, precomputed signer, dan verifier tetap benar.

| Properti | Status | Lokasi |
|----------|--------|--------|
| Setiap signature diverifikasi | Covered | `backend/pkg/jwt/fndsa_correctness_test.go`, `backend/pkg/fndsa/sign_precomputed_test.go` |
| Bit-flip signature gagal | Covered | `backend/pkg/jwt/fndsa_correctness_test.go`, `backend/pkg/fndsa/sign_precomputed_test.go` |
| Bit-flip message gagal | Covered | `backend/pkg/jwt/fndsa_correctness_test.go`, `backend/pkg/fndsa/sign_precomputed_test.go` |
| Dynamic verifier dan precomputed verifier interoperabel | Covered | `backend/pkg/jwt/fndsa_precomputed_test.go`, `backend/pkg/jwt/fndsa_correctness_test.go` |
| Signature untuk pesan sama tetap valid | Covered | `backend/pkg/jwt/fndsa_correctness_test.go` |
| Known-answer test | Covered | `backend/pkg/fndsa/fndsa_test.go` dynamic + precomputed KAT |
| Property test | Covered | `backend/pkg/jwt/fndsa_correctness_test.go` |
| Concurrent verification | Covered | `backend/pkg/jwt/fndsa_correctness_test.go` |
| Concurrent signing + race detector | Wajib dijalankan | `go test -race ./fndsa ./jwt ./utils/jwtutils` |

---

## 13. Checklist Perbaikan Ilmiah

### 13.1 Prioritas 0 — Kritis

| Item | Status | Tindakan |
|------|--------|----------|
| Ubah klaim kebaruan | Wajib redaksi | Klaim sebagai evaluasi implementasi dan benchmark, bukan penemuan algoritma baru |
| Perbaiki status FN-DSA/FN-DSA | Wajib redaksi | Tulis FN-DSA/FN-DSA sebagai profil eksperimen; ikuti status standar resmi terbaru saat publikasi |
| Jangan gunakan `FN-DSA-Precomputed-512` sebagai nilai `alg` | Covered | Nilai JWS `alg` tetap `FN-DSA-512`; precomputed hanya profil signer internal |
| Jelaskan library, commit, modifikasi kode | Wajib catat saat run | Sertakan `git rev-parse HEAD`, `go list -m all`, dan ringkasan patch lokal |
| Redaksi token, kredensial, IP, data server | Wajib sebelum publikasi | Jangan commit raw token, password, IP privat, host VPS sensitif |
| Ukur persistent memory expanded key | Covered | `PrecomputedSigner.PersistentBytes()` dan benchmark precompute |
| Ukur startup cost | Covered | `BenchmarkBuildPrecomputedSigner512` |
| Uji race condition dan concurrent signing | Sebagian covered | Test concurrency ada; jalankan `go test -race` untuk klaim race-free |
| Ulangi stress test 30 VU | Wajib rerun | Minimal beberapa independent run; jangan pakai satu run sebagai kesimpulan final |
| Pisahkan k6 dari server | Wajib deployment | k6 harus berjalan di mesin klien terpisah atau container terisolasi dari service benchmark |

### 13.2 Prioritas 1 — Penguatan Ilmiah

| Item | Status | Tindakan |
|------|--------|----------|
| Pure signing benchmark | Covered | Gunakan `isolated.pure_signing_gc_free_ms` dari k6 atau `pkg/fndsa`; jangan samakan dengan JWT issuance |
| Break-even analysis | Perlu analisis | Bandingkan startup/memory precompute vs penghematan runtime per token |
| CI dan effect size | Ada script statistik | Jalankan `benchmark_stat_tests.py` dan laporkan CI/effect size |
| Beberapa independent run | Wajib rerun | Simpan run ID, waktu, host, commit, dan env |
| Acak urutan eksperimen | Perlu mode tambahan | Hindari bias urutan algoritma/cache/server |
| p99 dan error rate | Covered | `benchmark_sign_result.json` menyimpan p99 dan error rate |
| Threat model | Perlu dokumen | Definisikan attacker, aset, batas trust, dan asumsi key management |
| Pengujian klaim JWT | Sebagian covered | Lihat bagian 6.5; audience/replay/key rotation masih gap |
| Validity threats | Perlu bab pembahasan | Bahas single host, cold/warm cache, GC, network, dan external validity |
| Token size aktual | Covered | k6 summary melaporkan ukuran header/body/token; kutip dari hasil terbaru |

---

## 14. Perintah Eksekusi

```bash
cd backend

# Validasi otomatis sebelum benchmark:
make falcon-check

# Multi-gateway lokal, semua fase:
make bench-sign
make bench-down

# Isolated saja (untuk pengambilan data skripsi):
make client-k6-isolated BASE_URL=http://localhost:8080

# Dengan lebih banyak iterasi (rekomendasi: 500 untuk data final):
k6 run -e BASE_URL=http://localhost:8080 -e ISOLATED_ONLY=true -e ITERATIONS=500 k6/benchmark_sign.js
```

---

## 15. Referensi

Format sitasi: IEEE. Nomor `[n]` di seluruh dokumen ini merujuk ke daftar berikut. Diverifikasi terhadap sumber resmi (RFC Editor, SIAM, NIST, falcon-sign.info) — lihat catatan status pada [7] untuk satu referensi yang belum berupa publikasi final.

[1] M. Jones, J. Bradley, and N. Sakimura, "JSON Web Token (JWT)," IETF RFC 7519, May 2015. doi: 10.17487/RFC7519. [Online]. Available: https://www.rfc-editor.org/rfc/rfc7519

[2] Y. Sheffer, D. Hardt, and M. Jones, "JSON Web Token Best Current Practices," IETF RFC 8725, BCP 225, Feb. 2020. doi: 10.17487/RFC8725. [Online]. Available: https://www.rfc-editor.org/rfc/rfc8725

[3] T. Bray, Ed., "The JavaScript Object Notation (JSON) Data Interchange Format," IETF RFC 8259, Dec. 2017. doi: 10.17487/RFC8259. [Online]. Available: https://www.rfc-editor.org/rfc/rfc8259

[4] P.-A. Fouque, J. Hoffstein, P. Kirchner, V. Lyubashevsky, T. Pornin, T. Prest, T. Ricosset, G. Seiler, W. Whyte, and Z. Zhang, "Falcon: Fast-Fourier Lattice-based Compact Signatures over NTRU," NIST Post-Quantum Cryptography Standardization Project, Round 3 submission, specification v1.2, Oct. 1, 2020. [Online]. Available: https://falcon-sign.info/falcon.pdf

[5] S. Goldwasser, S. Micali, and R. L. Rivest, "A digital signature scheme secure against adaptive chosen-message attacks," SIAM J. Comput., vol. 17, no. 2, pp. 281–308, Apr. 1988. doi: 10.1137/0217017.

[6] National Institute of Standards and Technology, "Module-Lattice-Based Digital Signature Standard," NIST, Gaithersburg, MD, USA, FIPS PUB 204, Aug. 13, 2024. doi: 10.6028/NIST.FIPS.204.

[7] National Institute of Standards and Technology, "FN-DSA (FIPS 206)," NIST, Gaithersburg, MD, USA — standardization in progress; as of this writing (per NIST PQC Forum status updates, late 2025) the Initial Public Draft has not yet been published to a stable public URL and remains in NIST/Department of Commerce internal clearance. Cited here for the FN-DSA name/status only; [4] is the normative source for the algorithm this document's tests target.

[8] M. Jones, J. Bradley, and N. Sakimura, "JSON Web Signature (JWS)," IETF RFC 7515, May 2015. doi: 10.17487/RFC7515. [Online]. Available: https://www.rfc-editor.org/rfc/rfc7515

---

*Dokumen ini dibuat berdasarkan kode sumber `backend/k6/benchmark_sign.js` dan `backend/gateway/internal/delivery/http/handler/benchmark_handler.go`.*
