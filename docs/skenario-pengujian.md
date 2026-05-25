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
| 1 | Isolated Benchmark | Mengukur latensi tanda tangan murni tanpa gangguan (*noise*) eksternal |
| 2 | Stress Test | Mengukur degradasi performa di bawah beban konkuren |
| 3 | Attack Block-Rate | Memverifikasi integritas token — sistem harus menolak token yang dimanipulasi |

---

## 2. Arsitektur Sistem Benchmark

```
┌─────────────┐         HTTP          ┌──────────────────────────────┐
│   k6 Client │ ─────────────────────▶│ Gateway Service              │
│  (1 mesin)  │                       │  /api/benchmark/sign  (Ph.1) │
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
| **Multi Gateway** | `BENCH_HOST=localhost` | Satu gateway per algoritma, port berbeda (5001–5005) |

Pada mode multi-gateway, setiap algoritma mendapatkan proses gateway terpisah sehingga tidak ada kontestasi sumber daya antar algoritma selama pengujian.

---

## 3. Algoritma yang Diuji

| ID Internal | Nama Algoritma | Kategori | Port (Multi-GW) |
|-------------|---------------|----------|-----------------|
| `FNP512` | Falcon-Precomputed-512 | PQC | 5001 |
| `FN512` | Falcon-512 | PQC | 5002 |
| `MLDSA44` | ML-DSA-44 | PQC | 5003 |
| `SLHDSA128f` | SLH-DSA-SHA2-128f | PQC | 5004 |
| `SLHDSA128s` | SLH-DSA-SHA2-128s | PQC | 5005 |

Semua algoritma merupakan algoritma kriptografi pasca-kuantum (*Post-Quantum Cryptography*/PQC) yang telah distandarkan atau dicalonkan oleh NIST. Falcon-Precomputed-512 merupakan varian Falcon-512 yang menggunakan pohon LDL yang telah dihitung sebelumnya (*precomputed*) untuk mempercepat proses penandatanganan.

---

## 4. Fase 1 — Isolated Benchmark (Metrik Utama Skripsi)

### 4.1 Tujuan

Mengukur **latensi generasi token JWT murni** pada kondisi terkendali: 1 VU, tidak ada beban konkuren, tidak ada operasi basis data, dan tidak ada bcrypt. Angka dari fase ini adalah yang digunakan sebagai **hasil utama dalam skripsi**.

### 4.2 Endpoint

```
POST /api/benchmark/sign
```

Endpoint ini menjalankan loop penandatanganan langsung di dalam proses gateway, memanggil fungsi kriptografi secara langsung tanpa melalui lapisan basis data atau layanan autentikasi.

### 4.3 Konfigurasi

| Parameter | Nilai Default | Variabel Lingkungan | Keterangan |
|-----------|--------------|---------------------|------------|
| Jumlah iterasi | 100 | `ITERATIONS` | Jumlah penandatanganan yang diukur per algoritma |
| Iterasi warmup | 20 | `ISOLATED_WARMUP` | Iterasi yang dibuang sebelum pengukuran dimulai |
| VU (pengguna virtual) | 1 | — | Selalu 1, tidak dapat diubah |
| Timeout per skenario | ≥ 60 detik | — | Dihitung otomatis: `max(60, ceil(N×0.01)+30)` detik |

**Minimum 100 iterasi** ditetapkan sebagai standar minimum untuk validitas akademik — memberikan sampel statistik yang cukup untuk menghitung persentil P95 dan P99 yang representatif.

### 4.4 Mekanisme Warmup

Sebelum iterasi yang diukur dimulai, server menjalankan **20 iterasi warmup** yang hasilnya dibuang. Tujuannya:

1. **Pemanasan JIT kompiler** — Go mengoptimalkan kode panas setelah beberapa eksekusi
2. **Pemanasan cache CPU** — instruksi dan data kriptografi masuk ke cache L1/L2
3. **Alokasi memori awal** — Go runtime melakukan alokasi heap awal

Setelah warmup, **dua siklus GC paksa** (`runtime.GC()` dipanggil dua kali) dijalankan untuk memastikan pengukuran dimulai dari kondisi heap yang bersih.

### 4.5 Pengukuran Latensi di Sisi Server

Latensi diukur **di dalam proses server** (bukan dari sisi k6) menggunakan `time.Now()` tepat sebelum dan sesudah pemanggilan fungsi `Sign()`. Ini mengeliminasi latensi jaringan dan overhead HTTP dari pengukuran.

```
[timerStart] → Sign(payload) → [timerStop]
signMs = (timerStop - timerStart) dalam milidetik
```

### 4.6 Deteksi Kontaminasi GC

Selama setiap iterasi, sistem memantau apakah *Garbage Collector* (GC) Go berjalan selama pemanggilan `Sign()` menggunakan `runtime.ReadMemStats().NumGC`. Iterasi yang terkena GC ditandai sebagai **GC-contaminated** karena GC menyebabkan jeda STW (*Stop-The-World*) yang dapat menggelembungkan latensi pengukuran.

Dua set statistik dilaporkan:

| Set | Keterangan |
|-----|------------|
| `token_generation_ms` | Semua iterasi, termasuk yang terkena GC |
| `token_generation_gc_free_ms` | Hanya iterasi bersih (GC tidak terjadi) — **gunakan ini sebagai hasil primer skripsi** |

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

Mengukur **degradasi performa dan throughput** ketika banyak pengguna mengakses sistem secara bersamaan (*concurrent*). Fase ini menggunakan dua endpoint berbeda dalam satu iterasi VU:

1. `/api/benchmark/token` — Tanda tangan JWT murni (tanpa bcrypt/DB)
2. `/api/auth/signin` — Login lengkap (bcrypt verifikasi password + query DB + tanda tangan JWT)

### 5.2 Konfigurasi

| Parameter | Nilai | Keterangan |
|-----------|-------|------------|
| Level konkurensi | 10, 30, 50 VU | Tiga skenario per algoritma |
| Durasi per skenario | 30 detik | Setiap level VU berjalan selama 30 detik |
| Jeda antar skenario | 20 detik | Memberi waktu server pulih sebelum level VU berikutnya |
| Jeda antar fase | 30 detik | Jeda antara Fase 1 dan Fase 2 |
| Warmup per VU | 3 permintaan | Setiap VU mengirim 3 permintaan di iterasi pertama untuk memanaskan connection pool |
| Jeda per iterasi | 50 ms | `sleep(0.05)` setelah setiap iterasi |

### 5.3 Urutan Eksekusi per Iterasi VU

```
Iterasi VU ke-N:
├── [Hanya iterasi pertama] 3x warmup request ke /api/benchmark/token
├── POST /api/benchmark/token  → ukur: sign_actual, dirty, clean, network
└── POST /api/auth/signin       → ukur: login_dirty (terpisah, tidak campur dengan signing)
```

Panggilan login dieksekusi **di luar grup pengukuran signing** agar tidak mengkontaminasi metrik latensi penandatanganan.

### 5.4 Anggaran Latensi per Algoritma

Ambang batas (*threshold*) p95 yang ditetapkan untuk setiap algoritma:

| Algoritma | p95 Dirty (ms) | p95 Actual (ms) |
|-----------|---------------|-----------------|
| Falcon-Precomputed-512 | 5.000 | 500 |
| Falcon-512 | 10.000 | 1.000 |
| ML-DSA-44 | 10.000 | 500 |
| SLH-DSA-SHA2-128f | 90.000 | 30.000 |
| SLH-DSA-SHA2-128s | 300.000 | 120.000 |

Pengujian dinyatakan **gagal** (exit code non-zero) apabila nilai p95 melampaui anggaran yang ditetapkan.

### 5.5 Metrik yang Dikumpulkan (Fase 2)

#### Metrik Tanda Tangan (`/api/benchmark/token`)

| Nama Metrik | Sumber | Keterangan |
|-------------|--------|------------|
| `stress_token_generation_clean` | Header `X-Token-Generation-Time-Ms` | Latensi penandatanganan murni di sisi server (ms) |
| `stress_sign_dirty` | `timings.duration` | Waktu total round-trip k6 (ms) |
| `stress_sign_clean` | `timings.waiting` | Waktu menunggu respons server / TTFB (ms) |
| `stress_sign_network` | dirty − clean | Estimasi overhead jaringan (ms) |

#### Metrik Login Penuh (`/api/auth/signin`)

| Nama Metrik | Sumber | Keterangan |
|-------------|--------|------------|
| `stress_login_dirty` | `timings.duration` | Waktu total round-trip login lengkap: bcrypt + DB + JWT (ms) |

#### Metrik Keberhasilan

| Nama Metrik | Tipe | Keterangan |
|-------------|------|------------|
| `stress_req_success` | Counter | Jumlah permintaan berhasil (HTTP 200 + ada token) |
| `stress_req_failed` | Counter | Jumlah permintaan gagal |
| `stress_error_rate` | Rate | Proporsi permintaan gagal; gagal jika > 5% per skenario |

---

## 6. Fase 3 — Attack Block-Rate

### 6.1 Tujuan

Memverifikasi bahwa sistem **menolak token JWT yang telah dimanipulasi**. Ini menguji integritas verifikasi tanda tangan dari sisi server.

### 6.2 Mekanisme

Setiap iterasi melakukan dua langkah:

1. **Dapatkan token valid** — `POST /api/benchmark/token` → token JWT asli
2. **Manipulasi token** — Satu karakter di segmen tanda tangan (bagian ketiga JWT setelah titik kedua) diganti dengan karakter lain
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

---

## 7. Variabel Kontrol

Variabel kontrol adalah parameter yang dijaga konstan selama pengujian untuk memastikan perbandingan antar algoritma bersifat adil (*fair comparison*).

### 7.1 Variabel Tetap (Tidak Berubah Antar Algoritma)

| Variabel | Nilai | Justifikasi |
|----------|-------|-------------|
| Jumlah iterasi isolated | 100 | Sama untuk semua algoritma |
| Iterasi warmup | 20 | Menghilangkan bias cold-start yang sama |
| Payload JWT | `{userID, email, algorithm}` | Klaim token identik |
| Akun pengguna | 1 akun benchmark dibuat di `setup()` | Mengeliminasi variabilitas dari pembuatan akun berbeda |
| Infrastruktur server | Proses gateway identik | Dikompilasi dari kode base yang sama |
| Metode pengukuran | `time.Now()` Go di dalam proses | Konsisten untuk semua algoritma |
| Pembersihan GC | 2x `runtime.GC()` setelah warmup | Kondisi heap awal yang sama |

### 7.2 Variabel Bebas (Berbeda Antar Algoritma)

| Variabel | Keterangan |
|----------|------------|
| Algoritma tanda tangan | Falcon-Precomputed-512, Falcon-512, ML-DSA-44, SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s |
| Ukuran kunci privat | Berbeda per algoritma |
| Kompleksitas komputasi penandatanganan | Karakteristik matematis algoritma |

### 7.3 Variabel Terikat (Diukur)

| Variabel | Satuan | Fase |
|----------|--------|------|
| Latensi generasi token (avg, p95, p99, stdev) | milidetik | 1 |
| Jumlah iterasi terkontaminasi GC | integer | 1 |
| Latensi penandatanganan di bawah beban (avg, p95) | milidetik | 2 |
| Latensi login penuh di bawah beban (avg, p95) | milidetik | 2 |
| Throughput autentikasi | req/detik | 2 |
| Tingkat kesalahan | persen | 2 |
| Tingkat pemblokiran token palsu | persen | 3 |

---

## 8. Taksonomi Latensi

Pengujian ini membedakan beberapa lapisan latensi dengan istilah spesifik:

```
┌─────────────────────────────────────────────────────────────┐
│                    dirty (k6 timings.duration)               │
│  ┌──────────────────────────────┐  ┌────────────────────┐   │
│  │  clean (timings.waiting)     │  │ network (dirt-clean)│   │
│  │  ┌───────────────────────┐  │  └────────────────────┘   │
│  │  │ token_generation_clean │  │                           │
│  │  │ (X-Token-Generation-  │  │                           │
│  │  │  Time-Ms header)      │  │                           │
│  │  └───────────────────────┘  │                           │
│  └──────────────────────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

| Istilah | Sumber | Mencakup |
|---------|--------|----------|
| `token_generation_clean` | Header HTTP dari server | Hanya tanda tangan kriptografi — **metrik utama skripsi** |
| `clean` | `timings.waiting` k6 | Server processing + jaringan satu arah (TTFB) |
| `network` | dirty − clean | Estimasi latensi jaringan total |
| `dirty` | `timings.duration` k6 | Total round-trip dari k6 termasuk koneksi TCP |
| `login_dirty` | `timings.duration` k6 | Total round-trip login penuh (bcrypt + DB + sign) |

---

## 9. Urutan Waktu Eksekusi Pengujian Penuh

```
t=0s       Fase 1 — Isolated Falcon-Precomputed-512 (≤ 60 detik)
t=65s      Fase 1 — Isolated Falcon-512             (≤ 60 detik)
t=130s     Fase 1 — Isolated ML-DSA-44              (≤ 60 detik)
t=195s     Fase 1 — Isolated SLH-DSA-SHA2-128f      (≤ 60 detik)
t=260s     Fase 1 — Isolated SLH-DSA-SHA2-128s      (≤ 60 detik)
t=325s     [Jeda 30 detik antar fase]
t=355s     Fase 2 — Stress FNP512 @ 10 VU (30 detik)
t=405s     Fase 2 — Stress FNP512 @ 30 VU (30 detik)
t=455s     Fase 2 — Stress FNP512 @ 50 VU (30 detik)
...        [ulangi untuk setiap algoritma]
t=N        Fase 3 — Attack per algoritma (25 iterasi masing-masing)
```

Jeda antar skenario stress (20 detik) dan antar fase (30 detik) memberi waktu server untuk memulihkan antrian koneksi dan melakukan GC sebelum skenario berikutnya dimulai.

---

## 10. Keluaran Pengujian

k6 menghasilkan tiga berkas keluaran di akhir pengujian:

| Berkas | Isi |
|--------|-----|
| `stdout` | Tabel ringkasan terformat untuk dibaca manusia |
| `benchmark_sign_result.json` | Hasil akademik terstruktur per algoritma (isolated + stress + attack) |
| `benchmark_sign_raw.json` | Seluruh metrik mentah k6 (untuk analisis lanjutan) |

### 10.1 Struktur `benchmark_sign_result.json`

```json
{
  "algorithms": [
    {
      "algorithm": "Falcon-Precomputed-512",
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

Gunakan `token_generation_gc_free_ms` dari isolated benchmark sebagai **angka utama yang dikutip dalam skripsi**:

- **avg** — latensi rata-rata generasi token (milidetik)
- **p95** — 95% token selesai dalam waktu ini; metrik yang umum digunakan dalam SLA
- **stdev** — konsistensi latensi; stdev kecil berarti algoritma berperilaku prediktabel

### 11.2 Metrik Pendukung (Fase 2)

- **token_generation_ms avg @ 10/30/50 VU** — latensi signing murni di bawah beban
- **login_ms avg @ 10/30/50 VU** — waktu respon login pengguna nyata (termasuk bcrypt + DB)
- **throughput_ok_per_s** — berapa autentikasi berhasil per detik

### 11.3 Validasi Keamanan (Fase 3)

- **tampered_token_block_rate_pct = 100%** — sistem berhasil memblokir seluruh token palsu

### 11.4 Perbandingan Falcon-Precomputed vs Falcon-512

Falcon-Precomputed-512 menggunakan pohon LDL yang dihitung satu kali saat inisialisasi dan disimpan di memori. Perbandingan `avg_ms` keduanya pada Fase 1 menunjukkan **tradeoff waktu-memori** (*time-memory tradeoff*): penggunaan memori lebih tinggi pada Precomputed sebagai imbalan latensi penandatanganan yang lebih rendah.

---

## 12. Perintah Eksekusi

```bash
cd backend

# Mode standar (semua fase, single gateway):
k6 run -e BASE_URL=http://localhost:8080 k6/benchmark_sign.js

# Isolated saja (untuk pengambilan data skripsi):
k6 run -e BASE_URL=http://localhost:8080 -e ISOLATED_ONLY=true k6/benchmark_sign.js

# Dengan lebih banyak iterasi (rekomendasi: 500 untuk data final):
k6 run -e BASE_URL=http://localhost:8080 -e ISOLATED_ONLY=true -e ITERATIONS=500 k6/benchmark_sign.js

# Multi-gateway (docker-compose):
k6 run -e BENCH_HOST=localhost k6/benchmark_sign.js
```

---

*Dokumen ini dibuat berdasarkan kode sumber `backend/k6/benchmark_sign.js` dan `backend/gateway/internal/delivery/http/handler/benchmark_handler.go`.*
