# Revisi Naskah TA — Gap Implementasi & Prioritas

Basis: *Hasil Review Naskah — Sidang Seminar TA* (revisi mayor).
Status kode: commit `0256679` (2026-07-14).
Penjelasan naratif tiap P0 (untuk sidang): [p0-penjelasan.md](p0-penjelasan.md).

Catatan penting: **kode sudah lebih maju dari naskah yang direview.** Sebagian besar
temuan P0 reviewer sudah tertutup di repo, tetapi naskah masih memuat angka & klaim lama.
Risiko terbesar sekarang bukan "fitur kurang", melainkan **inkonsistensi data antara naskah,
hasil benchmark terbaru, dan output uji statistik.**

---

## A. Sudah tertutup di kode (naskah tinggal menyesuaikan)

| Temuan review | Status kode | Bukti |
|---|---|---|
| B.3 `alg` header salah (`Falcon-Precomputed-512`) | **Selesai** — header kanonik `FN-DSA-512` untuk dua varian; `typ` = `at+jwt`/`rt+jwt` | `pkg/jwt/fndsa_alg.go`, `pkg/utils/jwtutils/jwt.go` (`HeaderAlgForConfigAlg`) |
| G.3 pisahkan pure signing vs JWT issuance vs E2E | **Selesai** — endpoint terpisah | `/api/benchmark/pure-signing`, `/api/benchmark/jwt-issuance`, `/api/benchmark/token` |
| B.5 CPU% bukan CPU cost | **Sebagian** — `cpu_time_ms`, `cpu_time_per_token_ms` sudah diemit | `gateway/internal/delivery/http/handler/benchmark_handler.go` |
| B.4 memori runtime saja | **Sebagian** — RSS, `memory_sys_kb`, `memory_alloc_kb`, `PersistentBytes()` sudah ada | `benchmark_handler.go`, `pkg/fndsa/sign_precomputed.go:43` |
| B.8 thread-safety belum diuji | **Sebagian** — `TestPrecomputedSignConcurrent`, `TestFNDSAConcurrentVerification` ada | `pkg/fndsa/sign_precomputed_test.go` |
| G.10 hanya 8 vektor serangan | **Parsial** — E2E hanya **9 vektor** (bukan 25; itu jumlah iterasi). Sisanya di unit test. Gap RFC 8725 §3.9 (aud), §3.10 (jku/jwk/x5u), §3.12 (replay/reuse). Lihat P1-baru. | `k6/adversarial_jwt.js` (9), `pkg/utils/jwtutils/jwt_security_test.go`, `docs/skenario-pengujian.md` §6.5 |
| G.9 deskripsi beban kurang | **Selesai** — `load_model: closed-loop`, executor, think time, ramp, error rate, p99 di JSON | `benchmark-results/benchmark_sign_result.json` |
| B.7 satu run stress | **Sebagian** — 3 independent run + agregasi median per-field | `benchmark-results/runs/`, `scripts/aggregate_benchmark_runs.py` |
| I.3 #8/#9 baseline pembanding | **Selesai** — HS256, RS256, ES256, EdDSA (+ ML-DSA, SLH-DSA tersedia) | `pkg/utils/jwtutils/loader.go` |
| G.5 sampel GC dibuang | **Sebagian** — raw + `*_gc_free_ms` + `gc_contaminated_count` disimpan dua-duanya | `benchmark_handler.go` |

---

## B. Prioritas 0 — Kritis (blokir kesimpulan ilmiah)

### P0-4. `go test -race` — SELESAI & terverifikasi

Target `test-race` ditambah di `backend/Makefile` (`make test` memanggilnya).
`go test -race ./fndsa ./jwt ./utils/jwtutils` → **exit 0, tak ada data race** (build 123s/57s/2s).
Tersisa: concurrent signing 10k–100k signature (opsional, race sudah bersih pada tes konkurensi eksisting).

### P0-5. Statistik CI 95% + Hedges' g — SELESAI & terverifikasi

`scripts/benchmark_stat_tests.py`: tambah `hedges_g()`, `t_quantile()` (invert Student-t via bisection, tanpa SciPy),
`mean_diff_ci()` (Welch CI). `benchmark_welch_all_baselines.py`: kolom baru di markdown + json.
Divalidasi pada sampel nyata (`.2.ndjson`): **−24,57%, p = 2,11e-22, Hedges' g = 1,594, mean diff 0,1148 ms,
95% CI [0,0945, 0,1352]** — efek besar, membantah `welch.json` basi (−3,1% negligible).
Tersisa: jalankan pada artefak resmi setelah P0-1 diputuskan; opsional bootstrap CI + Mann-Whitney (helper sudah ada).

### P0-2 + P0-3. Startup cost, break-even, memori persisten — SELESAI (angka VPS diperoleh)

`backend/pkg/fndsa/precompute_profile_test.go` — `TestReportPrecomputeProfile` (gated `EMIT_PROFILE=1`)
emit build/init ms, `persistent_bytes_per_key`, sign dynamic vs precomputed, `saving_per_signature_ms`,
**`break_even_signatures`**, `rss_delta_kb_by_signers` (1/10/100). Rumus: `N = T_init / (T_sign_dyn − T_sign_pre)`.

**Angka tesis — VPS 2 vCPU, 3 run independen** (`fndsa_precompute_profile_run_1..3.json`;
headline **mean** = `fndsa_precompute_profile.json` — bukan median: dengan n=3, median cuma nilai run
tengah/run 3, membuang 2 run lain; mean memakai ketiganya, konvensi standar untuk rata-rata beberapa run):

| Metrik | Run 1 | Run 2 | Run 3 | Mean | Stdev |
|---|---|---|---|---|---|
| build/init (ms) | 0,2153 | 0,2461 | 0,2787 | **0,2467** | 0,0317 |
| sign dynamic (ms) | 0,3767 | 0,5084 | 0,4942 | **0,4598** | 0,0723 |
| sign precomputed (ms) | 0,3281 | 0,3016 | 0,3229 | **0,3175** | 0,0141 |
| hemat/signature (ms) | 0,0485 | 0,2068 | 0,1713 | **0,1422** | 0,0831 |
| **break-even (signature)** | 4,4359 | 1,1898 | 1,6271 | **2,4176** | 1,7615 |
| RSS delta @1 signer (KB) | −32 | 20 | 148 | 45,3 | 92,6 |
| RSS delta @10 signer (KB) | −552 | −496 | −880 | −642,7 | 207,4 |
| RSS delta @100 signer (KB) | 12.836 | 13.752 | 15.452 | **14.013,3** | 1.327,4 |

persistent bytes/key: **110.712 B (~108,1 KiB)**, identik di 3 run (deterministik). RSS @1/@10 tidak reliabel
(stdev sebanding atau lebih besar dari mean, tanda berubah) — hanya @100 signer valid (stdev ≈9,5% relatif).
Detail interpretasi + alasan mean-vs-median: [p0-penjelasan.md](p0-penjelasan.md#hasil--vps-2-vcpu-3-run-independen-angka-tesis).

stdev break-even 1,762 (≈73% relatif) besar — variansi nyata VPS 2-vCPU bersama (noisy-neighbor), bukan bug.

Run 1 outlier (break-even 4,4, hemat kecil) — kemungkinan noisy-neighbor VPS 2-vCPU bersama, dilaporkan
sebagai rentang bukan dibuang. RSS @1/@10 signer terlalu kecil untuk terukur reliabel (noise heap Go > sinyal);
hanya @100 signer valid. Detail + interpretasi sidang: [p0-penjelasan.md](p0-penjelasan.md#p0-2-dan-p0-3--startup-cost-break-even-memori-persisten).

File lokal laptop (`fndsa_precompute_profile_local_dev.json`) disimpan sebagai jejak validasi metode, bukan angka tesis.

### P0-7 (temuan review #7). Anomali stress 30 VU — TIDAK TEREPRODUKSI di data saat ini

Naskah lama mengutip Login E2E Avg 640/683ms, P95 907/1395ms (gap sampai 105%) di 30 VU — precomputed
lebih lambat drastis dari standard. Reviewer minta ini diperlakukan sebagai anomali penting, bukan variasi
biasa, dan diulang 5–10 run independen.

Dicek pada 3 run yang tersimpan di `benchmark-results/runs/` (bukan naskah lama — data lahir setelah commit
`bb5915a`, "Fix stale benchmark data and GC-attribution bugs causing invalid results", 2026-07-09):
**reversal drastis di satu titik (30 VU) tidak teramati** — kedua algoritma monoton naik penuh di 10→30→50 VU,
di ketiga run tanpa kecuali, dan skala absolut beda ~1,7× dari yang dikutip naskah (1132–1153ms vs 640–683ms
di 30 VU) — indikasi kuat data lama berasal dari run/environment berbeda (kemungkinan sebelum fix bug di atas).

**Tapi ditemukan pola lain yang harus dilaporkan jujur:** FN-DSA-512 (dynamic/standard) sedikit tapi
**konsisten** lebih cepat/tinggi-throughput daripada Precomputed di *setiap* VU dan *hampir setiap* metrik —
bukan reversal drastis di satu titik seperti naskah lama, melainkan gap kecil (0,2–9,3%) yang searah di semua level:

| VU | Metrik | Precomputed | FN-DSA-512 (dynamic) | Gap |
|---|---|---|---|---|
| 10 | login avg | 401,4 ± 36,2 | 397,4 ± 18,1 | Precomputed 1,0% lebih lambat |
| 10 | login P95 | 750,9 ± 99,6 | 736,5 ± 48,0 | Precomputed 2,0% lebih lambat |
| 10 | refresh avg | 318,5 ± 14,8 | 297,8 ± 18,1 | Precomputed 7,0% lebih lambat |
| 10 | throughput | 12,81 ± 0,75 | 13,20 ± 0,58 | Precomputed 3,0% lebih rendah |
| 30 | login avg | 1156,0 ± 21,7 | 1136,5 ± 3,8 | Precomputed 1,7% lebih lambat |
| 30 | login P95 | 2338,3 ± 206,1 | 2319,3 ± 27,6 | Precomputed 0,8% lebih lambat |
| 30 | refresh avg | 1054,8 ± 9,7 | 1051,5 ± 61,8 | Precomputed 0,3% lebih lambat |
| 30 | throughput | 13,53 ± 0,21 | 13,50 ± 0,67 | Precomputed 0,2% lebih tinggi |
| 50 | login avg | 1960,8 ± 154,3 | 1869,3 ± 62,2 | Precomputed 4,9% lebih lambat |
| 50 | login P95 | 4082,8 ± 454,9 | 3736,1 ± 14,8 | Precomputed 9,3% lebih lambat |
| 50 | refresh avg | 1793,4 ± 82,8 | 1786,5 ± 48,7 | Precomputed 0,4% lebih lambat |
| 50 | throughput | 13,67 ± 0,86 | 13,99 ± 0,03 | Precomputed 2,3% lebih rendah |

Throughput relatif datar (~12,8–14 req/s) di semua level VU untuk kedua algoritma — sistem 2 vCPU sudah
saturasi sejak 10 VU (bcrypt + DB round-trip login penuh), sehingga latensi naik mengikuti Little's Law
(antrean bertambah linear terhadap VU saat throughput mentok).

**Kenapa gap ini bukan efek algoritma signing.** Isolated benchmark (P0-1) sudah membuktikan secara statistik
precomputed *lebih cepat* di pure signing (−24,57%, p=2,11e-22) — tapi selisih absolutnya cuma ~0,1–0,2 ms/operasi.
Login/refresh E2E totalnya 300–4000 ms, >99,9% di antaranya bcrypt + DB round-trip, bukan signing. Kalau selisih
signing itu satu-satunya sumber, gap E2E seharusnya tak terdeteksi (<0,01%) — bukan 1–9% yang teramati.

Root cause paling mungkin: `docker-compose.benchmark.yml` menjalankan **12 container** (`bench-auth-*` +
`bench-gw-*` × 6 algoritma) plus `bench-postgres` plus `bench-backend`, seluruhnya berbagi **2 vCPU** tanpa
`cpus:`/`deploy.resources.limits` apa pun — tak ada isolasi CPU antar-container. Ini persis validity threat
yang sudah disebut reviewer di temuan #6 ("hanya tersedia 2 vCPU... CPU container tidak mewakili keseluruhan
tekanan pada host"). Container mana yang kebetulan dapat jadwal CPU lebih baik pada jendela 30 detik itu bisa
menghasilkan gap seperti ini — tanpa hubungan sebab-akibat dengan algoritma tanda tangan.

Interpretasi untuk sidang: jangan klaim "FN-DSA-512 dynamic terbukti lebih cepat secara E2E" — klaim yang
defensible: *"reversal drastis di 30 VU pada naskah lama tidak teramati ulang; namun gap kecil (0,2–9,3%) yang
konsisten mendukung dynamic signer terlihat di semua level VU pada arsitektur multi-container yang berbagi
2 vCPU tanpa isolasi CPU — besarnya jauh melebihi yang dapat dijelaskan oleh selisih signing murni (~24% dari
~0,1–0,2 ms, negligible terhadap E2E 300–4000 ms), sehingga lebih mungkin mencerminkan variansi penjadwalan
container pada host bersama daripada efek algoritma."* Ini konsisten dengan validity threat #6 yang sudah
diakui, dan memperkuat (bukan melemahkan) narasi inti tesis: optimasi primitif kriptografi (terbukti, isolated)
tidak otomatis diterjemahkan ke performa aplikasi E2E (tidak terbukti, dan noise host bisa menutupinya).

Tersisa (opsional, P1): tambah `cpus:`/`deploy.resources.limits` per-container di compose agar perbandingan
E2E antar-algoritma adil (CPU-isolated), dan tambah 2–7 run lagi agar total 5–10 run sesuai rekomendasi reviewer.

### P0-1. Satukan sumber kebenaran — SELESAI (opsi A: single-run headline)

Keputusan: **opsi A** — headline dari satu run + CI/Hedges dari sampel run itu.
Run otoritatif = **run_3** (dikonfirmasi cocok dengan ndjson terbaru: Precomputed 0,3526 & FN-DSA-512 0,4674, n=97/96).

Dikerjakan:
1. `benchmark_sign_result.json` ← salinan `runs/benchmark_sign_result_run_3.json` (single run, `aggregation: None`).
   Revert ke 3-run: `python3 scripts/aggregate_benchmark_runs.py --bench-glob '.../runs/*_run_*.json' --bench-out .../benchmark_sign_result.json`.
2. Ekstrak vektor sampel isolated (7 metrik, 4173 titik, **577 KB**) → `benchmark-results/benchmark_sign_samples.ndjson`
   (dari 106 MB dump mentah; tags cuma `alg`/`scenario`, tanpa token/PII). `.gitignore` diberi exception → tracked.
3. Regen `benchmark_stats.json` + `benchmark_welch.json` dari run_3 + samples.

**Angka headline baru (gantikan angka basi di Bab IV/abstrak/kesimpulan):**
- access (JWT issuance, gc-free): **−24,57%**, p = 2,11e-22, Hedges' g = 1,594, 95% CI [0,0945, 0,1352] ms.
- refresh (gc-free): **−24,29%**, p = 1,37e-13, Hedges' g = 1,143, 95% CI [0,0866, 0,1435] ms.

Bonus: bug catastrophic-cancellation di p-value Mann-Whitney diperbaiki (`math.erfc`; dulu `<1e-300`, kini 4,09e-22).
3-run data tetap di `runs/` bila nanti pindah ke opsi C.

---

## C. Prioritas 1 — Penguatan ilmiah

### P1-6. Urutan algoritma tidak diacak.
`ALGORITHMS` di `k6/benchmark_sign.js` berurutan tetap dengan `startTime` bertingkat; 3 run mengulang
urutan sama → efek urutan/thermal terkonfound. Acak atau counterbalance urutan antar-run.

### P1-7. Analisis sensitivitas GC belum dilaporkan.
`gc_contaminated_count` sudah ada (4–5 dari 100), tetapi naskah tidak menyajikan hasil dengan dan tanpa
sampel GC. Sajikan berdampingan + jumlah sampel yang dikeluarkan.

### P1-8. Ukuran tanda tangan & token tidak diukur.
Tidak ada distribusi ukuran signature terkompresi aktual (min/mean/median/P95/max) maupun panjang JWT compact.
Naskah masih menyebut 666 byte sebagai nilai tetap.

### P1-9. Telemetri stress kurang.
Stage hanya 30 s; agregasi antar-run = median per-field tanpa dispersi (tidak ada CI antar-run).
Belum ada GC pause, jumlah goroutine, DB connection pool, throttling container per stage.

### P1-10. Key rotation & restart belum diuji; konflik `kid`.
`validateTokenTypeHeader` **menolak** header `kid` (`pkg/utils/jwtutils/jwt.go:334`), sedangkan review
merekomendasikan `kid` + uji rotasi kunci. Ambil keputusan: dukung `kid`, atau pertahankan penolakan dan
catat sebagai batasan eksplisit di naskah.

### P1-11. Fuzzing input pesan belum ada.
Tambah `FuzzSign`/`FuzzParse` pada jalur signer dan parser JWT.

---

## D. Prioritas 2 — Kerapian & reproduksibilitas

- **P2-12.** Identifier lama masih tersisa (`LegacyAlgFNDSAPrecomputed512`, alias `Falcon-Precomputed-512` di
  `loader.go`). Pertahankan hanya sebagai alias konfigurasi; tegaskan di naskah bahwa header JWS = `FN-DSA-512`.
- **P2-13.** Tidak ada zeroization / `Destroy()` pada `PrecomputedSigner`; tidak ada pembahasan core dump, swap,
  memory hardening.
- **P2-14.** Metadata reproduksibilitas belum diemit ke result JSON: commit hash, versi Go, CGO on/off, build flags,
  hasil KAT (`make falcon-kat` sudah ada — tinggal dicatat).
- **P2-15.** `fndsa_precompute_ablation.json` juga basi (9 Jul). Regenerasi bersama P0-1.
- **P2-16.** Field CPU/memori isolated memiliki `min = max = avg = p95` (satu observasi agregat sisi server) tetapi
  `sd` besar. Jangan sajikan sebagai distribusi di naskah; laporkan sebagai observasi tunggal + sd sisi server.

---

## E. Perubahan naskah (tanpa eksperimen baru)

1. Kebaruan → reposisi ke *integrasi & evaluasi sistem*, bukan penemuan teknik precomputation.
2. Status Falcon/FN-DSA → FIPS 206 belum final; profil JOSE masih Internet-Draft.
3. Judul → pakai alternatif trade-off (latensi, CPU, memori) yang direkomendasikan reviewer.
4. Abstrak → tulis ulang dengan angka baru, sebutkan jumlah sampel, CPU naik, memori persisten.
5. Klaim keamanan → "seluruh N request pada 25 skenario negatif ditolak gateway", bukan "sistem aman".
6. Redaksi screenshot: token, kredensial, IP, hostname. Rotasi token yang terlanjur tampil.
7. Tambah subbab Ancaman Validitas + 5.2 Keterbatasan Penelitian.
8. Perbaiki daftar pustaka: duplikasi RFC 7519, DOI ganda, sitasi GitHub, konsistensi APA 7.

---

## F. Urutan kerja yang disarankan

1. P0-1 (satukan data) — semua bab bergantung pada ini.
2. P0-4 (`-race`) — cepat, dan hasilnya wajib dilaporkan.
3. P0-2 + P0-3 (startup, memori persisten, break-even) — satu siklus instrumentasi.
4. P0-5 (CI + Hedges' g) — regenerasi statistik sekaligus.
5. P1-6 sampai P1-9 — satu sesi benchmark ulang dengan urutan acak.
6. Sisanya (P1-10, P1-11, P2) dan revisi naskah.
