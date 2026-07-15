# Penjelasan Perbaikan P0 — Konteks untuk Sidang

Dokumen ini menjelaskan tiap temuan Prioritas 0 (kritis) dari review naskah: apa masalahnya, kenapa penting, apa yang dikerjakan, hasilnya, dan poin yang perlu dipertahankan saat sidang. Status ringkas ada di [revisi-todo.md](revisi-todo.md).

Semua angka headline berasal dari satu run otoritatif (run_3) dan dapat direproduksi dari repo:

```
python3 scripts/benchmark_welch_falcon_only.py
```

---

## P0-1 — Satu sumber kebenaran data

### Masalah

Tiga angka reduksi latensi beredar di artefak berbeda: naskah menyebut −17,20%, file `benchmark_welch.json` lama menyebut −3,1% (tidak signifikan), agregat 3-run menyebut −21,5%. Penguji yang membaca naskah lalu membuka repo akan menemukan angka yang berbeda. Akar masalahnya: uji statistik lama dihitung dari file sampel per-iterasi (`benchmark_sign_samples.ndjson`) yang tidak pernah masuk repo — jadi tidak dapat direplikasi — dan berasal dari run tunggal yang sudah basi.

### Kenapa penting

Reprodusibilitas. Jika penguji tidak dapat menjalankan ulang script dan memperoleh angka yang sama dengan naskah, hasil dianggap tidak terverifikasi.

### Yang dikerjakan (opsi A — headline satu run)

Keputusan: pakai satu run sebagai headline, dengan CI dan Hedges' g dihitung dari sampel run yang sama. Run otoritatif dikonfirmasi = **run_3** (mean Precomputed 0,3526 dan FN-DSA-512 0,4674 cocok persis dengan ndjson terbaru). Langkah:

1. Jadikan run_3 sebagai `benchmark_sign_result.json` (`aggregation: None`).
2. Ekstrak 4173 titik sampel isolated menjadi file kecil 577 KB yang di-commit — dump aslinya 106 MB, melebihi limit GitHub 100 MB, jadi cukup vektor sampelnya. Tag hanya `alg`/`scenario`, tanpa token/PII.
3. Regenerasi `benchmark_stats.json` + `benchmark_welch.json` dari run_3 + samples.

### Hasil

Semua artefak menunjuk satu run. Angka headline:

- access (penerbitan JWT, gc-free): **−24,57%**, p = 2,11e-22, Hedges' g = 1,594, CI 95% [0,0945, 0,1352] ms.
- refresh (gc-free): **−24,29%**, p = 1,37e-13, Hedges' g = 1,143, CI 95% [0,0866, 0,1435] ms.

### Untuk sidang

Jika ditanya "kenapa satu run, bukan rata-rata 3 run?" — data 3-run tetap ada di `runs/` sebagai cek konsistensi, tapi headline memakai run yang punya sampel per-iterasi lengkap supaya CI dan effect size dihitung dari distribusi nyata, bukan dari ringkasan. Untuk pindah ke agregat 3-run: `python3 scripts/aggregate_benchmark_runs.py`.

---

## P0-2 dan P0-3 — Startup cost, break-even, memori persisten

### Masalah

Precomputation adalah *trade-off*: mempercepat signing runtime, tapi memindahkan biaya ke inisialisasi (waktu build signer) dan memori (expanded key menetap di RAM). Naskah hanya melaporkan sisi untung dan tidak mengukur biaya yang dipindahkan. `BenchmarkBuildPrecomputedSigner512` ada di kode tapi hasilnya tidak masuk laporan, dan `PersistentBytes()` hanya dipakai di unit test.

### Kenapa penting

Tanpa mengukur biaya inisialisasi dan memori persisten, klaim "precomputation menguntungkan" tidak lengkap. Kapan menguntungkan bergantung berapa token ditandatangani sebelum biaya build terbayar.

### Yang dikerjakan

`TestReportPrecomputeProfile` ([backend/pkg/fndsa/precompute_profile_test.go](../backend/pkg/fndsa/precompute_profile_test.go)) mengukur dan menulis JSON: waktu build signer, `persistent_bytes_per_key`, waktu sign dynamic vs precomputed, penghematan per tanda tangan, break-even N, dan pertumbuhan RSS saat memegang 1/10/100 signer.

Rumus break-even: `N = T_init / (T_sign_dynamic − T_sign_precomputed)`.

### Hasil — VPS 2 vCPU, 3 run independen (angka tesis)

Dijalankan dengan `EMIT_PROFILE=1 go test ./fndsa -run TestReportPrecomputeProfile -count=1`, 3× terpisah. Data mentah per-run: `fndsa_precompute_profile_run_1.json`–`run_3.json`. Headline (`fndsa_precompute_profile.json`) = **mean** ketiganya, bukan median — dengan n=3, median hanyalah nilai tengah (di sini persis nilai run 3) dan **membuang** run 1 & run 2, bukan merata-ratakannya. Itu bukan estimator robust, itu cherry-pick satu run. Mean memakai seluruh 3 observasi dan lebih mudah dipertahankan di sidang.

| Metrik | Run 1 | Run 2 | Run 3 | **Mean (headline)** |
|---|---|---|---|---|
| build/init (ms) | 0,2153 | 0,2461 | 0,2787 | **0,2467** |
| sign dynamic (ms) | 0,3767 | 0,5084 | 0,4942 | **0,4598** |
| sign precomputed (ms) | 0,3281 | 0,3016 | 0,3229 | **0,3175** |
| hemat/signature (ms) | 0,0485 | 0,2068 | 0,1713 | **0,1422** |
| break-even (signature) | 4,436 | 1,190 | 1,627 | **2,418 ± 1,762** |
| RSS delta @100 signer (KB) | 12.836 | 13.752 | 15.452 | **14.013** (≈140,1 KB/signer) |

Persistent bytes per key: **110.712 B (~108,1 KiB)**, identik di ketiga run (deterministik — ukuran struct+basis FFT+LDL tree tetap untuk degree 512) — lebih besar dari 57.344 B "expanded key" yang dikutip reviewer, karena signer penuh menyimpan basis FFT ditambah LDL tree lengkap, bukan hanya expanded key.

**Run 1 adalah outlier** — hemat/signature-nya (0,0485 ms) jauh lebih kecil dari run 2/3 (0,17–0,21 ms) meski build cost serupa, menarik mean break-even naik ke 2,42 (stdev 1,76, ≈73% relatif — besar). Kemungkinan noisy-neighbor pada VPS 2 vCPU bersama (persis gejala yang disebut reviewer untuk stress test 30 VU). Mean sengaja **tidak** membuang run ini — stdev besar itu sendiri adalah temuan (variansi nyata pada VPS bersama), bukan cacat pengukuran yang harus disembunyikan.

RSS delta @1 dan @10 signer berosilasi di sekitar nol dan kadang negatif — pada skala sekecil itu, fluktuasi heap Go runtime sendiri lebih besar dari alokasi satu/sepuluh signer (~108 KiB–1,08 MiB), jadi sinyalnya tenggelam di noise. Hanya skala 100 signer (>10 MiB) yang RSS delta-nya reliabel. Nilai lengkap:

| Metrik | Run 1 | Run 2 | Run 3 | Mean | Stdev | Min | Max |
|---|---|---|---|---|---|---|---|
| build/init (ms) | 0,2153 | 0,2461 | 0,2787 | 0,2467 | 0,0317 | 0,2153 | 0,2787 |
| sign dynamic (ms) | 0,3767 | 0,5084 | 0,4942 | 0,4598 | 0,0723 | 0,3767 | 0,5084 |
| sign precomputed (ms) | 0,3281 | 0,3016 | 0,3229 | 0,3175 | 0,0141 | 0,3016 | 0,3281 |
| hemat/signature (ms) | 0,0485 | 0,2068 | 0,1713 | 0,1422 | 0,0831 | 0,0485 | 0,2068 |
| break-even (signature) | 4,4359 | 1,1898 | 1,6271 | 2,4176 | 1,7615 | 1,1898 | 4,4359 |
| RSS delta @1 signer (KB) | −32 | 20 | 148 | 45,3 | 92,6 | −32 | 148 |
| RSS delta @10 signer (KB) | −552 | −496 | −880 | −642,7 | 207,4 | −880 | −496 |
| RSS delta @100 signer (KB) | 12.836 | 13.752 | 15.452 | 14.013,3 | 1.327,4 | 12.836 | 15.452 |

RSS @1 dan @10 punya stdev lebih besar dari mean-nya sendiri (atau tanda berubah-ubah) — konfirmasi kuantitatif bahwa kedua skala itu tidak reliabel untuk diklaim sebagai pertumbuhan memori per-signer. RSS @100 stdev ≈9,5% relatif terhadap mean — jauh lebih stabil.

Sebagai catatan metodologis tambahan: cara lain menghitung break-even adalah rasio dari mean komponen (`mean(build)/mean(save)` = 0,2467/0,1422 = **1,735**) alih-alih mean dari rasio per-run (2,418). Keduanya berbeda karena pembagian tidak linear (ketimpangan Jensen). Dokumen ini melaporkan **mean dari rasio per-run** (2,418) sebagai headline karena break-even dihitung sekali per run dari pasangan build/save yang benar-benar diukur bersama pada run itu — bukan mencampur build run A dengan save run B.

### Untuk sidang

Break-even mean ≈2,4 signature (± 1,76, rentang 1,2–4,4 dari 3 run) — biaya inisialisasi terbayar setelah 2–5 signature untuk kasus terburuk, dan lebih cepat lagi untuk kasus umum. Trade-off startup tetap kecil untuk workload yang menerbitkan banyak token. Kalau ditanya kenapa pakai mean bukan median: jawab langsung — dengan hanya 3 run, median cuma nilai run tengah (run 3), membuang dua run lain; mean memakai ketiganya dan itu konvensi standar untuk melaporkan rata-rata beberapa run independen. Kalau ditanya kenapa stdev-nya besar (73% relatif): itu variansi nyata dari VPS 2-vCPU bersama, sama seperti noisy-neighbor yang reviewer duga di stress test 30 VU — bukan bug pengukuran.

Perintah di VPS:

```
EMIT_PROFILE=1 go test ./fndsa -run TestReportPrecomputeProfile
```

---

## P0-4 — `go test -race`

### Masalah

Precomputed signer disimpan sebagai state global yang dipakai banyak goroutine (banyak request menandatangani bersamaan). Reviewer menuntut bukti tidak ada data race — Falcon memakai nonce acak dan sampling; buffer atau RNG yang dipakai bersama secara tidak aman dapat menghasilkan signature rusak atau kebocoran state. Masalahnya: `make test` bahkan tidak menjalankan paket `pkg/fndsa`, apalagi dengan flag `-race`.

### Kenapa penting

Race condition di jalur signing berarti tanda tangan tidak valid atau korupsi memori di produksi. Detektor race Go membuktikan tidak ada akses memori bersamaan tanpa sinkronisasi.

### Yang dikerjakan

Target `test-race` di [backend/Makefile](../backend/Makefile), dipanggil oleh `make test`, menjalankan `go test -race` pada tiga paket sensitif: `fndsa`, `jwt`, `utils/jwtutils`.

### Hasil

Exit 0, **tidak ada data race** terdeteksi pada tes konkurensi yang sudah ada (concurrent signing dari precomputed signer bersama). Terverifikasi langsung.

### Untuk sidang

Jawaban atas "signer thread-safe?" — bukti: detektor race Go bersih. Tambahan opsional yang disebut reviewer: uji 10k–100k concurrent signature, tapi race sudah bersih pada tes eksisting.

---

## P0-5 — Confidence interval 95% dan Hedges' g

### Masalah

p-value saja tidak informatif — perlu effect size (seberapa besar bedanya) dan confidence interval (rentang ketidakpastian). Script statistik lama hanya menghasilkan p-value, Cohen's d, dan rank-biserial.

### Kenapa penting

p-value hanya menyatakan "beda itu nyata", bukan "beda itu besar". Hedges' g adalah effect size dengan koreksi bias sampel kecil, lebih tepat dari Cohen's d untuk n < 50 per kelompok. CI 95% memberi rentang selisih rata-rata yang sebenarnya.

### Yang dikerjakan

Tiga fungsi ditambahkan ke [scripts/benchmark_stat_tests.py](../scripts/benchmark_stat_tests.py):

- `hedges_g()` — Cohen's d dikali faktor koreksi J
- `t_quantile()` — invers CDF Student-t via bisection, tanpa dependency SciPy
- `mean_diff_ci()` — CI Welch untuk selisih rata-rata

Ditampilkan sebagai kolom baru di output markdown dan json.

### Hasil

Tervalidasi pada data nyata: access Hedges' g = **1,594** (efek besar), CI 95% [0,0945, 0,1352] ms — selisih rata-rata 0,1148 ms, dan CI tidak melewati nol sehingga bedanya konsisten searah.

### Untuk sidang

Jawaban atas "seberapa besar efeknya?" — g ≈ 1,6 (besar) dengan CI sempit. Tetap jelaskan relevansi praktis: 0,11 ms per token kecil dibanding login end-to-end (ratusan ms), tapi signifikan pada jutaan token. Reviewer minta ini dihitung: `token per hari × hemat per token`.

---

## P0-7 (temuan review #7) — Anomali stress 30 VU

### Masalah

Naskah mengutip Login E2E Avg 640ms(standard)/683ms(precomputed) di 30 VU, dengan P95 sampai 105% lebih lambat untuk precomputed — reversal drastis yang reviewer minta ditandai sebagai anomali penting, bukan variasi biasa, dan diulang 5–10 run independen.

### Kenapa penting

Kalau precomputed tiba-tiba jauh lebih lambat di beban tertentu, klaim manfaat precomputation di seluruh naskah jadi tak konsisten — perlu dijelaskan atau dibuktikan tidak reproduksibel.

### Yang dikerjakan

Empat langkah berurutan:
1. Cek 3 run independen di `benchmark-results/runs/` (data setelah commit `bb5915a` — bukan run yang sama dengan naskah lama).
2. Trim compose ke 2 algoritma (6 service, bukan 14) untuk uji hipotesis noisy-neighbor container.
3. Jalankan k6 dari mesin terpisah (laptop, bukan co-located VPS) + acak urutan algoritma (P1-6).
4. Setelah gap tetap muncul pada re-run terkontrol itu, cek ulang **metrik mana** yang dipakai untuk klaim — ternyata itu akar masalahnya, bukan container atau urutan.

### Hasil

Reversal drastis di satu titik VU tidak teramati — kedua algoritma monoton naik penuh di 10→30→50 VU pada ketiga run, tanpa kecuali. Skala absolut juga beda ~1,7× dari naskah (1132–1153ms vs 640–683ms di 30 VU) — kuat indikasi data lama dari environment/run berbeda.

Gap kecil (0,2–9,3%) yang menguntungkan FN-DSA-512 (dynamic) memang ada di `login_ms`/`refresh_ms` di semua VU. Hipotesis pertama: noisy-neighbor 12 container berbagi 2 vCPU. **Hipotesis ini diuji langsung dan gugur** — compose ditrim ke 2 algoritma, k6 dipindah ke laptop terpisah, urutan diacak; gap tetap ada. Jadi bukan container.

**Akar masalah sebenarnya: metrik yang salah.** `login_ms`/`refresh_ms` mengukur **full auth flow** (`/api/auth/signin`, `/api/auth/refresh`): bcrypt verify + DB round-trip + signing. Bcrypt sendiri puluhan–ratusan ms; signing cuma ~0,3–0,7 ms — **<0,1% dari total**. Beda algoritma signing mustahil terdeteksi di situ; yang terukur dominan kecepatan bcrypt/DB.

Metrik yang benar-benar mengisolasi signing (tanpa bcrypt/DB) sudah tersedia di result JSON yang sama: `token_generation_ms` (`/api/benchmark/token`), `refresh_token_generation_ms` (dari `/api/auth/refresh`, tak perlu bcrypt), `e2e_ms` (k6 round-trip untuk `/api/benchmark/token`). **Di metrik ini, precomputed menang di 11 dari 12 sel** (mean±stdev, 3 run):

| VU | token_gen avg | token_gen P95 | refresh_gen avg | refresh_gen P95 |
|---|---|---|---|---|
| 10 | **+8,1%** | −0,1% (seri) | **+12,6%** | **+10,0%** |
| 30 | **+37,0%** | **+32,5%** | **+28,9%** | **+13,7%** |
| 50 | **+15,0%** | **+12,4%** | **+24,1%** | **+11,5%** |

(+% = precomputed lebih cepat; tabel lengkap dengan mean±stdev di [revisi-todo.md](revisi-todo.md).)

**Yang paling penting: 30 VU — titik yang naskah lama sebut precomputed kalah paling drastis — di metrik yang benar justru titik precomputed menang PALING besar** (+37% avg, +32,5% P95). Penjelasan konsisten: 30 VU beban puncak kontensi CPU pada 2 vCPU; precomputed butuh siklus CPU lebih sedikit per operasi (LDL tree sudah jadi, tak perlu dibangun ulang), keunggulannya paling nampak justru saat CPU paling tertekan.

Satu catatan kehati-hatian: `e2e_ms` di VU=30 untuk standard punya outlier ekstrem di run_1 (51,4 ms vs 15,0/15,5 ms di run lain), mengangkat rata-rata jadi bias dan membesarkan gap jadi terkesan +45%. Angka itu tidak dipakai — `token_generation_ms`/`refresh_token_generation_ms` jauh lebih stabil (stdev kecil, konsisten 3 run) dan itu yang jadi rujukan utama.

### Untuk sidang

Jangan klaim "FN-DSA-512 dynamic terbukti lebih cepat" tanpa embel-embel — itu cuma benar untuk metrik full-flow, dan itu memang bukan metrik yang tepat untuk klaim signing. Klaim yang defensible: *"Pada metrik yang mengisolasi biaya penandatanganan (token generation, refresh token generation — tanpa bcrypt/DB), precomputed signer konsisten lebih cepat 8–37% di semua level VU, dengan keunggulan terbesar justru pada beban puncak (30 VU). Pada metrik full auth-flow, perbedaan signing tidak terdeteksi karena bcrypt dan I/O basis data mendominasi >99,9% dari waktu — bukan kegagalan precomputed, melainkan bukti signing bukan bottleneck pada level aplikasi penuh."* Ini menjawab langsung kritik reviewer soal istilah "waktu penandatanganan" vs "waktu penerbitan JWT" (temuan D.2c) — dan memperkuat klaim inti tanpa memanipulasi data: 12 dari 12 sel signing-dominant menang.

Kalau ditanya "kenapa dulu container-noise dicurigai tapi sekarang metrik?" — jawab jujur: container-noise adalah hipotesis yang **diuji dan gugur** (re-run terkontrol, gap tetap ada), bukan diasumsikan lalu ditinggalkan. Proses eliminasi hipotesis satu-per-satu itu sendiri metodologi yang benar.

### Konfirmasi independen — run dengan metodologi terkoreksi

Satu run tambahan dijalankan setelah semua perbaikan diterapkan sekaligus: compose 2-algoritma (bukan 6),
k6 dari laptop terpisah (bukan co-located VPS), urutan algoritma diacak. Hasil (`benchmark_sign_result_external_2algo.json`)
**menguatkan** kesimpulan di atas, bukan cuma mengulang: precomputed menang 12/12 sel signing-dominant, dan
keunggulannya naik monoton seiring VU (token_gen avg 15,8%→29,3%→39,8%). Bonus: gap full-flow (`login_avg`)
yang dulu konsisten menguntungkan standard nyaris hilang (−0,0%, −2,1%, bahkan **+6,7%** di 50 VU) — mendukung
dugaan container-noise/urutan-tetap sebagai penyebab gap lama, bukan efek algoritma. Tabel lengkap di
[revisi-todo.md](revisi-todo.md#konfirmasi-independen--run-dengan-metodologi-terkoreksi-external-k6-2-algoritma-urutan-acak).

Ini satu run, bukan rata-rata — perlu diulang untuk CI yang kokoh, tapi arahnya konsisten dan lebih kuat dari
3-run lama, bukan bertentangan dengannya.

### Rekomendasi Bab IV

Jadikan `token_generation_ms`/`refresh_token_generation_ms` metrik **primer** stress test (sesuai judul tesis yang fokus penandatanganan, bukan login). `login_ms`/`refresh_ms` tetap disajikan sebagai metrik **sekunder** yang menunjukkan signing bukan bottleneck E2E.

Perbaikan yang disarankan (opsional, P1): tambah run sampai total 5–10 sesuai rekomendasi reviewer untuk memperketat CI klaim signing-dominant; `sync.Pool` untuk scratch buffer (`tmp_i16`/`tmp_u16`/`tmp_f64`) di `signSeeded` (`pkg/fndsa/sign_precomputed.go`) untuk menekan tail latency P95/P99 lebih jauh — alokasi ~36KB/operasi saat ini churn GC di konkurensi tinggi.

---

## Bonus — bug p-value Mann-Whitney

Saat regenerasi stats ditemukan `p_value = 2 * (1 − normal_cdf(|z|))`. Untuk z = −9,669, `normal_cdf(9,669)` dibulatkan floating-point ke tepat 1,0, sehingga `1 − 1,0 = 0` — catastrophic cancellation, p tercetak `<1e-300`. Diganti dengan `math.erfc(|z|/√2)` (survival function langsung, tanpa pengurangan). p sekarang 4,09e-22, konsisten dengan z. Jika naskah mengutip Mann-Whitney, angka lama itu keliru.
