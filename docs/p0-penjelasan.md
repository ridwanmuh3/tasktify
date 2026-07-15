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

Dijalankan dengan `EMIT_PROFILE=1 go test ./fndsa -run TestReportPrecomputeProfile -count=1`, 3× terpisah. Data mentah per-run: `fndsa_precompute_profile_run_1.json`–`run_3.json`. Headline (`fndsa_precompute_profile.json`) = median ketiganya.

| Metrik | Run 1 | Run 2 | Run 3 | **Median (headline)** |
|---|---|---|---|---|
| build/init (ms) | 0,2153 | 0,2461 | 0,2787 | **0,2461** |
| sign dynamic (ms) | 0,3767 | 0,5084 | 0,4942 | **0,4942** |
| sign precomputed (ms) | 0,3281 | 0,3016 | 0,3229 | **0,3229** |
| hemat/signature (ms) | 0,0485 | 0,2068 | 0,1713 | **0,1713** |
| break-even (signature) | 4,436 | 1,190 | 1,627 | **1,627** |
| RSS delta @100 signer (KB) | 12.836 | 13.752 | 15.452 | **13.752** (≈137,5 KB/signer) |

Persistent bytes per key: **110.712 B (~108,1 KiB)**, identik di ketiga run (deterministik — ukuran struct+basis FFT+LDL tree tetap untuk degree 512) — lebih besar dari 57.344 B "expanded key" yang dikutip reviewer, karena signer penuh menyimpan basis FFT ditambah LDL tree lengkap, bukan hanya expanded key.

**Run 1 adalah outlier** — hemat/signature-nya (0,0485 ms) jauh lebih kecil dari run 2/3 (0,17–0,21 ms) meski build cost serupa, mendorong break-even naik ke 4,4. Kemungkinan noisy-neighbor pada VPS 2 vCPU bersama (persis gejala yang disebut reviewer untuk stress test 30 VU) — bukan alasan untuk membuang run itu, tapi alasan untuk melaporkan rentang, bukan angka tunggal.

RSS delta @1 dan @10 signer (tak ditampilkan di tabel) berosilasi di sekitar nol dan kadang negatif — pada skala sekecil itu, fluktuasi heap Go runtime sendiri lebih besar dari alokasi satu/sepuluh signer (~108 KiB–1,08 MiB), jadi sinyalnya tenggelam di noise. Hanya skala 100 signer (>10 MiB) yang RSS delta-nya reliabel.

### Untuk sidang

Break-even median ≈1,6 signature (rentang 1,2–4,4 dari 3 run) — biaya inisialisasi terbayar setelah 2–5 signature untuk kasus terburuk, dan lebih cepat lagi untuk kasus umum. Trade-off startup kecil untuk workload yang menerbitkan banyak token. Kalau ditanya kenapa rentangnya lebar: jawab jujur — 3 run pada VPS bersama menunjukkan variansi, konsisten dengan yang reviewer duga soal noisy-neighbor; median dipakai sebagai estimasi titik, bukan run tunggal yang kebetulan bagus.

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

## Bonus — bug p-value Mann-Whitney

Saat regenerasi stats ditemukan `p_value = 2 * (1 − normal_cdf(|z|))`. Untuk z = −9,669, `normal_cdf(9,669)` dibulatkan floating-point ke tepat 1,0, sehingga `1 − 1,0 = 0` — catastrophic cancellation, p tercetak `<1e-300`. Diganti dengan `math.erfc(|z|/√2)` (survival function langsung, tanpa pengurangan). p sekarang 4,09e-22, konsisten dengan z. Jika naskah mengutip Mann-Whitney, angka lama itu keliru.
