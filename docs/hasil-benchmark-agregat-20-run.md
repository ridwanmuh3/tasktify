# Hasil Benchmark Agregat 20 Run — FN-DSA Precomputed vs FN-DSA Dinamis vs Algoritma Klasik

Dokumen ini melaporkan hasil agregat dari **20 sweep benchmark independen** (`result.txt`, `result2.txt` … `result20.txt`, 18 Jul – 19 Jul 2026) terhadap enam profil penandatanganan JWT, beserta hasil uji keamanan pendampingnya.

Figure: `figures/multirun/`. Generator: `scripts/generate_multirun_figures.py`. Data numerik tiap batang/titik: `figures/multirun/multirun_data.csv`.

---

## 1. Metodologi Agregasi

### 1.1 Estimator

| Butir | Pilihan | Alasan |
|---|---|---|
| Estimator pusat | **Median lintas 20 run** | Distribusi per-run menceng kanan di bawah beban (ekor GC/penjadwal). Mean tercemar ekor dan pada beberapa metrik **membalik peringkat** — lihat `docs/skenario-pengujian.md` §5.6. |
| Estimator sebaran | **IQR (Q1–Q3)**, digambar sebagai whisker | Bukan *confidence interval*: 20 run bukan sampel independen dari proses stasioner (VPS berbagi host dengan beban tak terkait yang bergeser antar-run). CI parametrik akan melebih-lebihkan presisi. |
| Konvensi kuartil | `statistics.quantiles(n=4, method="exclusive")` | Konsisten untuk seluruh figure. |

### 1.2 Mengapa 20 run, bukan run terbaik

Metrik dilaporkan sebagai **median lintas run**, bukan run tunggal dengan hasil paling menguntungkan. Selain median, dokumen ini melaporkan **win-rate**: berapa dari 20 run di mana precomputed benar-benar mengungguli baseline dinamis.

Win-rate adalah pembeda antara efek nyata dan derau host. Metrik dengan win-rate 20/20 mereproduksi diri di setiap run; metrik dengan win-rate 10/20 adalah lemparan koin, dan run tunggal mana pun yang "menang" di situ adalah artefak seleksi, bukan temuan. Kedua kelas dilaporkan apa adanya di §3 dan §4.

### 1.3 Konfigurasi

| Butir | Nilai |
|---|---|
| Jumlah run | 20 sweep penuh (isolated + stress + attack) |
| Isolated | 1 VU, 100 iterasi, 20 iterasi warmup dibuang |
| Stress | 10 / 30 / 50 VU, 30 s per tahap, `constant-vus`, closed-loop |
| Target | VPS 2 vCPU; k6 dari mesin klien lewat jaringan |
| Algoritma | FN-DSA-Precomputed-512, FN-DSA-512, RS256, ES256, EdDSA, HS256 |

---

## 2. Ringkasan Temuan

1. **Precomputation menghasilkan percepatan ~25–27% yang reproducible** pada seluruh metrik penandatanganan terisolasi, dengan win-rate 16–20 dari 20 run. Ini adalah temuan utama.
2. **FN-DSA Precomputed mengungguli RS256** pada seluruh metrik latensi dan CPU — 3,5× lebih cepat pada pure signing — sambil menyediakan ketahanan kuantum yang tidak dimiliki RSA.
3. **FN-DSA masih tertinggal dari ECC/simetris** (ES256, EdDSA, HS256) sebesar satu hingga dua orde magnitudo pada pure signing. Precomputation memperkecil, tetapi tidak menutup, jarak itu.
4. **Pada beban stres end-to-end, keenam algoritma setara.** Selisih ≤5% dan win-rate mendekati 50% → tidak ada perbedaan yang dapat dibedakan dari derau. Temuan yang dilaporkan adalah *overhead E2E PQC dapat diabaikan*, bukan keunggulan precomputed.
5. **Precomputation adalah tukar-guling waktu-memori**: 110 712 B memori residen permanen per kunci penandatangan sebagai harga percepatan tersebut.
6. **Seluruh profil memblokir 100% dari 7 vektor serangan JWT.** Keamanan lapisan JOSE identik lintas algoritma; PQC tidak memberi keunggulan block-rate.

---

## 3. Skenario Pure Signing

Latensi `SigningMethod.Sign` murni — tanpa serialisasi JWT, Base64URL, atau perakitan compact. Endpoint `/api/benchmark/pure-signing`, sampel GC-free.

| Metrik | FN-DSA-Precomp | FN-DSA-512 | RS256 | ES256 | EdDSA | HS256 |
|---|---|---|---|---|---|---|
| Signing avg (ms) | **0,321** | 0,436 | 1,127 | 0,047 | 0,030 | 0,002 |
| Signing p95 (ms) | **0,408** | 0,556 | 1,398 | 0,067 | 0,042 | 0,003 |

**Precomputed vs dinamis:**

| Metrik | Delta median | Win-rate |
|---|---|---|
| Signing avg | **−26,4%** | **20/20** |
| Signing p95 | **−26,7%** | 18/20 |

Win-rate 20/20 pada `signing avg` berarti precomputed lebih cepat di **setiap** run tanpa kecuali — bukti terkuat dalam kumpulan data ini.

**Precomputed vs klasik:** 3,51× lebih cepat dari RS256; 6,8× lebih lambat dari ES256; 10,7× lebih lambat dari EdDSA; 161× lebih lambat dari HS256.

Figure: `mrun_01_pure_signing_avg_ms.png`, `mrun_02_pure_signing_p95_ms.png`.

---

## 4. Skenario Isolated (Penerbitan JWT, 1 VU)

Generasi token lengkap dari payload benchmark, diukur di sisi server lewat header `X-Token-Generation-Time-Ms` / `X-Refresh-Token-Generation-Time-Ms`.

| Metrik | FN-DSA-Precomp | FN-DSA-512 | RS256 | ES256 | EdDSA | HS256 |
|---|---|---|---|---|---|---|
| Access avg (ms) | **0,329** | 0,436 | 1,138 | 0,059 | 0,043 | 0,014 |
| Access p95 (ms) | **0,424** | 0,561 | 1,405 | 0,084 | 0,063 | 0,024 |
| Refresh avg (ms) | **0,330** | 0,438 | 1,148 | 0,060 | 0,042 | 0,014 |
| Refresh p95 (ms) | **0,428** | 0,572 | 1,420 | 0,086 | 0,063 | 0,025 |
| CPU per token (ms) | **0,400** | 0,550 | 1,250 | 0,100 | 0,100 | 0,050 |

**Precomputed vs dinamis:**

| Metrik | Delta median | Win-rate |
|---|---|---|
| Access avg | −24,5% | 18/20 (18 menang, 2 seri, 0 kalah) |
| Access p95 | −24,4% | 17/20 |
| Refresh avg | −24,6% | 19/20 |
| Refresh p95 | −25,1% | 18/20 |
| CPU per token | −27,3% | 16/20 |

Keunggulan bertahan konsisten dari penandatanganan murni sampai penerbitan token penuh, dan tampak juga pada CPU — jadi percepatan bukan sekadar pergeseran waktu tunggu, melainkan penghematan kerja komputasi nyata.

> **Batas resolusi CPU per token.** `readCPUTicks()` membaca `utime+stime` dari `/proc/self/stat` dalam satuan clock tick `USER_HZ=100`, jadi satu tick = 10 ms, sedangkan satu `Sign` hanya 0,002–1,2 ms. Delta per operasi karena itu bernilai 0 atau 1 tick saja. Setelah dirata-ratakan atas 100 iterasi lalu dibagi dua (access+refresh → per token), setiap pembacaan jatuh pada kisi 50 µs. Estimator ini **tidak bias** secara agregat (tick terakumulasi sebanding dengan CPU sebenarnya), tetapi untuk algoritma di bawah 100 µs nilai sebenarnya berada di bawah kisi: pada 20 run, HS256 terbaca 0,00 sebanyak 8 run dan EdDSA 6 run. **Nilai 0 itu adalah batas resolusi, bukan biaya CPU nol** — wall time pasangannya bukan nol (HS256 14 µs/token). Hanya RS256 (25 tick) dan kedua varian FN-DSA (8 dan 11 tick) yang teresolusi baik, sehingga perbandingan FN-DSA precomputed↔dinamis di atas tidak terpengaruh. Bukti per algoritma: `figures/multirun/multirun_cpu_quantization.csv`.
>
> **Jangan pakai `pure_signing_cpu_time_per_token_ms`.** Field itu terbaca `{"avg": 0, "sd": 0}` untuk keenam algoritma di `benchmark_sign_result.json` — metrik mati, bukan pengukuran. Penyebab: respons endpoint pure-signing pada container yang menjalankan sweep belum memuat field tersebut, sehingga `addStat()` di k6 keluar lebih awal (`if (!stats) return`) dan trend yang sudah dideklarasikan diserialisasi sebagai nol. Bahwa ini bukan nol asli terbukti dari dua sisi: `bench_pure_signing_memory_alloc_kb_avg` (objek `s.resource` yang sama) terisi 3199 KB, dan harness tick-delta berdiri sendiri atas 100 tanda tangan RSA-2048 menghasilkan 2,0 ms — nol tidak masuk akal secara fisik. Kolom CPU/tok pada tabel dan figure `mrun_08` **tidak** memakai field ini; keduanya memakai `cpu_time_per_token_ms` (jalur auth) yang bernilai 0,05–1,4 ms. Dideteksi otomatis oleh `scripts/validate_multirun_data.py` sebagai `dead-metric`.

Figure: `mrun_04` … `mrun_08`.

---

## 5. Memori

### 5.1 RSS proses (tidak sah untuk klaim per-algoritma)

| Profil | RSS median (KB) | Win-rate precomp |
|---|---|---|
| FN-DSA-Precomp | 41 081 | 12/20 |
| FN-DSA-512 | 39 347 | — |

**Metrik ini tidak boleh dipakai untuk klaim memori per-algoritma.** Keenam algoritma dilayani satu proses gateway yang sama, sehingga `VmRSS` mengukur seluruh proses, bukan algoritma yang sedang diuji. Win-rate 12/20 mengonfirmasi angka ini adalah derau. Figure `mrun_03_process_rss_avg_mb.png` disertakan dengan peringatan tercetak di atasnya, semata untuk transparansi — bukan sebagai bukti.

### 5.2 Memori persisten precomputation (sumber sah)

Sumber: `pkg/fndsa/precompute_profile_test.go` (`PersistentBytes()`), proses Go terisolasi, deterministik dan tidak bergantung host.

| Profil | Memori persisten per signer |
|---|---|
| FN-DSA-Precomputed-512 | **110 712 B (108,1 KB)** |
| FN-DSA-512 (dinamis) | 0 B — tidak menyimpan kunci terekspansi |

Inilah **sisi biaya** dari tukar-guling. Analisis titik impas terkait ada pada `fndsa_precompute_profile.json`: `break_even_signatures_mean` ≈ 2,42 tanda tangan, artinya biaya pembangunan signer terbayar setelah ~3 tanda tangan.

Figure: `mrun_15_precompute_persistent_memory_per_key_kb.png`.

---

## 6. Skenario Stress (Round-trip Penuh di Bawah Konkurensi)

`/api/auth/signin` (bcrypt + lookup DB + generasi JWT) dan `/api/auth/refresh` (verifikasi + rotasi token).

| Metrik @ VU | FN-DSA-Precomp | FN-DSA-512 | RS256 | ES256 | EdDSA | HS256 |
|---|---|---|---|---|---|---|
| Login avg @10 | 386,96 | 395,70 | 400,81 | 379,95 | 378,55 | 380,26 |
| Login avg @30 | 1127,33 | 1138,60 | 1196,65 | 1120,56 | 1140,81 | 1137,81 |
| Login avg @50 | 1903,06 | 1900,42 | 1932,26 | 1877,07 | 1900,15 | 1842,75 |
| Login p95 @50 | 3822,56 | 3829,37 | 3892,10 | 3871,75 | 3836,52 | 3743,03 |
| Refresh avg @50 | 1748,15 | 1762,92 | 1792,98 | 1721,03 | 1721,26 | 1708,67 |
| Refresh p95 @50 | 3634,56 | 3700,95 | 3806,34 | 3601,11 | 3704,17 | 3585,96 |
| Throughput @50 (req/s) | 14,03 | 13,95 | 13,68 | 14,23 | 14,10 | 14,32 |

**Win-rate precomputed vs dinamis (10 / 30 / 50 VU):**

| Metrik | 10 VU | 30 VU | 50 VU |
|---|---|---|---|
| Login avg | 12/20 | 13/20 | 9/20 |
| Login p95 | 11/20 | 12/20 | 9/20 |
| Refresh avg | 12/20 | 12/20 | 11/20 |
| Refresh p95 | 12/20 | 14/20 | 11/20 |
| Throughput | 14/20 | 10/20 | 11/20 |

**Interpretasi (wajib dibaca).** Seluruh win-rate berada di sekitar 10/20 dan seluruh selisih median ≤5%. **Tidak ada perbedaan yang dapat dibedakan dari derau host pada lapisan ini.** Penjelasannya struktural: latensi round-trip didominasi bcrypt, akses basis data, dan antrean — biaya penandatanganan (0,3–1,1 ms) tenggelam di dalam total 380–1900 ms, yakni di bawah 0,3% dari anggaran latensi.

Klaim yang benar untuk lapisan ini adalah **"overhead PQC end-to-end dapat diabaikan"** — yang justru merupakan hasil positif bagi kelayakan penerapan. Klaim **"precomputed lebih cepat di bawah beban" tidak didukung data ini** dan tidak boleh ditulis.

Figure: `mrun_09` … `mrun_13`.

---

## 7. Pendampingan Uji Keamanan

Sumber: `backend/benchmark-results/adversarial_result.json` (k6 `adversarial_jwt.js`, 7 vektor × 10 iterasi × 2 endpoint = 140 request).

| # | Vektor serangan | Rujukan | Block rate |
|---|---|---|---|
| 1 | Signature Tampering | RFC 8725 §3.3 | 100% |
| 2 | Token Forgery | RFC 8725 §3.1, §3.3 | 100% |
| 3 | Algorithm Confusion | RFC 8725 §3.1 | 100% |
| 4 | None Algorithm | RFC 7519 §6; RFC 8725 §3.1–3.2 | 100% |
| 5 | Payload Manipulation | RFC 8725 §3.3 | 100% |
| 6 | Cross-Algorithm Injection | RFC 8725 §3.1 | 100% |
| 7 | RS256→HS256 Key Confusion | RFC 8725 §3.1 | 100% |

Total: 140/140 request diblokir; 7 PROTECTED, 0 VULNERABLE.

**Interpretasi.** Hasil ini **tidak membedakan** algoritma: keenam profil memblokir seluruh vektor, karena vektor-vektor itu menyerang lapisan JOSE (validasi `alg`, verifikasi tanda tangan, parsing compact) yang identik untuk semua algoritma. Keunggulan FN-DSA atas RS256/ES256/EdDSA bukanlah block-rate, melainkan **ketahanan terhadap lawan kuantum** — properti yang tidak diukur oleh uji ini dan tidak dapat diukur oleh uji black-box mana pun.

Uji keamanan pada tingkat primitif FN-DSA (norm-bound, cross-key forgery, domain-separation, pre-hash confusion, bit-flip, truncation) berada di dokumen terpisah: **[`docs/pengujian-kat-dan-adversarial-fndsa.md`](pengujian-kat-dan-adversarial-fndsa.md)**. Di sana hasil precomputed dan dinamis identik pada seluruh vektor berpasangan — precomputation tidak melemahkan penolakan yang diuji.

Figure: `fig_13_security_attack_block_rate_pct.png`.

---

## 8. Indeks Figure

| Berkas | Skenario | Metrik | Win-rate precomp |
|---|---|---|---|
| `mrun_01_pure_signing_avg_ms.png` | Pure | Signing avg | 20/20 |
| `mrun_02_pure_signing_p95_ms.png` | Pure | Signing p95 | 18/20 |
| `mrun_03_process_rss_avg_mb.png` | Pure/Isolated | RSS proses (**tidak sah per-alg**) | 12/20 (derau) |
| `mrun_04_isolated_access_avg_ms.png` | Isolated | Access avg | 18/20 |
| `mrun_05_isolated_access_p95_ms.png` | Isolated | Access p95 | 17/20 |
| `mrun_06_isolated_refresh_avg_ms.png` | Isolated | Refresh avg | 19/20 |
| `mrun_07_isolated_refresh_p95_ms.png` | Isolated | Refresh p95 | 18/20 |
| `mrun_08_isolated_cpu_per_token_us.png` | Isolated | CPU per token (µs) | 16/20 |
| `mrun_09_stress_login_avg_ms.png` | Stress | Login avg | 12/13/9 |
| `mrun_10_stress_login_p95_ms.png` | Stress | Login p95 | 11/12/9 |
| `mrun_11_stress_refresh_avg_ms.png` | Stress | Refresh avg | 12/12/11 |
| `mrun_12_stress_refresh_p95_ms.png` | Stress | Refresh p95 | 12/14/11 |
| `mrun_13_stress_throughput_rps.png` | Stress | Throughput | 14/10/11 |
| `fig_13_security_attack_block_rate_pct.png` | Attack | Block rate 7 vektor | seri (100% semua) |
| `mrun_15_precompute_persistent_memory_per_key_kb.png` | Profile | Memori persisten/kunci | biaya, bukan keunggulan |

Bentuk grafik: figure latensi pure/isolated (`mrun_01`, `mrun_02`, `mrun_04`–`mrun_07`) memakai batang skala log10, karena rentang HS256↔RS256 mencapai tiga orde magnitudo. Dua figure memakai skala linear: `mrun_03` (RSS, rentang sempit) dan `mrun_08` (CPU per token) — log10 tidak dipakai di `mrun_08` karena batas bawah IQR bernilai 0 pada HS256 dan EdDSA, dan sumbu log akan menjepit nilai 0 itu ke dasar sumbu sehingga menyesatkan. Figure stress memakai batang berkelompok per level VU — **bukan** grafik garis, karena keenam seri bertumpuk sehingga garis menjadi satu pita tebal tanpa informasi. Setiap batang mencantumkan IQR numerik di bawah label algoritma.

---

## 9. Batasan

1. **Host bersama.** VPS menjalankan beban tak terkait. Ini alasan agregasi 20 run dan pelaporan IQR, bukan CI.
2. **Selisih stress berada di dalam derau.** Lihat §6. Tidak boleh diklaim sebagai keunggulan.
3. **RSS proses tidak sah per-algoritma.** Lihat §5.1.
4. **20 run bukan sampel acak.** Run berurutan dalam waktu; drift host tidak diacak. Uji signifikansi formal (Welch/Mann-Whitney) belum dijalankan pada agregat 20 run ini — `scripts/benchmark_stat_tests.py` masih beroperasi pada berkas hasil tunggal.
5. **Win-rate bukan uji hipotesis.** Angka 20/20 kuat secara deskriptif (di bawah hipotesis nol "tak ada beda", peluangnya 2⁻²⁰), tetapi run tidak sepenuhnya independen sehingga p-value literal tidak boleh dikutip.
6. **Hasil terikat host.** Angka absolut berlaku untuk VPS 2 vCPU ini; yang portabel adalah rasio, bukan milidetiknya.

---

## 10. Reproduksi

```bash
# Regenerasi seluruh figure agregat dari result*.txt yang ada:
python3 scripts/generate_multirun_figures.py

# Keluaran: figures/multirun/ (PNG + multirun_data.csv + multirun_manifest.csv)

# Sweep benchmark baru (menambah result*.txt berikutnya):
make bench-figures-repeat VPS_SSH=<user>@<host> BENCH_HOST=<host> RUNS=3
```

Skrip menerima berapa pun jumlah `result*.txt`; jumlah run yang dipakai dicatat di `figures/multirun/multirun_runs.json` dan di kolom `runs` pada `multirun_data.csv`.

---

*Dibuat dari 20 laporan `result*.txt` (18–19 Jul 2026) pada commit `3e2cdc1`. Metrik memori persisten berasal dari `backend/benchmark-results/fndsa_precompute_profile.json` (rata-rata 3 run VPS); block rate serangan dari `backend/benchmark-results/adversarial_result.json`.*
