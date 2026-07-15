# Dasar Pemilihan Vektor Serangan

Dokumen ini menjelaskan **bagaimana** himpunan vektor serangan diturunkan, bukan sekadar apa rujukan tiap vektor. Tabel pemetaan per-vektor ada di [skenario-pengujian.md §6.5–§6.6](skenario-pengujian.md). Dokumen ini adalah bahan untuk Bab III (Metodologi), subbab yang mendahului tabel tersebut.

Rujukan mengikuti penomoran yang sama seperti di [skenario-pengujian.md §15](skenario-pengujian.md): [1] RFC 7519, [2] RFC 8725, [3] RFC 8259, [4] Falcon spec (Fouque dkk.), [5] Goldwasser–Micali–Rivest (EUF-CMA), [6] FIPS 204, [7] FIPS 206, [8] RFC 7515. Rujukan taksonomi eksternal ditambahkan: [9] OWASP API Security Top 10 (2023), [10] MITRE CWE.

Pertanyaan penguji yang dijawab dokumen ini: *"kenapa himpunan vektor ini yang dipilih, dan atas dasar apa dianggap cukup?"* Jawaban per-baris "vektor X berpijak pada RFC Y" hanya membuktikan tiap vektor absah, bukan bahwa pemilihannya sistematis. Yang membuktikan sistematis adalah **prosedur penurunan** di bawah.

---

## 1. Model Ancaman (prasyarat — tanpa ini pemilihan vektor tak dapat dipertanggungjawabkan)

Vektor serangan hanya dapat dipertanggungjawabkan jika kemampuan penyerang didefinisikan lebih dulu. Tiap vektor kemudian merupakan satu kemampuan penyerang yang dieksploitasi pada satu titik validasi.

### 1.1 Kemampuan penyerang (asumsi)

- Dapat mengamati dan memodifikasi token yang lewat (posisi network / klien jahat).
- Memiliki kunci publik verifikasi (bukan rahasia; disebarkan untuk verifikasi).
- Dapat menyusun header dan payload JWT arbitrer serta mengirim request HTTP arbitrer ke gateway.
- Dapat memakai ulang token lama yang pernah sah (replay).

### 1.2 Batasan penyerang (di luar cakupan)

- Tidak memiliki kunci privat penandatanganan.
- Tidak memiliki akses baca memori proses server, core dump, atau swap (dibahas terpisah sebagai isu memory hardening, bukan vektor JWT).
- Tidak melakukan side-channel atau fault injection terhadap primitif FN-DSA (dibatasi eksplisit di Batasan Penelitian).

### 1.3 Aset yang dilindungi

Integritas dan keaslian klaim identitas dalam token (siapa, untuk layanan apa, sampai kapan), serta pemisahan peran token akses versus token penyegaran.

---

## 2. Kerangka Seleksi (tiga sumbu)

Himpunan vektor tidak disusun ad hoc, melainkan diturunkan dari tiga sumbu yang saling menyilang.

### 2.1 Sumbu utama — enumerasi standar

RFC 8725 [2] adalah *Best Current Practices*: dokumen IETF yang isinya justru katalog serangan JWT yang diketahui beserta mitigasinya. Karena itu "memilih vektor" setara dengan "mengenumerasi tiap sub-bagian RFC 8725 §3 dan tiap klaim RFC 7519 [1] §4.1 serta tiap header RFC 7515 [8] §4.1, lalu menurunkan satu kasus uji per butir yang relevan". Kelengkapan dibuktikan lewat matriks di §4, bukan lewat jumlah vektor.

### 2.2 Sumbu pelengkap — model ancaman

Tiap vektor dipetakan ke satu kemampuan penyerang di §1.1. Ini menjelaskan kenapa vektor seperti *algorithm confusion*, *none algorithm*, dan *key confusion* wajib ada: ketiganya tepat berada di batas kemampuan "punya kunci publik, tidak punya kunci privat" — penyerang mencoba mengubah token yang tak dapat ia tandatangani menjadi token yang lolos verifikasi tanpa kunci privat.

### 2.3 Sumbu validasi silang — taksonomi eksternal

Himpunan dipetakan ke taksonomi industri agar tidak hanya bergantung pada RFC: OWASP API Security Top 10 [9] (terutama API2:2023 Broken Authentication) dan MITRE CWE [10] (CWE-347 Improper Verification of Cryptographic Signature, CWE-345 Insufficient Verification of Data Authenticity, CWE-290 Authentication Bypass by Spoofing, CWE-294 Authentication Bypass by Capture-replay). Peta di §5.

---

## 3. Kriteria Penempatan (E2E vs unit vs gap)

Kriteria pemisahan bersifat objektif, bukan berdasar kemudahan. Dasarnya adalah kemampuan black-box pada §1.1: pengujian k6 di lapisan HTTP tidak memiliki kunci privat, sehingga tidak dapat membuat token sah dengan klaim arbitrer.

| Jenis vektor | Lokasi uji | Alasan |
|---|---|---|
| Cukup memanipulasi token (tanpa perlu tanda tangan sah baru) | E2E (k6, black-box) | Sesuai kemampuan penyerang nyata: hanya bisa mengubah, tidak bisa menandatangani |
| Butuh token sah dengan klaim/konteks spesifik (issuer, subject, nbf, iat, typ) | Unit test Go | Butuh kunci privat untuk membentuk token sah; hanya tersedia di dalam proses |
| Butuh state lintas-request (replay, revocation, rotation) | Gap — diakui eksplisit | Butuh penyimpanan stateful yang belum ada; jangan diklaim tertutup |

Konsekuensi: 9 vektor E2E di [skenario-pengujian.md §6.5](skenario-pengujian.md) adalah tepat vektor yang dapat diserang tanpa kunci privat. Sisanya di unit test bukan karena lebih mudah, melainkan karena secara metodologis tidak dapat diuji dari black-box.

---

## 4. Matriks Coverage RFC 8725 §3

Bukti kelengkapan: tiap sub-bagian §3 yang berlaku untuk profil JWS-signed (bukan JWE) dipetakan ke status. Detail per-vektor ada di [§6.5](skenario-pengujian.md).

| Klausa RFC 8725 [2] | Serangan yang dicegah | Status | Lokasi |
|---|---|---|---|
| §3.1 Perform Algorithm Verification | alg confusion, none, cross-alg injection, key confusion | Tertutup | k6 #3/#4/#8/#9 + unit |
| §3.2 Use Appropriate Algorithms | algoritma di luar allow-list | Tertutup | allow-list gateway + unit (`algorithm case variation`) |
| §3.3 Validate All Cryptographic Operations | signature tampering, payload manipulation, unsigned token | Tertutup | k6 #1/#5/#7 + unit |
| §3.4 Validate Cryptographic Inputs | signature terpotong, over-norm signature | Tertutup (unit) | `fndsa_adversarial_test.go` |
| §3.5 Sufficient Entropy | kunci lemah | Di luar cakupan | keygen memakai RNG sistem; tidak diuji sebagai vektor |
| §3.6 Avoid Compression (JWE) | — | Tidak berlaku | profil JWS-signed, bukan JWE |
| §3.7 Use UTF-8 | ambiguitas encoding | Tertutup (parser) | invalid Base64URL / malformed JSON, RFC 8259 [3] |
| §3.8 Validate Issuer and Subject | issuer/subject palsu | Tertutup (unit) | `jwt_security_test.go` — issuer, subject, sub=user_id |
| §3.9 Use and Validate Audience | audience salah/kosong | **Gap → ditutup di PR ini** | issue + validasi `aud`, unit test |
| §3.10 Do Not Trust Received Public Keys | kunci pihak penyerang via header | **Gap → ditutup di PR ini** | guard `jku`/`jwk`/`x5u`/`x5c`, unit test |
| §3.11 Use Explicit Typing | type confusion antar jenis token | Tertutup | `typ` = `at+jwt`/`rt+jwt`, unit + middleware |
| §3.12 Mutually Exclusive Validation | access dipakai sebagai refresh dan sebaliknya | Tertutup sebagian | `token_use` diperiksa; replay/reuse = gap stateful |

Butir yang ditandai "Gap → ditutup di PR ini" adalah pekerjaan P1 yang menyertai dokumen ini. Butir replay/reuse tetap gap karena memerlukan penyimpanan stateful (JTI store / rotasi refresh token dengan invalidasi) — diakui jujur, tidak diklaim tertutup.

---

## 5. Peta ke Taksonomi Eksternal

| Vektor (kelompok) | OWASP API [9] | CWE [10] |
|---|---|---|
| Signature tampering, payload manipulation | API2:2023 | CWE-347, CWE-345 |
| Algorithm confusion, none, cross-alg, key confusion | API2:2023 | CWE-347, CWE-290 |
| Unsigned / empty signature | API2:2023 | CWE-347 |
| Expired token, nbf/iat tidak logis | API2:2023 | CWE-613 (Insufficient Session Expiration) |
| Issuer/subject/audience salah | API2:2023 | CWE-290 |
| Type confusion access/refresh | API2:2023 | CWE-290 |
| Replay refresh token (gap) | API2:2023 | CWE-294 |

---

## 6. Gap yang Diakui Eksplisit

Kejujuran cakupan menguatkan, bukan melemahkan. Gap berikut dinyatakan terbuka:

- **Replay / reuse refresh token** (§3.12, CWE-294) — butuh JTI store atau rotasi refresh token dengan invalidasi; belum diimplementasikan.
- **Revoked / rotated key** — butuh key registry, `kid`, dan prosedur rotasi operasional; di luar cakupan.
- **Side-channel dan fault injection** terhadap primitif FN-DSA — dibatasi eksplisit di Batasan Penelitian.
- **Entropi kunci (§3.5)** — bergantung RNG sistem; tidak diuji sebagai vektor.

Ketiga sumbu di §2 memberi pemilihan yang dapat dipertanggungjawabkan; matriks §4 memberi bukti kelengkapan relatif terhadap standar; §6 memberi batas jujur cakupan.
