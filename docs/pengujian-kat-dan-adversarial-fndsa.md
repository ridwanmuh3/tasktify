# Pengujian *Known-Answer Test* (KAT) dan Adversarial pada Primitif FN-DSA/Falcon

Dokumen ini mendokumentasikan dua kelas pengujian yang dijalankan langsung terhadap **primitif tanda tangan** FN-DSA/Falcon di `backend/pkg/fndsa`, terpisah dari pengujian lapisan JOSE/JWT:

1. **Known-Answer Test (KAT)** — pengujian *conformance* deterministik: memastikan implementasi menghasilkan keluaran yang identik bit-per-bit dengan vektor referensi untuk masukan yang telah ditentukan.
2. **Pengujian adversarial** — pengujian negatif terhadap kriteria penerimaan algoritma `Verify`: memastikan masukan yang seharusnya ditolak memang ditolak.

Dokumen ini melengkapi `docs/skenario-pengujian.md` §6.5 (vektor JWT/JOSE) dan §6.6 (ringkasan vektor adversarial primitif), dan menjadi rujukan rinci untuk keduanya.

> **Pembatasan klaim (dibaca lebih dulu).** Tidak satu pun hasil dalam dokumen ini merupakan bukti bahwa FN-DSA aman, bahwa implementasi ini bebas cacat, atau bahwa sistem Tasktify aman. Bagian §7 menjabarkan secara eksplisit apa yang **tidak** dibuktikan oleh pengujian ini. Rumusan klaim yang diizinkan untuk naskah ada di §8.

---

## 1. Ruang Lingkup dan Posisi Epistemik

### 1.1 Mengapa kedua kelas uji ini terpisah dari uji JWT

Suite adversarial JWT (`backend/k6/adversarial_jwt.js`, `backend/pkg/jwt/jwt_confusion_attack_test.go`) berpijak pada RFC 7519 [1] dan RFC 8725 [2]. RFC tersebut mendefinisikan *envelope* JOSE — verifikasi header `alg`, klaim `exp`/`iat`, dan *compact serialization*. RFC tersebut **tidak menyatakan apa pun** tentang ketahanan skema tanda tangan yang membungkusnya terhadap pemalsuan; itu properti primitif kriptografi, bukan properti format token.

Konsekuensinya: uji yang memalsukan header JWT hanya dapat membuktikan kebenaran kode *parsing envelope*. Uji tersebut tidak dapat menyokong klaim apa pun mengenai FN-DSA itu sendiri. Karena itu pengujian di dokumen ini memanggil `fndsa.Sign`/`fndsa.Verify` secara langsung, melewati `pkg/jwt`, JSON, dan base64url sepenuhnya.

### 1.2 Apa yang dapat dan tidak dapat dibuktikan KAT

KAT adalah metodologi validasi *conformance* baku dalam praktik kriptografi tersertifikasi. Program validasi algoritma kriptografi NIST (CAVP/ACVP) [3] menggunakan pertukaran vektor uji bergaya KAT sebagai mekanisme validasi implementasi, dan ISO/IEC 19790 [4] — yang diadopsi FIPS 140-3 — mensyaratkan *self-test* algoritma kriptografi berbasis known-answer sebelum modul dianggap operasional.

| KAT **membuktikan** | KAT **tidak membuktikan** |
|---|---|
| Implementasi mereproduksi keluaran referensi secara *bit-exact* untuk himpunan masukan yang diuji | Kebenaran untuk masukan di luar himpunan tersebut |
| Tidak ada regresi fungsional antar-commit pada jalur yang tercakup | Ketiadaan cacat (lihat Dijkstra [5]: pengujian menunjukkan keberadaan *bug*, bukan ketiadaannya) |
| Interoperabilitas dengan implementasi yang menghasilkan vektor tersebut | Interoperabilitas dengan implementasi lain yang tidak diuji |
| Optimasi (precomputation) mempertahankan semantik keluaran | Keamanan kriptografis, ketahanan *side-channel*, atau kualitas RNG |

### 1.3 Apa yang dapat dan tidak dapat dibuktikan uji adversarial

Uji adversarial di sini berbentuk **upaya falsifikasi terhadap syarat perlu (*necessary conditions*)** keamanan EUF-CMA [6]. Skema yang gagal pada salah satu vektor di §5 secara trivial gagal EUF-CMA. Sebaliknya, **lolosnya seluruh vektor bukan bukti EUF-CMA** — hanya berarti upaya falsifikasi pada himpunan vektor tersebut tidak berhasil. Keamanan EUF-CMA Falcon bersandar pada reduksi ke masalah kekisi (NTRU/SIS) sebagaimana diargumentasikan pada spesifikasi Falcon [7], bukan pada pengujian empiris.

---

## 2. Artefak dan Perintah Eksekusi

| Perintah | Cakupan | Lokasi eksekusi |
|---|---|---|
| `make falcon-kat` | `TestFNDSA_KAT` + `TestFNDSA_Precomputed_KAT` saja (KAT end-to-end) | Klien atau VPS (deterministik, hasil identik) |
| `make adversarial-kat` | KAT end-to-end + seluruh `TestAttack_*` + `TestPrecomputedSignRejectsTampering`, mode `-v -count=1` | Klien atau VPS |
| `make hostinger-adversarial-kat` | `make adversarial-kat` melalui SSH pada VPS target | VPS (dipakai untuk pengambilan data skripsi) |
| `make falcon-check` | `falcon-kat` + seluruh test `pkg/fndsa`, `pkg/jwt`, `pkg/utils/jwtutils`, `cmd/keygen`, validasi konfigurasi Compose, dan `k6 inspect` | Klien (gerbang pra-benchmark) |

Definisi target ada di `backend/Makefile:241` (`falcon-kat`), `backend/Makefile:278` (`adversarial-kat`), dan `backend/Makefile:375` (`hostinger-adversarial-kat`). Orkestrasi skripsi memanggil `hostinger-adversarial-kat` satu kali di akhir `bench-figures-repeat` (`Makefile:186`).

**Catatan lokasi eksekusi.** KAT bersifat deterministik dan tidak bergantung pada *host* (seluruh sumber acak digantikan seed tetap, lihat §4.1), sehingga hasil di klien dan di VPS wajib identik. Alasan menjalankannya di VPS bukan validitas numerik, melainkan **pengikatan bukti**: hasil KAT harus berasal dari toolchain dan *binary* yang sama dengan yang mengeksekusi benchmark, agar angka performa dan bukti kebenaran merujuk pada artefak yang sama.

---

## 3. Objek Uji: Parameter Implementasi

Nilai berikut diambil langsung dari kode dan dipakai di seluruh dokumen.

| Parameter | logn = 9 (FN-DSA-512) | logn = 10 (FN-DSA-1024) | Sumber |
|---|---|---|---|
| Derajat n | 512 | 1024 | — |
| Ukuran *verifying key* | 897 B | 1793 B | `util.go:VerifyingKeySize` |
| Ukuran *signing key* | 1281 B | 2305 B | `util.go:SigningKeySize` |
| Ukuran signature | 666 B | 1280 B | `util.go:SignatureSize` |
| Batas norma kuadrat β² (`sqbeta`) | 34 034 726 | 70 265 242 | `mq.go:268` |
| Byte header signature | `0x30 \| logn` | `0x30 \| logn` | `vrfy.go:verify_inner` |
| Panjang nonce | 40 B (`sig[1:41]`) | 40 B | `vrfy.go:verify_inner` |

Ukuran kunci dan signature pada tabel di atas sama dengan Falcon-512 dan Falcon-1024 pada spesifikasi Round-3 [7].

Struktur algoritma `Verify` (`vrfy.go`), yang menjadi objek seluruh uji adversarial di §5:

1. Validasi *header nibble* kunci (`0x0_`) dan signature (`0x3_`), kecocokan `logn` keduanya, rentang `logn` yang diizinkan, dan panjang buffer eksak. Kegagalan mana pun → `false`.
2. Dekode kunci publik `h` (`modq_decode`) dan `s2` (`comp_decode`, format terkompresi). Kegagalan dekode → `false`.
3. Hitung `c = hash_to_point(nonce, H(vkey), ctx, id, data)`.
4. Hitung `s1 = c − s2·h` di ring ℤq[x]/(xⁿ+1), q = 12289.
5. Terima **jika dan hanya jika** `‖s1‖² + ‖s2‖² ≤ sqbeta[logn]`, dengan pemeriksaan luapan `norm1 < −norm2` mendahului penjumlahan.

Langkah 5 adalah kriteria penerimaan Falcon [7]; langkah 3 adalah titik pengikatan konteks domain (§5.3).

---

## 4. Bagian A — Known-Answer Test FN-DSA/Falcon

### 4.1 Konstruksi vektor uji end-to-end

`TestFNDSA_KAT` (`backend/pkg/fndsa/fndsa_test.go:180`) menguji rantai penuh *keygen → sign → verify* secara deterministik. Untuk vektor ke-*j* pada derajat 2^logn:

```
seed1 = 0x00 ‖ logn ‖ j        (logn 1 byte; j 4 byte little-endian)
seed2 = 0x01 ‖ logn ‖ j

seed_kgen  = SHAKE256(seed1) → 32 byte
(sk, vk)   = KeyGen(logn, seed_kgen)

ctx = "domain" (6 byte)
msg = "message" (7 byte)
id  = 0 (raw) jika j genap; crypto.SHA3_256 dengan msg ← SHA3-256(msg) jika j ganjil

sig = sign_inner_seeded(logn, seed2, sk, ctx, id, msg)

KAT[j] =? SHA3-256(sk ‖ vk ‖ sig)
```

Determinisme diperoleh dengan mengganti seluruh sumber acak: `KeyGen` menerima `bytes.Reader` atas seed tetap, dan penandatanganan memakai `sign_inner_seeded` yang menurunkan nonce serta *randomness* sampler Gaussian dari `seed2`. Setiap vektor juga diverifikasi ulang dengan `Verify`/`VerifyWeak` sebelum digest dibandingkan, sehingga kegagalan digest dapat dibedakan dari kegagalan verifikasi.

Digest mencakup **sk ‖ vk ‖ sig** sekaligus. Konsekuensinya, satu perbandingan menutup tiga jalur: pembangkitan kunci, pengkodean kunci, dan penandatanganan. Kelemahan konstruksi ini adalah **lokalisasi kegagalan yang buruk** — digest yang tidak cocok tidak menunjukkan komponen mana yang berubah. Itulah alasan KAT tingkat komponen di §4.3 tetap dipertahankan.

### 4.2 Cakupan vektor

| Uji | Derajat | Vektor/derajat | Total vektor |
|---|---|---|---|
| `TestFNDSA_KAT` | logn 2–10 (n = 4 … 1024) | 10 | **90** |
| `TestFNDSA_Precomputed_KAT` | logn 9, 10 | 10 | **20** |

Derajat 4–256 (logn 2–8) **bukan derajat aman**; keduanya disegregasi di tingkat API lewat `SignWeak`/`VerifyWeak` dan hanya dipakai untuk pengujian (`doc.go:10-17`). Cakupannya di KAT bernilai sebagai uji jalur kode (rutin NTT, pengkodean, sampler pada ukuran berbeda), bukan sebagai bukti keamanan pada derajat tersebut. **Konfigurasi produksi Tasktify hanya memakai logn = 9 (FN-DSA-512).**

### 4.3 KAT tingkat komponen

Selain KAT end-to-end, `pkg/fndsa` memuat vektor referensi per komponen. Seluruhnya dijalankan oleh `make falcon-check` (`go test ./fndsa`), bukan oleh `falcon-kat`.

| Uji | Apa yang dikunci | Volume vektor | Berkas |
|---|---|---|---|
| `TestKeygenRef` | Digest SHA-256 atas koefisien (f, g, F, G) hasil `keygen_inner` untuk seed `"test<i>"` | 100 seed × 3 derajat (256/512/1024) = **300** | `kgen_test.go:62` |
| `TestKeygenSelf` | Invarian aljabar NTRU `f·G − g·F ≡ 12289 (mod xⁿ+1)` dan rentang koefisien | 10 seed × 9 derajat | `kgen_test.go:42` |
| `TestVerifyOrig512` / `TestVerifyOrig1024` | Verifikasi triplet (pk, msg, sig) pada **format Falcon asli** (`id = 0xFFFFFFFF`, tanpa pencampuran ctx/H(vk)), plus penolakan seluruh *bit-flip* signature pada vektor pertama | 5 triplet per derajat; ~5 328 dan ~10 240 verifikasi *bit-flip* | `vrfy_test.go:9` |
| `TestSampler` | Keluaran sampler Gaussian terhadap vektor yang dibangkitkan implementasi C referensi | 1 vektor | `sign_sampler_test.go:15` |
| `TestSignCore` | `sign_core` atas basis trapdoor tetap dan seed tetap | 1 vektor | `sign_core_test.go:9` |
| `TestSign` | Signature FN-DSA-512 *bit-exact* dari seed konstan `0x54…` | 1 vektor | `sign_test.go:8` |

`TestVerifyOrig*` penting secara metodologis: `id = 0xFFFFFFFF` memaksa `hash_to_point` mengambil cabang **Falcon asli** (`util.go:79-81`) yang hanya menyerap `nonce ‖ data`, tanpa `H(vkey)`, tanpa `ctx`, dan tanpa OID pra-hash. Uji ini karenanya memvalidasi verifier terhadap format signature Falcon Round-3 [7], bukan terhadap varian ber-konteks yang dipakai Tasktify.

### 4.4 Provenance vektor dan batasan validitasnya

Poin ini wajib dinyatakan dalam naskah dan **tidak boleh dilewati**.

1. **Vektor KAT di repositori ini bukan vektor uji resmi NIST untuk FIPS 206.** Vektor pada `fndsa_test.go`, `kgen_test.go`, dan `vrfy_test.go` adalah vektor internal implementasi; komentar pada `sign_sampler_test.go:16-17` menyatakan eksplisit bahwa vektor sampler "was generated with the C implementation". Konsekuensinya, kecocokan digest membuktikan **kesesuaian silang dengan implementasi referensi keluarga yang sama**, bukan kesesuaian dengan standar NIST.
2. **Implementasi ini secara eksplisit menyatakan dirinya spekulatif.** `doc.go:3-8`: *"FN-DSA is currently being specified by NIST … This implementation is a prospective guess on what FN-DSA will look like. When the (draft) standard is published, this code will be adjusted, very probably breaking backward compatibility."* Naskah harus memposisikan implementasi sebagai **profil eksperimen pra-standar**, bukan implementasi FIPS 206.
3. **Status FIPS 206 harus diverifikasi ulang saat publikasi.** Catatan status pada `docs/skenario-pengujian.md` §15 [7] menyatakan Initial Public Draft belum terbit ke URL publik stabil per akhir 2025. Status ini dapat berubah; verifikasi ke sumber NIST wajib dilakukan sebelum naskah difinalkan. Bila FIPS 206 telah terbit, seluruh klaim *conformance* harus diuji ulang terhadap vektor resminya, dan hasil pada dokumen ini diturunkan statusnya menjadi *conformance* terhadap Falcon Round-3 [7] semata.
4. **Provenance *upstream* belum tercatat di repositori.** Tidak ada berkas LICENSE, `go.mod` *replace*, atau catatan versi yang mengidentifikasi asal `pkg/fndsa`. Untuk reproduktibilitas, URL dan *commit* sumber asli beserta ringkasan modifikasi lokal harus dicatat (lihat `docs/revisi-todo.md` P0 "Jelaskan library, commit, modifikasi kode").

### 4.5 Nilai khusus KAT precomputed

`TestFNDSA_Precomputed_KAT` (`fndsa_test.go:193`) menjalankan konstruksi §4.1 dengan `PrecomputedSigner.signSeeded` menggantikan `sign_inner_seeded`, lalu membandingkan terhadap **tabel KAT yang sama persis** (`kat_512`, `kat_1024`).

Ini adalah bukti terkuat yang tersedia bagi optimasi yang diusulkan: pada seed, kunci, konteks, dan pesan yang identik, *signer* precomputed menghasilkan **byte signature yang identik** dengan *signer* dinamis. Precomputation karenanya terbukti **mempertahankan semantik (*semantics-preserving*)** pada seluruh 20 vektor tersebut — bukan sekadar "menghasilkan signature yang juga valid", melainkan menghasilkan signature yang sama.

Batasannya tetap sama seperti KAT mana pun: kesetaraan terbukti pada 20 pasang masukan yang diuji, bukan pada seluruh ruang masukan. Klaim yang diizinkan adalah *"tidak ditemukan divergensi keluaran pada seluruh vektor KAT yang diuji"*, bukan *"ekuivalen secara fungsional"* — kesetaraan fungsional penuh memerlukan verifikasi formal atau argumen kesetaraan program, yang tidak dilakukan dalam penelitian ini.

---

## 5. Bagian B — Suite Adversarial terhadap Primitif

Berkas: `backend/pkg/fndsa/fndsa_adversarial_test.go`.

### 5.1 Metodologi pemasangan (*paired subtests*)

Lima dari enam vektor dijalankan dua kali melalui helper `signerVariants()` (`fndsa_adversarial_test.go:125`), dengan kunci dan pesan identik:

- `Falcon (FN-DSA-512 original/dynamic)` — `fndsa.Sign`, baseline.
- `Falcon Precomputed (FN-DSA-Precomputed-512)` — `PrecomputedSigner.Sign`, metode yang diusulkan.

Rancangan berpasangan ini dipilih agar hasil PROTECTED/VULNERABLE kedua varian dapat dibandingkan langsung di bawah kondisi yang sama, sehingga klaim "precomputation tidak melemahkan penolakan" memiliki bukti terkontrol dan bukan sekadar asumsi.

Vektor norm-bound (§5.2) **tidak** dipasangkan: pemeriksaannya berada di sisi `Verify()` dan tidak menyentuh jalur signing sama sekali, sehingga pemasangan tidak akan menghasilkan informasi tambahan.

### 5.2 Vektor 1 — Penolakan batas norma (norm-bound rejection)

**Rujukan.** Falcon [7], algoritma Verify: signature (s1, s2) diterima **hanya jika** terdekode dengan benar **dan** ‖(s1, s2)‖ ≤ β. Implementasi menegakkannya lewat `mqpoly_sqnorm_is_acceptable()` terhadap tabel `sqbeta[]`.

**Mekanisme.** Untuk logn ∈ {9, 10}, predikat penerimaan diuji pada tiga titik: tepat di batas (`sqbeta[logn]`), satu satuan di atas batas, dan empat kali batas.

**Hasil yang diharapkan.** Terima di batas; tolak di `bound+1`; tolak di `bound*4`.

**Signifikansi.** Batas norma adalah satu-satunya penghalang yang memisahkan "vektor kekisi sembarang yang memenuhi kongruensi" dari "signature yang sah". Predikat yang longgar satu satuan saja memperluas ruang penerimaan dan menurunkan biaya pemalsuan.

**Batasan yang wajib dinyatakan (penting).** Uji ini adalah **uji unit *white-box* atas predikat**, bukan uji *end-to-end*. Uji ini **tidak** mengonstruksi signature ber-norma berlebih yang nyata lalu menyerahkannya ke `Verify`. Yang dibuktikan: predikat `mqpoly_sqnorm_is_acceptable` menegakkan ambang yang benar pada ketiga titik uji, termasuk arah pertidaksamaannya (`≤`, bukan `<`) — kesalahan *off-by-one* yang lazim. Yang **tidak** dibuktikan: bahwa `verify_inner` memanggil predikat itu pada nilai norma yang benar. Perlindungan atas jalur pemanggilan tersebut diperoleh secara tidak langsung dari KAT (§4) dan dari uji *bit-flip* menyeluruh pada `TestVerifyOrig512` (§4.3), yang menolak seluruh mutasi satu-bit atas signature yang sah.

### 5.3 Vektor 2 — Pemalsuan lintas-kunci (cross-key forgery)

**Rujukan.** EUF-CMA [6]. Skema yang signature-nya terverifikasi di bawah kunci publik sembarang secara trivial mengakui pemalsuan eksistensial.

**Mekanisme.** Bangkitkan dua pasang kunci independen (A dan B) pada logn = 9. Tandatangani pesan dengan sk_A, verifikasi dengan vk_B.

**Hasil yang diharapkan.** Ditolak.

**Signifikansi.** Ini adalah syarat perlu minimum EUF-CMA. Analog lapisan JWT-nya adalah `TestAttack_CrossKeyVerification` di `pkg/jwt`; versi ini beroperasi pada byte signature mentah.

### 5.4 Vektor 3 — Kebingungan konteks domain (domain-separation confusion)

**Rujukan.** Konstruksi *context string*/μ gaya FIPS 204 [8] §5.4 yang diwarisi profil FN-DSA. Falcon Round-3 [7] sendiri tidak mendefinisikan `ctx`; pengikatan konteks adalah tambahan pada implementasi ini.

**Mekanisme.** `hash_to_point` (`util.go:73`) menyerap, berurutan: `nonce`, `H(vkey)` (SHAKE256, 64 byte), satu byte penanda pra-hash (`0x00` raw / `0x01` pra-hash), satu byte panjang `ctx`, isi `ctx`, OID fungsi hash, lalu `data`. Uji menandatangani pesan di bawah `ctxA = "tasktify-protocol-A"` lalu mencoba verifikasi di bawah `ctxB`, di bawah `DOMAIN_NONE`, dan sebaliknya (signature `DOMAIN_NONE` diverifikasi di bawah `ctxA`). Kasus positif (verifikasi di bawah `ctxA` yang benar) juga diuji, agar kegagalan menyeluruh tidak salah dibaca sebagai keberhasilan.

**Hasil yang diharapkan.** Seluruh kombinasi silang ditolak; kombinasi yang cocok diterima.

**Signifikansi.** Pengikatan konteks mencegah signature yang sah pada satu protokol diputar-ulang sebagai sah pada protokol lain yang memakai kunci sama. Pengikatan `H(vkey)` pada titik hash yang sama juga mengikat signature pada kunci publiknya, memperkuat §5.3.

### 5.5 Vektor 4 — Kebingungan identifier pra-hash

**Rujukan.** Falcon [7] (pengkodean pesan); prinsip pemisahan domain sebagaimana [8].

**Mekanisme.** Dengan buffer `data` 32 byte yang sama persis, tandatangani sebagai `id = 0` (pesan mentah) lalu verifikasi sebagai `id = crypto.SHA256`, dan sebaliknya.

**Hasil yang diharapkan.** Kedua arah ditolak.

**Signifikansi.** Tanpa pengikatan `id`, penyerang dapat melabel-ulang signature atas *digest* sebagai signature atas pesan mentah dengan byte yang sama (atau sebaliknya) untuk menyelundupkannya ke konteks verifikasi lain. Pemisahan ditegakkan lewat byte penanda dan OID pada `hash_to_point` (`util.go:84-124`).

### 5.6 Vektor 5 — *Bit-flip* pada signature dan pesan

**Rujukan.** Falcon [7], algoritma Verify; EUF-CMA [6].

**Mekanisme.** Balik satu bit (`^= 0x80`) di tengah signature; verifikasi. Kembalikan, lalu balik satu bit (`^= 0x01`) pada byte pertama pesan; verifikasi.

**Hasil yang diharapkan.** Keduanya ditolak.

**Catatan cakupan.** Uji ini mengambil sampel dua posisi bit saja. Cakupan menyeluruh atas seluruh posisi bit disediakan `TestVerifyOrig512` (§4.3), yang membalik **setiap** bit signature pada vektor pertama (≈5 328 verifikasi) dan mensyaratkan seluruhnya ditolak. `TestPrecomputedSignRejectsTampering` (`sign_precomputed_test.go:97`) menyediakan pemeriksaan setara khusus jalur precomputed.

### 5.7 Vektor 6 — Signature terpotong atau malformed

**Rujukan.** Falcon [7] (pengkodean signature terkompresi berukuran tetap).

**Mekanisme.** Lima kasus panjang: `nil`, 1 byte, setengah panjang, kurang 1 byte, dan lebih 1 byte (dipad nol).

**Hasil yang diharapkan.** Seluruhnya ditolak, tanpa *panic*.

**Signifikansi.** Ini adalah pengujian *fail-closed* pada masukan malformed, bukan pemalsuan kriptografis. `verify_inner` menolak dini lewat pemeriksaan `len(sig) != SignatureSize(logn)` dan pemeriksaan *header nibble*; uji ini mengunci perilaku tersebut agar tidak beregresi menjadi *out-of-bounds read* atau penerimaan diam-diam.

### 5.8 Ringkasan pemetaan vektor

| # | Vektor | Fungsi uji | Dipasangkan dyn/precomp | Rujukan utama |
|---|---|---|---|---|
| 1 | Norm-bound rejection | `TestAttack_SignatureNormBoundRejection` | Tidak (sisi Verify) | Falcon [7] |
| 2 | Cross-key forgery | `TestAttack_CrossKeyForgery` | Ya | EUF-CMA [6] |
| 3 | Domain-context confusion | `TestAttack_DomainContextConfusion` | Ya | FIPS 204 [8] §5.4 (gaya konstruksi) |
| 4 | Pre-hash identifier confusion | `TestAttack_PreHashIdentifierConfusion` | Ya | Falcon [7], [8] |
| 5 | Bit-flip signature/pesan | `TestAttack_BitFlipTampering` | Ya | Falcon [7], EUF-CMA [6] |
| 6 | Truncated/malformed encoding | `TestAttack_TruncatedSignatureRejected` | Ya | Falcon [7] |

---

## 6. Hasil Eksekusi

### 6.1 Metadata run

| Butir | Nilai |
|---|---|
| Perintah | `make adversarial-kat`; plus `go test ./fndsa -run '^(TestKeygenRef\|TestVerifyOrig512\|TestVerifyOrig1024\|TestSampler\|TestSign\|TestSignCore)$'` |
| Tanggal | 2026-07-19 |
| Commit | `3e2cdc1933c216c382e45f6289a2c6e4ee97ec70` |
| Toolchain | go1.26.4, GOOS=linux, GOARCH=amd64, CGO_ENABLED=1 |
| Host | Intel Core i5-6300U @ 2.40 GHz, 4 vCPU, Linux 7.1.3-201.fc44.x86_64 |
| Sifat hasil | Deterministik; tidak bergantung pada *host* |

> Run di atas dijalankan pada mesin klien. Untuk pengambilan data skripsi, jalankan `make hostinger-adversarial-kat` agar bukti terikat pada *binary* dan *host* yang sama dengan benchmark performa (§2), lalu ganti blok metadata ini dengan metadata run VPS tersebut.

### 6.2 Hasil KAT

| Uji | Vektor | Hasil | Durasi |
|---|---|---|---|
| `TestFNDSA_KAT` | 90 (logn 2–10 × 10) | **PASS** | 0,84 s |
| `TestFNDSA_Precomputed_KAT` | 20 (logn 9–10 × 10) | **PASS** | 0,74 s |
| `TestKeygenRef` | 300 (3 derajat × 100 seed) | **PASS** | 7,74 s |
| `TestVerifyOrig512` | 5 triplet + ≈5 328 uji bit-flip | **PASS** | 0,40 s |
| `TestVerifyOrig1024` | 5 triplet + ≈10 240 uji bit-flip | **PASS** | 2,28 s |
| `TestSampler` | 1 | **PASS** | <0,01 s |
| `TestSignCore` | 1 | **PASS** | <0,01 s |
| `TestSign` | 1 | **PASS** | <0,01 s |

Tidak ada ketidakcocokan digest pada seluruh 110 vektor KAT end-to-end maupun 300 vektor KAT keygen.

### 6.3 Hasil adversarial

Seluruh subtest berstatus PASS. Untuk vektor berpasangan, hasil **identik antara Falcon dinamis dan Falcon Precomputed**.

| Vektor | Falcon (dinamis) | Falcon Precomputed | Keterangan |
|---|---|---|---|
| Norm-bound, FN-DSA-512 | PROTECTED | *(n/a — sisi Verify)* | `sqbeta[9] = 34034726` ditegakkan |
| Norm-bound, FN-DSA-1024 | PROTECTED | *(n/a — sisi Verify)* | `sqbeta[10] = 70265242` ditegakkan |
| Cross-key forgery | PROTECTED | PROTECTED | — |
| Domain-context confusion | PROTECTED | PROTECTED | ctxA↛ctxB, ctxA↛NONE, NONE↛ctxA; ctxA→ctxA diterima |
| Pre-hash id confusion | PROTECTED | PROTECTED | raw↛SHA-256 dan SHA-256↛raw |
| Bit-flip signature/pesan | PROTECTED | PROTECTED | — |
| Truncated/malformed (5 kasus) | PROTECTED | PROTECTED | empty, 1 B, ½ panjang, −1 B, +1 B |
| `TestPrecomputedSignRejectsTampering` | *(n/a)* | PASS | uji precomputed-only tambahan |

Total durasi paket: 1,712 s.

---

## 7. Apa yang **Tidak** Dibuktikan Pengujian Ini

Bagian ini adalah pembatas klaim dan harus disalin ke subbab "Keterbatasan Penelitian" pada naskah.

1. **Bukan bukti keamanan EUF-CMA.** Uji §5 hanya memfalsifikasi syarat perlu. Keamanan Falcon bersandar pada asumsi kekerasan masalah kekisi sebagaimana diargumentasikan [7], bukan pada hasil pengujian ini.
2. **Bukan bukti *conformance* terhadap FIPS 206.** Vektor yang dipakai bukan vektor resmi NIST (§4.4). Implementasinya sendiri menyatakan diri sebagai *prospective guess* pra-standar.
3. **Tidak ada pengujian *side-channel* maupun *timing*.** Falcon memiliki riwayat serangan *side-channel* terpublikasi terhadap implementasi tertentu — antara lain serangan berbasis *electromagnetic*/daya oleh Karabulut dan Aysu [9], analisis daya terhadap sampler Gaussian oleh Guerreau dkk. [10], dan penyempurnaannya oleh Zhang dkk. [11]. Serangan tersebut menyasar implementasi dan platform spesifik dan **tidak** dapat diasumsikan berlaku atau tidak berlaku pada implementasi ini tanpa pengukuran. Penelitian ini tidak melakukan pengukuran tersebut, sehingga **tidak ada klaim apa pun** mengenai ketahanan *side-channel* yang boleh dibuat. Risiko ini justru relevan bagi jalur precomputed, karena basis trapdoor dan pohon LDL bertahan di memori sepanjang umur proses.
4. **Tidak ada pengujian *fault injection*, *rowhammer*, atau serangan fisik lain.**
5. **Tidak ada evaluasi kualitas RNG operasional.** Determinisme KAT justru diperoleh dengan **mengganti** RNG dengan seed tetap. Kualitas `crypto/rand.Reader` pada *host* produksi tidak diuji di sini, padahal keamanan Falcon bergantung padanya.
6. **Tidak ada *fuzzing*.** `FuzzSign`/`FuzzParse` masih *gap* terbuka (`docs/revisi-todo.md` P1-11). Masukan malformed hanya diuji pada lima kasus panjang tetap (§5.7).
7. **Tidak ada verifikasi formal maupun bukti kesetaraan program** antara *signer* dinamis dan precomputed. Kesetaraan bersifat empiris atas 20 vektor (§4.5).
8. **Tidak ada *hardening* memori.** Zeroization/`Destroy()` pada `PrecomputedSigner` belum ada (`docs/revisi-todo.md` P2-13); paparan *core dump*/swap belum dianalisis.
9. **Tidak ada pengujian rotasi kunci maupun pencabutan kunci** pada tingkat primitif.
10. **Uji norm-bound bersifat *white-box* pada predikat**, bukan uji *end-to-end* dengan signature ber-norma berlebih yang nyata (§5.2).

---

## 8. Rumusan Klaim yang Diizinkan untuk Naskah

Gunakan rumusan berikut; hindari padanan yang lebih kuat.

| Boleh ditulis | Jangan ditulis |
|---|---|
| "Implementasi lolos seluruh 110 vektor KAT end-to-end dan 300 vektor KAT keygen tanpa ketidakcocokan digest." | "Implementasi terbukti benar." |
| "*Signer* precomputed menghasilkan signature yang identik bit-per-bit dengan *signer* dinamis pada seluruh 20 vektor KAT yang diuji; tidak ditemukan divergensi keluaran." | "*Signer* precomputed ekuivalen secara fungsional dengan *signer* dinamis." |
| "Seluruh enam vektor adversarial ditolak sebagaimana diharapkan pada kedua varian *signer*." | "FN-DSA terbukti tahan pemalsuan." / "Precomputation terbukti aman." |
| "Hasil identik antara varian dinamis dan precomputed pada seluruh vektor berpasangan; tidak ditemukan bukti bahwa precomputation melemahkan penolakan yang diuji." | "Precomputation tidak menurunkan keamanan." |
| "Implementasi sesuai dengan spesifikasi Falcon Round-3 [7] pada jalur yang tercakup vektor uji internal." | "Implementasi *conformant* terhadap FIPS 206." |
| "Tidak dilakukan evaluasi *side-channel*." | *(diam mengenai side-channel)* — kelalaian ini sendiri merupakan bentuk *overclaim* implisit. |

---

## 9. Reproduksi

```bash
cd backend

# KAT saja (cepat, ~2 detik):
make falcon-kat

# KAT + seluruh vektor adversarial, verbose:
make adversarial-kat

# Di VPS target, untuk pengambilan data skripsi:
make hostinger-adversarial-kat VPS_SSH=<user>@<host>

# Termasuk KAT tingkat komponen (~11 detik):
cd pkg && GOCACHE=/tmp/go-build-cache go test ./fndsa -count=1

# Gerbang pra-benchmark lengkap:
cd backend && make falcon-check
```

Catat bersama hasil: `git rev-parse HEAD`, `go version`, `go env GOARCH CGO_ENABLED`, dan identitas *host* (`docs/skenario-pengujian.md` §13.1).

---

## 10. Referensi

Format sitasi: IEEE. Penomoran bersifat lokal untuk dokumen ini.

[1] M. Jones, J. Bradley, and N. Sakimura, "JSON Web Token (JWT)," IETF RFC 7519, May 2015. doi: 10.17487/RFC7519. [Online]. Available: https://www.rfc-editor.org/rfc/rfc7519

[2] Y. Sheffer, D. Hardt, and M. Jones, "JSON Web Token Best Current Practices," IETF RFC 8725, BCP 225, Feb. 2020. doi: 10.17487/RFC8725. [Online]. Available: https://www.rfc-editor.org/rfc/rfc8725

[3] National Institute of Standards and Technology, "Cryptographic Algorithm Validation Program (CAVP)," NIST, Gaithersburg, MD, USA. [Online]. Available: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program — dirujuk sebagai preseden metodologis penggunaan vektor uji bergaya known-answer untuk validasi implementasi.

[4] International Organization for Standardization/International Electrotechnical Commission, "Information technology — Security techniques — Security requirements for cryptographic modules," ISO/IEC 19790:2012 — mensyaratkan *self-test* algoritma kriptografi berbasis known-answer; diadopsi oleh NIST FIPS 140-3.

[5] E. W. Dijkstra, "Notes on Structured Programming," Technological University Eindhoven, EWD249, Apr. 1970 — "Program testing can be used to show the presence of bugs, but never to show their absence."

[6] S. Goldwasser, S. Micali, and R. L. Rivest, "A digital signature scheme secure against adaptive chosen-message attacks," SIAM J. Comput., vol. 17, no. 2, pp. 281–308, Apr. 1988. doi: 10.1137/0217017.

[7] P.-A. Fouque, J. Hoffstein, P. Kirchner, V. Lyubashevsky, T. Pornin, T. Prest, T. Ricosset, G. Seiler, W. Whyte, and Z. Zhang, "Falcon: Fast-Fourier Lattice-based Compact Signatures over NTRU," NIST Post-Quantum Cryptography Standardization Project, Round 3 submission, specification v1.2, Oct. 1, 2020. [Online]. Available: https://falcon-sign.info/falcon.pdf

[8] National Institute of Standards and Technology, "Module-Lattice-Based Digital Signature Standard," NIST, Gaithersburg, MD, USA, FIPS PUB 204, Aug. 13, 2024. doi: 10.6028/NIST.FIPS.204 — dirujuk untuk konstruksi *context string*/μ, bukan sebagai standar yang diimplementasikan di sini.

[9] E. Karabulut and A. Aysu, "FALCON Down: Breaking FALCON Post-Quantum Signature Scheme through Side-Channel Attacks," in Proc. 58th ACM/IEEE Design Automation Conference (DAC), San Francisco, CA, USA, Dec. 2021, pp. 691–696. doi: 10.1109/DAC18074.2021.9586131.

[10] M. Guerreau, A. Martinelli, T. Ricosset, and M. Rossi, "The Hidden Parallelepiped Is Back Again: Power Analysis Attacks on Falcon," IACR Trans. Cryptogr. Hardw. Embed. Syst. (TCHES), vol. 2022, no. 3, pp. 141–164, 2022. doi: 10.46586/tches.v2022.i3.141-164.

[11] S. Zhang, X. Lin, Y. Yu, and W. Wang, "Improved Power Analysis Attacks on Falcon," in Advances in Cryptology — EUROCRYPT 2023, LNCS vol. 14007, Springer, 2023, pp. 565–595. doi: 10.1007/978-3-031-30634-1_19.

[12] National Institute of Standards and Technology, "FN-DSA (FIPS 206)," NIST, Gaithersburg, MD, USA — standardisasi masih berjalan. Status per catatan `docs/skenario-pengujian.md` §15: Initial Public Draft belum terbit ke URL publik stabil (akhir 2025). **Status wajib diverifikasi ulang sebelum naskah difinalkan.** Dikutip hanya untuk nama/status; [7] adalah sumber normatif algoritma yang diuji dokumen ini.

---

*Angka dan nama fungsi pada dokumen ini diambil langsung dari `backend/pkg/fndsa/` dan `backend/Makefile` pada commit `3e2cdc1`. Bila kode berubah, jalankan ulang §9 dan perbarui §6.*
