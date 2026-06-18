package fndsa

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	sha3 "golang.org/x/crypto/sha3"
)

const ablationJWTBaseUnix = int64(1715648400)

type ablationJWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type ablationJWTClaims struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	TokenUse  string `json:"token_use"`
	JWTID     string `json:"jti"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Issuer    string `json:"iss"`
}

type precomputeAblationSigner struct {
	logn     uint
	hashedVK [64]byte
	f        []int8
	g        []int8
	F        []int8
	G        []int8
	b00      []f64
	b01      []f64
	b10      []f64
	b11      []f64
	g00      []f64
	g01      []f64
	g11      []f64
	full     *PrecomputedSigner
}

func newPrecomputeAblationSigner(lognMin uint, lognMax uint,
	skey []byte) (*precomputeAblationSigner, error) {

	if len(skey) == 0 {
		return nil, errors.New("Invalid private key")
	}
	head1 := skey[0]
	if (head1 & 0xF0) != 0x50 {
		return nil, errors.New("Invalid private key")
	}
	logn := uint(head1 & 0x0F)
	if logn < lognMin || logn > lognMax {
		return nil, errors.New("Invalid private key")
	}
	if len(skey) != SigningKeySize(logn) {
		return nil, errors.New("Invalid private key")
	}

	n := 1 << logn
	f := make([]int8, n)
	g := make([]int8, n)
	F := make([]int8, n)
	off := 1
	j, err := trim_i8_decode(logn, skey[off:], f, nbits_fg(logn))
	if err != nil {
		return nil, err
	}
	off += j
	j, err = trim_i8_decode(logn, skey[off:], g, nbits_fg(logn))
	if err != nil {
		return nil, err
	}
	off += j
	_, err = trim_i8_decode(logn, skey[off:], F, 8)
	if err != nil {
		return nil, err
	}

	G := make([]int8, n)
	t0 := make([]uint16, n)
	t1 := make([]uint16, n)
	mqpoly_small_to_int(logn, g, t0)
	mqpoly_small_to_int(logn, f, t1)
	mqpoly_int_to_ntt(logn, t0)
	mqpoly_int_to_ntt(logn, t1)
	if !mqpoly_div_ntt(logn, t0, t1) {
		return nil, errors.New("Invalid signing key (f not invertible)")
	}
	mqpoly_small_to_int(logn, F, t1)
	mqpoly_int_to_ntt(logn, t1)
	mqpoly_mul_ntt(logn, t1, t0)
	mqpoly_ntt_to_int(logn, t1)
	if !mqpoly_int_to_small(logn, t1, G) {
		return nil, errors.New("Invalid signing key (G is out-of-range)")
	}

	mqpoly_ntt_to_int(logn, t0)
	mqpoly_int_to_ext(logn, t0)
	vrfyKey := make([]byte, VerifyingKeySize(logn))
	vrfyKey[0] = byte(0x00 + logn)
	_ = modq_encode(logn, t0, vrfyKey[1:])
	var hashedVK [64]byte
	sh := sha3.NewShake256()
	sh.Write(vrfyKey)
	sh.Read(hashedVK[:])

	basis := make([]f64, n*4)
	basis_to_FFT(logn, f, g, F, G, basis)
	b00 := append([]f64(nil), basis[:n]...)
	b01 := append([]f64(nil), basis[n:n*2]...)
	b10 := append([]f64(nil), basis[n*2:n*3]...)
	b11 := append([]f64(nil), basis[n*3:n*4]...)

	gram := append([]f64(nil), basis...)
	g00 := gram[:n]
	g01 := gram[n : n*2]
	g11 := gram[n*2 : n*3]
	fpoly_gram_fft(logn, g00, g01, g11, gram[n*3:n*4])

	var full *PrecomputedSigner
	if logn >= 9 {
		full, err = NewPrecomputedSigner(skey)
	} else {
		full, err = NewPrecomputedSignerWeak(skey)
	}
	if err != nil {
		return nil, err
	}

	return &precomputeAblationSigner{
		logn:     logn,
		hashedVK: hashedVK,
		f:        f,
		g:        g,
		F:        F,
		G:        G,
		b00:      b00,
		b01:      b01,
		b10:      b10,
		b11:      b11,
		g00:      append([]f64(nil), g00...),
		g01:      append([]f64(nil), g01...),
		g11:      append([]f64(nil), g11...),
		full:     full,
	}, nil
}

func (s *precomputeAblationSigner) signA1(seed []byte,
	ctx DomainContext, id crypto.Hash, data []byte) ([]byte, error) {

	n := 1 << s.logn
	tmpI16 := make([]int16, n)
	tmpU16 := make([]uint16, n)
	tmpF64 := make([]f64, n*9)
	sig := make([]byte, SignatureSize(s.logn))
	err := sign_core(s.logn, s.f, s.g, s.F, s.G, s.hashedVK[:],
		ctx, id, data, seed, sig, tmpI16, tmpU16, tmpF64)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (s *precomputeAblationSigner) signA2(seed []byte,
	ctx DomainContext, id crypto.Hash, data []byte) ([]byte, error) {

	n := 1 << s.logn
	tmpI16 := make([]int16, n)
	tmpU16 := make([]uint16, n)
	tmpF64 := make([]f64, n*10)
	sig := make([]byte, SignatureSize(s.logn))
	err := s.signCoreWithBasis(seed, ctx, id, data, sig, tmpI16, tmpU16, tmpF64)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (s *precomputeAblationSigner) signA3(seed []byte,
	ctx DomainContext, id crypto.Hash, data []byte) ([]byte, error) {

	n := 1 << s.logn
	tmpI16 := make([]int16, n)
	tmpU16 := make([]uint16, n)
	tmpF64 := make([]f64, n*10)
	sig := make([]byte, SignatureSize(s.logn))
	err := s.signCoreWithGram(seed, ctx, id, data, sig, tmpI16, tmpU16, tmpF64)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (s *precomputeAblationSigner) signA4(seed []byte,
	ctx DomainContext, id crypto.Hash, data []byte) ([]byte, error) {

	return s.full.signSeeded(seed, ctx, id, data)
}

func (s *precomputeAblationSigner) signA5(seed []byte,
	ctx DomainContext, id crypto.Hash, data []byte) ([]byte, error) {

	return s.full.signSeeded(seed, ctx, id, data)
}

func (s *precomputeAblationSigner) signCoreWithBasis(
	seed []byte, ctx DomainContext, id crypto.Hash, data []byte,
	sig []byte, tmpI16 []int16, tmpU16 []uint16, tmpF64 []f64) error {

	return s.signCoreDetached(seed, ctx, id, data, sig, tmpI16, tmpU16, tmpF64,
		func(g00 []f64, g01 []f64, g11 []f64, gx []f64) {
			copy(g00, s.b00)
			copy(g01, s.b01)
			copy(g11, s.b10)
			copy(gx, s.b11)
			fpoly_gram_fft(s.logn, g00, g01, g11, gx)
		})
}

func (s *precomputeAblationSigner) signCoreWithGram(
	seed []byte, ctx DomainContext, id crypto.Hash, data []byte,
	sig []byte, tmpI16 []int16, tmpU16 []uint16, tmpF64 []f64) error {

	return s.signCoreDetached(seed, ctx, id, data, sig, tmpI16, tmpU16, tmpF64,
		func(g00 []f64, g01 []f64, g11 []f64, _ []f64) {
			copy(g00, s.g00)
			copy(g01, s.g01)
			copy(g11, s.g11)
		})
}

func (s *precomputeAblationSigner) signCoreDetached(
	seed []byte, ctx DomainContext, id crypto.Hash, data []byte,
	sig []byte, tmpI16 []int16, tmpU16 []uint16, tmpF64 []f64,
	prepareGram func(g00 []f64, g01 []f64, g11 []f64, gx []f64)) error {

	logn := s.logn
	n := 1 << logn
	sh := sha3.NewShake256()
	hm := tmpU16
	s2 := tmpI16
	sig = sig[:SignatureSize(logn)]

	for counter := 0; ; counter++ {
		sh.Reset()
		sh.Write(seed)
		var cbuf [4]byte
		cbuf[0] = uint8(counter)
		cbuf[1] = uint8(counter >> 8)
		cbuf[2] = uint8(counter >> 16)
		cbuf[3] = uint8(counter >> 24)
		sh.Write(cbuf[:])
		var nonce [40]byte
		var subseed [56]byte
		sh.Read(nonce[:])
		sh.Read(subseed[:])

		err := hash_to_point(logn, nonce[:], s.hashedVK[:], ctx, id, data, hm)
		if err != nil {
			return err
		}

		g00 := tmpF64[:n]
		g01 := tmpF64[n : n*2]
		g11 := tmpF64[n*2 : n*3]
		gx := tmpF64[n*3 : n*4]
		prepareGram(g00, g01, g11, gx)

		t0 := tmpF64[n*4 : n*5]
		t1 := tmpF64[n*5 : n*6]
		fpoly_apply_basis(logn, t0, t1, s.b01, s.b11, hm)

		ss := newSampler(logn, subseed[:])
		ss.ffsamp_fft(t0, t1, g00, g01, g11, tmpF64[n*6:])

		tx := tmpF64[:n]
		ty := tmpF64[n : n*2]
		copy(tx, t0)
		copy(ty, t1)
		fpoly_mul_fft(logn, tx, s.b00)
		fpoly_mul_fft(logn, ty, s.b10)
		fpoly_add(logn, tx, ty)
		copy(ty, t0)
		fpoly_mul_fft(logn, ty, s.b01)
		copy(t0, tx)
		fpoly_mul_fft(logn, t1, s.b11)
		fpoly_add(logn, t1, ty)
		fpoly_iFFT(logn, t0)
		fpoly_iFFT(logn, t1)

		sqn := uint32(0)
		ng := uint32(0)
		for i := 0; i < n; i++ {
			zu := hm[i] - uint16(f64_rint(t0[i]))
			z := int32(int16(zu))
			sqn += uint32(z * z)
			ng |= sqn
		}
		for i := 0; i < n; i++ {
			zu := -uint16(f64_rint(t1[i]))
			z := int32(int16(zu))
			sqn += uint32(z * z)
			ng |= sqn
			s2[i] = int16(z)
		}
		sqn |= uint32(int32(ng) >> 31)
		if !mqpoly_sqnorm_is_acceptable(logn, sqn) {
			continue
		}

		if comp_encode(logn, s2, sig[41:]) {
			sig[0] = byte(0x30 + logn)
			copy(sig[1:41], nonce[:])
			return nil
		}
	}
}

func TestPrecomputeAblationVariantsMatchOriginal(t *testing.T) {
	for logn := uint(2); logn <= 10; logn++ {
		var keySeed [32]byte
		for i := 0; i < len(keySeed); i++ {
			keySeed[i] = byte(i + int(logn)*19)
		}
		skey, vkey, err := KeyGen(logn, bytes.NewReader(keySeed[:]))
		if err != nil {
			t.Fatalf("keygen failed (logn=%d): %v", logn, err)
		}
		signer, err := newPrecomputeAblationSigner(logn, logn, skey)
		if err != nil {
			t.Fatalf("ablation signer failed (logn=%d): %v", logn, err)
		}

		for msgID := 0; msgID < 3; msgID++ {
			data := ablationJWTSigningInput(logn, msgID)
			seed := ablationSeed(logn, msgID)
			want, err := sign_inner_seeded(logn, logn, seed[:], skey, DOMAIN_NONE, crypto.SHA3_256, data)
			if err != nil {
				t.Fatalf("A0 failed (logn=%d, msg=%d): %v", logn, msgID, err)
			}

			variants := []struct {
				name string
				sign func([]byte, DomainContext, crypto.Hash, []byte) ([]byte, error)
			}{
				{"A1", signer.signA1},
				{"A2", signer.signA2},
				{"A3", signer.signA3},
				{"A4", signer.signA4},
				{"A5", signer.signA5},
			}
			for _, variant := range variants {
				got, err := variant.sign(seed[:], DOMAIN_NONE, crypto.SHA3_256, data)
				if err != nil {
					t.Fatalf("%s failed (logn=%d, msg=%d): %v", variant.name, logn, msgID, err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("%s signature differs from A0 (logn=%d, msg=%d)",
						variant.name, logn, msgID)
				}
			}

			if !verifyAblationSignature(vkey, logn, data, want) {
				t.Fatalf("signature verification failed (logn=%d, msg=%d)", logn, msgID)
			}
			assertAblationJWTBoundSignature(t, vkey, logn, data, want)
		}
	}
}

func BenchmarkFalconPrecomputeAblation512(b *testing.B) {
	skey, _, err := KeyGen(9, nil)
	if err != nil {
		b.Fatal(err)
	}
	signer, err := newPrecomputeAblationSigner(9, 10, skey)
	if err != nil {
		b.Fatal(err)
	}

	benchmarks := []struct {
		name string
		sign func([]byte, DomainContext, crypto.Hash, []byte) ([]byte, error)
	}{
		{"A0_Original", func(seed []byte, ctx DomainContext, id crypto.Hash, data []byte) ([]byte, error) {
			return sign_inner_seeded(9, 10, seed, skey, ctx, id, data)
		}},
		{"A1_KeyMaterialDetached", signer.signA1},
		{"A2_FFTBasisDetached", signer.signA2},
		{"A3_GramDetached", signer.signA3},
		{"A4_LDLTreeDetached", signer.signA4},
		{"A5_AllPrecomputedCombined", signer.signA5},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			benchmarkAblationVariant(b, bm.sign)
		})
	}
}

func benchmarkAblationVariant(
	b *testing.B,
	sign func([]byte, DomainContext, crypto.Hash, []byte) ([]byte, error)) {

	inputs := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		inputs[i] = ablationJWTSigningInput(9, i)
	}

	b.ReportAllocs()
	b.ResetTimer()
	var lastSig []byte
	for i := 0; i < b.N; i++ {
		seed := ablationSeed(9, i)
		sig, err := sign(seed[:], DOMAIN_NONE, crypto.SHA3_256, inputs[i])
		if err != nil {
			b.Fatal(err)
		}
		lastSig = sig
	}
	ablationSignatureSink = lastSig
}

func ablationSeed(logn uint, iteration int) [40]byte {
	var seed [40]byte
	for i := 0; i < len(seed); i++ {
		seed[i] = byte(i*31 + iteration*17 + int(logn)*13)
	}
	return seed
}

var ablationSignatureSink []byte

func ablationJWTSigningInput(logn uint, iteration int) []byte {
	issuedAt := ablationJWTBaseUnix + int64(iteration)
	header := ablationJWTHeader{
		Alg: "Falcon-512",
		Typ: "JWT",
	}
	claims := ablationJWTClaims{
		UserID:    ablationUUID(logn, iteration),
		Email:     fmt.Sprintf("ablation-%d-%d@example.test", logn, iteration),
		TokenUse:  "access",
		JWTID:     fmt.Sprintf("ablation-%d-%d", logn, iteration),
		IssuedAt:  issuedAt,
		ExpiresAt: issuedAt + 3600,
		Issuer:    "tasktify",
	}

	return []byte(ablationBase64URL(mustAblationJSON(header)) + "." +
		ablationBase64URL(mustAblationJSON(claims)))
}

func mustAblationJSON(value any) []byte {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}

func ablationBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func ablationUUID(logn uint, iteration int) string {
	tail := (uint64(logn)<<32 | uint64(iteration)) & 0xffffffffffff
	return fmt.Sprintf("00000000-0000-0000-0000-%012x", tail)
}

func ablationCompactJWT(signingInput []byte, sig []byte) string {
	return string(signingInput) + "." + ablationBase64URL(sig)
}

func verifyAblationSignature(vkey []byte, logn uint, data []byte, sig []byte) bool {
	if logn < 9 {
		return VerifyWeak(vkey, DOMAIN_NONE, crypto.SHA3_256, data, sig)
	}
	return Verify(vkey, DOMAIN_NONE, crypto.SHA3_256, data, sig)
}

func assertAblationJWTBoundSignature(t *testing.T, vkey []byte, logn uint, signingInput []byte, sig []byte) {
	t.Helper()

	token := ablationCompactJWT(signingInput, sig)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT compact token must have 3 segments, got %d", len(parts))
	}

	decodedSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("JWT signature segment decode failed: %v", err)
	}
	if !bytes.Equal(decodedSig, sig) {
		t.Fatal("JWT signature segment differs from generated signature")
	}

	tokenSigningInput := []byte(parts[0] + "." + parts[1])
	if !bytes.Equal(tokenSigningInput, signingInput) {
		t.Fatal("JWT signing input changed during compact token assembly")
	}
	if !verifyAblationSignature(vkey, logn, tokenSigningInput, decodedSig) {
		t.Fatal("JWT compact token signature did not verify")
	}
	if verifyAblationSignature(vkey, logn, ablationJWTSigningInput(logn, 10000+int(logn)), decodedSig) {
		t.Fatal("signature verified against different JWT header/payload")
	}
}
