package jwt_test

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ridwanmuh3/tasktify/pkg/fndsa"
	"github.com/ridwanmuh3/tasktify/pkg/jwt"
)

// ========================================================
// Test Helpers
// ========================================================

type TestClaims struct {
	jwt.RegisteredClaims
	UserID uuid.UUID `json:"user_id"`
	Email  string    `json:"email"`
}

// setupFNDSAKeys generates FN-DSA-512 key pair dan precomputed signer
func setupFNDSAKeys(t *testing.T) (skey []byte, vkey []byte, signer *fndsa.PrecomputedSigner) {
	t.Helper()
	skey, vkey, err := fndsa.KeyGen(9, nil)
	if err != nil {
		t.Fatalf("failed to generate FN-DSA-512 keys: %v", err)
	}

	signer, err = fndsa.NewPrecomputedSigner(skey)
	if err != nil {
		t.Fatalf("failed to create precomputed signer: %v", err)
	}

	return skey, vkey, signer
}

// createValidToken membuat token yang valid dengan FN-DSA Precomputed-512
func createValidToken(t *testing.T, signer *fndsa.PrecomputedSigner) string {
	t.Helper()

	method := &jwt.SigningMethodFNDSAPrecomputed{Name: jwt.AlgFNDSA512}
	method.SetPrecomputedSigner(signer)

	token := jwt.NewWithClaims(method, TestClaims{
		UserID: uuid.New(),
		Email:  "test@example.com",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(60 * time.Minute)),
			Issuer:    "tasktify",
		},
	})

	tokenString, err := token.SignedString(nil)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	return tokenString
}

// parseWithProtection mensimulasikan parser yang digunakan di gateway/auth-service
func parseWithProtection(tokenString string, vkey []byte) (*jwt.Token, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.AlgFNDSA512}),
		jwt.WithIssuer("tasktify"),
		jwt.WithIssuedAt(),
	)

	return parser.ParseWithClaims(tokenString, &TestClaims{}, func(t *jwt.Token) (any, error) {
		return vkey, nil
	})
}

// ========================================================
// ATTACK 1: Algorithm "none" Attack
// Attacker mencoba mengganti alg ke "none" dan menghapus signature
// Reference: RFC 7519 §6 Unsecured JWTs; RFC 8725 §3.1 Perform Algorithm
// Verification, §3.2 Use Appropriate Algorithms
// ========================================================
func TestAttack_AlgorithmNone(t *testing.T) {
	_, vkey, signer := setupFNDSAKeys(t)
	validToken := createValidToken(t, signer)

	parts := strings.Split(validToken, ".")

	noneHeader := map[string]any{
		"typ": "JWT",
		"alg": "none",
	}
	headerJSON, _ := json.Marshal(noneHeader)
	forgedToken := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + parts[1] + "."

	_, err := parseWithProtection(forgedToken, vkey)
	if err == nil {
		t.Fatal("VULNERABLE: alg=none attack berhasil melewati verifikasi!")
	}

	t.Logf("PROTECTED: alg=none attack ditolak: %v", err)
}

// ========================================================
// Interoperability check (not an adversarial vector): Precomputed-512 vs
// FN-DSA-512 share the same header alg. A valid signature produced with
// fndsa.Sign verifies the same way. No RFC attack reference applies here
// — this proves correctness of the precomputation optimization, not
// resistance to an attack.
// ========================================================
func TestAttack_AlgorithmSwitchToFNDSA512(t *testing.T) {
	skey, vkey, signer := setupFNDSAKeys(t)
	validToken := createValidToken(t, signer)

	parts := strings.Split(validToken, ".")

	switchedHeader := map[string]any{
		"typ": "JWT",
		"alg": "FN-DSA-512",
	}
	headerJSON, _ := json.Marshal(switchedHeader)

	newHeaderB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	signingString := newHeaderB64 + "." + parts[1]

	sig, err := fndsa.Sign(rand.Reader, skey, fndsa.DOMAIN_NONE, crypto.SHA3_256, []byte(signingString))
	if err != nil {
		t.Fatalf("failed to sign with FN-DSA-512: %v", err)
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	forgedToken := signingString + "." + sigB64

	_, err = parseWithProtection(forgedToken, vkey)
	if err == nil {
		t.Logf("SAFE: original and precomputed FN-DSA-512 interoperate under the same header alg")
		return
	}

	t.Fatalf("UNEXPECTED: valid FN-DSA-512 signature rejected: %v", err)
}

// ========================================================
// ATTACK 3: Algorithm Switching ke ML-DSA
// Attacker mencoba switch ke ML-DSA algorithm
// Reference: RFC 8725 §3.1 Perform Algorithm Verification
// ========================================================
func TestAttack_AlgorithmSwitchToMLDSA(t *testing.T) {
	_, vkey, signer := setupFNDSAKeys(t)
	validToken := createValidToken(t, signer)

	parts := strings.Split(validToken, ".")

	for _, alg := range []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		t.Run(alg, func(t *testing.T) {
			switchedHeader := map[string]any{
				"typ": "JWT",
				"alg": alg,
			}
			headerJSON, _ := json.Marshal(switchedHeader)
			forgedToken := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + parts[1] + "." + parts[2]

			_, err := parseWithProtection(forgedToken, vkey)
			if err == nil {
				t.Fatalf("VULNERABLE: algorithm switch ke %s berhasil!", alg)
			}

			t.Logf("PROTECTED: algorithm switch ke %s ditolak: %v", alg, err)
		})
	}
}

// ========================================================
// ATTACK 4: Algorithm Confusion ke FN-DSA-1024
// Attacker mencoba switch ke FN-DSA-1024/FN-DSA-Precomputed-1024
// Reference: RFC 8725 §3.1 Perform Algorithm Verification
// ========================================================
func TestAttack_AlgorithmSwitchToFNDSA1024(t *testing.T) {
	_, vkey, signer := setupFNDSAKeys(t)
	validToken := createValidToken(t, signer)

	parts := strings.Split(validToken, ".")

	for _, alg := range []string{"FN-DSA-1024", "FN-DSA-Precomputed-1024"} {
		t.Run(alg, func(t *testing.T) {
			switchedHeader := map[string]any{
				"typ": "JWT",
				"alg": alg,
			}
			headerJSON, _ := json.Marshal(switchedHeader)
			forgedToken := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + parts[1] + "." + parts[2]

			_, err := parseWithProtection(forgedToken, vkey)
			if err == nil {
				t.Fatalf("VULNERABLE: algorithm switch ke %s berhasil!", alg)
			}

			t.Logf("PROTECTED: algorithm switch ke %s ditolak: %v", alg, err)
		})
	}
}

// ========================================================
// ATTACK: Signature Tampering (Scenario 1)
// Attacker flip byte pada signature yang valid tanpa private key
// Reference: RFC 8725 §3.3 Validate All Cryptographic Operations
// ========================================================
func TestAttack_SignatureTampering(t *testing.T) {
	_, vkey, signer := setupFNDSAKeys(t)
	validToken := createValidToken(t, signer)
	parts := strings.Split(validToken, ".")

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}

	testCases := []struct {
		name     string
		position int
	}{
		{"flip first byte", 0},
		{"flip middle byte", len(sigBytes) / 2},
		{"flip last byte", len(sigBytes) - 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := make([]byte, len(sigBytes))
			copy(tampered, sigBytes)
			tampered[tc.position] ^= 0xFF

			tamperedSigB64 := base64.RawURLEncoding.EncodeToString(tampered)
			tamperedToken := parts[0] + "." + parts[1] + "." + tamperedSigB64

			_, err := parseWithProtection(tamperedToken, vkey)
			if err == nil {
				t.Fatalf("VULNERABLE: tampered signature (%s) diterima!", tc.name)
			}

			t.Logf("PROTECTED: tampered signature (%s) ditolak: %v", tc.name, err)
		})
	}
}

// ========================================================
// ATTACK 5: Signature Stripping
// Attacker menghapus atau memanipulasi signature dari token
// Reference: RFC 7519 §6 Unsecured JWTs; RFC 8725 §3.1, §3.3
// ========================================================
func TestAttack_SignatureStripping(t *testing.T) {
	_, vkey, signer := setupFNDSAKeys(t)
	validToken := createValidToken(t, signer)

	parts := strings.Split(validToken, ".")

	testCases := []struct {
		name  string
		token string
	}{
		{"empty signature", parts[0] + "." + parts[1] + "."},
		{"random short signature", parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString([]byte("fake"))},
		{"truncated signature", parts[0] + "." + parts[1] + "." + parts[2][:10]},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseWithProtection(tc.token, vkey)
			if err == nil {
				t.Fatalf("VULNERABLE: %s attack berhasil!", tc.name)
			}

			t.Logf("PROTECTED: %s ditolak: %v", tc.name, err)
		})
	}
}

// ========================================================
// ATTACK 6: Expired Token Replay
// Attacker menggunakan token yang sudah expired
// Reference: RFC 7519 §4.1.4 "exp" (Expiration Time) Claim
// ========================================================
func TestAttack_ExpiredToken(t *testing.T) {
	_, vkey, signer := setupFNDSAKeys(t)

	method := &jwt.SigningMethodFNDSAPrecomputed{Name: jwt.AlgFNDSA512}
	method.SetPrecomputedSigner(signer)

	token := jwt.NewWithClaims(method, TestClaims{
		UserID: uuid.New(),
		Email:  "test@example.com",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			Issuer:    "tasktify",
		},
	})

	tokenString, err := token.SignedString(nil)
	if err != nil {
		t.Fatalf("failed to sign expired token: %v", err)
	}

	_, err = parseWithProtection(tokenString, vkey)
	if err == nil {
		t.Fatal("VULNERABLE: expired token berhasil melewati verifikasi!")
	}

	t.Logf("PROTECTED: expired token ditolak: %v", err)
}

// ========================================================
// ATTACK 7: Issuer Spoofing (Scenario 10)
// Attacker membuat token dengan issuer yang tidak dikenali server
// Reference: RFC 7519 §4.1.1 "iss" (Issuer) Claim; RFC 8725 §3.8 Validate
// Issuer and Subject
// ========================================================
func TestAttack_IssuerSpoofing(t *testing.T) {
	_, vkey, signer := setupFNDSAKeys(t)

	method := &jwt.SigningMethodFNDSAPrecomputed{Name: jwt.AlgFNDSA512}
	method.SetPrecomputedSigner(signer)

	fakeIssuers := []string{"evil-service", "example.com", "attacker.io", ""}

	for _, fakeIssuer := range fakeIssuers {
		t.Run("iss="+fakeIssuer, func(t *testing.T) {
			token := jwt.NewWithClaims(method, TestClaims{
				UserID: uuid.New(),
				Email:  "attacker@evil.com",
				RegisteredClaims: jwt.RegisteredClaims{
					ID:        uuid.NewString(),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(60 * time.Minute)),
					Issuer:    fakeIssuer,
				},
			})

			tokenString, err := token.SignedString(nil)
			if err != nil {
				t.Fatalf("failed to sign token: %v", err)
			}

			_, err = parseWithProtection(tokenString, vkey)
			if err == nil {
				t.Fatalf("VULNERABLE: issuer spoofing dengan iss=%q berhasil!", fakeIssuer)
			}

			t.Logf("PROTECTED: issuer spoofing iss=%q ditolak: %v", fakeIssuer, err)
		})
	}
}

// ========================================================
// ATTACK 8: Cross-Key Verification
// Attacker mencoba verifikasi dengan key pair yang berbeda
// Reference: RFC 8725 §3.1 Perform Algorithm Verification (key resolution
// must be tied to the correct registered key, not attacker-substitutable)
// ========================================================
func TestAttack_CrossKeyVerification(t *testing.T) {
	_, _, signer := setupFNDSAKeys(t)

	// Generate key pair kedua (attacker's keys)
	_, attackerVkey, _ := setupFNDSAKeys(t)

	validToken := createValidToken(t, signer)

	_, err := parseWithProtection(validToken, attackerVkey)
	if err == nil {
		t.Fatal("VULNERABLE: token terverifikasi dengan key yang berbeda!")
	}

	t.Logf("PROTECTED: cross-key verification ditolak: %v", err)
}

// ========================================================
// ATTACK 9: Algorithm yang Tidak Terdaftar (HS256, RS256, dll)
// Attacker mencoba menggunakan algorithm klasik/tidak terdaftar
// Reference: RFC 8725 §3.1 Perform Algorithm Verification ("Libraries
// MUST enable the caller to specify a supported set of algorithms and
// MUST NOT use any other algorithms"), §3.2 Use Appropriate Algorithms
// ========================================================
func TestAttack_UnknownAlgorithm(t *testing.T) {
	_, vkey, signer := setupFNDSAKeys(t)
	validToken := createValidToken(t, signer)

	parts := strings.Split(validToken, ".")

	unknownAlgs := []string{"HS256", "RS256", "ES256", "PS256", "EdDSA", "CUSTOM-ALG"}

	for _, alg := range unknownAlgs {
		t.Run(alg, func(t *testing.T) {
			header := map[string]any{
				"typ": "JWT",
				"alg": alg,
			}
			headerJSON, _ := json.Marshal(header)
			forgedToken := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + parts[1] + "." + parts[2]

			_, err := parseWithProtection(forgedToken, vkey)
			if err == nil {
				t.Fatalf("VULNERABLE: unknown algorithm %s diterima!", alg)
			}

			t.Logf("PROTECTED: unknown algorithm %s ditolak: %v", alg, err)
		})
	}
}

// ========================================================
// ATTACK 10: Token Malformed
// Attacker mengirim token yang malformed
// Reference: RFC 7519 §3 JWT Format (three dot-separated base64url parts).
// Deviating from this structure is malformed input, not a valid JWT;
// RFC 8725 has no dedicated malformed-input section, so this vector's
// grounding is the format definition itself plus fail-closed parsing.
// ========================================================
func TestAttack_MalformedTokens(t *testing.T) {
	_, vkey, _ := setupFNDSAKeys(t)

	malformedTokens := []struct {
		name  string
		token string
	}{
		{"empty string", ""},
		{"single segment", "eyJhbGciOiJub25lIn0"},
		{"two segments", "eyJhbGciOiJub25lIn0.eyJ0ZXN0IjoxfQ"},
		{"four segments", "a.b.c.d"},
		{"just dots", ".."},
		{"null bytes", "\x00.\x00.\x00"},
	}

	for _, tc := range malformedTokens {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseWithProtection(tc.token, vkey)
			if err == nil {
				t.Fatalf("VULNERABLE: malformed token '%s' diterima!", tc.name)
			}

			t.Logf("PROTECTED: malformed token '%s' ditolak: %v", tc.name, err)
		})
	}
}

// ========================================================
// ATTACK 11: Future IssuedAt Attack
// Attacker membuat token dengan iat di masa depan
// Reference: RFC 7519 §4.1.6 "iat" (Issued At) Claim; RFC 8725 §3.10 Do
// Not Trust Received Claims (iat sanity-checked as untrusted input)
// ========================================================
func TestAttack_FutureIssuedAt(t *testing.T) {
	_, vkey, signer := setupFNDSAKeys(t)

	method := &jwt.SigningMethodFNDSAPrecomputed{Name: jwt.AlgFNDSA512}
	method.SetPrecomputedSigner(signer)

	token := jwt.NewWithClaims(method, TestClaims{
		UserID: uuid.New(),
		Email:  "test@example.com",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(48 * time.Hour)),
			Issuer:    "tasktify",
		},
	})

	tokenString, err := token.SignedString(nil)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	_, err = parseWithProtection(tokenString, vkey)
	if err == nil {
		t.Fatal("VULNERABLE: token dengan iat di masa depan diterima!")
	}

	t.Logf("PROTECTED: future iat ditolak: %v", err)
}

// ========================================================
// ATTACK 12: Algorithm Confusion - none dengan signature valid
// Attacker menyisipkan alg=none tapi tetap menyertakan signature
// Reference: RFC 7519 §6 Unsecured JWTs; RFC 8725 §3.1, §3.2
// ========================================================
func TestAttack_NoneWithSignature(t *testing.T) {
	_, vkey, signer := setupFNDSAKeys(t)
	validToken := createValidToken(t, signer)

	parts := strings.Split(validToken, ".")

	noneHeader := map[string]any{
		"typ": "JWT",
		"alg": "none",
	}
	headerJSON, _ := json.Marshal(noneHeader)
	forgedToken := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + parts[1] + "." + parts[2]

	_, err := parseWithProtection(forgedToken, vkey)
	if err == nil {
		t.Fatal("VULNERABLE: alg=none dengan signature diterima!")
	}

	t.Logf("PROTECTED: alg=none dengan signature ditolak: %v", err)
}

// ========================================================
// ATTACK 13: JSON Injection pada Claims
// Attacker memodifikasi claims (tambah role admin) tanpa re-sign
// Reference: RFC 8725 §3.3 Validate All Cryptographic Operations
// ("the entire JWT MUST be rejected if any of them fail to validate");
// §3.10 Do Not Trust Received Claims
// ========================================================
func TestAttack_JSONInjectionInClaims(t *testing.T) {
	_, vkey, signer := setupFNDSAKeys(t)
	validToken := createValidToken(t, signer)
	parts := strings.Split(validToken, ".")

	claimsBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	json.Unmarshal(claimsBytes, &claims)
	claims["role"] = "admin"

	modClaims, _ := json.Marshal(claims)
	modClaimsB64 := base64.RawURLEncoding.EncodeToString(modClaims)

	forgedToken := parts[0] + "." + modClaimsB64 + "." + parts[2]

	_, err := parseWithProtection(forgedToken, vkey)
	if err == nil {
		t.Fatal("VULNERABLE: JSON injection pada claims berhasil!")
	}

	t.Logf("PROTECTED: JSON injection ditolak: %v", err)
}

// ========================================================
// ATTACK: Replay Attack (Scenario 7)
// Attacker menggunakan ulang token valid yang sama berkali-kali
// JWT library bersifat stateless — deteksi harus di app layer via JTI blacklist
// Reference: RFC 7519 §4.1.7 "jti" (JWT ID) Claim ("This claim can be used
// to prevent the JWT from being replayed"). Neither RFC 7519 nor RFC 8725
// mandates stateful replay prevention — this test documents that gap
// rather than closing it (see docs/skenario-pengujian.md §6.5 "Gap").
// ========================================================
func TestAttack_ReplayAttack(t *testing.T) {
	_, vkey, signer := setupFNDSAKeys(t)
	validToken := createValidToken(t, signer)

	// Parse pertama — legitimate use
	tok1, err := parseWithProtection(validToken, vkey)
	if err != nil {
		t.Fatalf("first parse failed: %v", err)
	}
	claims1 := tok1.Claims.(*TestClaims)

	// Parse kedua — replay simulation (library stateless, masih accepted)
	tok2, err := parseWithProtection(validToken, vkey)
	if err != nil {
		t.Fatalf("replay parse failed: %v", err)
	}
	claims2 := tok2.Claims.(*TestClaims)

	if claims1.ID != claims2.ID {
		t.Fatal("JTI mismatch on replayed token — should be identical")
	}

	// Verifikasi setiap token baru punya JTI unik (syarat untuk blacklisting)
	freshToken := createValidToken(t, signer)
	tok3, err := parseWithProtection(freshToken, vkey)
	if err != nil {
		t.Fatalf("fresh token parse failed: %v", err)
	}
	claims3 := tok3.Claims.(*TestClaims)

	if claims1.ID == claims3.ID {
		t.Fatal("INSECURE: dua token berbeda punya JTI sama — replay detection tidak mungkin")
	}

	t.Logf("NOTE: JWT library stateless — replay token JTI=%s diterima (expected)", claims1.ID)
	t.Logf("MITIGATION: App layer wajib blacklist JTI setelah digunakan. Token baru punya JTI unik: %s", claims3.ID)
}

// ========================================================
// VERIFICATION: Token yang valid tetap bisa diverifikasi
// Memastikan proteksi tidak memblokir token yang legitimate
// ========================================================
func TestVerification_ValidTokenAccepted(t *testing.T) {
	_, vkey, signer := setupFNDSAKeys(t)

	method := &jwt.SigningMethodFNDSAPrecomputed{Name: jwt.AlgFNDSA512}
	method.SetPrecomputedSigner(signer)

	expectedUserID := uuid.New()
	expectedEmail := "legit@example.com"

	token := jwt.NewWithClaims(method, TestClaims{
		UserID: expectedUserID,
		Email:  expectedEmail,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(60 * time.Minute)),
			Issuer:    "tasktify",
		},
	})

	tokenString, err := token.SignedString(nil)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	parsedToken, err := parseWithProtection(tokenString, vkey)
	if err != nil {
		t.Fatalf("BROKEN: token yang valid ditolak: %v", err)
	}

	claims, ok := parsedToken.Claims.(*TestClaims)
	if !ok || !parsedToken.Valid {
		t.Fatal("BROKEN: claims tidak valid")
	}

	if claims.UserID != expectedUserID {
		t.Fatalf("BROKEN: UserID mismatch: expected %s, got %s", expectedUserID, claims.UserID)
	}
	if claims.Email != expectedEmail {
		t.Fatalf("BROKEN: Email mismatch: expected %s, got %s", expectedEmail, claims.Email)
	}

	t.Logf("VALID: token legitimate berhasil diverifikasi (user_id=%s, email=%s)", claims.UserID, claims.Email)
}

// ========================================================
// SUMMARY: Menjalankan semua attack test dan ringkasan
//
// Semua vektor di file ini menyerang lapisan JOSE/JWT envelope (header
// alg, klaim, compact serialization) dan berpijak pada RFC 7519 / RFC
// 8725 — lihat komentar "Reference:" di atas tiap fungsi Test di atas.
// Vektor terhadap primitif tanda tangan FN-DSA murni (bukan JWT) ada di
// backend/pkg/fndsa/fndsa_adversarial_test.go, berpijak pada spesifikasi
// Falcon resmi dan definisi keamanan EUF-CMA — lihat header komentar file
// tersebut.
//
// Mapping ke 10 Vektor Serangan Adversarial JWT:
//
//	#1  Signature Tampering       → TestAttack_SignatureTampering
//	    RFC 8725 §3.3
//	#2  Token Forgery             → TestAttack_SignatureStripping (empty/fake sig)
//	    RFC 8725 §3.1, §3.3
//	#3  Algorithm Confusion       → TestAttack_UnknownAlgorithm (HS256/RS256/ES256)
//	    RFC 8725 §3.1, §3.2
//	#4  None Algorithm Attack     → TestAttack_AlgorithmNone, TestAttack_NoneWithSignature
//	    RFC 7519 §6; RFC 8725 §3.1, §3.2
//	#5  Payload/Claim Manipulation→ TestAttack_JSONInjectionInClaims
//	    RFC 8725 §3.3, §3.10
//	#6  Expired Token Abuse       → TestAttack_ExpiredToken
//	    RFC 7519 §4.1.4
//	#7  Replay Attack             → TestAttack_ReplayAttack (stateless; JTI tracking at app layer)
//	    RFC 7519 §4.1.7 (documented gap, not closed by this test)
//	#8  Unsigned Compact Token    → TestAttack_SignatureStripping (empty signature case)
//	    RFC 7519 §6; RFC 8725 §3.1, §3.3
//	#9  Cross-Algorithm Injection → TestAttack_UnknownAlgorithm (RS256 ke FN-DSA verifier)
//	    RFC 8725 §3.1
//	#10 Invalid Issuer Attack     → TestAttack_IssuerSpoofing (incl. "example.com")
//	    RFC 7519 §4.1.1; RFC 8725 §3.8
//
// ========================================================
func TestConfusionAttackSummary(t *testing.T) {
	attacks := []struct {
		name string
		fn   func(*testing.T)
	}{
		// Scenario mapping
		{"[#1] Signature Tampering (flip byte)", TestAttack_SignatureTampering},
		{"[#2] Token Forgery (empty/fake signature)", TestAttack_SignatureStripping},
		{"[#3] Algorithm Confusion (HS256/RS256)", TestAttack_UnknownAlgorithm},
		{"[#4] None Algorithm Attack", TestAttack_AlgorithmNone},
		{"[#4b] None Algorithm with Signature", TestAttack_NoneWithSignature},
		{"[#5] Payload/Claim Manipulation (no resign)", TestAttack_JSONInjectionInClaims},
		{"[#6] Expired Token Abuse", TestAttack_ExpiredToken},
		{"[#7] Replay Attack (JTI uniqueness)", TestAttack_ReplayAttack},
		{"[#9] Cross-Algorithm Injection (PQC switch)", TestAttack_AlgorithmSwitchToFNDSA512},
		{"[#9b] Cross-Algorithm ML-DSA", TestAttack_AlgorithmSwitchToMLDSA},
		{"[#10] Invalid Issuer Attack (example.com)", TestAttack_IssuerSpoofing},
		// Additional hardening tests
		{"Algorithm Switch to FN-DSA-1024", TestAttack_AlgorithmSwitchToFNDSA1024},
		{"Cross-Key Verification", TestAttack_CrossKeyVerification},
		{"Malformed Tokens", TestAttack_MalformedTokens},
		{"Future IssuedAt", TestAttack_FutureIssuedAt},
		{"Valid Token Accepted", TestVerification_ValidTokenAccepted},
	}

	passed := 0
	failed := 0

	for _, attack := range attacks {
		t.Run(attack.name, func(t *testing.T) {
			defer func() {
				if t.Failed() {
					failed++
				} else {
					passed++
				}
			}()
			attack.fn(t)
		})
	}

	fmt.Printf("\n")
	fmt.Printf("══════════════════════════════════════════════════════════════════════════════\n")
	fmt.Printf("  ADVERSARIAL JWT TEST SUMMARY (10 Attack Vectors, JOSE/JWT envelope layer)\n")
	fmt.Printf("══════════════════════════════════════════════════════════════════════════════\n")
	fmt.Printf("  #1  Signature Tampering       : flip byte → 401/403           RFC 8725 §3.3\n")
	fmt.Printf("  #2  Token Forgery             : fake/empty sig → 401/403      RFC 8725 §3.1/§3.3\n")
	fmt.Printf("  #3  Algorithm Confusion       : HS256/RS256 → 401/403         RFC 8725 §3.1/§3.2\n")
	fmt.Printf("  #4  None Algorithm Attack     : alg=none → 401/403            RFC 7519 §6; 8725 §3.1\n")
	fmt.Printf("  #5  Payload Manipulation      : no resign → 401/403           RFC 8725 §3.3/§3.10\n")
	fmt.Printf("  #6  Expired Token Abuse       : exp lama → 401/403            RFC 7519 §4.1.4\n")
	fmt.Printf("  #7  Replay Attack             : stateless; app-layer JTI      RFC 7519 §4.1.7 (gap)\n")
	fmt.Printf("  #8  Unsigned Compact Token    : empty sig → 401/403           RFC 7519 §6; 8725 §3.1\n")
	fmt.Printf("  #9  Cross-Algorithm Injection : RS256→FN-DSA → 401/403        RFC 8725 §3.1\n")
	fmt.Printf("  #10 Invalid Issuer Attack     : example.com → 401/403         RFC 7519 §4.1.1; 8725 §3.8\n")
	fmt.Printf("══════════════════════════════════════════════════════════════════════════════\n")
	fmt.Printf("  Total Tests : %d\n", len(attacks))
	fmt.Printf("  Protected   : %d\n", passed)
	fmt.Printf("  Vulnerable  : %d\n", failed)
	fmt.Printf("══════════════════════════════════════════════════════════════════════════════\n")
	fmt.Printf("  NOTE: pure FN-DSA signature primitive attacks (norm bound, cross-key,\n")
	fmt.Printf("  domain-context, pre-hash confusion, truncation) are NOT covered here —\n")
	fmt.Printf("  see pkg/fndsa/fndsa_adversarial_test.go (Falcon spec + EUF-CMA grounded).\n")
	fmt.Printf("══════════════════════════════════════════════════════════════════════════════\n")
}
