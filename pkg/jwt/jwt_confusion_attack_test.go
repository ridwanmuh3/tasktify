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

// setupFalconKeys generates Falcon-512 key pair dan precomputed signer
func setupFalconKeys(t *testing.T) (skey []byte, vkey []byte, signer *fndsa.PrecomputedSigner) {
	t.Helper()
	skey, vkey, err := fndsa.KeyGen(9, nil)
	if err != nil {
		t.Fatalf("failed to generate Falcon-512 keys: %v", err)
	}

	signer, err = fndsa.NewPrecomputedSigner(skey)
	if err != nil {
		t.Fatalf("failed to create precomputed signer: %v", err)
	}

	return skey, vkey, signer
}

// createValidToken membuat token yang valid dengan Falcon Precomputed-512
func createValidToken(t *testing.T, signer *fndsa.PrecomputedSigner) string {
	t.Helper()

	method := &jwt.SigningMethodFalconPrecomputed{Name: "Falcon-Precomputed-512"}
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
		jwt.WithValidMethods([]string{"Falcon-Precomputed-512"}),
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
// ========================================================
func TestAttack_AlgorithmNone(t *testing.T) {
	_, vkey, signer := setupFalconKeys(t)
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
// ATTACK 2: Algorithm Switching (Precomputed-512 -> Falcon-512)
// Attacker mencoba switch dari precomputed ke non-precomputed
// lalu re-sign dengan private key menggunakan Falcon-512 standard
// ========================================================
func TestAttack_AlgorithmSwitchToFalcon512(t *testing.T) {
	skey, vkey, signer := setupFalconKeys(t)
	validToken := createValidToken(t, signer)

	parts := strings.Split(validToken, ".")

	switchedHeader := map[string]any{
		"typ": "JWT",
		"alg": "Falcon-512",
	}
	headerJSON, _ := json.Marshal(switchedHeader)

	newHeaderB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	signingString := newHeaderB64 + "." + parts[1]

	sig, err := fndsa.Sign(rand.Reader, skey, fndsa.DOMAIN_NONE, crypto.SHA3_256, []byte(signingString))
	if err != nil {
		t.Fatalf("failed to sign with Falcon-512: %v", err)
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	forgedToken := signingString + "." + sigB64

	_, err = parseWithProtection(forgedToken, vkey)
	if err == nil {
		t.Fatal("VULNERABLE: algorithm switch dari Precomputed-512 ke Falcon-512 berhasil!")
	}

	t.Logf("PROTECTED: algorithm switch Falcon-512 ditolak: %v", err)
}

// ========================================================
// ATTACK 3: Algorithm Switching ke ML-DSA
// Attacker mencoba switch ke ML-DSA algorithm
// ========================================================
func TestAttack_AlgorithmSwitchToMLDSA(t *testing.T) {
	_, vkey, signer := setupFalconKeys(t)
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
// ATTACK 4: Algorithm Confusion ke Falcon-1024
// Attacker mencoba switch ke Falcon-1024/Falcon-Precomputed-1024
// ========================================================
func TestAttack_AlgorithmSwitchToFalcon1024(t *testing.T) {
	_, vkey, signer := setupFalconKeys(t)
	validToken := createValidToken(t, signer)

	parts := strings.Split(validToken, ".")

	for _, alg := range []string{"Falcon-1024", "Falcon-Precomputed-1024"} {
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
// ATTACK 5: Signature Stripping
// Attacker menghapus atau memanipulasi signature dari token
// ========================================================
func TestAttack_SignatureStripping(t *testing.T) {
	_, vkey, signer := setupFalconKeys(t)
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
// ========================================================
func TestAttack_ExpiredToken(t *testing.T) {
	_, vkey, signer := setupFalconKeys(t)

	method := &jwt.SigningMethodFalconPrecomputed{Name: "Falcon-Precomputed-512"}
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
// ATTACK 7: Issuer Spoofing
// Attacker membuat token dengan issuer yang berbeda
// ========================================================
func TestAttack_IssuerSpoofing(t *testing.T) {
	_, vkey, signer := setupFalconKeys(t)

	method := &jwt.SigningMethodFalconPrecomputed{Name: "Falcon-Precomputed-512"}
	method.SetPrecomputedSigner(signer)

	token := jwt.NewWithClaims(method, TestClaims{
		UserID: uuid.New(),
		Email:  "attacker@evil.com",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(60 * time.Minute)),
			Issuer:    "evil-service",
		},
	})

	tokenString, err := token.SignedString(nil)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	_, err = parseWithProtection(tokenString, vkey)
	if err == nil {
		t.Fatal("VULNERABLE: issuer spoofing berhasil!")
	}

	t.Logf("PROTECTED: issuer spoofing ditolak: %v", err)
}

// ========================================================
// ATTACK 8: Cross-Key Verification
// Attacker mencoba verifikasi dengan key pair yang berbeda
// ========================================================
func TestAttack_CrossKeyVerification(t *testing.T) {
	_, _, signer := setupFalconKeys(t)

	// Generate key pair kedua (attacker's keys)
	_, attackerVkey, _ := setupFalconKeys(t)

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
// ========================================================
func TestAttack_UnknownAlgorithm(t *testing.T) {
	_, vkey, signer := setupFalconKeys(t)
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
// ========================================================
func TestAttack_MalformedTokens(t *testing.T) {
	_, vkey, _ := setupFalconKeys(t)

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
// ========================================================
func TestAttack_FutureIssuedAt(t *testing.T) {
	_, vkey, signer := setupFalconKeys(t)

	method := &jwt.SigningMethodFalconPrecomputed{Name: "Falcon-Precomputed-512"}
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
// ========================================================
func TestAttack_NoneWithSignature(t *testing.T) {
	_, vkey, signer := setupFalconKeys(t)
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
// ========================================================
func TestAttack_JSONInjectionInClaims(t *testing.T) {
	_, vkey, signer := setupFalconKeys(t)
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
// VERIFICATION: Token yang valid tetap bisa diverifikasi
// Memastikan proteksi tidak memblokir token yang legitimate
// ========================================================
func TestVerification_ValidTokenAccepted(t *testing.T) {
	_, vkey, signer := setupFalconKeys(t)

	method := &jwt.SigningMethodFalconPrecomputed{Name: "Falcon-Precomputed-512"}
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
// ========================================================
func TestConfusionAttackSummary(t *testing.T) {
	attacks := []struct {
		name string
		fn   func(*testing.T)
	}{
		{"Algorithm None", TestAttack_AlgorithmNone},
		{"Algorithm Switch to Falcon-512", TestAttack_AlgorithmSwitchToFalcon512},
		{"Algorithm Switch to ML-DSA", TestAttack_AlgorithmSwitchToMLDSA},
		{"Algorithm Switch to Falcon-1024", TestAttack_AlgorithmSwitchToFalcon1024},
		{"Signature Stripping", TestAttack_SignatureStripping},
		{"Expired Token", TestAttack_ExpiredToken},
		{"Issuer Spoofing", TestAttack_IssuerSpoofing},
		{"Cross-Key Verification", TestAttack_CrossKeyVerification},
		{"Unknown Algorithms", TestAttack_UnknownAlgorithm},
		{"Malformed Tokens", TestAttack_MalformedTokens},
		{"Future IssuedAt", TestAttack_FutureIssuedAt},
		{"None with Signature", TestAttack_NoneWithSignature},
		{"JSON Injection", TestAttack_JSONInjectionInClaims},
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
	fmt.Printf("══════════════════════════════════════════════════════\n")
	fmt.Printf("  JWT CONFUSION ATTACK TEST SUMMARY\n")
	fmt.Printf("══════════════════════════════════════════════════════\n")
	fmt.Printf("  Total Tests : %d\n", len(attacks))
	fmt.Printf("  Protected   : %d\n", passed)
	fmt.Printf("  Vulnerable  : %d\n", failed)
	fmt.Printf("══════════════════════════════════════════════════════\n")
}
