package jwtutils

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/google/uuid"

	jwtlib "github.com/ridwanmuh3/tasktify/pkg/jwt"
)

// ========================================================
// ATTACK: RS256 -> HS256 key confusion
//
// Reference: RFC 8725 §3.1 Perform Algorithm Verification — verbatim:
// "attackers can change 'RS256' to 'HS256' and use the RSA public key as
// an HMAC secret." This is the single named example in RFC 8725 §3.1, not
// a vector this test suite invented.
//
// Textbook JWT vulnerability: a verifier that resolves the verification key
// without regard to the token's declared algorithm can be tricked into
// treating an RSA *public* key (not secret — attacker-obtainable) as an
// HMAC secret. If alg=HS256 and the server's keyFunc still hands back the
// RS256 public key, HMAC-SHA256(publicKeyBytes, signingInput) verifies.
//
// multiAlgJwtUtil.configForHeaderAlg resolves the verify key by matching
// the token header alg against each registered AlgConfig's own
// cfg.Method.Alg(), so alg=HS256 always resolves to the HS256 config's
// key — never the RS256 config's key — regardless of what the attacker
// puts in the header. This test proves that resolution holds even when
// both RS256 and HS256 are registered on the same verifier (the scenario
// where classic key-confusion libraries fail).
// ========================================================

func newKeyConfusionTestJWT(t *testing.T) (JwtUtil, *rsa.PublicKey) {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen failed: %v", err)
	}

	hmacSecret := make([]byte, 32)
	if _, err := rand.Read(hmacSecret); err != nil {
		t.Fatalf("hmac secret generation failed: %v", err)
	}

	util := NewMultiAlgJwtUtil("tasktify", "", 60, "RS256", map[string]*AlgConfig{
		"RS256": {
			Method:    jwtlib.SigningMethodRS256,
			SignKey:   rsaKey,
			VerifyKey: &rsaKey.PublicKey,
		},
		"HS256": {
			Method:    jwtlib.SigningMethodHS256,
			SignKey:   hmacSecret,
			VerifyKey: hmacSecret,
		},
	})

	return util, &rsaKey.PublicKey
}

func rsaPublicKeyPEMBytes(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal RS256 public key failed: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der})
}

func TestAttack_RS256ToHS256KeyConfusion(t *testing.T) {
	util, rsaPub := newKeyConfusionTestJWT(t)

	validToken, err := util.Sign(&JWTPayload{
		UserID:    uuid.New(),
		Algorithm: "RS256",
		TokenUse:  TokenUseAccess,
	})
	if err != nil {
		t.Fatalf("failed to sign valid RS256 token: %v", err)
	}

	parts := strings.Split(validToken, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected token shape: %d parts", len(parts))
	}

	// Attacker only has the RS256 public key (published, not secret).
	pubKeyBytes := rsaPublicKeyPEMBytes(t, rsaPub)

	// Forge alg=HS256 header, keep original payload, sign with HMAC-SHA256
	// using the RS256 public key bytes as the "secret".
	forgedHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"at+jwt","alg":"HS256"}`))
	signingInput := forgedHeader + "." + parts[1]

	mac := hmac.New(sha256.New, pubKeyBytes)
	mac.Write([]byte(signingInput))
	forgedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	forgedToken := signingInput + "." + forgedSig

	if _, err := util.Parse(forgedToken); err == nil {
		t.Fatal("VULNERABLE: RS256->HS256 key confusion forged token accepted")
	} else {
		t.Logf("PROTECTED: RS256->HS256 key confusion rejected: %v", err)
	}

	// Sanity: a token genuinely signed with the real HS256 secret still
	// verifies — proves the rejection above is due to correct per-algorithm
	// key resolution, not a broken HS256 path.
	hsToken, err := util.Sign(&JWTPayload{
		UserID:    uuid.New(),
		Algorithm: "HS256",
		TokenUse:  TokenUseAccess,
	})
	if err != nil {
		t.Fatalf("failed to sign valid HS256 token: %v", err)
	}
	if _, err := util.Parse(hsToken); err != nil {
		t.Fatalf("SAFE HS256 path broken: genuinely signed HS256 token rejected: %v", err)
	}
}

// TestAttack_RS256ToHS256KeyConfusion_RawDERSecret confirms rejection isn't
// merely an artifact of PEM framing bytes changing the HMAC input — a raw
// DER-encoded public key as the forged secret is rejected the same way.
func TestAttack_RS256ToHS256KeyConfusion_RawDERSecret(t *testing.T) {
	util, rsaPub := newKeyConfusionTestJWT(t)

	validToken, err := util.Sign(&JWTPayload{
		UserID:    uuid.New(),
		Algorithm: "RS256",
		TokenUse:  TokenUseAccess,
	})
	if err != nil {
		t.Fatalf("failed to sign valid RS256 token: %v", err)
	}
	parts := strings.Split(validToken, ".")

	// Even a guessed-correct-looking but wrong-shaped secret (raw DER
	// instead of PEM) must not verify — resolution is per-alg, not
	// per-byte-content.
	der, err := x509.MarshalPKIXPublicKey(rsaPub)
	if err != nil {
		t.Fatalf("marshal RS256 public key failed: %v", err)
	}
	forgedHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"at+jwt","alg":"HS256"}`))
	signingInput := forgedHeader + "." + parts[1]
	mac := hmac.New(sha256.New, der)
	mac.Write([]byte(signingInput))
	forgedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	forgedToken := signingInput + "." + forgedSig

	if _, err := util.Parse(forgedToken); err == nil {
		t.Fatal("VULNERABLE: RS256->HS256 key confusion (raw DER secret) accepted")
	}
}
