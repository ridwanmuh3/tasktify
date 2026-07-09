package jwtutils

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ridwanmuh3/tasktify/pkg/fndsa"
	jwtlib "github.com/ridwanmuh3/tasktify/pkg/jwt"
)

func newSecurityTestJWT(t *testing.T) (JwtUtil, *jwtlib.SigningMethodFNDSAPrecomputed) {
	t.Helper()
	skey, vkey, err := fndsa.KeyGen(9, nil)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	signer, err := fndsa.NewPrecomputedSigner(skey)
	if err != nil {
		t.Fatalf("precompute failed: %v", err)
	}
	method := &jwtlib.SigningMethodFNDSAPrecomputed{Name: jwtlib.AlgFNDSA512}
	method.SetPrecomputedSigner(signer)
	util := NewMultiAlgJwtUtil("tasktify", 60, "FN-DSA-Precomputed-512", map[string]*AlgConfig{
		"FN-DSA-Precomputed-512": {
			Method:    method,
			SignKey:   nil,
			VerifyKey: vkey,
		},
	})
	return util, method
}

func baseSecurityClaims(tokenUse string) JWTClaims {
	now := time.Now()
	userID := uuid.New()
	return JWTClaims{
		UserID:   userID,
		Email:    "security@example.test",
		TokenUse: tokenUse,
		RegisteredClaims: jwtlib.RegisteredClaims{
			ID:        uuid.NewString(),
			Subject:   userID.String(),
			IssuedAt:  jwtlib.NewNumericDate(now),
			ExpiresAt: jwtlib.NewNumericDate(now.Add(time.Hour)),
			Issuer:    "tasktify",
		},
	}
}

func signSecurityClaims(
	t *testing.T,
	method *jwtlib.SigningMethodFNDSAPrecomputed,
	claims JWTClaims,
	header map[string]any,
) string {
	t.Helper()
	token := jwtlib.NewWithClaims(method, claims)
	token.Header["typ"] = TokenTypeForUse(claims.TokenUse)
	for k, v := range header {
		token.Header[k] = v
	}
	tokenString, err := token.SignedString(nil)
	if err != nil {
		t.Fatalf("sign token failed: %v", err)
	}
	return tokenString
}

func TestJWTUtilsRejectsSignedInvalidClaims(t *testing.T) {
	util, method := newSecurityTestJWT(t)

	tests := []struct {
		name   string
		mutate func(*JWTClaims)
	}{
		{
			name: "invalid issuer",
			mutate: func(claims *JWTClaims) {
				claims.Issuer = "evil-issuer"
			},
		},
		{
			name: "missing issuer",
			mutate: func(claims *JWTClaims) {
				claims.Issuer = ""
			},
		},
		{
			name: "empty subject",
			mutate: func(claims *JWTClaims) {
				claims.Subject = ""
			},
		},
		{
			name: "subject does not match user_id",
			mutate: func(claims *JWTClaims) {
				claims.Subject = uuid.NewString()
			},
		},
		{
			name: "nbf in future",
			mutate: func(claims *JWTClaims) {
				claims.NotBefore = jwtlib.NewNumericDate(time.Now().Add(time.Hour))
			},
		},
		{
			name: "iat in future",
			mutate: func(claims *JWTClaims) {
				claims.IssuedAt = jwtlib.NewNumericDate(time.Now().Add(time.Hour))
			},
		},
		{
			name: "invalid token_use",
			mutate: func(claims *JWTClaims) {
				claims.TokenUse = "id"
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := baseSecurityClaims(TokenUseAccess)
			tc.mutate(&claims)
			token := signSecurityClaims(t, method, claims, nil)
			if _, err := util.Parse(token); err == nil {
				t.Fatal("invalid signed token accepted")
			}
		})
	}
}

func TestJWTUtilsRejectsUnsupportedJOSEHeaders(t *testing.T) {
	util, method := newSecurityTestJWT(t)

	tests := []struct {
		name   string
		header map[string]any
	}{
		{name: "unknown kid", header: map[string]any{"kid": "unknown-key"}},
		{name: "kid path traversal", header: map[string]any{"kid": "../../private.pem"}},
		{name: "invalid crit", header: map[string]any{"crit": []string{"exp"}}},
		{name: "altered typ", header: map[string]any{"typ": "JWT"}},
		{name: "token type confusion", header: map[string]any{"typ": TokenTypeRefresh}},
		{name: "algorithm case variation", header: map[string]any{"alg": "fn-dsa-512"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := baseSecurityClaims(TokenUseAccess)
			token := signSecurityClaims(t, method, claims, tc.header)
			if _, err := util.Parse(token); err == nil {
				t.Fatal("token with unsupported header accepted")
			}
		})
	}
}

func TestJWTUtilsRejectsOversizedCompactToken(t *testing.T) {
	util, _ := newSecurityTestJWT(t)
	if _, err := util.Parse(strings.Repeat("a", maxJWTCompactBytes+1)); err == nil {
		t.Fatal("oversized token accepted")
	}
}
