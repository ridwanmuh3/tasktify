package jwtutils

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ridwanmuh3/tasktify/pkg/fndsa"
	"github.com/ridwanmuh3/tasktify/pkg/jwt"
)

func TestMultiAlgJwtUtilUsesCanonicalFNDSAHeaderForPrecomputedProfile(t *testing.T) {
	util := newTestFNDSAJwtUtil(t, "tasktify")
	userID := uuid.New()

	tokenString, err := util.Sign(&JWTPayload{
		UserID:    userID,
		Email:     "profile@example.com",
		Algorithm: "FN-DSA-Precomputed-512",
		TokenUse:  TokenUseAccess,
	})
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	header := decodeJWTHeader(t, tokenString)
	if header["alg"] != jwt.AlgFNDSA512 {
		t.Fatalf("wrong alg header: got %v, want %s", header["alg"], jwt.AlgFNDSA512)
	}
	if header["alg"] == "FN-DSA-Precomputed-512" {
		t.Fatal("precomputed signer profile leaked into JWS alg header")
	}
	if header["typ"] != TokenTypeAccess {
		t.Fatalf("wrong typ header: got %v, want %s", header["typ"], TokenTypeAccess)
	}

	claims, err := util.Parse(tokenString)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if claims.UserID != userID || claims.Subject != userID.String() {
		t.Fatalf("subject/user_id mismatch: sub=%q user_id=%s", claims.Subject, claims.UserID)
	}

	headerAlg, err := AlgorithmFromToken(tokenString)
	if err != nil {
		t.Fatalf("read alg failed: %v", err)
	}
	if headerAlg != jwt.AlgFNDSA512 {
		t.Fatalf("AlgorithmFromToken got %s, want %s", headerAlg, jwt.AlgFNDSA512)
	}
}

func TestMultiAlgJwtUtilRejectsUnconfiguredFNDSASigningProfile(t *testing.T) {
	util := newTestFNDSAJwtUtil(t, "tasktify")

	_, err := util.Sign(&JWTPayload{
		UserID:    uuid.New(),
		Email:     "profile@example.com",
		Algorithm: "HS256",
		TokenUse:  TokenUseAccess,
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported algorithm: HS256") {
		t.Fatalf("Sign(HS256) error = %v, want unsupported algorithm", err)
	}
}

func TestMultiAlgJwtUtilAllowsCanonicalFNDSASigningProfile(t *testing.T) {
	util := newTestFNDSAJwtUtil(t, "tasktify")
	userID := uuid.New()

	tokenString, err := util.Sign(&JWTPayload{
		UserID:    userID,
		Email:     "profile@example.com",
		Algorithm: jwt.AlgFNDSA512,
		TokenUse:  TokenUseAccess,
	})
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	claims, err := util.Parse(tokenString)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if claims.UserID != userID {
		t.Fatalf("wrong user_id: got %s, want %s", claims.UserID, userID)
	}
}

func TestMultiAlgJwtUtilRejectsJWTProfileViolations(t *testing.T) {
	util, method := newTestFNDSAJwtUtilWithMethod(t, "tasktify")
	userID := uuid.New()
	now := time.Now()

	tests := []struct {
		name   string
		claims JWTClaims
		typ    string
	}{
		{
			name: "invalid issuer",
			claims: JWTClaims{
				UserID:   userID,
				Email:    "profile@example.com",
				TokenUse: TokenUseAccess,
				RegisteredClaims: jwt.RegisteredClaims{
					ID:        uuid.NewString(),
					Subject:   userID.String(),
					IssuedAt:  jwt.NewNumericDate(now),
					ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
					Issuer:    "evil-service",
				},
			},
			typ: TokenTypeAccess,
		},
		{
			name: "future iat",
			claims: JWTClaims{
				UserID:   userID,
				Email:    "profile@example.com",
				TokenUse: TokenUseAccess,
				RegisteredClaims: jwt.RegisteredClaims{
					ID:        uuid.NewString(),
					Subject:   userID.String(),
					IssuedAt:  jwt.NewNumericDate(now.Add(time.Hour)),
					ExpiresAt: jwt.NewNumericDate(now.Add(2 * time.Hour)),
					Issuer:    "tasktify",
				},
			},
			typ: TokenTypeAccess,
		},
		{
			name: "subject mismatch",
			claims: JWTClaims{
				UserID:   userID,
				Email:    "profile@example.com",
				TokenUse: TokenUseAccess,
				RegisteredClaims: jwt.RegisteredClaims{
					ID:        uuid.NewString(),
					Subject:   uuid.NewString(),
					IssuedAt:  jwt.NewNumericDate(now),
					ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
					Issuer:    "tasktify",
				},
			},
			typ: TokenTypeAccess,
		},
		{
			name: "altered typ",
			claims: JWTClaims{
				UserID:   userID,
				Email:    "profile@example.com",
				TokenUse: TokenUseAccess,
				RegisteredClaims: jwt.RegisteredClaims{
					ID:        uuid.NewString(),
					Subject:   userID.String(),
					IssuedAt:  jwt.NewNumericDate(now),
					ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
					Issuer:    "tasktify",
				},
			},
			typ: "JWT",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := jwt.NewWithClaims(method, tc.claims)
			token.Header["typ"] = tc.typ
			tokenString, err := token.SignedString(nil)
			if err != nil {
				t.Fatalf("sign failed: %v", err)
			}
			if _, err := util.Parse(tokenString); err == nil {
				t.Fatal("expected profile violation to be rejected")
			}
		})
	}
}

func newTestFNDSAJwtUtil(t *testing.T, issuer string) JwtUtil {
	t.Helper()
	util, _ := newTestFNDSAJwtUtilWithMethod(t, issuer)
	return util
}

func newTestFNDSAJwtUtilWithMethod(t *testing.T, issuer string) (JwtUtil, *jwt.SigningMethodFNDSAPrecomputed) {
	t.Helper()
	sk, vk, err := fndsa.KeyGen(9, nil)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	signer, err := fndsa.NewPrecomputedSigner(sk)
	if err != nil {
		t.Fatalf("precompute failed: %v", err)
	}
	method := &jwt.SigningMethodFNDSAPrecomputed{Name: jwt.AlgFNDSA512}
	method.SetPrecomputedSigner(signer)
	configs := map[string]*AlgConfig{
		"FN-DSA-Precomputed-512": {
			Method:    method,
			VerifyKey: vk,
		},
	}
	return NewMultiAlgJwtUtil(issuer, "", 60, "FN-DSA-Precomputed-512", configs), method
}

func decodeJWTHeader(t *testing.T, tokenString string) map[string]any {
	t.Helper()
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header failed: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("unmarshal header failed: %v", err)
	}
	return header
}
