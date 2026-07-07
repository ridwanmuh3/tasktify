package jwt

import (
	"encoding/base64"
	"testing"
)

func compactForParserTest(headerJSON, claimsJSON, sig string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	claims := base64.RawURLEncoding.EncodeToString([]byte(claimsJSON))
	return header + "." + claims + "." + sig
}

func TestParserRejectsDuplicateHeaderNames(t *testing.T) {
	token := compactForParserTest(
		`{"typ":"JWT","alg":"none","alg":"FN-DSA-512"}`,
		`{"sub":"user"}`,
		"",
	)
	if _, _, err := NewParser().ParseUnverified(token, MapClaims{}); err == nil {
		t.Fatal("duplicate header name accepted")
	}
}

func TestParserRejectsDuplicateClaimNames(t *testing.T) {
	token := compactForParserTest(
		`{"typ":"JWT","alg":"none"}`,
		`{"sub":"user","sub":"admin"}`,
		"",
	)
	if _, _, err := NewParser().ParseUnverified(token, MapClaims{}); err == nil {
		t.Fatal("duplicate claim name accepted")
	}
}

func TestParserRejectsInvalidBase64URLAndMalformedJSON(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{name: "invalid header base64url", token: "%." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user"}`)) + "."},
		{name: "invalid claim base64url", token: base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + ".%."},
		{name: "malformed header json", token: compactForParserTest(`{"alg":`, `{"sub":"user"}`, "")},
		{name: "malformed claim json", token: compactForParserTest(`{"alg":"none"}`, `{"sub":`, "")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := NewParser().ParseUnverified(tc.token, MapClaims{}); err == nil {
				t.Fatal("malformed token accepted")
			}
		})
	}
}
