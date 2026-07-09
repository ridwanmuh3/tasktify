package jwt

import (
	"encoding/base64"
	"testing"
)

// ========================================================
// Parser hardening tests. Two different reference classes apply here —
// stated explicitly because not everything below is RFC 7519/8725
// grounded, and claiming otherwise would misrepresent the citation:
//
//   - Duplicate header/claim names: RFC 8259 (JSON) §4 Objects — "The
//     names within an object SHOULD be unique... When the names within an
//     object are not unique, the behavior of software that receives such
//     an object is unpredictable." This is a JSON-level ambiguity, not an
//     RFC 7519/8725 requirement; RFC 8725 does not have a dedicated
//     duplicate-member section. Rejecting duplicates outright (rather than
//     silently taking last-wins, as many parsers do) is this
//     implementation's choice to fail closed, in the spirit of RFC 8725
//     §3.3's "the entire JWT MUST be rejected if any [check] fail[s] to
//     validate" — but that section does not itself name this vector.
//   - Malformed base64url / malformed JSON: RFC 7519 §3 JWT Format
//     defines a JWT as three base64url-encoded, dot-separated parts; a
//     part that fails to decode, or a header/payload that fails to parse
//     as JSON (RFC 8259), is not a valid JWT by that definition and must
//     be rejected before any claim/signature check runs.
// ========================================================

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
