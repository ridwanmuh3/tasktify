package jwtutils

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"

	"github.com/ridwanmuh3/tasktify/pkg/jwt"
)

type JwtUtil interface {
	Sign(payload *JWTPayload) (string, error)
	Parse(token string) (*JWTClaims, error)
}

type JWTClaims struct {
	jwt.RegisteredClaims
	UserID   uuid.UUID `json:"user_id"`
	Email    string    `json:"email"`
	TokenUse string    `json:"token_use,omitempty"`
}

type JWTPayload struct {
	UserID    uuid.UUID
	Email     string
	Algorithm string // optional: override signing algorithm
	TokenUse  string
}

const (
	TokenUseAccess  = "access"
	TokenUseRefresh = "refresh"

	TokenTypeAccess  = "at+jwt"
	TokenTypeRefresh = "rt+jwt"

	maxJWTCompactBytes = 64 * 1024
)

// AlgConfig holds the signing method, sign key, and verify key for a single algorithm.
type AlgConfig struct {
	Method    jwt.SigningMethod
	SignKey   any // private key (nil for precomputed signers)
	VerifyKey any // public key
}

func (c JWTClaims) Validate() error {
	if c.UserID == uuid.Nil {
		return errors.New("user_id claim is required")
	}
	if c.Email == "" {
		return errors.New("email claim is required")
	}
	if c.TokenUse != TokenUseAccess && c.TokenUse != TokenUseRefresh {
		return errors.New("token_use claim is invalid")
	}
	if c.Subject == "" {
		return errors.New("sub claim is required")
	}
	if c.Subject != c.UserID.String() {
		return errors.New("sub claim must match user_id")
	}
	return nil
}

func TokenTypeForUse(tokenUse string) string {
	switch tokenUse {
	case TokenUseRefresh:
		return TokenTypeRefresh
	default:
		return TokenTypeAccess
	}
}

func HeaderAlgForConfigAlg(alg string) string {
	switch alg {
	case "Falcon-512", "Falcon-Precomputed-512", "FN-DSA-512":
		return jwt.AlgFNDSA512
	default:
		return alg
	}
}

func normalizeAllowedAlgs(algs []string) []string {
	seen := make(map[string]struct{}, len(algs))
	out := make([]string, 0, len(algs))
	for _, alg := range algs {
		headerAlg := HeaderAlgForConfigAlg(alg)
		if _, ok := seen[headerAlg]; ok {
			continue
		}
		seen[headerAlg] = struct{}{}
		out = append(out, headerAlg)
	}
	return out
}

// ════════════════════════════════════════════════════════════════
// Single-algorithm JwtUtil (backward compatible)
// ════════════════════════════════════════════════════════════════

type jwtUtil struct {
	allowedAlgs []string
	issuer      string
	verifyKey   []byte
	method      jwt.SigningMethod
	duration    int
}

// NewJwtUtil creates a JwtUtil for verification only (gateway).
// The verifyKey is the Falcon public key bytes.
func NewJwtUtil(config *viper.Viper, verifyKey []byte) JwtUtil {
	return &jwtUtil{
		allowedAlgs: normalizeAllowedAlgs(config.GetStringSlice("JWT_ALLOWED_ALGS")),
		issuer:      config.GetString("JWT_ISSUER"),
		verifyKey:   verifyKey,
		duration:    config.GetInt("JWT_TOKEN_DURATION"),
	}
}

// NewJwtUtilWithSigner creates a JwtUtil with precomputed signer (auth-service).
// The method should already have PrecomputedSigner set via SetPrecomputedSigner.
func NewJwtUtilWithSigner(config *viper.Viper, method jwt.SigningMethod, verifyKey []byte) JwtUtil {
	return &jwtUtil{
		allowedAlgs: normalizeAllowedAlgs(config.GetStringSlice("JWT_ALLOWED_ALGS")),
		issuer:      config.GetString("JWT_ISSUER"),
		verifyKey:   verifyKey,
		method:      method,
		duration:    config.GetInt("JWT_TOKEN_DURATION"),
	}
}

func (j *jwtUtil) Sign(payload *JWTPayload) (string, error) {
	if j.method == nil {
		return "", errors.New("signing method not configured, use NewJwtUtilWithSigner for signing")
	}

	currentTime := time.Now()
	tokenUse := payload.TokenUse
	if tokenUse == "" {
		tokenUse = TokenUseAccess
	}

	token := jwt.NewWithClaims(j.method, JWTClaims{
		UserID:   payload.UserID,
		Email:    payload.Email,
		TokenUse: tokenUse,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Subject:   payload.UserID.String(),
			IssuedAt:  jwt.NewNumericDate(currentTime),
			ExpiresAt: jwt.NewNumericDate(currentTime.Add(time.Duration(j.duration) * time.Minute)),
			Issuer:    j.issuer,
		},
	})
	token.Header["typ"] = TokenTypeForUse(tokenUse)

	// For precomputed Falcon, key is ignored by Sign() as signer is embedded
	s, err := token.SignedString(nil)
	if err != nil {
		return "", err
	}

	return s, nil
}

func (j *jwtUtil) Parse(token string) (*JWTClaims, error) {
	if len(token) > maxJWTCompactBytes {
		return nil, errors.New("token exceeds maximum compact size")
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods(j.allowedAlgs),
		jwt.WithIssuer(j.issuer),
		jwt.WithIssuedAt(),
	)

	parsedToken, err := parser.ParseWithClaims(token, &JWTClaims{}, func(t *jwt.Token) (any, error) {
		return j.verifyKey, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := parsedToken.Claims.(*JWTClaims); ok && parsedToken.Valid {
		if err := validateTokenTypeHeader(parsedToken, claims.TokenUse); err != nil {
			return nil, err
		}
		return claims, nil
	}
	return nil, errors.New("token is not valid")
}

// ════════════════════════════════════════════════════════════════
// Multi-algorithm JwtUtil
// ════════════════════════════════════════════════════════════════

type multiAlgJwtUtil struct {
	issuer     string
	duration   int
	defaultAlg string
	configs    map[string]*AlgConfig // alg name -> config
}

// NewMultiAlgJwtUtil creates a JwtUtil that supports multiple signing algorithms.
// defaultAlg is used when JWTPayload.Algorithm is empty.
// For verification, the algorithm is read from the token header and the
// corresponding verify key is returned.
func NewMultiAlgJwtUtil(issuer string, duration int, defaultAlg string, configs map[string]*AlgConfig) JwtUtil {
	return &multiAlgJwtUtil{
		issuer:     issuer,
		duration:   duration,
		defaultAlg: defaultAlg,
		configs:    configs,
	}
}

func (m *multiAlgJwtUtil) Sign(payload *JWTPayload) (string, error) {
	alg := payload.Algorithm
	if alg == "" {
		alg = m.defaultAlg
	}

	cfg, ok := m.configs[alg]
	if !ok {
		cfg, ok = m.configForSignAlg(alg)
		if !ok {
			return "", fmt.Errorf("unsupported algorithm: %s", alg)
		}
	}

	currentTime := time.Now()
	tokenUse := payload.TokenUse
	if tokenUse == "" {
		tokenUse = TokenUseAccess
	}

	token := jwt.NewWithClaims(cfg.Method, JWTClaims{
		UserID:   payload.UserID,
		Email:    payload.Email,
		TokenUse: tokenUse,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Subject:   payload.UserID.String(),
			IssuedAt:  jwt.NewNumericDate(currentTime),
			ExpiresAt: jwt.NewNumericDate(currentTime.Add(time.Duration(m.duration) * time.Minute)),
			Issuer:    m.issuer,
		},
	})
	token.Header["typ"] = TokenTypeForUse(tokenUse)

	s, err := token.SignedString(cfg.SignKey)
	if err != nil {
		return "", err
	}
	return s, nil
}

func (m *multiAlgJwtUtil) Parse(tokenStr string) (*JWTClaims, error) {
	if len(tokenStr) > maxJWTCompactBytes {
		return nil, errors.New("token exceeds maximum compact size")
	}

	allowedAlgs := m.allowedHeaderAlgs()

	parser := jwt.NewParser(
		jwt.WithValidMethods(allowedAlgs),
		jwt.WithIssuer(m.issuer),
		jwt.WithIssuedAt(),
	)

	parsedToken, err := parser.ParseWithClaims(tokenStr, &JWTClaims{}, func(t *jwt.Token) (any, error) {
		// Return the correct verify key based on the token's algorithm
		alg := t.Method.Alg()
		cfg, ok := m.configForHeaderAlg(alg)
		if !ok {
			return nil, fmt.Errorf("no key configured for algorithm: %s", alg)
		}
		return cfg.VerifyKey, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := parsedToken.Claims.(*JWTClaims); ok && parsedToken.Valid {
		if err := validateTokenTypeHeader(parsedToken, claims.TokenUse); err != nil {
			return nil, err
		}
		return claims, nil
	}
	return nil, errors.New("token is not valid")
}

func (m *multiAlgJwtUtil) configForSignAlg(alg string) (*AlgConfig, bool) {
	headerAlg := HeaderAlgForConfigAlg(alg)
	if cfg, ok := m.configs[m.defaultAlg]; ok && cfg.Method.Alg() == headerAlg {
		return cfg, true
	}
	return m.configForHeaderAlg(headerAlg)
}

func (m *multiAlgJwtUtil) configForHeaderAlg(headerAlg string) (*AlgConfig, bool) {
	for _, cfg := range m.configs {
		if cfg.Method.Alg() == headerAlg {
			return cfg, true
		}
	}
	return nil, false
}

func (m *multiAlgJwtUtil) allowedHeaderAlgs() []string {
	seen := make(map[string]struct{}, len(m.configs))
	algs := make([]string, 0, len(m.configs))
	for _, cfg := range m.configs {
		if cfg == nil || cfg.Method == nil {
			continue
		}
		alg := cfg.Method.Alg()
		if _, ok := seen[alg]; ok {
			continue
		}
		seen[alg] = struct{}{}
		algs = append(algs, alg)
	}
	return algs
}

func validateTokenTypeHeader(token *jwt.Token, tokenUse string) error {
	if _, ok := token.Header["crit"]; ok {
		return errors.New("crit header is not supported")
	}
	if _, ok := token.Header["kid"]; ok {
		return errors.New("kid header is not supported")
	}

	expected := TokenTypeForUse(tokenUse)
	if expected == "" {
		return nil
	}
	got, _ := token.Header["typ"].(string)
	if got != expected {
		return fmt.Errorf("token typ %q does not match token_use %q", got, tokenUse)
	}
	return nil
}

func AlgorithmFromToken(tokenStr string) (string, error) {
	token, _, err := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return "", err
	}
	if token.Method == nil {
		return "", errors.New("token algorithm unavailable")
	}
	return token.Method.Alg(), nil
}
