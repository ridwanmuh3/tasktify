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
	UserID uuid.UUID `json:"user_id"`
	Email  string    `json:"email"`
}

type JWTPayload struct {
	UserID    uuid.UUID
	Email     string
	Algorithm string // optional: override signing algorithm
}

// AlgConfig holds the signing method, sign key, and verify key for a single algorithm.
type AlgConfig struct {
	Method    jwt.SigningMethod
	SignKey   any // private key (nil for precomputed signers)
	VerifyKey any // public key
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
		allowedAlgs: config.GetStringSlice("JWT_ALLOWED_ALGS"),
		issuer:      config.GetString("JWT_ISSUER"),
		verifyKey:   verifyKey,
		duration:    config.GetInt("JWT_TOKEN_DURATION"),
	}
}

// NewJwtUtilWithSigner creates a JwtUtil with precomputed signer (auth-service).
// The method should already have PrecomputedSigner set via SetPrecomputedSigner.
func NewJwtUtilWithSigner(config *viper.Viper, method jwt.SigningMethod, verifyKey []byte) JwtUtil {
	return &jwtUtil{
		allowedAlgs: config.GetStringSlice("JWT_ALLOWED_ALGS"),
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

	token := jwt.NewWithClaims(j.method, JWTClaims{
		UserID: payload.UserID,
		Email:  payload.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(currentTime),
			ExpiresAt: jwt.NewNumericDate(currentTime.Add(time.Duration(j.duration) * time.Minute)),
			Issuer:    j.issuer,
		},
	})

	// For precomputed Falcon, key is ignored by Sign() as signer is embedded
	s, err := token.SignedString(nil)
	if err != nil {
		return "", err
	}

	return s, nil
}

func (j *jwtUtil) Parse(token string) (*JWTClaims, error) {
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
		return "", fmt.Errorf("unsupported algorithm: %s", alg)
	}

	currentTime := time.Now()

	token := jwt.NewWithClaims(cfg.Method, JWTClaims{
		UserID: payload.UserID,
		Email:  payload.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(currentTime),
			ExpiresAt: jwt.NewNumericDate(currentTime.Add(time.Duration(m.duration) * time.Minute)),
			Issuer:    m.issuer,
		},
	})

	s, err := token.SignedString(cfg.SignKey)
	if err != nil {
		return "", err
	}
	return s, nil
}

func (m *multiAlgJwtUtil) Parse(tokenStr string) (*JWTClaims, error) {
	// Build allowed algorithms list from all configured algorithms
	allowedAlgs := make([]string, 0, len(m.configs))
	for alg := range m.configs {
		allowedAlgs = append(allowedAlgs, alg)
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods(allowedAlgs),
		jwt.WithIssuer(m.issuer),
		jwt.WithIssuedAt(),
	)

	parsedToken, err := parser.ParseWithClaims(tokenStr, &JWTClaims{}, func(t *jwt.Token) (any, error) {
		// Return the correct verify key based on the token's algorithm
		alg := t.Method.Alg()
		cfg, ok := m.configs[alg]
		if !ok {
			return nil, fmt.Errorf("no key configured for algorithm: %s", alg)
		}
		return cfg.VerifyKey, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := parsedToken.Claims.(*JWTClaims); ok && parsedToken.Valid {
		return claims, nil
	}
	return nil, errors.New("token is not valid")
}
