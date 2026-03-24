package jwtutils

import (
	"errors"
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
	UserID uuid.UUID
	Email  string
}

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
