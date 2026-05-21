package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"

	"github.com/ridwanmuh3/tasktify/pkg/utils/jwtutils"
)

type AuthMiddleware struct {
	log     *zap.SugaredLogger
	jwtUtil jwtutils.JwtUtil
}

func NewAuthMiddleware(log *zap.SugaredLogger, jwtUtil jwtutils.JwtUtil) *AuthMiddleware {
	return &AuthMiddleware{
		log:     log,
		jwtUtil: jwtUtil,
	}
}

func (m *AuthMiddleware) Handle(c fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "authorization header required")
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		return fiber.NewError(fiber.StatusUnauthorized, "invalid authorization format")
	}

	// Verifikasi Signature PQC Falcon (Menggunakan Public Key)
	claims, err := m.jwtUtil.Parse(tokenString)
	if err != nil {
		m.log.Warnf("token verification failed: %v", err)
		return fiber.NewError(fiber.StatusUnauthorized, "invalid or expired token")
	}
	if claims.TokenUse != "" && claims.TokenUse != jwtutils.TokenUseAccess {
		return fiber.NewError(fiber.StatusUnauthorized, "invalid token type")
	}

	// Set user info ke locals untuk diteruskan sebagai X-User-ID
	c.Locals("user_id", claims.UserID.String())
	c.Locals("user_email", claims.Email)

	return c.Next()
}
