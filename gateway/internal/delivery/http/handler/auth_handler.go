package handler

import (
	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"
	"google.golang.org/grpc/status"

	"github.com/ridwanmuh3/tasktify/gateway/internal/model"
)

type AuthHandler struct {
	log        *zap.SugaredLogger
	authClient model.AuthServiceClient
}

func NewAuthHandler(log *zap.SugaredLogger, authClient model.AuthServiceClient) *AuthHandler {
	return &AuthHandler{
		log:        log,
		authClient: authClient,
	}
}

type SignInRequest struct {
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required"`
	Algorithm string `json:"algorithm"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// SignIn - Permintaan Login (Username, Password)
// Flow: Client -> Gateway -> Auth Service (gRPC) -> Validate -> Generate JWT (Falcon + Precomputed LDL Tree) -> Return Token
func (h *AuthHandler) SignIn(c fiber.Ctx) error {
	var req SignInRequest
	if err := c.Bind().JSON(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}

	// Forward Kredensial Login ke Auth Service via gRPC
	resp, err := h.authClient.SignIn(c.Context(), &model.SignInRequest{
		Email:     req.Email,
		Password:  req.Password,
		Algorithm: req.Algorithm,
	})
	if err != nil {
		st, ok := status.FromError(err)
		if ok {
			return fiber.NewError(fiber.StatusUnauthorized, st.Message())
		}
		h.log.Errorf("sign-in failed: %v", err)
		return fiber.NewError(fiber.StatusInternalServerError, "internal server error")
	}

	// Mengirim Token JWT ke Client
	return c.JSON(model.Response[any]{
		Status:  fiber.StatusOK,
		Message: "sign in successful",
		Data: fiber.Map{
			"token_type":    resp.Auth.TokenType,
			"access_token":  resp.Auth.AccessToken,
			"refresh_token": resp.Auth.RefreshToken,
		},
	})
}

// RefreshToken - Refresh access token menggunakan refresh token
func (h *AuthHandler) RefreshToken(c fiber.Ctx) error {
	var req RefreshTokenRequest
	if err := c.Bind().JSON(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}

	resp, err := h.authClient.RefreshToken(c.Context(), &model.RefreshTokenRequest{
		RefreshToken: req.RefreshToken,
	})
	if err != nil {
		st, ok := status.FromError(err)
		if ok {
			return fiber.NewError(fiber.StatusUnauthorized, st.Message())
		}
		h.log.Errorf("refresh token failed: %v", err)
		return fiber.NewError(fiber.StatusInternalServerError, "internal server error")
	}

	return c.JSON(model.Response[any]{
		Status:  fiber.StatusOK,
		Message: "token refreshed",
		Data: fiber.Map{
			"token_type":    resp.Auth.TokenType,
			"access_token":  resp.Auth.AccessToken,
			"refresh_token": resp.Auth.RefreshToken,
		},
	})
}
