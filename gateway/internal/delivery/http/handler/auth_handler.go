package handler

import (
	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
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

// SignIn - Permintaan Login (Username, Password)
// Flow: Client -> Gateway -> Auth Service (gRPC) -> Validate -> Generate JWT (Falcon + Precomputed LDL Tree) -> Return Token
// Sets X-Sign-Time-Ms response header with pure cryptographic signing duration (ms).
func (h *AuthHandler) SignIn(c fiber.Ctx) error {
	var req SignInRequest
	if err := c.Bind().JSON(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}

	var trailer metadata.MD
	resp, err := h.authClient.SignIn(c.Context(), &model.SignInRequest{
		Email:     req.Email,
		Password:  req.Password,
		Algorithm: req.Algorithm,
	}, grpc.Trailer(&trailer))
	if err != nil {
		st, ok := status.FromError(err)
		if ok {
			return fiber.NewError(fiber.StatusUnauthorized, st.Message())
		}
		h.log.Errorf("sign-in failed: %v", err)
		return fiber.NewError(fiber.StatusInternalServerError, "internal server error")
	}

	// Forward clean token-generation latency and auth-service resource metrics for k6.
	for trailerKey, headerKey := range map[string]string{
		"x-sign-time-ms":             "X-Sign-Time-Ms",
		"x-token-generation-time-ms": "X-Token-Generation-Time-Ms",
		"x-auth-cpu-pct":             "X-Auth-CPU-Pct",
		"x-auth-mem-alloc-mb":        "X-Auth-Mem-Alloc-MB",
		"x-auth-mem-sys-mb":          "X-Auth-Mem-Sys-MB",
	} {
		if vals := trailer.Get(trailerKey); len(vals) > 0 {
			c.Set(headerKey, vals[0])
		}
	}

	return c.JSON(model.Response[any]{
		Status:  fiber.StatusOK,
		Message: "sign in successful",
		Data: fiber.Map{
			"token_type":   resp.Auth.TokenType,
			"access_token": resp.Auth.AccessToken,
		},
	})
}
