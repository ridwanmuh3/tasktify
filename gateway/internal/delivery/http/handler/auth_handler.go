package handler

import (
	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
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
			return fiber.NewError(httpStatusFromGRPCCode(st.Code()), st.Message())
		}
		h.log.Errorf("sign-in failed: %v", err)
		return fiber.NewError(fiber.StatusInternalServerError, "internal server error")
	}

	forwardAuthTrailers(c, trailer)

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

func (h *AuthHandler) RefreshToken(c fiber.Ctx) error {
	var req RefreshTokenRequest
	if err := c.Bind().JSON(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}

	var trailer metadata.MD
	resp, err := h.authClient.RefreshToken(c.Context(), &model.RefreshTokenRequest{
		UserId:       req.UserID,
		RefreshToken: req.RefreshToken,
	}, grpc.Trailer(&trailer))
	if err != nil {
		st, ok := status.FromError(err)
		if ok {
			return fiber.NewError(httpStatusFromGRPCCode(st.Code()), st.Message())
		}
		h.log.Errorf("refresh token failed: %v", err)
		return fiber.NewError(fiber.StatusInternalServerError, "internal server error")
	}

	forwardAuthTrailers(c, trailer)

	return c.JSON(model.Response[any]{
		Status:  fiber.StatusOK,
		Message: "refresh token successful",
		Data: fiber.Map{
			"token_type":    resp.Auth.TokenType,
			"access_token":  resp.Auth.AccessToken,
			"refresh_token": resp.Auth.RefreshToken,
		},
	})
}

func forwardAuthTrailers(c fiber.Ctx, trailer metadata.MD) {
	for _, h := range []struct {
		trailer string
		header  string
	}{
		{"x-sign-time-ms", "X-Sign-Time-Ms"},
		{"x-access-token-generation-time-ms", "X-Access-Token-Generation-Time-Ms"},
		{"x-refresh-token-generation-time-ms", "X-Refresh-Token-Generation-Time-Ms"},
		{"x-token-generation-time-ms", "X-Token-Generation-Time-Ms"},
		{"x-auth-cpu-pct", "X-Auth-CPU-Pct"},
		{"x-auth-mem-alloc-mb", "X-Auth-Mem-Alloc-MB"},
		{"x-auth-mem-sys-mb", "X-Auth-Mem-Sys-MB"},
	} {
		if vals := trailer.Get(h.trailer); len(vals) > 0 {
			c.Set(h.header, vals[0])
		}
	}
}

func httpStatusFromGRPCCode(code codes.Code) int {
	switch code {
	case codes.InvalidArgument:
		return fiber.StatusBadRequest
	case codes.Unauthenticated:
		return fiber.StatusUnauthorized
	case codes.NotFound:
		return fiber.StatusNotFound
	default:
		return fiber.StatusInternalServerError
	}
}
