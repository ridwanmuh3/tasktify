package handler

import (
	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"
	"google.golang.org/grpc/status"

	"github.com/ridwanmuh3/tasktify/gateway/internal/model"
)

type UserHandler struct {
	log        *zap.SugaredLogger
	userClient model.UserServiceClient
}

func NewUserHandler(log *zap.SugaredLogger, userClient model.UserServiceClient) *UserHandler {
	return &UserHandler{
		log:        log,
		userClient: userClient,
	}
}

func (h *UserHandler) Register(c fiber.Ctx) error {
	var req RegisterRequest
	if err := c.Bind().JSON(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}

	if _, err := h.userClient.Create(c.Context(), &model.CreateUserRequest{
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
	}); err != nil {
		st, ok := status.FromError(err)
		if ok {
			return fiber.NewError(fiber.StatusBadRequest, st.Message())
		}
		h.log.Errorf("register failed: %v", err)
		return fiber.NewError(fiber.StatusInternalServerError, "internal server error")
	}

	return c.Status(fiber.StatusCreated).JSON(model.Response[any]{
		Status:  fiber.StatusCreated,
		Message: "user registered",
	})
}

func (h *UserHandler) GetProfile(c fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	resp, err := h.userClient.Get(c.Context(), &model.GetUserRequest{Id: userID})
	if err != nil {
		st, ok := status.FromError(err)
		if ok {
			return fiber.NewError(fiber.StatusNotFound, st.Message())
		}
		h.log.Errorf("get profile failed: %v", err)
		return fiber.NewError(fiber.StatusInternalServerError, "internal server error")
	}

	return c.JSON(model.Response[any]{
		Status:  fiber.StatusOK,
		Message: "success",
		Data: fiber.Map{
			"id":    resp.User.Id,
			"name":  resp.User.Name,
			"email": resp.User.Email,
		},
	})
}
