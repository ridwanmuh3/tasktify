package handler

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ridwanmuh3/tasktify/gateway/internal/model"
)

type TaskHandler struct {
	log        *zap.SugaredLogger
	taskClient model.TaskServiceClient
}

func NewTaskHandler(log *zap.SugaredLogger, taskClient model.TaskServiceClient) *TaskHandler {
	return &TaskHandler{
		log:        log,
		taskClient: taskClient,
	}
}

// forwardContext - Forward Request + Internal Header (X-User-ID) ke Resource Service
func forwardContext(c fiber.Ctx) context.Context {
	userID := c.Locals("user_id").(string)
	md := metadata.Pairs("x-user-id", userID)
	return metadata.NewOutgoingContext(c.Context(), md)
}

func grpcToHTTPError(err error) *fiber.Error {
	st, ok := status.FromError(err)
	if !ok {
		return fiber.NewError(fiber.StatusInternalServerError, "internal server error")
	}
	switch st.Code() {
	case 3: // InvalidArgument
		return fiber.NewError(fiber.StatusBadRequest, st.Message())
	case 5: // NotFound
		return fiber.NewError(fiber.StatusNotFound, st.Message())
	case 16: // Unauthenticated
		return fiber.NewError(fiber.StatusUnauthorized, st.Message())
	default:
		return fiber.NewError(fiber.StatusInternalServerError, st.Message())
	}
}

func toTaskResponse(task *model.Task) TaskResponse {
	resp := TaskResponse{
		Id:          task.Id,
		Title:       task.Title,
		Description: task.Description,
		Status:      task.Status,
		UserId:      task.UserId,
	}
	if task.DueDate != nil {
		resp.DueDate = task.DueDate.AsTime().UnixMilli()
	}
	if task.CreatedAt != nil {
		resp.CreatedAt = task.CreatedAt.AsTime().UnixMilli()
	}
	if task.UpdatedAt != nil {
		resp.UpdatedAt = task.UpdatedAt.AsTime().UnixMilli()
	}
	return resp
}

func (h *TaskHandler) Create(c fiber.Ctx) error {
	var req CreateTaskRequest
	if err := c.Bind().JSON(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}

	userID := c.Locals("user_id").(string)
	ctx := forwardContext(c)

	grpcReq := &model.CreateTaskRequest{
		UserId:      userID,
		Title:       req.Title,
		Description: req.Description,
		Status:      req.Status,
	}

	if req.DueDate != nil {
		grpcReq.DueDate = timestamppb.New(time.UnixMilli(*req.DueDate))
	}

	if _, err := h.taskClient.Create(ctx, grpcReq); err != nil {
		h.log.Errorf("failed to create task: %v", err)
		return grpcToHTTPError(err)
	}

	return c.Status(fiber.StatusCreated).JSON(model.Response[any]{
		Status:  fiber.StatusCreated,
		Message: "task created",
	})
}

func (h *TaskHandler) Update(c fiber.Ctx) error {
	taskId := c.Params("id")
	var req UpdateTaskRequest
	if err := c.Bind().JSON(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}

	userID := c.Locals("user_id").(string)
	ctx := forwardContext(c)

	grpcReq := &model.UpdateTaskRequest{
		Id:          taskId,
		UserId:      userID,
		Title:       req.Title,
		Description: req.Description,
		Status:      req.Status,
	}

	if req.DueDate != nil {
		grpcReq.DueDate = timestamppb.New(time.UnixMilli(*req.DueDate))
	}

	if _, err := h.taskClient.Update(ctx, grpcReq); err != nil {
		h.log.Errorf("failed to update task: %v", err)
		return grpcToHTTPError(err)
	}

	return c.JSON(model.Response[any]{
		Status:  fiber.StatusOK,
		Message: "task updated",
	})
}

func (h *TaskHandler) Delete(c fiber.Ctx) error {
	taskId := c.Params("id")
	userID := c.Locals("user_id").(string)
	ctx := forwardContext(c)

	if _, err := h.taskClient.Delete(ctx, &model.DeleteTaskRequest{
		Id:     taskId,
		UserId: userID,
	}); err != nil {
		h.log.Errorf("failed to delete task: %v", err)
		return grpcToHTTPError(err)
	}

	return c.JSON(model.Response[any]{
		Status:  fiber.StatusOK,
		Message: "task deleted",
	})
}

func (h *TaskHandler) GetById(c fiber.Ctx) error {
	taskId := c.Params("id")
	userID := c.Locals("user_id").(string)
	ctx := forwardContext(c)

	resp, err := h.taskClient.Get(ctx, &model.GetTaskRequest{
		Id:     taskId,
		UserId: userID,
	})
	if err != nil {
		h.log.Errorf("failed to get task: %v", err)
		return grpcToHTTPError(err)
	}

	return c.JSON(model.Response[TaskResponse]{
		Status:  fiber.StatusOK,
		Message: "success",
		Data:    toTaskResponse(resp.Task),
	})
}

func (h *TaskHandler) GetAll(c fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	ctx := forwardContext(c)

	resp, err := h.taskClient.GetAll(ctx, &model.GetAllTaskRequest{
		UserId: userID,
	})
	if err != nil {
		h.log.Errorf("failed to get tasks: %v", err)
		return grpcToHTTPError(err)
	}

	tasks := make([]TaskResponse, 0, len(resp.Tasks))
	for _, task := range resp.Tasks {
		tasks = append(tasks, toTaskResponse(task))
	}

	return c.JSON(model.Response[*[]TaskResponse]{
		Status:  fiber.StatusOK,
		Message: "success",
		Data:    &tasks,
	})
}
