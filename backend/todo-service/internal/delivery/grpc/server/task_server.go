package server

import (
	"context"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"todo-service/internal/model"
	"todo-service/internal/service"
)

type contextKey string

const AuthContextKey contextKey = "auth"

type TaskServer struct {
	model.UnimplementedTaskServiceServer
	log         *zap.SugaredLogger
	taskService *service.TaskService
}

func NewTaskServer(log *zap.SugaredLogger, taskService *service.TaskService) *TaskServer {
	return &TaskServer{
		log:         log,
		taskService: taskService,
	}
}

func getUserID(ctx context.Context) (string, error) {
	userID, ok := ctx.Value(AuthContextKey).(string)
	if !ok || userID == "" {
		return "", status.Error(codes.Unauthenticated, "user not authenticated")
	}
	return userID, nil
}

func (s *TaskServer) Create(ctx context.Context, request *model.CreateTaskRequest) (*emptypb.Empty, error) {
	userID, err := getUserID(ctx)
	if err != nil {
		return nil, err
	}

	request.UserId = userID
	if err := s.taskService.Create(ctx, request); err != nil {
		return nil, err
	}
	return new(emptypb.Empty), nil
}

func (s *TaskServer) Update(ctx context.Context, request *model.UpdateTaskRequest) (*emptypb.Empty, error) {
	userID, err := getUserID(ctx)
	if err != nil {
		return nil, err
	}

	request.UserId = userID
	if err := s.taskService.Update(ctx, request); err != nil {
		return nil, err
	}
	return new(emptypb.Empty), nil
}

func (s *TaskServer) Delete(ctx context.Context, request *model.DeleteTaskRequest) (*emptypb.Empty, error) {
	userID, err := getUserID(ctx)
	if err != nil {
		return nil, err
	}

	request.UserId = userID
	if err := s.taskService.Delete(ctx, request); err != nil {
		return nil, err
	}
	return new(emptypb.Empty), nil
}

func (s *TaskServer) Get(ctx context.Context, request *model.GetTaskRequest) (*model.TaskResponse, error) {
	userID, err := getUserID(ctx)
	if err != nil {
		return nil, err
	}

	request.UserId = userID
	task, err := s.taskService.GetById(ctx, request.Id, userID)
	if err != nil {
		return nil, err
	}

	return &model.TaskResponse{Task: task}, nil
}

func (s *TaskServer) GetAll(ctx context.Context, request *model.GetAllTaskRequest) (*model.ListTaskResponse, error) {
	userID, err := getUserID(ctx)
	if err != nil {
		return nil, err
	}

	request.UserId = userID
	return s.taskService.GetAll(ctx, userID)
}
