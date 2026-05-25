package service

import (
	"context"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"

	"todo-service/internal/entity"
	"todo-service/internal/model"
	"todo-service/internal/repository"
)

type TaskService struct {
	db             *gorm.DB
	validate       *validator.Validate
	log            *zap.SugaredLogger
	taskRepository *repository.TaskRepository
}

func NewTaskService(db *gorm.DB, validate *validator.Validate, logger *zap.SugaredLogger, taskRepository *repository.TaskRepository) *TaskService {
	return &TaskService{
		db:             db,
		validate:       validate,
		log:            logger,
		taskRepository: taskRepository,
	}
}

func (s *TaskService) Create(ctx context.Context, request *model.CreateTaskRequest) error {
	tx := s.db.WithContext(ctx).Begin()
	defer tx.Rollback()

	parsedUserId, err := uuid.Parse(request.UserId)
	if err != nil {
		s.log.Errorf("failed to parse user id: %v", err)
		return status.Error(codes.InvalidArgument, "invalid user id")
	}

	task := &entity.Task{
		Title:       request.Title,
		Description: request.Description,
		Status:      request.Status,
		UserId:      parsedUserId,
	}

	if request.DueDate != nil {
		task.DueDate = request.DueDate.AsTime().UnixMilli()
	}

	if err := s.taskRepository.Create(tx, task); err != nil {
		s.log.Errorf("failed to create task: %v", err)
		return status.Error(codes.Internal, "failed to create task")
	}

	if err := tx.Commit().Error; err != nil {
		s.log.Errorf("failed to commit transaction: %v", err)
		return status.Error(codes.Internal, "internal server error")
	}

	return nil
}

func (s *TaskService) Update(ctx context.Context, request *model.UpdateTaskRequest) error {
	tx := s.db.WithContext(ctx).Begin()
	defer tx.Rollback()

	parsedTaskId, err := uuid.Parse(request.Id)
	if err != nil {
		s.log.Errorf("failed to parse task id: %v", err)
		return status.Error(codes.InvalidArgument, "invalid task id")
	}

	parsedUserId, err := uuid.Parse(request.UserId)
	if err != nil {
		s.log.Errorf("failed to parse user id: %v", err)
		return status.Error(codes.InvalidArgument, "invalid user id")
	}

	task := new(entity.Task)
	if err := s.taskRepository.GetById(tx, parsedTaskId, parsedUserId, task); err != nil {
		s.log.Errorf("failed to find task: %v", err)
		return status.Error(codes.NotFound, "task not found")
	}

	task.Title = request.Title
	task.Description = request.Description
	task.Status = request.Status

	if request.DueDate != nil {
		task.DueDate = request.DueDate.AsTime().UnixMilli()
	}

	if err := s.taskRepository.Update(tx, task); err != nil {
		s.log.Errorf("failed to update task: %v", err)
		return status.Error(codes.Internal, "failed to update task")
	}

	if err := tx.Commit().Error; err != nil {
		s.log.Errorf("failed to commit transaction: %v", err)
		return status.Error(codes.Internal, "internal server error")
	}

	return nil
}

func (s *TaskService) Delete(ctx context.Context, request *model.DeleteTaskRequest) error {
	tx := s.db.WithContext(ctx).Begin()
	defer tx.Rollback()

	parsedTaskId, err := uuid.Parse(request.Id)
	if err != nil {
		s.log.Errorf("failed to parse task id: %v", err)
		return status.Error(codes.InvalidArgument, "invalid task id")
	}

	parsedUserId, err := uuid.Parse(request.UserId)
	if err != nil {
		s.log.Errorf("failed to parse user id: %v", err)
		return status.Error(codes.InvalidArgument, "invalid user id")
	}

	task := new(entity.Task)
	if err := s.taskRepository.GetById(tx, parsedTaskId, parsedUserId, task); err != nil {
		s.log.Errorf("failed to find task: %v", err)
		return status.Error(codes.NotFound, "task not found")
	}

	if err := s.taskRepository.Delete(tx, task); err != nil {
		s.log.Errorf("failed to delete task: %v", err)
		return status.Error(codes.Internal, "failed to delete task")
	}

	if err := tx.Commit().Error; err != nil {
		s.log.Errorf("failed to commit transaction: %v", err)
		return status.Error(codes.Internal, "internal server error")
	}

	return nil
}

func (s *TaskService) GetById(ctx context.Context, taskId, userId string) (*model.Task, error) {
	db := s.db.WithContext(ctx)

	parsedTaskId, err := uuid.Parse(taskId)
	if err != nil {
		s.log.Errorf("failed to parse task id: %v", err)
		return nil, status.Error(codes.InvalidArgument, "invalid task id")
	}

	parsedUserId, err := uuid.Parse(userId)
	if err != nil {
		s.log.Errorf("failed to parse user id: %v", err)
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}

	task := new(entity.Task)
	if err := s.taskRepository.GetById(db, parsedTaskId, parsedUserId, task); err != nil {
		s.log.Errorf("failed to find task: %v", err)
		return nil, status.Error(codes.NotFound, "task not found")
	}

	return &model.Task{
		Id:          task.Id.String(),
		Title:       task.Title,
		Description: task.Description,
		Status:      task.Status,
		DueDate:     timestamppb.New(time.UnixMilli(task.DueDate)),
		UserId:      userId,
		CreatedAt:   timestamppb.New(time.UnixMilli(task.CreatedAt)),
		UpdatedAt:   timestamppb.New(time.UnixMilli(task.UpdatedAt)),
	}, nil
}

func (s *TaskService) GetAll(ctx context.Context, userId string) (*model.ListTaskResponse, error) {
	db := s.db.WithContext(ctx)

	parsedUserId, err := uuid.Parse(userId)
	if err != nil {
		s.log.Errorf("failed to parse user id: %v", err)
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}

	tasks, err := s.taskRepository.GetAll(db, parsedUserId)
	if err != nil {
		s.log.Errorf("failed to find all tasks: %v", err)
		return nil, status.Error(codes.Internal, "internal server error")
	}

	var tasksResponse []*model.Task
	for _, task := range tasks {
		tasksResponse = append(tasksResponse, &model.Task{
			Id:          task.Id.String(),
			Title:       task.Title,
			Description: task.Description,
			Status:      task.Status,
			DueDate:     timestamppb.New(time.UnixMilli(task.DueDate)),
			UserId:      userId,
			CreatedAt:   timestamppb.New(time.UnixMilli(task.CreatedAt)),
			UpdatedAt:   timestamppb.New(time.UnixMilli(task.UpdatedAt)),
		})
	}

	return &model.ListTaskResponse{
		Tasks: tasksResponse,
	}, nil
}
