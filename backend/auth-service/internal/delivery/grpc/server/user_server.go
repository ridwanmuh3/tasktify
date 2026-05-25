package server

import (
	"context"

	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"auth-service/internal/model"
	"auth-service/internal/service"

	"time"
)

type UserServer struct {
	model.UnimplementedUserServiceServer
	log         *zap.SugaredLogger
	userService *service.UserService
}

func NewUserServer(log *zap.SugaredLogger, userService *service.UserService) *UserServer {
	return &UserServer{
		log:         log,
		userService: userService,
	}
}

func (s *UserServer) Create(ctx context.Context, request *model.CreateUserRequest) (*emptypb.Empty, error) {
	if err := s.userService.Create(ctx, request); err != nil {
		return nil, err
	}
	return new(emptypb.Empty), nil
}

func (s *UserServer) Update(ctx context.Context, request *model.UpdateUserRequest) (*emptypb.Empty, error) {
	if err := s.userService.Update(ctx, request); err != nil {
		return nil, err
	}
	return new(emptypb.Empty), nil
}

func (s *UserServer) Delete(ctx context.Context, request *model.DeleteUserRequest) (*emptypb.Empty, error) {
	if err := s.userService.Delete(ctx, request.Id); err != nil {
		return nil, err
	}
	return new(emptypb.Empty), nil
}

func (s *UserServer) Get(ctx context.Context, request *model.GetUserRequest) (*model.UserResponse, error) {
	user, err := s.userService.Get(ctx, request.Id)
	if err != nil {
		return nil, err
	}

	return &model.UserResponse{
		User: &model.User{
			Id:        user.Id.String(),
			Name:      user.Name,
			Email:     user.Email,
			CreatedAt: timestamppb.New(time.UnixMilli(user.CreatedAt)),
			UpdatedAt: timestamppb.New(time.UnixMilli(user.UpdatedAt)),
		},
	}, nil
}

func (s *UserServer) GetAll(ctx context.Context, _ *emptypb.Empty) (*model.ListUserResponse, error) {
	users, err := s.userService.GetAll(ctx)
	if err != nil {
		return nil, err
	}

	var usersResponse []*model.User
	for _, user := range users {
		usersResponse = append(usersResponse, &model.User{
			Id:        user.Id.String(),
			Name:      user.Name,
			Email:     user.Email,
			CreatedAt: timestamppb.New(time.UnixMilli(user.CreatedAt)),
			UpdatedAt: timestamppb.New(time.UnixMilli(user.UpdatedAt)),
		})
	}

	return &model.ListUserResponse{
		Users: usersResponse,
	}, nil
}
