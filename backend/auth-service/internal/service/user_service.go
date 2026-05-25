package service

import (
	"context"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	"auth-service/internal/entity"
	"auth-service/internal/model"
	"auth-service/internal/repository"
)

type UserService struct {
	db             *gorm.DB
	validate       *validator.Validate
	log            *zap.SugaredLogger
	userRepository *repository.UserRepository
}

func NewUserService(
	db *gorm.DB,
	validate *validator.Validate,
	log *zap.SugaredLogger,
	userRepository *repository.UserRepository,
) *UserService {
	return &UserService{
		db:             db,
		validate:       validate,
		log:            log,
		userRepository: userRepository,
	}
}

func (s *UserService) Create(ctx context.Context, request *model.CreateUserRequest) error {
	tx := s.db.WithContext(ctx).Begin()
	defer tx.Rollback()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		s.log.Errorf("failed to hash password: %v", err)
		return status.Error(codes.Internal, "internal server error")
	}

	user := &entity.User{
		Name:     request.Name,
		Email:    request.Email,
		Password: string(hashedPassword),
	}

	if err := s.userRepository.Create(tx, user); err != nil {
		s.log.Errorf("failed to create user: %v", err)
		return status.Error(codes.Internal, "failed to create user")
	}

	if err := tx.Commit().Error; err != nil {
		s.log.Errorf("failed to commit transaction: %v", err)
		return status.Error(codes.Internal, "internal server error")
	}

	return nil
}

func (s *UserService) Update(ctx context.Context, request *model.UpdateUserRequest) error {
	tx := s.db.WithContext(ctx).Begin()
	defer tx.Rollback()

	parsedId, err := uuid.Parse(request.Id)
	if err != nil {
		return status.Error(codes.InvalidArgument, "invalid user id")
	}

	user := new(entity.User)
	if err := s.userRepository.GetById(tx, parsedId, user); err != nil {
		return status.Error(codes.NotFound, "user not found")
	}

	user.Name = request.Name
	user.Email = request.Email

	if request.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
		if err != nil {
			s.log.Errorf("failed to hash password: %v", err)
			return status.Error(codes.Internal, "internal server error")
		}
		user.Password = string(hashedPassword)
	}

	if err := s.userRepository.Update(tx, user); err != nil {
		s.log.Errorf("failed to update user: %v", err)
		return status.Error(codes.Internal, "failed to update user")
	}

	if err := tx.Commit().Error; err != nil {
		s.log.Errorf("failed to commit transaction: %v", err)
		return status.Error(codes.Internal, "internal server error")
	}

	return nil
}

func (s *UserService) Delete(ctx context.Context, id string) error {
	tx := s.db.WithContext(ctx).Begin()
	defer tx.Rollback()

	parsedId, err := uuid.Parse(id)
	if err != nil {
		return status.Error(codes.InvalidArgument, "invalid user id")
	}

	user := new(entity.User)
	if err := s.userRepository.GetById(tx, parsedId, user); err != nil {
		return status.Error(codes.NotFound, "user not found")
	}

	if err := s.userRepository.Delete(tx, user); err != nil {
		s.log.Errorf("failed to delete user: %v", err)
		return status.Error(codes.Internal, "failed to delete user")
	}

	if err := tx.Commit().Error; err != nil {
		s.log.Errorf("failed to commit transaction: %v", err)
		return status.Error(codes.Internal, "internal server error")
	}

	return nil
}

func (s *UserService) Get(ctx context.Context, id string) (*entity.User, error) {
	db := s.db.WithContext(ctx)

	parsedId, err := uuid.Parse(id)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}

	user := new(entity.User)
	if err := s.userRepository.GetById(db, parsedId, user); err != nil {
		return nil, status.Error(codes.NotFound, "user not found")
	}

	return user, nil
}

func (s *UserService) GetAll(ctx context.Context) ([]entity.User, error) {
	db := s.db.WithContext(ctx)

	users, err := s.userRepository.GetAll(db)
	if err != nil {
		s.log.Errorf("failed to get all users: %v", err)
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return users, nil
}
