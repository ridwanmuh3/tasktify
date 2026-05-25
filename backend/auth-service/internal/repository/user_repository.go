package repository

import (
	"github.com/google/uuid"
	"gorm.io/gorm"

	"auth-service/internal/entity"
)

type UserRepository struct{}

func NewUserRepository() *UserRepository {
	return &UserRepository{}
}

func (UserRepository) Create(tx *gorm.DB, user *entity.User) error {
	return tx.Create(user).Error
}

func (UserRepository) Update(tx *gorm.DB, user *entity.User) error {
	return tx.Where("id = ?", user.Id).Updates(user).Error
}

func (UserRepository) Delete(tx *gorm.DB, user *entity.User) error {
	return tx.Where("id = ?", user.Id).Delete(user).Error
}

func (UserRepository) GetById(tx *gorm.DB, id uuid.UUID, user *entity.User) error {
	return tx.Where("id = ?", id).First(user).Error
}

func (UserRepository) GetByEmail(tx *gorm.DB, email string, user *entity.User) error {
	return tx.Where("email = ?", email).First(user).Error
}

func (UserRepository) GetAll(tx *gorm.DB) ([]entity.User, error) {
	var users []entity.User
	err := tx.Find(&users).Error
	return users, err
}
