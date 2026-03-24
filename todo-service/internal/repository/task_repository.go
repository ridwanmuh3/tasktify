package repository

import (
	"github.com/google/uuid"
	"gorm.io/gorm"

	"todo-service/internal/entity"
)

type TaskRepository struct{}

func NewTaskRepository() *TaskRepository {
	return &TaskRepository{}
}

func (TaskRepository) Create(tx *gorm.DB, task *entity.Task) error {
	return tx.Create(task).Error
}

func (TaskRepository) Update(tx *gorm.DB, task *entity.Task) error {
	return tx.Where("id = ? AND user_id = ?", task.Id, task.UserId).Updates(task).Error
}

func (TaskRepository) Delete(tx *gorm.DB, task *entity.Task) error {
	return tx.Where("id = ? AND user_id = ?", task.Id, task.UserId).Delete(task).Error
}

func (TaskRepository) GetById(tx *gorm.DB, id, userId uuid.UUID, task *entity.Task) error {
	return tx.Where("id = ? AND user_id = ?", id, userId).First(task).Error
}

func (TaskRepository) GetAll(tx *gorm.DB, userId uuid.UUID) ([]entity.Task, error) {
	var tasks []entity.Task
	err := tx.Where("user_id = ?", userId).Find(&tasks).Error
	return tasks, err
}
