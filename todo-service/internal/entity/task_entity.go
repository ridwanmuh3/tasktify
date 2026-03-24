package entity

import (
	"github.com/google/uuid"
)

type Task struct {
	Id          uuid.UUID `gorm:"primaryKey;default:uuid_generate_v4()"`
	Title       string    `gorm:"type:varchar;size:100;not null"`
	Description string    `gorm:"type:text"`
	Status      string    `gorm:"type:varchar;size:30;not null"`
	DueDate     int64     `gorm:"default:null"`
	UserId      uuid.UUID
	CreatedAt   int64 `gorm:"autoCreateTime"`
	UpdatedAt   int64 `gorm:"autoUpdateTime"`
}

func (Task) TableName() string {
	return "tasks"
}
