package entity

import (
	"github.com/google/uuid"
)

type User struct {
	Id        uuid.UUID `gorm:"primaryKey;default:gen_random_uuid()"`
	Name      string    `gorm:"type:varchar;size:100;not null"`
	Email     string    `gorm:"type:varchar;size:300;unique;not null"`
	Password  string    `gorm:"not null"`
	CreatedAt int64     `gorm:"autoCreateTime"`
	UpdatedAt int64     `gorm:"autoUpdateTime"`
}
