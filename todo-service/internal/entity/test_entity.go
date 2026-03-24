package entity

type Test struct {
	Name string `gorm:"column:name;type:varchar;size:255"`
}
