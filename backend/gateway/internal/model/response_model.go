package model

type Response[T any] struct {
	Status  int           `json:"status"`
	Message string        `json:"message,omitempty"`
	Data    T             `json:"data,omitempty"`
	Paging  *PageMetadata `json:"paging,omitempty"`
	Error   any           `json:"error,omitempty"`
}

type PageResponse[T any] struct {
	Data         []T           `json:"data,omitempty"`
	PageMetadata *PageMetadata `json:"paging,omitempty"`
}

type PageMetadata struct {
	Page      int   `json:"page"`
	Size      int   `json:"size"`
	TotalItem int64 `json:"total_item"`
	TotalPage int64 `json:"total_page"`
}
