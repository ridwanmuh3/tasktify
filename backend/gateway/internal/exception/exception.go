package exception

import (
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"

	"github.com/ridwanmuh3/tasktify/gateway/internal/model"
)

var (
	InternalServerError = fiber.NewError(fiber.StatusInternalServerError, "internal server error")
)

func NewErrorHandler() fiber.ErrorHandler {
	return func(ctx fiber.Ctx, err error) error {
		var errors any = fiber.ErrInternalServerError.Message

		code := fiber.StatusInternalServerError
		if e, ok := err.(*fiber.Error); ok {
			code = e.Code
			errors = e.Error()
		}

		if validationErrors, ok := err.(validator.ValidationErrors); ok {
			for _, validationError := range validationErrors {
				errors = append(validationErrors, validationError)
			}
			code = fiber.StatusBadRequest
		}

		return ctx.Status(code).JSON(model.Response[any]{
			Status: code,
			Error:  errors,
		})
	}
}
