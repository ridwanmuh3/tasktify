package route

import (
	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"

	"github.com/ridwanmuh3/tasktify/gateway/internal/delivery/http/handler"
	"github.com/ridwanmuh3/tasktify/gateway/internal/delivery/http/middleware"
)

type RouteConfig struct {
	App            *fiber.App
	Log            *zap.SugaredLogger
	AuthHandler    *handler.AuthHandler
	UserHandler    *handler.UserHandler
	TaskHandler    *handler.TaskHandler
	AuthMiddleware *middleware.AuthMiddleware
}

func (c *RouteConfig) Setup() {
	c.App.Get("/", func(ctx fiber.Ctx) error {
		return ctx.SendString("API OK")
	})

	// define group
	api := c.App.Group("/api")

	// Public routes
	auth := api.Group("/auth")
	auth.Post("/signin", c.AuthHandler.SignIn)
	// auth.Post("/refresh", c.AuthHandler.RefreshToken)
	auth.Post("/register", c.UserHandler.Register)

	// Protected routes - Verifikasi Signature PQC Falcon di middleware
	protected := api.Group("/", c.AuthMiddleware.Handle)

	// User profile
	protected.Get("/profile", c.UserHandler.GetProfile)

	// Task CRUD - Forward ke Resource Service dengan X-User-ID
	tasks := protected.Group("/tasks")
	tasks.Post("/", c.TaskHandler.Create)
	tasks.Get("/", c.TaskHandler.GetAll)
	tasks.Get("/:id", c.TaskHandler.GetById)
	tasks.Put("/:id", c.TaskHandler.Update)
	tasks.Delete("/:id", c.TaskHandler.Delete)
}
