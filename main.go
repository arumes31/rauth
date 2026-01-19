package main

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/signal"
	"rauth/internal/core"
	"rauth/internal/handlers"
	"rauth/internal/middleware"
	"time"

	"github.com/labstack/echo/v4"
	echoMiddleware "github.com/labstack/echo/v4/middleware"
)

//go:embed static/*
var staticFS embed.FS

//go:embed templates/*
var templateFS embed.FS

type TemplateRenderer struct {
	templates *template.Template
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func main() {
	cfg := core.LoadConfig()

	if err := core.InitRedis(cfg); err != nil {
		fmt.Printf("Redis error: %v\n", err)
		os.Exit(1)
	}

	// Startup Initialization
	initializeSystem(cfg)

	e := echo.New()
	e.HideBanner = true
	e.Use(echoMiddleware.Logger())
	e.Use(echoMiddleware.Recover())

	renderer := &TemplateRenderer{
		templates: template.Must(template.ParseFS(templateFS, "templates/*.html")),
	}
	e.Renderer = renderer

	e.GET("/static/*", echo.WrapHandler(http.FileServer(http.FS(staticFS))))

	authHandler := &handlers.AuthHandler{Cfg: cfg}
	adminHandler := &handlers.AdminHandler{Cfg: cfg}
	profileHandler := &handlers.ProfileHandler{Cfg: cfg}

	// Public Routes
	e.GET("/rauthvalidate", authHandler.Validate)
	e.GET("/login", func(c echo.Context) error { return c.Render(http.StatusOK, "login.html", nil) })
	e.POST("/login", authHandler.Login)

	// Protected Routes
	protected := e.Group("")
	protected.Use(middleware.AuthMiddleware(cfg))
	
	protected.POST("/logout", func(c echo.Context) error {
		cookie := &http.Cookie{
			Name:     "X-rcloudauth-authtoken",
			Value:    "",
			Path:     "/",
			Domain:   cfg.CookieDomain,
			Expires:  time.Now().Add(-1 * time.Hour),
			HttpOnly: true,
		}
		c.SetCookie(cookie)
		return c.Redirect(http.StatusFound, "/login")
	})

	// Profile Routes
	protected.GET("/rauthprofile", profileHandler.Show)
	protected.POST("/rauthprofile/password", profileHandler.ChangePassword)

	// Admin Routes
	admin := protected.Group("/rauthmgmt")
	admin.Use(middleware.AdminMiddleware)
	admin.GET("", adminHandler.Dashboard)
	admin.POST("/user/create", adminHandler.CreateUser)
	admin.POST("/user/delete", adminHandler.DeleteUser)
	admin.POST("/session/invalidate", adminHandler.InvalidateSession)

	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "OK"})
	})

	go func() {
		if err := e.Start(":80"); err != nil && err != http.ErrServerClosed {
			e.Logger.Fatal("shutting down the server")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		e.Logger.Fatal(err)
	}
}

func initializeSystem(cfg *core.Config) {
	if cfg.InitialUser != "" && cfg.InitialPassword != "" {
		fmt.Printf("Checking initial user: %s\n", cfg.InitialUser)
		err := core.CreateUser(cfg.InitialUser, cfg.InitialPassword, "admin@local", true)
		if err == nil {
			fmt.Println("Initial admin user created.")
		} else {
			fmt.Println("Initial user already exists or error occurred.")
		}
	}
}
