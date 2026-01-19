package main

import (
	"context"
	"embed"
	"fmt"
	html/template
	"io"
	"net/http"
	"os"
	"os/signal"
	"rauth/internal/core"
	"rauth/internal/handlers"
	"rauth/internal/middleware"
	time

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

	e := echo.New()
	e.HideBanner = true
	e.Use(echoMiddleware.Logger())
	e.Use(echoMiddleware.Recover())

	// Templates
	renderer := &TemplateRenderer{
		templates: template.Must(template.ParseFS(templateFS, "templates/*.html")),
	}
	e.Renderer = renderer

	// Static files from embedded FS
	e.GET("/static/*", echo.WrapHandler(http.FileServer(http.FS(staticFS))))

	// Handlers
	authHandler := &handlers.AuthHandler{Cfg: cfg}
	adminHandler := &handlers.AdminHandler{Cfg: cfg}

	// Public Routes
	e.GET("/rauthvalidate", authHandler.Validate)
	e.GET("/login", func(c echo.Context) error { return c.Render(http.StatusOK, "login.html", nil) })
	e.POST("/login", authHandler.Login)

	// Protected Routes
	protected := e.Group("")
	protected.Use(middleware.AuthMiddleware(cfg))
	
	protected.POST("/logout", func(c echo.Context) error {
		// Logic to clear cookie and invalidate token
		cookie := new(http.Cookie)
		cookie.Name = "X-rcloudauth-authtoken"
		cookie.Value = ""
		cookie.Expires = time.Now().Add(-1 * time.Hour)
		cookie.Path = "/"
		cookie.Domain = cfg.CookieDomain
		c.SetCookie(cookie)
		return c.Redirect(http.StatusFound, "/login")
	})

	// Admin Routes
	admin := protected.Group("/rauthmgmt")
	admin.Use(middleware.AdminMiddleware)
	admin.GET("", adminHandler.Dashboard)
	admin.POST("/user/create", adminHandler.CreateUser)

	// Health check
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "OK"})
	})

	// Start server
	go func() {
		if err := e.Start(":80"); err != nil && err != http.ErrServerClosed {
			e.Logger.Fatal("shutting down the server")
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		e.Logger.Fatal(err)
	}
}