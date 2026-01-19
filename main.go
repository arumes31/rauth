package main

import (
	"context"
	"embed"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/signal"
	"rauth/internal/core"
	"rauth/internal/handlers"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
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
		panic(err)
	}

	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Templates
	renderer := &TemplateRenderer{
		templates: template.Must(template.ParseFS(templateFS, "templates/*.html")),
	}
	e.Renderer = renderer

	// Static files
	e.GET("/static/*", echo.WrapHandler(http.FileServer(http.FS(staticFS))))

	authHandler := &handlers.AuthHandler{Cfg: cfg}

	// Routes
	e.GET("/rauthvalidate", authHandler.Validate)
	e.GET("/login", func(c echo.Context) error { return c.Render(http.StatusOK, "login.html", nil) })
	e.POST("/login", authHandler.Login)
	// ... more routes ...

	// Start server
	go func() {
		if err := e.Start(":80"); err != nil && err != http.ErrServerClosed {
			e.Logger.Fatal("shutting down the server")
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		e.Logger.Fatal(err)
	}
}
