package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"rauth/internal/core"
	"time"

	"github.com/labstack/echo/v4"
)

func main() {
	// Initialize slog
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg := core.LoadConfig()

	if err := core.InitRedis(cfg); err != nil {
		slog.Error("Redis initialization failed", "error", err)
		os.Exit(1)
	}

	if err := core.InitWebAuthn(cfg); err != nil {
		slog.Error("WebAuthn initialization failed", "error", err)
	}

	// Startup Initialization
	initializeSystem(cfg)

	e := echo.New()
	e.HideBanner = true

	// Configure real IP extraction
	configureIPExtractor(e, cfg)

	// Setup everything
	setupMiddleware(e, cfg)
	setupRenderer(e)
	setupRoutes(e, cfg)

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
