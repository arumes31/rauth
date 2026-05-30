package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"rauth/internal/core"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestMainFunctions(t *testing.T) {
	// Dummy test to execute main.go code paths

	// Setup miniredis for core tests that require DB
	s := miniredis.RunT(t)
	core.UserDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.RateLimitDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.AuditDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.Ctx = context.Background()

	e := echo.New()
	cfg := &core.Config{
		CookieDomains:      []string{"localhost"},
		ServerSecret:       "testsecret1234567890123456789012",
		WebAuthnOrigins:    []string{"http://localhost"},
		TokenValidityMinutes: 60,
	}

	t.Run("setupMiddleware", func(t *testing.T) {
		setupMiddleware(e, cfg)
		// Should add middlewares and set HTTPErrorHandler
		assert.NotNil(t, e.HTTPErrorHandler)
	})

	t.Run("setupRenderer", func(t *testing.T) {
		setupRenderer(e)
		assert.NotNil(t, e.Renderer)
	})

	t.Run("setupRoutes", func(t *testing.T) {
		setupRoutes(e, cfg)
		// Request a route to see if it's set
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("Render", func(t *testing.T) {
		// Mock echo context
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := e.Renderer.Render(c.Response().Writer, "login.html", nil, c)
		assert.NoError(t, err)
	})

	t.Run("initializeSystem", func(t *testing.T) {
		// Just run it to execute the code paths
		// Set minimal config to avoid errors
		initCfg := &core.Config{
			InitialUser:      "admin",
			InitialPassword:  "password123!",
		}

		// Create a mock context for the background goroutine
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		core.Ctx = ctx

		// Run initializeSystem
		initializeSystem(initCfg)

		// Wait a tiny bit for the goroutine
		time.Sleep(10 * time.Millisecond)
	})
}
