package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"rauth/internal/core"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMainSetup(t *testing.T) {
	s := miniredis.RunT(t)
	defer s.Close()

	core.UserDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.TokenDB = core.UserDB
	core.RateLimitDB = core.UserDB
	core.AuditDB = core.UserDB
	core.InviteDB = core.UserDB

	cfg := &core.Config{
		CookieDomains: []string{"localhost"},
	}

	t.Run("setupMiddleware", func(t *testing.T) {
		e := echo.New()
		setupMiddleware(e, cfg)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		// Check for some security headers injected by middleware
		assert.Equal(t, "Sec-CH-UA-Platform, Sec-CH-UA-Mobile, Sec-CH-UA-Model", rec.Header().Get("Accept-CH"))
		assert.Equal(t, "Sec-CH-UA-Platform, Sec-CH-UA-Mobile, Sec-CH-UA-Model", rec.Header().Get("Critical-CH"))
	})

	t.Run("setupRenderer", func(t *testing.T) {
		e := echo.New()
		setupRenderer(e)
		assert.NotNil(t, e.Renderer)

		// Render uses our TemplateRenderer with custom funcs.
		// A full test of Render requires a template to exist, but we can verify it's configured.
		renderer, ok := e.Renderer.(*TemplateRenderer)
		assert.True(t, ok)
		assert.NotNil(t, renderer.templates)

		var buf bytes.Buffer
		err := renderer.Render(&buf, "nonexistent", nil, echo.New().NewContext(nil, nil))
		// It will fail because we are in testing and might not load templates perfectly, or nonexistent template, but it proves Render is wired up.
		assert.Error(t, err)
	})

	t.Run("setupRoutes", func(t *testing.T) {
		e := echo.New()
		setupRoutes(e, cfg)

		// Verify some routes are registered
		routes := e.Routes()
		var foundLogin, foundMetrics bool
		for _, r := range routes {
			if r.Path == "/rauthlogin" && r.Method == http.MethodGet {
				foundLogin = true
			}
			if r.Path == "/metrics" && r.Method == http.MethodGet {
				foundMetrics = true
			}
		}
		assert.True(t, foundLogin)
		assert.True(t, foundMetrics)
	})

	t.Run("initializeSystem", func(t *testing.T) {
		cfgWithInit := &core.Config{
			InitialUser:      "admin2",
			InitialPassword:  "password123!",
			InitialEmail:     "admin@example.com",
			Initial2FASecret: "",
		}

		// Run initializeSystem to create user
		initializeSystem(cfgWithInit)

		// Sleep briefly to let the background goroutine start and sync (though we won't strictly wait for it to loop)
		time.Sleep(10 * time.Millisecond)

		// Check if user was created
		exists, err := core.UserDB.Exists(core.Ctx, "user:admin2").Result()
		require.NoError(t, err)
		assert.Equal(t, int64(1), exists)
	})
}
