package main

import (
	"bytes"
	"html/template"
	"log/slog"
	"path/filepath"
	"rauth/internal/core"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLogLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"DEBUG":   slog.LevelDebug,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
		"info":    slog.LevelInfo,
		"":        slog.LevelInfo,
		"unknown": slog.LevelInfo,
		"  warn ": slog.LevelWarn,
	}
	for in, want := range cases {
		assert.Equal(t, want, parseLogLevel(in), "parseLogLevel(%q)", in)
	}
}

func TestTemplateRenderer_Render(t *testing.T) {
	tr := &TemplateRenderer{
		templates: template.Must(template.New("t.html").Parse("hello {{.}}")),
	}
	var buf bytes.Buffer
	err := tr.Render(&buf, "t.html", "world", nil)
	require.NoError(t, err)
	assert.Equal(t, "hello world", buf.String())
}

func TestSetupRenderer(t *testing.T) {
	e := echo.New()
	setupRenderer(e)
	assert.NotNil(t, e.Renderer)
}

func TestSetupMiddleware(t *testing.T) {
	e := echo.New()
	cfg := &core.Config{CookieDomains: []string{"example.com"}}
	// Should register middleware and error/not-found handlers without panicking.
	setupMiddleware(e, cfg)
	assert.NotNil(t, e.HTTPErrorHandler)
}

func TestSetupRoutes(t *testing.T) {
	e := echo.New()
	cfg := &core.Config{
		CookieDomains:   []string{"example.com"},
		MetricsAllowedIPs: []string{"127.0.0.1"},
	}
	setupRoutes(e, cfg)

	routes := e.Routes()
	require.NotEmpty(t, routes)

	paths := make(map[string]bool)
	for _, r := range routes {
		paths[r.Method+" "+r.Path] = true
	}
	assert.True(t, paths["GET /rauthlogin"], "login route registered")
	assert.True(t, paths["POST /rauthlogin"], "login POST route registered")
	assert.True(t, paths["GET /rauthvalidate"], "validate route registered")
	assert.True(t, paths["GET /health"], "health route registered")
	assert.True(t, paths["POST /rauthmgmt/user/create"], "admin create-user route registered")
}

func TestInitializeSystem(t *testing.T) {
	origUserDB := core.UserDB
	origTokenDB := core.TokenDB
	origAuditDB := core.AuditDB
	defer func() {
		core.UserDB = origUserDB
		core.TokenDB = origTokenDB
		core.AuditDB = origAuditDB
	}()

	s := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.UserDB = client
	core.TokenDB = client
	core.AuditDB = client

	tmpDir := t.TempDir()
	cfg := &core.Config{
		// Point at a non-existent DB with no MaxMind creds so the initial download
		// fails fast (no network) rather than hanging.
		MaxMindDBPath:    filepath.Join(tmpDir, "GeoLite2-Country.mmdb"),
		InitialUser:      "bootadmin",
		InitialPassword:  "BootStrap123!",
		InitialEmail:     "boot@example.com",
		Initial2FASecret: "",
	}

	initializeSystem(cfg)

	// The initial admin user should have been created.
	exists, err := core.UserDB.Exists(core.Ctx, "user:bootadmin").Result()
	require.NoError(t, err)
	assert.Equal(t, int64(1), exists)
}
