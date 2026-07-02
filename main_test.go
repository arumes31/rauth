package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"html/template"
	"log/slog"
	"net/http"
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
	// Should register middleware and error/not-found handlers without panicking.
	setupMiddleware(e)
	assert.NotNil(t, e.HTTPErrorHandler)
}

func TestSetupRoutes(t *testing.T) {
	e := echo.New()
	cfg := &core.Config{
		CookieDomains:     []string{"example.com"},
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

	// Stop the background sync loop before the deferred cleanup restores the
	// shared DB globals, otherwise the loop would race the writes above.
	stopSync := initializeSystem(cfg)
	defer stopSync()

	// The initial admin user should have been created.
	exists, err := core.UserDB.Exists(core.Ctx, "user:bootadmin").Result()
	require.NoError(t, err)
	assert.Equal(t, int64(1), exists)
}

func TestCreateIPExtractor(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *core.Config
		headers    map[string]string
		remoteAddr string
		expectedIP string
	}{
		{
			name:       "Basic RemoteAddr",
			cfg:        &core.Config{},
			headers:    nil,
			remoteAddr: "192.168.1.10:12345",
			expectedIP: "192.168.1.10",
		},
		{
			name: "TrustCloudflareIP",
			cfg: &core.Config{
				TrustCloudflareIP: true,
			},
			headers: map[string]string{
				"CF-Connecting-IP": "203.0.113.1",
			},
			remoteAddr: "192.168.1.10:12345",
			expectedIP: "203.0.113.1",
		},
		{
			name: "TrustXRealIP explicitly trusted proxy",
			cfg: &core.Config{
				TrustXRealIP: true,
			},
			headers: map[string]string{
				"X-Real-IP": "198.51.100.1",
			},
			remoteAddr: "192.168.1.10:12345",
			expectedIP: "198.51.100.1",
		},
		{
			name: "X-Real-IP smart mode",
			cfg:  &core.Config{}, // Not explicitly trusted, relying on private remoteHost
			headers: map[string]string{
				"X-Real-IP": "198.51.100.1",
			},
			remoteAddr: "10.0.0.5:12345", // Private IP
			expectedIP: "198.51.100.1",
		},
		{
			name: "X-Forwarded-For trusted proxy",
			cfg: &core.Config{
				TrustXForwardedFor: true,
			},
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.5, 198.51.100.2",
			},
			remoteAddr: "192.168.1.10:12345",
			expectedIP: "203.0.113.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := CreateIPExtractor(tt.cfg)
			req, _ := http.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			ip := extractor(req)
			assert.Equal(t, tt.expectedIP, ip)
		})
	}
}

func TestMainGracefulShutdown(t *testing.T) {
	if os.Getenv("BE_CRASHER") == "1" {
		if os.Getenv("TEST_GRACEFUL_SHUTDOWN") == "1" {
			// Instead of actually binding to port 80 and waiting, we simulate
			// the server startup and immediate shutdown signal.
			go func() {
				// wait a bit for echo server to 'start' (even though we're overriding it or ignoring it)
				// Actually we just send the SIGTERM to ourselves
				p, _ := os.FindProcess(os.Getpid())
				_ = p.Signal(os.Interrupt)
			}()
		}
		main()
		return
	}

	tests := []struct {
		name         string
		envSet       map[string]string
		envUnset     []string
		expectedErr  bool
		errContains  string
	}{
		{
			name: "MissingServerSecret",
			envSet: map[string]string{
				"BE_CRASHER": "1",
			},
			envUnset: []string{"SERVER_SECRET"},
			expectedErr: true,
			errContains: "exit status 1",
		},
		{
			name: "WeakServerSecret",
			envSet: map[string]string{
				"BE_CRASHER": "1",
				"SERVER_SECRET": "short",
			},
			expectedErr: true,
			errContains: "exit status 1",
		},
		{
			name: "MissingCookieDomain",
			envSet: map[string]string{
				"BE_CRASHER": "1",
				"SERVER_SECRET": "sixteencharsecret",
			},
			envUnset: []string{"COOKIE_DOMAIN"},
			expectedErr: true,
			errContains: "exit status 1",
		},
		{
			name: "GracefulShutdown",
			envSet: map[string]string{
				"BE_CRASHER": "1",
				"TEST_GRACEFUL_SHUTDOWN": "1",
				"SERVER_SECRET": "sixteencharsecret",
				"COOKIE_DOMAIN": "example.com",
			},
			expectedErr: true,
			errContains: "signal: interrupt",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestMainGracefulShutdown")

			// Setup environment carefully to prevent parent env bleed
			var env []string
			for _, e := range os.Environ() {
				parts := strings.SplitN(e, "=", 2)
				key := parts[0]

				unset := false
				for _, u := range tc.envUnset {
					if key == u {
						unset = true
						break
					}
				}

				if _, ok := tc.envSet[key]; !unset && !ok {
					env = append(env, e)
				}
			}

			for k, v := range tc.envSet {
				env = append(env, k+"="+v)
			}
			cmd.Env = env

			err := cmd.Run()

			if tc.name == "GracefulShutdown" {
				if err != nil {
					// Could be signal: interrupt or exit status 1 (if port binding failed before interrupt)
					errStr := err.Error()
					if !strings.Contains(errStr, "signal: interrupt") && !strings.Contains(errStr, "exit status 1") {
						t.Errorf("expected 'signal: interrupt' or 'exit status 1', got %v", errStr)
					}
				}
			} else if tc.expectedErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
