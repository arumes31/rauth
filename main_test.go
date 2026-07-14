package main

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"rauth/internal/core"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMainExecution(t *testing.T) {
	crasherEnv := os.Getenv("CRASHER")
	if crasherEnv != "" {
		if crasherEnv == "graceful" {
			go func() {
				time.Sleep(500 * time.Millisecond)
				p, _ := os.FindProcess(os.Getpid())
				_ = p.Signal(os.Interrupt)
			}()
		}
		main()
		return
	}

	s := miniredis.RunT(t)

	tests := []struct {
		name          string
		env           map[string]string
		crasherType   string
		expectExitErr bool
		expectOut     string
		checkGraceful bool
	}{
		{
			name:          "Missing server secret",
			env:           map[string]string{},
			crasherType:   "secret",
			expectExitErr: true,
			expectOut:     "SERVER_SECRET must be set to at least 16 characters",
		},
		{
			name: "Missing cookie domain",
			env: map[string]string{
				"SERVER_SECRET": "1234567890123456",
				"COOKIE_DOMAIN": "",
			},
			crasherType:   "cookie",
			expectExitErr: true,
			expectOut:     "COOKIE_DOMAIN must contain at least one domain",
		},
		{
			name: "Redis init failed",
			env: map[string]string{
				"SERVER_SECRET": "1234567890123456",
				"COOKIE_DOMAIN": "example.com",
				"REDIS_HOST":    "localhost",
				"REDIS_PORT":    "9999",
			},
			crasherType:   "redis",
			expectExitErr: true,
			expectOut:     "Redis initialization failed",
		},
		{
			name: "Graceful shutdown",
			env: map[string]string{
				"SERVER_SECRET": "1234567890123456",
				"COOKIE_DOMAIN": "example.com",
				"REDIS_HOST":    s.Host(),
				"REDIS_PORT":    s.Port(),
			},
			crasherType:   "graceful",
			expectExitErr: false,
			expectOut:     "",
			checkGraceful: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestMainExecution")

			filteredEnv := []string{}
			for _, e := range os.Environ() {
				if !strings.HasPrefix(e, "SERVER_SECRET=") &&
					!strings.HasPrefix(e, "COOKIE_DOMAIN=") &&
					!strings.HasPrefix(e, "REDIS_HOST=") &&
					!strings.HasPrefix(e, "REDIS_PORT=") {
					filteredEnv = append(filteredEnv, e)
				}
			}
			cmd.Env = filteredEnv

			for k, v := range tc.env {
				cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
			}
			cmd.Env = append(cmd.Env, fmt.Sprintf("CRASHER=%s", tc.crasherType))

			if !tc.checkGraceful {
				out, err := cmd.CombinedOutput()
				if tc.expectExitErr {
					require.Error(t, err, "expected command to fail")
				} else {
					require.NoError(t, err, "expected command to succeed")
				}
				if tc.expectOut != "" {
					require.Contains(t, string(out), tc.expectOut)
				}
			} else {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				errCh := make(chan error, 1)
				outCh := make(chan []byte, 1)

				go func() {
					out, err := cmd.CombinedOutput()
					if err != nil {
						errCh <- err
					} else {
						errCh <- nil
					}
					outCh <- out
				}()

				select {
				case <-ctx.Done():
					t.Fatal("test timed out")
				case err := <-errCh:
					out := <-outCh
					if err != nil {
						errStr := err.Error()
						if !strings.Contains(errStr, "signal: interrupt") && !strings.Contains(errStr, "exit status 1") {
							t.Fatalf("unexpected error: %v, output: %s", err, string(out))
						}
					}
				}
			}
		})
	}
}

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
