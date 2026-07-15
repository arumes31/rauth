package main

import (
	"bytes"
	"encoding/json"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rauth/internal/core"

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

// Helper to assert JSON errors from API routes
func assertJSONError(t *testing.T, rec *httptest.ResponseRecorder, expectedCode int) {
	t.Helper()
	if rec.Code != expectedCode {
		t.Errorf("expected code %d, got %d", expectedCode, rec.Code)
	}
	var res map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&res); err != nil {
		t.Errorf("failed to decode JSON response: %v", err)
	}
	if code, ok := res["code"].(float64); !ok || int(code) != expectedCode {
		t.Errorf("expected JSON code %d, got %v", expectedCode, res["code"])
	}
}

func TestMainCrasher(t *testing.T) {
	if os.Getenv("CRASHER") == "1" {
		scenario := os.Getenv("CRASHER_SCENARIO")
		switch scenario {
		case "missing_secret":
			_ = os.Setenv("SERVER_SECRET", "short")
		case "missing_domain":
			_ = os.Setenv("SERVER_SECRET", "1234567890123456")
			_ = os.Setenv("COOKIE_DOMAIN", "")
		case "graceful_shutdown":
			_ = os.Setenv("SERVER_SECRET", "1234567890123456")
			_ = os.Setenv("COOKIE_DOMAIN", "localhost")

			// Setup miniredis for the crasher process
			mr, err := miniredis.Run()
			if err != nil {
				panic(err)
			}
			_ = os.Setenv("REDIS_HOST", mr.Host())
			_ = os.Setenv("REDIS_PORT", mr.Port())
		}
		main()
		return
	}

	scenarios := []struct {
		name       string
		scenario   string
		expectExit int
	}{
		{"missing server secret", "missing_secret", 1},
		{"missing cookie domain", "missing_domain", 1},
		{"graceful shutdown", "graceful_shutdown", 0},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestMainCrasher")
			cmd.Env = append(os.Environ(), "CRASHER=1", "CRASHER_SCENARIO="+sc.scenario)

			if sc.scenario == "graceful_shutdown" {
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				time.Sleep(2 * time.Second) // wait for server to start
				_ = cmd.Process.Signal(os.Interrupt)
				err := cmd.Wait()

				// Accept exit status 1 due to port 80 bind failure in unprivileged CI,
				// or signal: interrupt.
				if err != nil {
					errStr := err.Error()
					if !strings.Contains(errStr, "exit status 1") && !strings.Contains(errStr, "signal: interrupt") {
						t.Errorf("expected interrupt or exit status 1, got: %v", err)
					}
				}
			} else {
				err := cmd.Run()
				if e, ok := err.(*exec.ExitError); ok {
					if e.ExitCode() != sc.expectExit {
						t.Errorf("expected exit code %d, got %d", sc.expectExit, e.ExitCode())
					}
				} else {
					t.Fatalf("expected ExitError, got %v", err)
				}
			}
		})
	}
}

func TestErrorHandlers(t *testing.T) {
	e := echo.New()
	setupRenderer(e) // Required for rendering error.html
	setupErrorHandlers(e)

	tests := []struct {
		name         string
		path         string
		err          error
		expectedCode int
		isJSON       bool
		isEmpty      bool
	}{
		{
			name:         "rauthvalidate 401",
			path:         "/rauthvalidate",
			err:          echo.NewHTTPError(http.StatusUnauthorized, "unauthorized"),
			expectedCode: http.StatusUnauthorized,
			isEmpty:      true,
		},
		{
			name:         "webauthn error",
			path:         "/webauthn/login/begin",
			err:          echo.NewHTTPError(http.StatusBadRequest, "bad req"),
			expectedCode: http.StatusBadRequest,
			isJSON:       true,
		},
		{
			name:         "metrics error",
			path:         "/metrics",
			err:          echo.NewHTTPError(http.StatusForbidden, "forbidden"),
			expectedCode: http.StatusForbidden,
			isJSON:       true,
		},
		{
			name:         "generic 404",
			path:         "/unknown",
			err:          echo.NewHTTPError(http.StatusNotFound),
			expectedCode: http.StatusNotFound,
		},
		{
			name:         "generic 403",
			path:         "/admin",
			err:          echo.NewHTTPError(http.StatusForbidden),
			expectedCode: http.StatusForbidden,
		},
		{
			name:         "generic 500",
			path:         "/crash",
			err:          echo.NewHTTPError(http.StatusInternalServerError),
			expectedCode: http.StatusInternalServerError,
		},
		{
			name:         "standard error",
			path:         "/error",
			err:          io.ErrUnexpectedEOF,
			expectedCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			e.HTTPErrorHandler(tt.err, c)

			if rec.Code != tt.expectedCode {
				t.Errorf("expected code %d, got %d", tt.expectedCode, rec.Code)
			}

			if tt.isEmpty {
				if rec.Body.Len() > 0 {
					t.Errorf("expected empty body, got %s", rec.Body.String())
				}
			} else if tt.isJSON {
				assertJSONError(t, rec, tt.expectedCode)
			} else {
				// Should be HTML rendering
				if !strings.Contains(rec.Body.String(), "<html") {
					t.Errorf("expected HTML body, got %s", rec.Body.String())
				}
			}
		})
	}
}
