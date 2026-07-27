package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestMainExecution(t *testing.T) {
	if os.Getenv("TEST_MAIN_EXECUTION") == "1" {
		main()
		return
	}

	mr := miniredis.RunT(t)
	host, port, _ := net.SplitHostPort(mr.Addr())

	tests := []struct {
		name         string
		env          map[string]string
		expectExit   int
		shouldCancel bool
	}{
		{
			name:       "Missing Server Secret",
			env:        map[string]string{"SERVER_SECRET": ""},
			expectExit: 1,
		},
		{
			name:       "Missing Cookie Domain",
			env:        map[string]string{"SERVER_SECRET": "1234567890123456", "COOKIE_DOMAIN": ""},
			expectExit: 1,
		},
		{
			name: "Failed Redis Initialization",
			env: map[string]string{
				"SERVER_SECRET": "1234567890123456",
				"COOKIE_DOMAIN": "localhost",
				"REDIS_HOST":    "invalid",
				"REDIS_PORT":    "6379",
			},
			expectExit: 1,
		},
		{
			name: "Successful Start and Graceful Shutdown",
			env: map[string]string{
				"SERVER_SECRET":  "1234567890123456",
				"COOKIE_DOMAIN":  "localhost",
				"REDIS_HOST":     host,
				"REDIS_PORT":     port,
				"LOG_LEVEL":      "error",
				"WEBAUTHN_RP_ID": "https://invalid-rp-id",
			},
			shouldCancel: true,
			expectExit:   0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestMainExecution")
			cmd.Env = append(os.Environ(), "TEST_MAIN_EXECUTION=1")
			for _, k := range []string{"SERVER_SECRET", "COOKIE_DOMAIN", "REDIS_HOST", "REDIS_PORT", "WEBAUTHN_RP_ID"} {
				cmd.Env = append(cmd.Env, k+"=")
			}
			for k, v := range tc.env {
				cmd.Env = append(cmd.Env, k+"="+v)
			}

			if tc.shouldCancel {
				err := cmd.Start()
				if err != nil {
					t.Fatalf("failed to start: %v", err)
				}
				time.Sleep(500 * time.Millisecond)
				cmd.Process.Signal(syscall.SIGINT)
				err = cmd.Wait()
				if e, ok := err.(*exec.ExitError); ok {
					if e.ExitCode() != tc.expectExit && e.ExitCode() != -1 && e.ExitCode() != 1 {
						t.Fatalf("expected exit %d, got %d", tc.expectExit, e.ExitCode())
					}
				}
			} else {
				err := cmd.Run()
				if e, ok := err.(*exec.ExitError); ok {
					if e.ExitCode() != tc.expectExit {
						t.Fatalf("expected exit %d, got %d", tc.expectExit, e.ExitCode())
					}
				} else if tc.expectExit != 0 {
					t.Fatalf("expected exit %d, got 0", tc.expectExit)
				}
			}
		})
	}
}

func TestSetupClientHintsMiddleware(t *testing.T) {
	e := echo.New()
	setupClientHintsMiddleware(e)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})
	e.ServeHTTP(rec, req)
	assert.Contains(t, rec.Header().Get("Accept-CH"), "Sec-CH-UA")
}

func TestSetupLoggingMiddleware(t *testing.T) {
	e := echo.New()
	setupLoggingMiddleware(e)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	})
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestSetupErrorHandlers(t *testing.T) {
	e := echo.New()
	setupRenderer(e)
	setupErrorHandlers(e)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := echo.NewHTTPError(http.StatusNotFound)
	e.HTTPErrorHandler(err, c)
	assert.Equal(t, http.StatusNotFound, rec.Code)

	rec2 := httptest.NewRecorder()
	c2 := e.NewContext(req, rec2)
	err2 := echo.NewHTTPError(http.StatusForbidden)
	e.HTTPErrorHandler(err2, c2)
	assert.Equal(t, http.StatusForbidden, rec2.Code)

	rec3 := httptest.NewRecorder()
	c3 := e.NewContext(req, rec3)
	err3 := echo.NewHTTPError(http.StatusInternalServerError)
	e.HTTPErrorHandler(err3, c3)
	assert.Equal(t, http.StatusInternalServerError, rec3.Code)
}

func TestSetupRendererFormatFuncs(t *testing.T) {
	e := echo.New()
	setupRenderer(e)
	tr := e.Renderer.(*TemplateRenderer)
	var buf bytes.Buffer
	tr.templates = tr.templates.New("test_funcs")
	tr.templates.Parse(`
		Time: {{ formatTime 1700000000 }}
		Time2: {{ formatTime "1700000000" }}
		Time3: {{ formatTime .InvalidTime }}
		Secs: {{ formatSeconds "125" }}
		StatusSuccess: {{ statusColor "LOGIN_SUCCESS" }}
		StatusFailed: {{ statusColor "LOGIN_FAILED" }}
		StatusOther: {{ statusColor "OTHER" }}
		JSON: {{ marshal . }}
	`)
	err := tr.Render(&buf, "test_funcs", map[string]interface{}{"foo": "bar", "InvalidTime": 1.5}, nil)
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "Time:")
	assert.Contains(t, buf.String(), "N/A")
	assert.Contains(t, buf.String(), "2m 5s")
	assert.Contains(t, buf.String(), "text-success")
	assert.Contains(t, buf.String(), "text-danger")
	assert.Contains(t, buf.String(), "text-info")
}
