package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"rauth/internal/core"

	"github.com/labstack/echo/v4"
)

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input string
		want  string // we can just test if it runs without panic since it returns slog.Level
	}{
		{"debug", "DEBUG"},
		{"warn", "WARN"},
		{"warning", "WARN"},
		{"error", "ERROR"},
		{"", "INFO"},
		{"unknown", "INFO"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			level := parseLogLevel(tc.input)
			if level.String() != tc.want {
				t.Errorf("parseLogLevel(%q) = %v; want %v", tc.input, level.String(), tc.want)
			}
		})
	}
}

func TestTemplateRenderer(t *testing.T) {
	e := echo.New()
	setupRenderer(e)

	// Since we mock it or just use the setupRenderer
	renderer, ok := e.Renderer.(*TemplateRenderer)
	if !ok {
		t.Fatalf("expected renderer to be *TemplateRenderer")
	}

	// Just execute a small dummy to cover Render method if possible? We don't have a small dummy template, we only have what's in templateFS
	// Let's call it on login.html or something
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := renderer.Render(rec, "login.html", map[string]interface{}{"Title": "Test"}, c)
	if err != nil {
		t.Errorf("expected no error rendering login.html, got %v", err)
	}
}

func TestSetupErrorHandlers(t *testing.T) {
	e := echo.New()
	setupErrorHandlers(e)
	setupRenderer(e) // needs renderer for error html

	tests := []struct {
		name         string
		path         string
		method       string
		err          error
		expectedCode int
	}{
		{
			name:         "404 not found HTML",
			path:         "/unknown",
			method:       http.MethodGet,
			err:          echo.NewHTTPError(http.StatusNotFound),
			expectedCode: http.StatusNotFound,
		},
		{
			name:         "403 forbidden HTML",
			path:         "/forbidden",
			method:       http.MethodGet,
			err:          echo.NewHTTPError(http.StatusForbidden),
			expectedCode: http.StatusForbidden,
		},
		{
			name:         "500 internal HTML",
			path:         "/internal",
			method:       http.MethodGet,
			err:          echo.NewHTTPError(http.StatusInternalServerError),
			expectedCode: http.StatusInternalServerError,
		},
		{
			name:         "rauthvalidate no content",
			path:         "/rauthvalidate",
			method:       http.MethodGet,
			err:          echo.NewHTTPError(http.StatusUnauthorized),
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "webauthn json error",
			path:         "/webauthn/login/begin",
			method:       http.MethodGet,
			err:          echo.NewHTTPError(http.StatusBadRequest, "bad request"),
			expectedCode: http.StatusBadRequest,
		},
		{
			name:         "metrics json error",
			path:         "/metrics",
			method:       http.MethodGet,
			err:          echo.NewHTTPError(http.StatusForbidden, "denied"),
			expectedCode: http.StatusForbidden,
		},
		{
			name:         "health json error",
			path:         "/health",
			method:       http.MethodGet,
			err:          echo.NewHTTPError(http.StatusInternalServerError, "fail"),
			expectedCode: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			e.HTTPErrorHandler(tc.err, c)

			if rec.Code != tc.expectedCode {
				t.Errorf("expected status %d, got %d", tc.expectedCode, rec.Code)
			}
		})
	}
}

func TestLoggingMiddleware(t *testing.T) {
	e := echo.New()
	setupLoggingMiddleware(e)
	e.GET("/test", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})
	e.GET("/error", func(c echo.Context) error {
		return echo.NewHTTPError(http.StatusInternalServerError, "fail")
	})

	tests := []struct {
		name    string
		path    string
		headers map[string]string
	}{
		{"normal request", "/test", nil},
		{"error request", "/error", nil},
		{"with headers", "/test", map[string]string{
			"X-Forwarded-For":  "1.2.3.4",
			"X-Real-IP":        "5.6.7.8",
			"CF-Connecting-IP": "9.10.11.12",
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
		})
	}
}

func TestClientHintsMiddleware(t *testing.T) {
	e := echo.New()
	setupClientHintsMiddleware(e)
	e.GET("/test", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})
	e.POST("/test", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	reqGet := httptest.NewRequest(http.MethodGet, "/test", nil)
	recGet := httptest.NewRecorder()
	e.ServeHTTP(recGet, reqGet)

	if recGet.Header().Get("Critical-CH") == "" {
		t.Errorf("expected Critical-CH header on GET")
	}

	reqPost := httptest.NewRequest(http.MethodPost, "/test", nil)
	recPost := httptest.NewRecorder()
	e.ServeHTTP(recPost, reqPost)

	if recPost.Header().Get("Critical-CH") != "" {
		t.Errorf("did not expect Critical-CH header on POST")
	}
}

func TestCreateIPExtractor(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *core.Config
		remoteAddr string
		headers    map[string]string
		expected   string
	}{
		{
			name:       "basic remote addr",
			cfg:        &core.Config{},
			remoteAddr: "192.168.1.1:1234",
			expected:   "192.168.1.1",
		},
		{
			name:       "trust cloudflare",
			cfg:        &core.Config{TrustCloudflareIP: true},
			remoteAddr: "192.168.1.1:1234",
			headers:    map[string]string{"CF-Connecting-IP": "8.8.8.8"},
			expected:   "8.8.8.8",
		},
		{
			name:       "trust real ip",
			cfg:        &core.Config{TrustXRealIP: true},
			remoteAddr: "192.168.1.1:1234",
			headers:    map[string]string{"X-Real-IP": "8.8.4.4"},
			expected:   "8.8.4.4",
		},
		{
			name:       "smart real ip from private",
			cfg:        &core.Config{},
			remoteAddr: "10.0.0.1:1234",
			headers:    map[string]string{"X-Real-IP": "8.8.4.4"},
			expected:   "8.8.4.4",
		},
		{
			name:       "smart real ip from private - but real ip is also private",
			cfg:        &core.Config{},
			remoteAddr: "10.0.0.1:1234",
			headers:    map[string]string{"X-Real-IP": "172.16.0.1", "X-Forwarded-For": "8.8.8.8"},
			expected:   "8.8.8.8",
		},
		{
			name:       "trust forwarded for",
			cfg:        &core.Config{TrustXForwardedFor: true},
			remoteAddr: "192.168.1.1:1234",
			headers:    map[string]string{"X-Forwarded-For": "1.1.1.1, 2.2.2.2"},
			expected:   "1.1.1.1",
		},
		{
			name:       "smart forwarded for from private",
			cfg:        &core.Config{},
			remoteAddr: "10.0.0.1:1234",
			headers:    map[string]string{"X-Forwarded-For": "3.3.3.3, 10.0.0.2"},
			expected:   "3.3.3.3",
		},
		{
			name:       "smart forwarded for all private",
			cfg:        &core.Config{},
			remoteAddr: "10.0.0.1:1234",
			headers:    map[string]string{"X-Forwarded-For": "192.168.1.100, 10.0.0.2"},
			expected:   "192.168.1.100",
		},
		{
			name:       "invalid IPs ignored",
			cfg:        &core.Config{TrustXRealIP: true, TrustXForwardedFor: true, TrustCloudflareIP: true},
			remoteAddr: "192.168.1.1:1234",
			headers:    map[string]string{"CF-Connecting-IP": "invalid", "X-Real-IP": "invalid", "X-Forwarded-For": "invalid"},
			expected:   "192.168.1.1",
		},
		{
			name:       "missing port in remoteAddr",
			cfg:        &core.Config{},
			remoteAddr: "192.168.1.2",
			expected:   "192.168.1.2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extractor := CreateIPExtractor(tc.cfg)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remoteAddr
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			ip := extractor(req)
			if ip != tc.expected {
				t.Errorf("expected IP %s, got %s", tc.expected, ip)
			}
		})
	}
}

// Add a test to hit the logout endpoint
func TestLogoutRoute(t *testing.T) {
	e := echo.New()
	cfg := &core.Config{
		CookieDomains: []string{"example.com"},
	}
	setupRoutes(e, cfg)

	// Test that the logout route is mounted and returns a redirect
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	rec := httptest.NewRecorder()
	// It's a protected route, but we can hit it anyway, middleware might redirect if no token
	// Actually we can inject a mock context if we want to test the token clearing logic.
	// For now, just test if it returns 302 Found to /rauthlogin
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/rauthlogin" && loc != "/rauthlogin?rd=%2Flogout" {
		t.Errorf("expected redirect to /rauthlogin, got %s", loc)
	}
}

func TestTemplateRendererFormatFunctions(t *testing.T) {
	e := echo.New()
	setupRenderer(e)
	renderer, _ := e.Renderer.(*TemplateRenderer)

	// Test that they don't panic or error out the template parsing
	if renderer.templates == nil {
		t.Fatal("templates not initialized")
	}
}

func TestTemplateRendererFormatFunctionsFull(t *testing.T) {
	e := echo.New()
	setupRenderer(e)
	renderer, _ := e.Renderer.(*TemplateRenderer)

	// Instead of extracting FuncMap, we render a dummy template.
	// However we cannot parse a new template into the existing one directly without changing it.
	// But we CAN add a template to the renderer's templates pool because it's a *template.Template.

	_, err := renderer.templates.New("test_dummy").Parse(`
        Time: {{formatTime 1234567890}}
        Time0: {{formatTime 0}}
        TimeStr: {{formatTime "1234567890"}}
        TimeInvalid: {{formatTime "invalid"}}
        Secs: {{formatSeconds "65"}}
        Marshal: {{marshal .Map}}
        Status1: {{statusColor "LOGIN_SUCCESS"}}
        Status2: {{statusColor "2FA_SETUP_SUCCESS"}}
        Status3: {{statusColor "LOGIN_FAILED"}}
        Status4: {{statusColor "2FA_FAILED"}}
        Status5: {{statusColor "COUNTRY_CHANGE_DETECTED"}}
        Status6: {{statusColor "OTHER"}}
    `)
	if err != nil {
		t.Fatalf("failed to add dummy template: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	data := map[string]interface{}{
		"Map": map[string]string{"a": "b"},
	}

	err = renderer.Render(rec, "test_dummy", data, c)
	if err != nil {
		t.Errorf("expected no error rendering dummy, got %v", err)
	}
}

func TestHealthAndMetricsRoutes(t *testing.T) {
	e := echo.New()
	cfg := &core.Config{
		MetricsAllowedIPs: []string{"192.168.1.1"},
	}
	setupRoutes(e, cfg)

	// Metrics is restricted
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "192.168.1.2:1234"
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected metrics to be forbidden for 192.168.1.2, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	// Not forbidden, likely hits prometheus handler and returns 200 or 500
	if rec.Code == http.StatusForbidden {
		t.Errorf("expected metrics to be allowed for 192.168.1.1")
	}
}
