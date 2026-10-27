package main

import (
	"net/http"
	"net/http/httptest"
	"rauth/internal/core"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

// Regression tests for the 2026-10-27 security audit findings.

// Finding 1: a same-site (sibling subdomain) POST is rejected before the
// double-submit token check, even when it carries a matching planted cookie.
func TestRegression_CrossOriginStateChangeBlocked(t *testing.T) {
	e := echo.New()
	setupCSRFMiddleware(e, &core.Config{})
	e.POST("/rauthmgmt/user/create", func(c echo.Context) error { return c.String(http.StatusOK, "created") })

	post := func(headers map[string]string) int {
		req := httptest.NewRequest(http.MethodPost, "https://auth.example.com/rauthmgmt/user/create", strings.NewReader("csrf=planted"))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		req.AddCookie(&http.Cookie{Name: "__Host-csrf", Value: "planted"})
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec.Code
	}

	assert.Equal(t, http.StatusForbidden, post(map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "https://app.example.com"}))
	assert.Equal(t, http.StatusForbidden, post(map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.test"}))
	assert.Equal(t, http.StatusForbidden, post(map[string]string{"Origin": "https://app.example.com"}))
	assert.Equal(t, http.StatusOK, post(map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "https://auth.example.com"}))
}

func TestRegression_CrossOriginTrustedOrigin(t *testing.T) {
	e := echo.New()
	setupCSRFMiddleware(e, &core.Config{CSRFTrustedOrigins: []string{"https://portal.example.com/"}})
	e.POST("/x", func(c echo.Context) error { return c.String(http.StatusOK, "ok") })
	req := httptest.NewRequest(http.MethodPost, "https://auth.example.com/x", strings.NewReader("csrf=t"))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Origin", "https://portal.example.com")
	req.AddCookie(&http.Cookie{Name: "__Host-csrf", Value: "t"})
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// Finding 3: in smart mode, a LAN client behind the proxy cannot choose its IP
// by prefixing X-Forwarded-For.
func TestRegression_SmartModeXFFSpoof(t *testing.T) {
	extract := CreateIPExtractor(&core.Config{})
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "172.18.0.5:1234"
	req.Header.Set("X-Real-IP", "192.168.1.50")
	req.Header.Set("X-Forwarded-For", "8.8.8.8, 192.168.1.50")
	assert.Equal(t, "192.168.1.50", extract(req))

	req.Header.Del("X-Real-IP")
	assert.Equal(t, "192.168.1.50", extract(req), "only the hop appended by the proxy is trusted")
}

// Finding 8: the HTTP server bounds slow and idle connections.
func TestRegression_ServerTimeouts(t *testing.T) {
	s := &http.Server{}
	configureServerTimeouts(s)
	assert.NotZero(t, s.ReadHeaderTimeout)
	assert.NotZero(t, s.ReadTimeout)
	assert.NotZero(t, s.IdleTimeout)
	assert.NotZero(t, s.WriteTimeout)
}

func TestRegression_ValidateServerSecret(t *testing.T) {
	assert.Error(t, validateServerSecret("short"))
	assert.Error(t, validateServerSecret("your_random_32_character_secret_here"))
	assert.Error(t, validateServerSecret("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	assert.NoError(t, validateServerSecret("0123456789abcdef"))
	assert.NoError(t, validateServerSecret("f3b9c1e07a5d4e2c9b8a7f6e5d4c3b2a"))
}

func TestRegression_RedactURI(t *testing.T) {
	assert.Equal(t, "/rauthredeem?token=REDACTED", redactURI("/rauthredeem?token=s3cr3t"))
	assert.Equal(t, "/rauthlogin?rd=%2Fx", redactURI("/rauthlogin?rd=%2Fx"))
	assert.Equal(t, "/health", redactURI("/health"))
}

func TestRegression_StaticNoDirectoryListing(t *testing.T) {
	fsys := noDirListingFS{fstest.MapFS{"static/app.js": {Data: []byte("x")}}}
	_, err := fsys.Open("static")
	assert.Error(t, err)
	f, err := fsys.Open("static/app.js")
	assert.NoError(t, err)
	_ = f.Close()
}
