package main

import (
	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"rauth/internal/core"
	"strings"
	"testing"
)

func TestSSOLogQueryRedaction(t *testing.T) {
	for _, s := range []string{"/_rauth/callback?code=secret-proof&state=secret-state", "/_rauth/authorize?transaction=secret-transaction", "/rauthlogin?rd=%2F_rauth%2Fauthorize%3Ftransaction%3Dsecret-transaction"} {
		out := redactURI(s)
		assert.NotContains(t, out, "secret")
		assert.Contains(t, out, "REDACTED")
	}
}

func TestSSOLogoutKeepsCSRFProtection(t *testing.T) {
	e := echo.New()
	setupCSRFMiddleware(e, &core.Config{})
	reached := false
	e.POST("/_rauth/logout", func(c *echo.Context) error { reached = true; return c.NoContent(http.StatusNoContent) })
	for _, headers := range []map[string]string{{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.test"}, {"Sec-Fetch-Site": "same-site", "Origin": "https://sibling.example.org"}, {}} {
		reached = false
		req := httptest.NewRequest(http.MethodPost, "https://app.example.org/_rauth/logout", strings.NewReader("csrf=forged"))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.False(t, reached)
	}
}
