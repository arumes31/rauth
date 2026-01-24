package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	echoMiddleware "github.com/labstack/echo/v4/middleware"
	"github.com/stretchr/testify/assert"
)

func TestCSRFProtection(t *testing.T) {
	setupHandlersTest(t)
	e := echo.New()
	
	// Apply CSRF middleware exactly as in main.go
	e.Use(echoMiddleware.CSRFWithConfig(echoMiddleware.CSRFConfig{
		TokenLookup: "form:csrf",
		CookieName:  "_csrf",
	}))

	e.POST("/test", func(c echo.Context) error {
		return c.String(http.StatusOK, "passed")
	})

	t.Run("POST without CSRF fails", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		// Echo CSRF returns 400 for missing token
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("POST with invalid CSRF fails", func(t *testing.T) {
		f := url.Values{}
		f.Set("csrf", "wrongtoken")
		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		// Set cookie but provide wrong form value
		req.AddCookie(&http.Cookie{Name: "_csrf", Value: "validtoken"})
		
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		// Echo returns 403 Forbidden for invalid token
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}