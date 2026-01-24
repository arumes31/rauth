package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/stretchr/testify/assert"
)

func TestSecurityHeaders(t *testing.T) {
	e := echo.New()
	e.Use(middleware.Secure())

	e.GET("/test", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	
	// Check for standard security headers provided by echo.middleware.Secure
	assert.NotEmpty(t, rec.Header().Get("X-Xss-Protection"))
	assert.NotEmpty(t, rec.Header().Get("X-Content-Type-Options"))
	assert.NotEmpty(t, rec.Header().Get("X-Frame-Options"))
}
