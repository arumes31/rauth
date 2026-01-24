package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/stretchr/testify/assert"
)

func TestCSRFProtection(t *testing.T) {
	e := echo.New()
	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLookup: "form:csrf",
	}))

	e.POST("/protected", func(c echo.Context) error {
		return c.String(http.StatusOK, "Success")
	})

	t.Run("POST without CSRF fails", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/protected", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		// Echo CSRF returns 400 Bad Request by default for missing token
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("POST with invalid CSRF fails", func(t *testing.T) {
		f := make(url.Values)
		f.Set("csrf", "invalid-token")

		req := httptest.NewRequest(http.MethodPost, "/protected", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}
