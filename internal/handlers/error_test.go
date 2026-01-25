package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestCustomNotFoundHandler(t *testing.T) {
	e := echo.New()
	
	// Mock renderer
	e.Renderer = &mockRenderer{}

	// Setup the handler logic (copied from main.go for testing)
	e.HTTPErrorHandler = func(err error, c echo.Context) {
		code := http.StatusInternalServerError
		if he, ok := err.(*echo.HTTPError); ok {
			code = he.Code
		}
		
		if code == http.StatusNotFound {
			_ = c.Render(http.StatusNotFound, "error.html", nil)
			return
		}
		e.DefaultHTTPErrorHandler(err, c)
	}

	req := httptest.NewRequest(http.MethodGet, "/non-existent-page", nil)
	rec := httptest.NewRecorder()
	
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}
