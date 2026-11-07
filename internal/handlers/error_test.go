package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
)

func TestCustomNotFoundHandler(t *testing.T) {
	e := echo.New()

	// Mock renderer
	e.Renderer = &mockRenderer{}

	// Setup the handler logic (copied from main.go for testing)
	e.HTTPErrorHandler = func(c *echo.Context, err error) {
		// Router errors such as echo.ErrNotFound are not *echo.HTTPError in v5.
		code := echo.StatusCode(err)
		if code == http.StatusNotFound {
			_ = c.Render(http.StatusNotFound, "error.html", nil)
			return
		}
		echo.DefaultHTTPErrorHandler(false)(c, err)
	}

	req := httptest.NewRequest(http.MethodGet, "/non-existent-page", nil)
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}
