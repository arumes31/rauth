package handlers

import (
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v4"
)

func NewHTTPErrorHandler(e *echo.Echo) echo.HTTPErrorHandler {
	return func(err error, c echo.Context) {
		if c.Response().Committed {
			return
		}
		code := http.StatusInternalServerError
		if he, ok := err.(*echo.HTTPError); ok {
			code = he.Code
		}

		errorData := map[string]interface{}{
			"Code":    code,
			"Title":   "Error",
			"Message": "An unexpected error occurred.",
			"Icon":    "bi-exclamation-triangle",
			"Color":   "warning",
		}

		switch code {
		case http.StatusNotFound:
			errorData["Title"] = "Page Not Found"
			errorData["Message"] = "The identity you are looking for does not exist or has moved to another dimension."
			errorData["Icon"] = "bi-exclamation-octagon"
			errorData["Color"] = "danger"
		case http.StatusForbidden:
			errorData["Title"] = "Access Forbidden"
			errorData["Message"] = "You do not have the required clearance to access this sector."
			errorData["Icon"] = "bi-shield-lock"
			errorData["Color"] = "danger"
		case http.StatusInternalServerError:
			errorData["Title"] = "System Error"
			errorData["Message"] = "Something went wrong in the core. Our engineers have been notified."
			errorData["Icon"] = "bi-cpu"
			errorData["Color"] = "primary"
		default:
			// Generic handler for other codes
			errorData["Title"] = http.StatusText(code)
		}

		if renderErr := c.Render(code, "error.html", errorData); renderErr != nil {
			slog.Error("Failed to render error page", "error", renderErr)
		}
	}
}
