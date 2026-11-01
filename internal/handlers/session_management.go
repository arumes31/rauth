package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"rauth/internal/authstate"
	"rauth/internal/core"

	"github.com/labstack/echo/v4"
)

func prepareSessionViews(sessions []map[string]string) {
	for _, data := range sessions {
		data["friendly_ua"] = core.FormatDevice(data["user_agent"], data["ua_ch_platform"], data["ua_ch_mobile"], data["ua_ch_model"])
		data["device_icon"] = core.GetDeviceIcon(data["user_agent"])
	}
}
func sessionManagementError(err error) error {
	if errors.Is(err, core.ErrInvalidSessionHandle) {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid session identifier")
	}
	slog.Error("Session management authority unavailable", "error", err)
	return echo.NewHTTPError(http.StatusServiceUnavailable, "Session management is temporarily unavailable")
}

// Credential mutations are already committed here. Preserve their audit and
// notification, and tell the user to sign in again without suggesting a retry
// of the credential change itself.
func retainedSessionError(err error) error {
	if errors.Is(err, authstate.ErrNotFound) {
		return echo.NewHTTPError(http.StatusUnauthorized, "Security changes saved. Please sign in again.")
	}
	slog.Error("Security changes committed but current session could not be retained", "error", err)
	return echo.NewHTTPError(http.StatusServiceUnavailable, "Security changes saved. Session service is temporarily unavailable; please sign in again when it recovers.")
}
