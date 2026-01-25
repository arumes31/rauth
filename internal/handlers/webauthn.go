package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"rauth/internal/core"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/labstack/echo/v4"
)

type WebAuthnHandler struct {
	Cfg *core.Config
}

func (h *WebAuthnHandler) BeginRegistration(c echo.Context) error {
	username, ok := c.Get("username").(string)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized)
	}

	user := &core.WebAuthnUser{
		ID:          []byte(username),
		DisplayName: username,
		Credentials: core.GetWebAuthnCredentials(username),
	}

	options, sessionData, err := core.WebAuthnInstance.BeginRegistration(user)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// Store session data in Redis temporarily (5 minutes)
	sessionJSON, _ := json.Marshal(sessionData)
	core.TokenDB.Set(core.Ctx, "webauthn_reg:"+username, sessionJSON, 5*time.Minute)

	return c.JSON(http.StatusOK, options.Response)
}

func (h *WebAuthnHandler) FinishRegistration(c echo.Context) error {
	username, ok := c.Get("username").(string)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized)
	}

	user := &core.WebAuthnUser{
		ID:          []byte(username),
		DisplayName: username,
		Credentials: core.GetWebAuthnCredentials(username),
	}

	redisKey := "webauthn_reg:" + username
	sessionJSON, err := core.TokenDB.Get(core.Ctx, redisKey).Result()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Session expired")
	}
	// Delete immediately to prevent replay
	core.TokenDB.Del(core.Ctx, redisKey)

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionJSON), &sessionData); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to parse session data")
	}

	credential, err := core.WebAuthnInstance.FinishRegistration(user, sessionData, c.Request())
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if err := core.SaveWebAuthnCredential(username, credential); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to save credential")
	}

	core.TokenDB.Del(core.Ctx, "webauthn_reg:"+username)
	return c.JSON(http.StatusOK, "Registration Success")
}

func (h *WebAuthnHandler) BeginLogin(c echo.Context) error {
	username := c.QueryParam("username")
	if username == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username required")
	}

	user := &core.WebAuthnUser{
		ID:          []byte(username),
		DisplayName: username,
		Credentials: core.GetWebAuthnCredentials(username),
	}

	options, sessionData, err := core.WebAuthnInstance.BeginLogin(user)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	sessionJSON, _ := json.Marshal(sessionData)
	core.TokenDB.Set(core.Ctx, "webauthn_login:"+username, sessionJSON, 5*time.Minute)

	return c.JSON(http.StatusOK, options.Response)
}

func (h *WebAuthnHandler) FinishLogin(c echo.Context) error {
	username := c.QueryParam("username")
	if username == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username required")
	}

	user := &core.WebAuthnUser{
		ID:          []byte(username),
		DisplayName: username,
		Credentials: core.GetWebAuthnCredentials(username),
	}

	redisKey := "webauthn_login:" + username
	sessionJSON, err := core.TokenDB.Get(core.Ctx, redisKey).Result()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Session expired")
	}
	// Delete immediately to prevent replay
	core.TokenDB.Del(core.Ctx, redisKey)

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionJSON), &sessionData); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to parse session data")
	}

	_, err = core.WebAuthnInstance.FinishLogin(user, sessionData, c.Request())
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
	}

	core.TokenDB.Del(core.Ctx, "webauthn_login:"+username)
	
	// Create actual auth session
	authHandler := &AuthHandler{Cfg: h.Cfg}
	
	// Temporarily capture the redirect
	rec := httptest.NewRecorder()
	e := echo.New()
	req := c.Request()
	ctx := e.NewContext(req, rec)
	ctx.Set("username", username) // Simulating login status for issueToken
	
	if err := authHandler.issueToken(c, username); err != nil {
		return err
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success", "redirect": c.Response().Header().Get("Location")})
}
