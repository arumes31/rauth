package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"rauth/internal/core"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
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
	clientIP := c.RealIP()
	if !core.CheckRateLimit("reg_ip:"+clientIP, 10, 300) {
		return echo.NewHTTPError(http.StatusTooManyRequests, "Too many registration attempts")
	}

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
	var options *protocol.CredentialAssertion
	var sessionData *webauthn.SessionData
	var err error

	if username != "" {
		user := &core.WebAuthnUser{
			ID:          []byte(username),
			DisplayName: username,
			Credentials: core.GetWebAuthnCredentials(username),
		}
		options, sessionData, err = core.WebAuthnInstance.BeginLogin(user)
	} else {
		// Nameless login
		options, sessionData, err = core.WebAuthnInstance.BeginDiscoverableLogin()
	}

	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	sessionJSON, _ := json.Marshal(sessionData)
	
	sessionID := core.GenerateRandomString(32)
	redisKey := "webauthn_login_session:" + sessionID
	core.TokenDB.Set(core.Ctx, redisKey, sessionJSON, 5*time.Minute)

	cookie := &http.Cookie{
		Name:     "rauth_webauthn_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(5 * time.Minute),
	}
	c.SetCookie(cookie)

	return c.JSON(http.StatusOK, options.Response)
}

func (h *WebAuthnHandler) FinishLogin(c echo.Context) error {
	clientIP := c.RealIP()
	if !core.CheckRateLimit("login_ip:"+clientIP, 10, 300) {
		return echo.NewHTTPError(http.StatusTooManyRequests, "Too many login attempts")
	}

	cookie, err := c.Cookie("rauth_webauthn_session")
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Missing WebAuthn session")
	}
	sessionID := cookie.Value
	redisKey := "webauthn_login_session:" + sessionID

	sessionJSON, err := core.TokenDB.Get(core.Ctx, redisKey).Result()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Session expired")
	}
	core.TokenDB.Del(core.Ctx, redisKey)
	c.SetCookie(&http.Cookie{Name: "rauth_webauthn_session", MaxAge: -1, Path: "/"})

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionJSON), &sessionData); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to parse session data")
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponse(c.Request())
	if err != nil {
		slog.Error("WebAuthn parse assertion failed", "error", err)
		return echo.NewHTTPError(http.StatusBadRequest, "Failed to parse assertion: "+err.Error())
	}

	// Identify user from UserHandle (which we store as the username string)
	username := string(parsedResponse.Response.UserHandle)
	if username == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Credential did not provide user information")
	}

	user := &core.WebAuthnUser{
		ID:          []byte(username),
		DisplayName: username,
		Credentials: core.GetWebAuthnCredentials(username),
	}

	credential, err := core.WebAuthnInstance.ValidateLogin(user, sessionData, parsedResponse)
	if err != nil {
		slog.Warn("WebAuthn login validation failed", "user", username, "error", err)
		return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
	}

	core.UpdateWebAuthnCredential(username, credential)
	
	// Create actual auth session
	authHandler := &AuthHandler{Cfg: h.Cfg}
	rec := httptest.NewRecorder()
	e := echo.New()
	req := c.Request()
	ctx := e.NewContext(req, rec)
	
	if err := authHandler.issueToken(ctx, username); err != nil {
		return err
	}

	return c.JSON(http.StatusOK, map[string]string{
		"status":   "success", 
		"redirect": rec.Header().Get("Location"),
	})
}