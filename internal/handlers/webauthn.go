package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
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

	userRecord, err := core.GetUser(username)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "User not found")
	}

	user := core.NewWebAuthnUser(userRecord)

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
		return echo.NewHTTPError(http.StatusTooManyRequests, fmt.Sprintf("Too many registration attempts from this IP (%s)", clientIP))
	}

	username, ok := c.Get("username").(string)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized)
	}

	userRecord, err := core.GetUser(username)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "User not found")
	}

	user := core.NewWebAuthnUser(userRecord)

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
		userRecord, getErr := core.GetUser(username)
		if getErr != nil {
			// Dummy user to prevent enumeration
			user := &core.WebAuthnUser{
				ID:          []byte("dummy"),
				DisplayName: username,
			}
			options, sessionData, err = core.WebAuthnInstance.BeginLogin(user)
		} else {
			user := core.NewWebAuthnUser(userRecord)
			options, sessionData, err = core.WebAuthnInstance.BeginLogin(user)
		}
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
		return echo.NewHTTPError(http.StatusTooManyRequests, fmt.Sprintf("Too many login attempts from this IP (%s)", clientIP))
	}

	cookie, err := c.Cookie("rauth_webauthn_session")
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Session expired or invalid")
	}
	sessionID := cookie.Value
	redisKey := "webauthn_login_session:" + sessionID

	sessionJSON, err := core.TokenDB.Get(core.Ctx, redisKey).Result()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Session expired or invalid")
	}

	// Clean up session immediately after retrieval (one-time use)
	core.TokenDB.Del(core.Ctx, redisKey)

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionJSON), &sessionData); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to parse session data")
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponse(c.Request())
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid assertion response")
	}

	// Identify user
	var username string
	var userID []byte
	usernameParam := c.QueryParam("username")

	slog.Debug("Identifying user from passkey", "userHandleLen", len(parsedResponse.Response.UserHandle), "usernameParam", usernameParam)

	// 1. Check UserHandle from authenticator (most reliable for passkeys)
	if len(parsedResponse.Response.UserHandle) > 0 {
		handle := string(parsedResponse.Response.UserHandle)
		slog.Debug("Checking UserHandle", "handleHex", fmt.Sprintf("%x", parsedResponse.Response.UserHandle))
		
		// Try multiple lookup methods for maximum compatibility
		
		// A. Try looking up by the string representation (UUID string or username)
		if u, err := core.GetUsernameByUID(handle); err == nil {
			username = u
			userID = parsedResponse.Response.UserHandle
			slog.Debug("Found username by string UID index", "username", username)
		} else {
			// B. Try looking up handle as a username directly (legacy)
			if userRecord, err := core.GetUser(handle); err == nil {
				username = userRecord.Username
				userID = parsedResponse.Response.UserHandle
				slog.Debug("Found username by legacy username check", "username", username)
			}
		}
	}

	// 2. Fallback to query param if still not identified (common for non-discoverable keys)
	if username == "" && usernameParam != "" {
		slog.Debug("Fallback to usernameParam", "username", usernameParam)
		username = usernameParam
		if userRecord, err := core.GetUser(username); err == nil {
			// Use the record's UID as the userID if the authenticator didn't provide one
			userID = []byte(userRecord.UID)
		}
	}

	if username == "" {
		slog.Warn("Could not identify user from passkey", "userHandle", fmt.Sprintf("%x", parsedResponse.Response.UserHandle), "usernameParam", usernameParam)
		return echo.NewHTTPError(http.StatusBadRequest, "Could not identify user from passkey")
	}

	userRecord, err := core.GetUser(username)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "User not found")
	}

	// If the authenticator didn't provide a handle, use the record's UID
	if len(userID) == 0 {
		userID = []byte(userRecord.UID)
	}

	// Create user object for validation. 
	// CRITICAL: The ID must match what the authenticator thinks it is (userID)
	user := &core.WebAuthnUser{
		ID:          userID,
		DisplayName: userRecord.Username,
		Credentials: core.GetWebAuthnCredentials(userRecord.Username),
	}

	// Sync sessionData.UserID with the identified userID to satisfy go-webauthn's internal checks.
	// This prevents "ID mismatch for User and Session".
	sessionData.UserID = userID

	credential, err := core.WebAuthnInstance.ValidateLogin(user, sessionData, parsedResponse)
	if err != nil {
		slog.Error("WebAuthn validation failed", "error", err, "username", username)
		return echo.NewHTTPError(http.StatusUnauthorized, "Passkey validation failed: "+err.Error())
	}

	// Update credential sign count
	core.UpdateWebAuthnSignCount(username, credential.ID, credential.Authenticator.SignCount)

	// Issue session
	ua := c.Request().UserAgent()
	token := core.GenerateRandomString(32)
	
	encryptedToken, encErr := core.EncryptToken(token, h.Cfg.ServerSecret)
	if encErr != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to encrypt token")
	}
	countryCode := core.GetCountryCode(clientIP)

	finalRedisKey := "X-rauth-authtoken=" + token
	core.TokenDB.HSet(core.Ctx, finalRedisKey, map[string]interface{}{
		"status":     "valid",
		"ip":         clientIP,
		"username":   username,
		"country":    countryCode,
		"user_agent": ua,
		"created_at": time.Now().Unix(),
	})
	
	tokenValidity := time.Duration(h.Cfg.TokenValidityMinutes) * time.Minute
	core.TokenDB.Expire(core.Ctx, finalRedisKey, tokenValidity)

	cookie = &http.Cookie{
		Name:     "X-rauth-authtoken",
		Value:    encryptedToken,
		Path:     "/",
		Domain:   h.Cfg.CookieDomains[0],
		Expires:  time.Now().Add(tokenValidity),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	c.SetCookie(cookie)

	// Send Login Notification Email (Asynchronous)
	if userRecord.Email != "" {
		go core.SendLoginNotification(userRecord.Email, username, clientIP, countryCode)
	}

	core.LogAudit("LOGIN_SUCCESS_PASSKEY", username, clientIP, map[string]interface{}{"country": countryCode})

	// Cleanup session cookie
	c.SetCookie(&http.Cookie{
		Name:     "rauth_webauthn_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
	})

	redirect := "/rauthprofile"
	if rd := c.QueryParam("rd"); rd != "" {
		redirect = rd
	}

	return c.JSON(http.StatusOK, map[string]string{"redirect": redirect})
}