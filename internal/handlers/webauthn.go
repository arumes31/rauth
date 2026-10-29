package handlers

import (
	"encoding/json"
	"errors"
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
	clientIP := c.RealIP()
	if !core.CheckRateLimit("reg_ip:"+core.RateLimitIP(clientIP), h.Cfg.RateLimitRegistrationMax, h.Cfg.RateLimitRegistrationDecay) {
		return echo.NewHTTPError(http.StatusTooManyRequests, fmt.Sprintf("Too many registration attempts from this IP (%s)", clientIP))
	}

	username, ok := c.Get("username").(string)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized)
	}

	// Step-up: a session cookie alone must not be able to enrol a passkey,
	// since a passkey logs in without password or TOTP.
	if herr := verifyStepUp(h.Cfg, username, c.FormValue("otp_code"), c.FormValue("current_password")); herr != nil {
		return herr
	}

	userRecord, err := core.GetUser(username)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "User not found")
	}

	user := core.NewWebAuthnUser(userRecord)

	// Exclude already-registered authenticators so the same key is not enrolled twice.
	options, sessionData, err := core.WebAuthnInstance.BeginRegistration(user,
		webauthn.WithExclusions(webauthn.Credentials(user.WebAuthnCredentials()).CredentialDescriptors()))
	if err != nil {
		slog.Error("WebAuthn BeginRegistration failed", "user", username, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start passkey registration")
	}

	// Store session data in Redis temporarily (5 minutes)
	sessionJSON, _ := json.Marshal(sessionData)
	core.TokenDB.Set(core.Ctx, "webauthn_reg:"+username, sessionJSON, 5*time.Minute)

	return c.JSON(http.StatusOK, options.Response)
}

func (h *WebAuthnHandler) FinishRegistration(c echo.Context) error {
	clientIP := c.RealIP()
	if !core.CheckRateLimit("reg_ip:"+core.RateLimitIP(clientIP), h.Cfg.RateLimitRegistrationMax, h.Cfg.RateLimitRegistrationDecay) {
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
		slog.Warn("WebAuthn FinishRegistration failed", "user", username, "error", err)
		return echo.NewHTTPError(http.StatusBadRequest, "Passkey registration failed")
	}

	// Save only while the session that authorized this request is still
	// current: a 2FA reset or account deletion that overtook the request must
	// not get the passkey it removed back.
	authGen, _ := c.Get("auth_gen").(string)
	if err := core.SaveWebAuthnCredential(username, credential, authGen); err != nil {
		if errors.Is(err, core.ErrStaleGeneration) {
			slog.Warn("Passkey registration overtaken by a credential reset", "user", username)
			return echo.NewHTTPError(http.StatusUnauthorized, "Session revoked during registration")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to save credential")
	}

	core.TokenDB.Del(core.Ctx, "webauthn_reg:"+username)

	core.LogAudit("PASSKEY_REGISTER", username, clientIP, nil)
	if userRecord.Email != "" {
		device := core.FormatDevice(c.Request().UserAgent(),
			c.Request().Header.Get("Sec-CH-UA-Platform"),
			c.Request().Header.Get("Sec-CH-UA-Mobile"),
			c.Request().Header.Get("Sec-CH-UA-Model"))
		go core.Send2FAModifiedNotification(core.TwoFactorNotificationOptions{Email: userRecord.Email, Username: username, Action: "Added (Passkey)", IP: clientIP, Device: device})
	}

	return c.JSON(http.StatusOK, "Registration Success")
}

func (h *WebAuthnHandler) BeginLogin(c echo.Context) error {
	clientIP := c.RealIP()
	if !core.CheckRateLimit("login_access:"+core.RateLimitIP(clientIP), h.Cfg.RateLimitLoginAccessMax, h.Cfg.RateLimitLoginAccessDecay) {
		return echo.NewHTTPError(http.StatusTooManyRequests, fmt.Sprintf("Too many login attempts from this IP (%s)", clientIP))
	}

	username := c.QueryParam("username")
	var options *protocol.CredentialAssertion
	var sessionData *webauthn.SessionData
	var err error

	if username != "" {
		// Unknown accounts and accounts without passkeys get a dummy
		// credential, so the response does not reveal which case applies.
		user := core.DummyWebAuthnUser(username)
		if userRecord, getErr := core.GetUser(username); getErr == nil {
			if real := core.NewWebAuthnUser(userRecord); len(real.Credentials) > 0 {
				user = real
			}
		}
		options, sessionData, err = core.WebAuthnInstance.BeginLogin(user)
	} else {
		// Nameless login
		options, sessionData, err = core.WebAuthnInstance.BeginDiscoverableLogin()
	}

	if err != nil {
		slog.Error("WebAuthn BeginLogin failed", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start passkey login")
	}

	sessionJSON, _ := json.Marshal(sessionData)

	sessionID := core.GenerateRandomString(32)
	if sessionID == "" {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to generate session")
	}
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
	if !core.CheckRateLimit("login_ip:"+core.RateLimitIP(clientIP), h.Cfg.RateLimitLoginMax, h.Cfg.RateLimitLoginDecay) {
		return echo.NewHTTPError(http.StatusTooManyRequests, fmt.Sprintf("Too many login attempts from this IP (%s)", clientIP))
	}

	sessionData, err := h.getWebAuthnLoginSession(c)
	if err != nil {
		return err
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponse(c.Request())
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid assertion response")
	}

	username, userID, userRecord, err := h.identifyWebAuthnUser(c, parsedResponse)
	if err != nil {
		return err
	}

	// Read the generation before the credentials and stamp exactly that into
	// the session: a 2FA reset that deletes this passkey while the login runs
	// leaves the session stale instead of granting it the post-reset value.
	authGen, err := core.AuthGeneration(username)
	if err != nil {
		slog.Error("Failed to read auth generation at passkey login", "user", username, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create session")
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

	// With WEBAUTHN_USER_VERIFICATION=required a passkey login must prove user
	// verification (PIN/biometric), not just presence. A ceremony begun under
	// an older "preferred" configuration is upgraded so the library enforces
	// it on this assertion.
	if h.Cfg.WebAuthnRequireUserVerification {
		sessionData.UserVerification = protocol.VerificationRequired
	}

	credential, err := core.WebAuthnInstance.ValidateLogin(user, *sessionData, parsedResponse)
	if err != nil {
		slog.Error("WebAuthn validation failed", "error", err, "username", username)
		return echo.NewHTTPError(http.StatusUnauthorized, "Passkey validation failed")
	}

	// Check the UV flag of this assertion's signed authenticator data, not
	// credential.Flags.UserVerified: the library latches that flag once any
	// earlier login verified the user.
	if h.Cfg.WebAuthnRequireUserVerification && !parsedResponse.Response.AuthenticatorData.Flags.HasUserVerified() {
		slog.Warn("WebAuthn assertion without user verification rejected", "username", username)
		core.LogAudit("PASSKEY_UV_MISSING", username, clientIP, nil)
		return echo.NewHTTPError(http.StatusUnauthorized, "Passkey validation failed: user verification (PIN or biometric) is required")
	}

	// A non-increasing signature counter means the authenticator may have been
	// cloned. Refuse the login and record it rather than silently accepting.
	if credential.Authenticator.CloneWarning {
		slog.Warn("WebAuthn clone warning, rejecting login", "username", username)
		core.LogAudit("PASSKEY_CLONE_WARNING", username, clientIP, map[string]interface{}{"sign_count": credential.Authenticator.SignCount})
		return echo.NewHTTPError(http.StatusUnauthorized, "Passkey validation failed: possible cloned authenticator")
	}

	// Update the sign count. A credential that vanished during the login (a
	// revocation or 2FA reset) fails the login, as does a write error: the
	// clone check above relies on the stored count.
	if err := core.UpdateWebAuthnSignCount(username, credential.ID, credential.Authenticator.SignCount); err != nil {
		if errors.Is(err, core.ErrCredentialGone) {
			slog.Warn("Passkey removed during login, rejecting", "username", username)
			core.LogAudit("PASSKEY_REVOKED_DURING_LOGIN", username, clientIP, nil)
			return echo.NewHTTPError(http.StatusUnauthorized, "Passkey validation failed")
		}
		slog.Error("Failed to update WebAuthn sign count", "error", err, "username", username)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create session")
	}

	if err := h.issuePasskeyToken(c, username, userRecord, authGen); err != nil {
		return err
	}

	redirect := core.ValidateRedirectURL(c.QueryParam("rd"), "/rauthprofile", username, h.Cfg)

	return c.JSON(http.StatusOK, map[string]string{"redirect": redirect})
}

func (h *WebAuthnHandler) getWebAuthnLoginSession(c echo.Context) (*webauthn.SessionData, error) {
	cookie, err := c.Cookie("rauth_webauthn_session")
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "Session expired or invalid")
	}
	sessionID := cookie.Value
	redisKey := "webauthn_login_session:" + sessionID

	sessionJSON, err := core.TokenDB.Get(core.Ctx, redisKey).Result()
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "Session expired or invalid")
	}

	// Clean up session immediately after retrieval (one-time use)
	core.TokenDB.Del(core.Ctx, redisKey)

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionJSON), &sessionData); err != nil {
		return nil, echo.NewHTTPError(http.StatusInternalServerError, "Failed to parse session data")
	}
	return &sessionData, nil
}

func (h *WebAuthnHandler) identifyWebAuthnUser(c echo.Context, parsedResponse *protocol.ParsedCredentialAssertionData) (string, []byte, *core.User, error) {
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
		return "", nil, nil, echo.NewHTTPError(http.StatusBadRequest, "Could not identify user from passkey")
	}

	userRecord, err := core.GetUser(username)
	if err != nil {
		return "", nil, nil, echo.NewHTTPError(http.StatusBadRequest, "User not found")
	}

	// If the authenticator didn't provide a handle, use the record's UID
	if len(userID) == 0 {
		userID = []byte(userRecord.UID)
	}

	return username, userID, &userRecord, nil
}

// issuePasskeyToken creates the session for a verified passkey login. authGen
// is the generation read before the credentials were loaded.
func (h *WebAuthnHandler) issuePasskeyToken(c echo.Context, username string, userRecord *core.User, authGen string) error {
	clientIP := c.RealIP()
	ua := c.Request().UserAgent()
	token := core.GenerateRandomString(32)
	if token == "" {
		// RNG failure: never issue a session keyed on an empty token.
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to generate session token")
	}

	encryptedToken, encErr := core.EncryptToken(token, h.Cfg.ServerSecret)
	if encErr != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to encrypt token")
	}
	countryCode := core.GetCountryCode(clientIP)

	if !h.Cfg.IsCountryAllowed(countryCode) {
		slog.Warn("Passkey login attempt from blocked country", "country", countryCode, "ip", clientIP, "user", username)
		core.LogAudit("BLOCKED_COUNTRY_PASSKEY_LOGIN_ATTEMPT", username, clientIP, map[string]interface{}{"country": countryCode})
		return echo.NewHTTPError(http.StatusForbidden, "Access from your location is restricted")
	}

	// Stamp groups/is_admin, the auth generation and Client Hints into the
	// session so the forward-auth path (/rauthvalidate) forwards
	// X-RAuth-Groups/X-RAuth-Admin and the device check behaves identically to a
	// password login (see issueToken). The write is atomic: a session missing
	// from the revocation index must never be issued.
	tokenValidity := time.Duration(h.Cfg.TokenValidityMinutes) * time.Minute
	if err := core.StoreSession(token, username, clientIP, map[string]interface{}{
		"status":         "valid",
		"ip":             clientIP,
		"username":       username,
		"country":        countryCode,
		"groups":         userRecord.Groups,
		"is_admin":       userRecord.IsAdmin,
		"auth_gen":       authGen,
		"user_agent":     ua,
		"ua_ch_platform": c.Request().Header.Get("Sec-CH-UA-Platform"),
		"ua_ch_mobile":   c.Request().Header.Get("Sec-CH-UA-Mobile"),
		"ua_ch_model":    c.Request().Header.Get("Sec-CH-UA-Model"),
		"created_at":     time.Now().Unix(),
	}, tokenValidity); err != nil {
		slog.Error("Failed to store passkey session", "user", username, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create session")
	}

	cookie := &http.Cookie{
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
		device := core.FormatDevice(c.Request().UserAgent(),
			c.Request().Header.Get("Sec-CH-UA-Platform"),
			c.Request().Header.Get("Sec-CH-UA-Mobile"),
			c.Request().Header.Get("Sec-CH-UA-Model"))
		go core.SendLoginNotification(userRecord.Email, username, clientIP, countryCode, device)
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
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	return nil
}
