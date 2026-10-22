package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"rauth/internal/core"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type AuthHandler struct {
	Cfg *core.Config
}

// dummyBcryptHash is a valid bcrypt hash of a random value used to perform a
// constant-time comparison when no real user/credential exists, mitigating
// username-enumeration timing attacks. It is a var so tests can substitute a
// low-cost hash; production code never reassigns it.
var dummyBcryptHash = "$2a$12$WJlQ/t/NbjXzEfIi2P54vecljh4fSRxYOkWj5Kbs7hM0eZFmL/Nyq"

const (
	// pendingTokenBytes sizes the short-lived 2FA/setup pending tokens.
	pendingTokenBytes = 16
	// sessionTokenBytes sizes the long-lived authenticated session token.
	sessionTokenBytes = 32
)

// getRD returns the post-login redirect target from the URL. Login forms keep
// rd in their action query so rate-limit responses never need to parse a body.
func getRD(c echo.Context) string {
	return c.QueryParam("rd")
}

func (h *AuthHandler) Root(c echo.Context) error {
	cookie, err := c.Cookie("X-rauth-authtoken")
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	token, err := core.DecryptToken(cookie.Value, h.Cfg.ServerSecret)
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	// ⚡ Bolt optimization: Use HMGet instead of HGetAll since we only need the status field.
	vals, err := core.TokenDB.HMGet(core.Ctx, "X-rauth-authtoken="+token, "status").Result()
	if err != nil || len(vals) == 0 || vals[0] == nil || vals[0].(string) != "valid" {
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	return c.Redirect(http.StatusFound, "/rauthprofile")
}

func (h *AuthHandler) Validate(c echo.Context) error {
	clientIP := c.RealIP()
	rateLimitKey := "validate:" + clientIP

	cookie, err := c.Cookie("X-rauth-authtoken")
	if err != nil {
		return h.rateLimitedUnauthorized(c, rateLimitKey)
	}

	token, err := core.DecryptToken(cookie.Value, h.Cfg.ServerSecret)
	if err != nil || token == "" {
		return h.rateLimitedUnauthorized(c, rateLimitKey)
	}

	redisKey := "X-rauth-authtoken=" + token
	data, err := core.TokenDB.HGetAll(core.Ctx, redisKey).Result()
	if err != nil || len(data) == 0 || data["status"] != "valid" {
		return h.rateLimitedUnauthorized(c, rateLimitKey)
	}

	// Session is present: reset the per-IP validate throttle.
	core.ResetRateLimit(rateLimitKey)

	if !core.SessionBindingValid(h.Cfg, c.Request(), token, redisKey, data, clientIP) {
		return c.NoContent(http.StatusUnauthorized)
	}

	// Forward identity headers to upstreams via nginx auth_request. groups and
	// is_admin are stamped into the token at issue time (see issueToken).
	c.Response().Header().Set("X-RAuth-User", data["username"])
	c.Response().Header().Set("X-RAuth-Groups", data["groups"])
	isAdmin := data["is_admin"]
	if isAdmin == "" {
		isAdmin = "0"
	}
	c.Response().Header().Set("X-RAuth-Admin", isAdmin)

	// Refresh the session/cookie expiry when the client IP is unchanged.
	if data["ip"] == clientIP {
		validity := time.Duration(h.Cfg.TokenValidityMinutes) * time.Minute

		// Optional: Automatic Token Rotation
		// If rotation is enabled and the token is older than the threshold,
		// issue a new token and invalidate the old one.
		now := time.Now().Unix()
		createdAt, _ := strconv.ParseInt(data["created_at"], 10, 64)
		if h.Cfg.TokenRotationMinutes > 0 && now-createdAt > int64(h.Cfg.TokenRotationMinutes)*60 {
			newTokenBytes := make([]byte, sessionTokenBytes)
			if _, err := rand.Read(newTokenBytes); err == nil {
				newToken := hex.EncodeToString(newTokenBytes)
				newRedisKey := "X-rauth-authtoken=" + newToken

				// Copy data and update created_at to current time
				data["created_at"] = fmt.Sprintf("%d", now)
				if err := core.TokenDB.HSet(core.Ctx, newRedisKey, data).Err(); err == nil {
					core.TokenDB.Expire(core.Ctx, newRedisKey, validity)

					// Register new token in indexes
					core.AddSessionIndex(data["username"], newToken)
					core.AddIPSessionIndex(clientIP, newToken)

					// Set a short grace period for the old token to avoid race conditions
					core.TokenDB.Expire(core.Ctx, redisKey, 30*time.Second)

					// Encrypt new token for cookie
					if encrypted, err := core.EncryptToken(newToken, h.Cfg.ServerSecret); err == nil {
						cookie.Value = encrypted
						redisKey = newRedisKey
						slog.Debug("Session token rotated", "user", data["username"], "ip", clientIP)
					}
				}
			}
		}

		core.TokenDB.Expire(core.Ctx, redisKey, validity)
		c.SetCookie(&http.Cookie{
			Name:     "X-rauth-authtoken",
			Value:    cookie.Value,
			Path:     "/",
			Domain:   h.Cfg.CookieDomains[0],
			Expires:  time.Now().Add(validity),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
	}

	return c.NoContent(http.StatusOK)
}

// rateLimitedUnauthorized applies the validate rate limit and returns 429 once
// it is exceeded, otherwise 401. Used for every pre-authentication failure path.
func (h *AuthHandler) rateLimitedUnauthorized(c echo.Context, rateLimitKey string) error {
	if !core.CheckRateLimit(rateLimitKey, h.Cfg.RateLimitValidateMax, h.Cfg.RateLimitValidateDecay) {
		return c.NoContent(http.StatusTooManyRequests)
	}
	return c.NoContent(http.StatusUnauthorized)
}

func (h *AuthHandler) Login(c echo.Context) error {
	clientIP := c.RealIP()
	slog.Debug("Login attempt", "ip", clientIP, "method", c.Request().Method)

	// 1. Basic IP Throttling for ALL requests (GET/POST)
	// Fast-path read-only check to prevent large payload parsing if already throttled.
	if core.IsRateLimitExceeded("login_access:"+clientIP, h.Cfg.RateLimitLoginAccessMax) {
		slog.Warn("General login access rate limit exceeded (fast-path)", "ip", clientIP)
		return c.Render(http.StatusTooManyRequests, "login.html", map[string]interface{}{"error": "Too many requests. Please wait a minute.", "csrf": c.Get("csrf"), "rd": c.QueryParam("rd")})
	}

	// Delegate 2FA verification before consuming this handler's rate-limit
	// budget: Verify2FA applies the same IP throttles itself, so checking here
	// too would double-count every 2FA attempt submitted via the login form.
	if c.Request().Method == http.MethodPost && c.FormValue("action") == "verify_2fa" {
		return h.Verify2FA(c)
	}

	if !core.CheckRateLimit("login_access:"+clientIP, h.Cfg.RateLimitLoginAccessMax, h.Cfg.RateLimitLoginAccessDecay) {
		slog.Warn("General login access rate limit exceeded", "ip", clientIP)
		return c.Render(http.StatusTooManyRequests, "login.html", map[string]interface{}{"error": "Too many requests. Please wait a minute.", "csrf": c.Get("csrf"), "rd": getRD(c)})
	}

	if c.Request().Method == http.MethodGet {
		return c.Render(http.StatusOK, "login.html", map[string]interface{}{"csrf": c.Get("csrf"), "rd": getRD(c)})
	}

	// 2. Strict Throttling for POST (Authentication Attempts)
	if !core.CheckRateLimit("login_post_ip:"+clientIP, h.Cfg.RateLimitLoginMax, h.Cfg.RateLimitLoginDecay) {
		slog.Warn("Login POST rate limit exceeded", "ip", clientIP)
		return c.Render(http.StatusTooManyRequests, "login.html", map[string]interface{}{"error": fmt.Sprintf("Too many login attempts from this IP (%s).", clientIP), "csrf": c.Get("csrf"), "rd": getRD(c)})
	}

	username := strings.TrimSpace(c.FormValue("username"))

	// 3. Per-User Throttling
	if throttled, err := h.checkUserThrottling(c, username); throttled {
		return err
	}

	password := c.FormValue("password")
	userRecord, valid := h.verifyCredentials(username, password)

	if !valid {
		return h.handleAuthFailure(c, username)
	}

	// Success! Reset the per-user penalty for this account only. IP-scoped
	// counters are deliberately left alone: resetting them on success would let
	// an attacker holding any valid account clear their own throttle.
	core.ResetRateLimit("login_fail_user:" + username)

	// Check if 2FA is enabled
	if userRecord.TwoFactor != "" {
		return h.initiate2FASession(c, username)
	}

	// Force 2FA Setup for new users (or users without 2FA)
	return h.initiate2FASetupSession(c, username)
}

func (h *AuthHandler) checkUserThrottling(c echo.Context, username string) (bool, error) {
	clientIP := c.RealIP()
	if username != "" && core.IsRateLimitExceeded("login_fail_user:"+username, h.Cfg.RateLimitLoginFailUserMax) {
		slog.Warn("Login user rate limit exceeded", "username", username, "ip", clientIP)
		// We still do the password check work to prevent timing attacks, but we will return 429
		core.CheckPasswordHash("dummy", dummyBcryptHash)
		return true, c.Render(http.StatusTooManyRequests, "login.html", map[string]interface{}{"error": "This account is temporarily locked due to too many failed attempts.", "csrf": c.Get("csrf"), "rd": getRD(c)})
	}
	return false, nil
}

// natFailureToleranceFactor raises the cross-user IP failure limit for IPs
// that already hold a valid session (e.g. an office behind one NAT address),
// instead of exempting them entirely.
const natFailureToleranceFactor = 4

// checkIPFailureLimit records a failed authentication attempt against the
// client IP and reports whether the IP is still within its failure budget.
func (h *AuthHandler) checkIPFailureLimit(clientIP string) bool {
	limit := h.Cfg.RateLimitLoginFailIPMax
	if core.HasActiveSessions(clientIP) {
		limit *= natFailureToleranceFactor
	}
	return core.CheckRateLimit("login_fail_ip:"+clientIP, limit, h.Cfg.RateLimitLoginFailIPDecay)
}

func (h *AuthHandler) verifyCredentials(username, password string) (*core.User, bool) {
	userRecord, err := core.GetUser(username)

	// Constant time password check to prevent username enumeration
	var valid bool
	if err == nil {
		valid = core.CheckPasswordHash(password, userRecord.Password)
	} else {
		// Dummy hash to simulate work
		core.CheckPasswordHash(password, dummyBcryptHash)
		valid = false
	}

	if !valid {
		return nil, false
	}
	return &userRecord, true
}

func (h *AuthHandler) handleAuthFailure(c echo.Context, username string) error {
	clientIP := c.RealIP()
	h.logLoginFailed(username, clientIP)
	core.LoginFailedTotal.Inc()

	if username != "" {
		core.CheckRateLimit("login_fail_user:"+username, h.Cfg.RateLimitLoginFailUserMax, h.Cfg.RateLimitLoginFailUserDecay)
	}

	// 4. Track FAILED attempts from IP across different users
	if !h.checkIPFailureLimit(clientIP) {
		slog.Warn("Global IP failure rate limit exceeded", "ip", clientIP)
		return c.Render(http.StatusTooManyRequests, "login.html", map[string]interface{}{"error": "Too many failed attempts from your network. Please try again later.", "csrf": c.Get("csrf"), "rd": getRD(c)})
	}

	return c.Render(http.StatusOK, "login.html", map[string]interface{}{"error": "Invalid credentials", "csrf": c.Get("csrf"), "rd": getRD(c)})
}

// logLoginFailed audits a failed password login. The submitted username is
// attacker-controlled, so it is only used as the audit owner (which creates a
// per-user audit list) when it names an existing account; otherwise the entry
// goes to the global log only, with the name included solely if well-formed.
func (h *AuthHandler) logLoginFailed(username, clientIP string) {
	if core.ValidateUsername(username) != nil {
		core.LogAudit("LOGIN_FAILED", "", clientIP, map[string]interface{}{"attempted_username": "(invalid)"})
		return
	}
	if exists, err := core.UserDB.Exists(core.Ctx, "user:"+username).Result(); err != nil || exists == 0 {
		core.LogAudit("LOGIN_FAILED", "", clientIP, map[string]interface{}{"attempted_username": username})
		return
	}
	core.LogAudit("LOGIN_FAILED", username, clientIP, nil)
}

func (h *AuthHandler) initiate2FASession(c echo.Context, username string) error {
	tempToken := h.issueTempToken(username)
	encrypted, _ := core.EncryptToken(tempToken, h.Cfg.ServerSecret)
	cookie := &http.Cookie{
		Name:     "rauth_2fa_pending",
		Value:    encrypted,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(5 * time.Minute),
	}
	c.SetCookie(cookie)
	return c.Render(http.StatusOK, "login.html", map[string]interface{}{
		"display2fa": true,
		"username":   username,
		"csrf":       c.Get("csrf"),
		"rd":         getRD(c),
	})
}

func (h *AuthHandler) initiate2FASetupSession(c echo.Context, username string) error {
	setupToken := h.issueSetupToken(username)
	encrypted, _ := core.EncryptToken(setupToken, h.Cfg.ServerSecret)
	c.SetCookie(&http.Cookie{
		Name:     "rauth_setup_pending",
		Value:    encrypted,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(10 * time.Minute),
	})

	redirectURL := "/rauthsetup2fa"
	if rd := getRD(c); rd != "" {
		redirectURL += "?rd=" + url.QueryEscape(rd)
	}
	return c.Redirect(http.StatusFound, redirectURL)
}

func (h *AuthHandler) checkLoginIPRateLimits(c echo.Context, clientIP, template string, extraContext map[string]interface{}) error {
	if core.IsRateLimitExceeded("login_access:"+clientIP, h.Cfg.RateLimitLoginAccessMax) {
		ctx := map[string]interface{}{"error": "Too many requests. Please wait a minute.", "csrf": c.Get("csrf"), "rd": c.QueryParam("rd")}
		for k, v := range extraContext {
			ctx[k] = v
		}
		return c.Render(http.StatusTooManyRequests, template, ctx)
	}
	if !core.CheckRateLimit("login_access:"+clientIP, h.Cfg.RateLimitLoginAccessMax, h.Cfg.RateLimitLoginAccessDecay) {
		ctx := map[string]interface{}{"error": "Too many requests. Please wait a minute.", "csrf": c.Get("csrf"), "rd": getRD(c)}
		for k, v := range extraContext {
			ctx[k] = v
		}
		return c.Render(http.StatusTooManyRequests, template, ctx)
	}
	if !core.CheckRateLimit("login_post_ip:"+clientIP, h.Cfg.RateLimitLoginMax, h.Cfg.RateLimitLoginDecay) {
		ctx := map[string]interface{}{"error": fmt.Sprintf("Too many attempts from this IP (%s). Please try again later.", clientIP), "csrf": c.Get("csrf"), "rd": getRD(c)}
		for k, v := range extraContext {
			ctx[k] = v
		}
		return c.Render(http.StatusTooManyRequests, template, ctx)
	}
	return nil
}

func (h *AuthHandler) validatePendingToken(c echo.Context, cookieName, prefix string) (string, string, error) {
	cookie, err := c.Cookie(cookieName)
	if err != nil {
		return "", "", err
	}
	token, err := core.DecryptToken(cookie.Value, h.Cfg.ServerSecret)
	if err != nil {
		return "", "", err
	}
	username, err := core.TokenDB.Get(core.Ctx, prefix+":"+token).Result()
	if err != nil {
		return "", "", err
	}
	return username, token, nil
}

func (h *AuthHandler) handle2FASuccess(c echo.Context, username, clientIP, pendingToken string, usedRecovery bool, userRecord *core.User) error {
	core.TokenDB.Del(core.Ctx, "pending_2fa:"+pendingToken)
	c.SetCookie(&http.Cookie{
		Name:     "rauth_2fa_pending",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	core.ResetRateLimit("login_fail_user:" + username)
	core.ResetRateLimit("2fa_fail_user:" + username)

	if usedRecovery {
		core.RecoveryCodeUsedTotal.Inc()
		remaining := core.CountRecoveryCodes(username)
		core.LogAudit("2FA_RECOVERY_CODE_USED", username, clientIP, map[string]interface{}{"remaining": remaining})
		if userRecord.Email != "" {
			device := core.FormatDevice(c.Request().UserAgent(),
				c.Request().Header.Get("Sec-CH-UA-Platform"),
				c.Request().Header.Get("Sec-CH-UA-Mobile"),
				c.Request().Header.Get("Sec-CH-UA-Model"))
			go core.Send2FAModifiedNotification(core.TwoFactorNotificationOptions{Email: userRecord.Email, Username: username, Action: fmt.Sprintf("Recovery code used (%d remaining)", remaining), IP: clientIP, Device: device})
		}
	}

	return h.issueToken(c, username)
}

func (h *AuthHandler) handle2FAFailure(c echo.Context, username, clientIP string) error {
	core.LogAudit("2FA_FAILED", username, clientIP, nil)
	core.CheckRateLimit("2fa_fail_user:"+username, h.Cfg.RateLimitLoginFailUserMax, h.Cfg.RateLimitLoginFailUserDecay)

	if !h.checkIPFailureLimit(clientIP) {
		return c.Render(http.StatusTooManyRequests, "login.html", map[string]interface{}{"error": "Too many failed attempts. Please try again later.", "csrf": c.Get("csrf"), "display2fa": true, "rd": getRD(c)})
	}

	return c.Render(http.StatusOK, "login.html", map[string]interface{}{
		"display2fa": true,
		"error":      "Invalid 2FA code",
		"csrf":       c.Get("csrf"),
		"rd":         getRD(c),
	})
}

func (h *AuthHandler) Verify2FA(c echo.Context) error {
	clientIP := c.RealIP()
	if err := h.checkLoginIPRateLimits(c, clientIP, "login.html", map[string]interface{}{"display2fa": true}); err != nil {
		return err
	}

	code := c.FormValue("totp_code")
	username, pendingToken, err := h.validatePendingToken(c, "rauth_2fa_pending", "pending_2fa")
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	userRecord, _ := core.GetUser(username)
	if userRecord.TwoFactor == "" {
		core.TokenDB.Del(core.Ctx, "pending_2fa:"+pendingToken)
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	if core.IsRateLimitExceeded("2fa_fail_user:"+username, h.Cfg.RateLimitLoginFailUserMax) {
		return c.Render(http.StatusTooManyRequests, "login.html", map[string]interface{}{"error": "Too many failed attempts. Please try again later.", "csrf": c.Get("csrf"), "display2fa": true, "rd": c.QueryParam("rd")})
	}

	// An unreadable stored secret disables TOTP validation (fail closed) but
	// still lets the independent recovery-code check below run.
	secret := core.Decrypt2FASecret(userRecord.TwoFactor, h.Cfg.ServerSecret)
	totpOK := secret != "" && totp.Validate(code, secret)
	if totpOK && core.TOTPCodeReused(username, code) {
		core.LogAudit("2FA_REPLAY_BLOCKED", username, clientIP, nil)
		return c.Render(http.StatusUnauthorized, "login.html", map[string]interface{}{
			"display2fa": true,
			"error":      "Invalid 2FA code",
			"csrf":       c.Get("csrf"),
			"rd":         getRD(c),
		})
	}

	usedRecovery := false
	if !totpOK {
		usedRecovery = core.ConsumeRecoveryCode(username, code)
	}

	if totpOK || usedRecovery {
		return h.handle2FASuccess(c, username, clientIP, pendingToken, usedRecovery, &userRecord)
	}

	return h.handle2FAFailure(c, username, clientIP)
}

func (h *AuthHandler) Setup2FA(c echo.Context) error {
	username, setupToken, err := h.validatePendingToken(c, "rauth_setup_pending", "pending_setup")
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	// Generate a new 2FA key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "RAuth",
		AccountName: username,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		slog.Error("Failed to generate 2FA key", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal Server Error")
	}

	// Store secret temporarily
	core.TokenDB.Set(core.Ctx, "pending_setup_secret:"+setupToken, key.Secret(), 5*time.Minute)

	return c.Render(http.StatusOK, "setup_2fa.html", map[string]interface{}{
		"secret": key.Secret(),
		"csrf":   c.Get("csrf"),
		"rd":     getRD(c),
	})
}

func (h *AuthHandler) CompleteSetup2FA(c echo.Context) error {
	clientIP := c.RealIP()
	if err := h.checkLoginIPRateLimits(c, clientIP, "setup_2fa.html", map[string]interface{}{}); err != nil {
		return err
	}

	username, setupToken, err := h.validatePendingToken(c, "rauth_setup_pending", "pending_setup")
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	secret, err := core.TokenDB.Get(core.Ctx, "pending_setup_secret:"+setupToken).Result()
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthsetup2fa")
	}

	if core.IsRateLimitExceeded("2fa_fail_user:"+username, h.Cfg.RateLimitLoginFailUserMax) {
		return c.Render(http.StatusTooManyRequests, "setup_2fa.html", map[string]interface{}{"error": "Too many failed attempts. Please try again later.", "csrf": c.Get("csrf"), "rd": c.QueryParam("rd")})
	}

	code := c.FormValue("totp_code")
	// Verify the code against the temporary secret
	if totp.Validate(code, secret) {
		// Save to user profile (encrypted)
		encryptedSecret, err := core.Encrypt2FASecret(secret, h.Cfg.ServerSecret)
		if err != nil {
			slog.Error("Failed to encrypt 2FA secret", "error", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Internal Server Error")
		}
		err = core.UserDB.HSet(core.Ctx, "user:"+username, "2fa_secret", encryptedSecret).Err()
		if err != nil {
			slog.Error("Failed to save 2FA secret", "error", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Database Error")
		}

		// Cleanup
		core.TokenDB.Del(core.Ctx, "pending_setup:"+setupToken)
		core.TokenDB.Del(core.Ctx, "pending_setup_secret:"+setupToken)
		c.SetCookie(&http.Cookie{
			Name:     "rauth_setup_pending",
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})

		// Send notification email
		userRecord, _ := core.GetUser(username)
		if userRecord.Email != "" {
			device := core.FormatDevice(c.Request().UserAgent(),
				c.Request().Header.Get("Sec-CH-UA-Platform"),
				c.Request().Header.Get("Sec-CH-UA-Mobile"),
				c.Request().Header.Get("Sec-CH-UA-Model"))
			go core.Send2FAModifiedNotification(core.TwoFactorNotificationOptions{Email: userRecord.Email, Username: username, Action: "Enabled", IP: clientIP, Device: device})
		}

		core.ResetRateLimit("login_fail_user:" + username)
		core.ResetRateLimit("2fa_fail_user:" + username)
		core.LogAudit("2FA_SETUP_SUCCESS", username, clientIP, nil)
		return h.issueToken(c, username)
	}

	// Penalize failed setup attempts
	core.CheckRateLimit("2fa_fail_user:"+username, h.Cfg.RateLimitLoginFailUserMax, h.Cfg.RateLimitLoginFailUserDecay)

	if !h.checkIPFailureLimit(clientIP) {
		return c.Render(http.StatusTooManyRequests, "setup_2fa.html", map[string]interface{}{"error": "Too many failed attempts. Please try again later.", "csrf": c.Get("csrf"), "rd": getRD(c)})
	}

	return c.Render(http.StatusOK, "setup_2fa.html", map[string]interface{}{
		"secret": secret,
		"error":  "Invalid code. Please try again.",
		"csrf":   c.Get("csrf"),
		"rd":     getRD(c),
	})
}

func (h *AuthHandler) issueTempToken(username string) string {
	b := make([]byte, pendingTokenBytes)
	if _, err := rand.Read(b); err != nil {
		slog.Error("Failed to generate random temp token", "error", err)
		return ""
	}
	token := hex.EncodeToString(b)
	core.TokenDB.Set(core.Ctx, "pending_2fa:"+token, username, 5*time.Minute)
	return token
}

func (h *AuthHandler) issueSetupToken(username string) string {
	b := make([]byte, pendingTokenBytes)
	if _, err := rand.Read(b); err != nil {
		slog.Error("Failed to generate random setup token", "error", err)
		return ""
	}
	token := hex.EncodeToString(b)
	core.TokenDB.Set(core.Ctx, "pending_setup:"+token, username, 10*time.Minute)
	return token
}

func (h *AuthHandler) issueToken(c echo.Context, username string) error {
	tokenBytes := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(tokenBytes); err != nil {
		slog.Error("Failed to generate random token", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal Server Error")
	}
	token := hex.EncodeToString(tokenBytes)

	encrypted, err := core.EncryptToken(token, h.Cfg.ServerSecret)
	if err != nil {
		slog.Error("Token encryption failed", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal Server Error")
	}
	clientIP := c.RealIP()
	country := core.GetCountryCode(clientIP)

	if !h.Cfg.IsCountryAllowed(country) {
		slog.Warn("Login attempt from blocked country", "country", country, "ip", clientIP, "user", username)
		core.LogAudit("BLOCKED_COUNTRY_LOGIN_ATTEMPT", username, clientIP, map[string]interface{}{"country": country})
		return echo.NewHTTPError(http.StatusForbidden, "Access from your location is restricted")
	}

	// Fetch the user up-front so groups/admin status are stamped into the
	// session token. The forward-auth (/rauthvalidate) and AuthMiddleware then
	// forward X-RAuth-Groups / X-RAuth-Admin without an extra Redis lookup.
	userRecord, err := core.GetUser(username)
	if err != nil {
		// Don't issue a session with empty groups/is_admin on a transient read
		// failure: that would silently downgrade the user's authorization. The
		// caller has already authenticated, so fail closed.
		slog.Error("Failed to load user record at token issue", "user", username, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal Server Error")
	}

	redisKey := "X-rauth-authtoken=" + token
	err = core.TokenDB.HSet(core.Ctx, redisKey, map[string]interface{}{
		"status":         "valid",
		"ip":             clientIP,
		"username":       username,
		"country":        country,
		"groups":         userRecord.Groups,
		"is_admin":       userRecord.IsAdmin,
		"user_agent":     c.Request().UserAgent(),
		"ua_ch_platform": c.Request().Header.Get("Sec-CH-UA-Platform"),
		"ua_ch_mobile":   c.Request().Header.Get("Sec-CH-UA-Mobile"),
		"ua_ch_model":    c.Request().Header.Get("Sec-CH-UA-Model"),
		"created_at":     time.Now().Unix(),
	}).Err()
	if err == nil {
		core.AddSessionIndex(username, token)
		core.AddIPSessionIndex(clientIP, token)
	}
	if err != nil {
		slog.Error("Failed to store token in Redis", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal Server Error")
	}

	validity := time.Duration(h.Cfg.TokenValidityMinutes) * time.Minute
	core.TokenDB.Expire(core.Ctx, redisKey, validity)

	// Send Login Notification Email (Asynchronous)
	if userRecord.Email != "" {
		device := core.FormatDevice(c.Request().UserAgent(),
			c.Request().Header.Get("Sec-CH-UA-Platform"),
			c.Request().Header.Get("Sec-CH-UA-Mobile"),
			c.Request().Header.Get("Sec-CH-UA-Model"))
		go core.SendLoginNotification(userRecord.Email, username, clientIP, country, device)
	}

	cookie := &http.Cookie{
		Name:     "X-rauth-authtoken",
		Value:    encrypted,
		Path:     "/",
		Domain:   h.Cfg.CookieDomains[0],
		Expires:  time.Now().Add(validity),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	c.SetCookie(cookie)

	core.LogAudit("LOGIN_SUCCESS", username, clientIP, map[string]interface{}{"country": country})
	core.LoginSuccessTotal.Inc()

	// Reset the per-user penalty on success. IP-scoped counters are not reset
	// so a successful login cannot be used to clear an IP's failure budget.
	core.ResetRateLimit("login_fail_user:" + username)

	redirect := core.ValidateRedirectURL(getRD(c), "/rauthprofile", username, h.Cfg)
	return c.Redirect(http.StatusFound, redirect)
}
