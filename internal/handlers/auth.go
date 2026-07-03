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

// getRD returns the post-login redirect target, accepting it from either the
// query string or a form field so it survives the multi-step 2FA flow.
func getRD(c echo.Context) string {
	if rd := c.QueryParam("rd"); rd != "" {
		return rd
	}
	return c.FormValue("rd")
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

	if !h.sessionGeoAllowed(token, redisKey, data, clientIP) {
		return c.NoContent(http.StatusUnauthorized)
	}

	if !h.sessionUAMatches(c, token, redisKey, data, clientIP) {
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

// invalidateSession removes a session token and both its user and per-IP index
// entries, so HasActiveSessions does not keep seeing a stale ip_sessions entry.
func (h *AuthHandler) invalidateSession(token, redisKey, username, clientIP string) {
	core.RemoveSessionIndex(username, token)
	core.RemoveIPSessionIndex(clientIP, token)
	core.TokenDB.Del(core.Ctx, redisKey)
}

// sessionGeoAllowed enforces the geo-fence: it blocks access from disallowed
// countries and invalidates a session whose origin country has changed.
// On any violation it invalidates the session and returns false.
func (h *AuthHandler) sessionGeoAllowed(token, redisKey string, data map[string]string, clientIP string) bool {
	currentCountry := core.GetCountryCode(clientIP)

	if !h.Cfg.IsCountryAllowed(currentCountry) {
		slog.Warn("Access from blocked country", "country", currentCountry, "ip", clientIP)
		core.LogAudit("BLOCKED_COUNTRY_ACCESS", data["username"], clientIP, map[string]interface{}{"country": currentCountry})
		h.invalidateSession(token, redisKey, data["username"], clientIP)
		return false
	}

	if data["country"] != "unknown" && currentCountry != "unknown" && data["country"] != currentCountry {
		details := map[string]interface{}{"old": data["country"], "new": currentCountry, "current_ip": clientIP}

		// In lenient mode, tolerate the change (still inside the allowlist) and
		// update the stored country so it is not repeatedly flagged. This avoids
		// spurious logouts for roaming/VPN/CGNAT users.
		if h.Cfg.GeoChangeMode == "lenient" {
			core.LogAudit("COUNTRY_CHANGE_TOLERATED", data["username"], clientIP, details)
			core.TokenDB.HSet(core.Ctx, redisKey, "country", currentCountry)
			return true
		}

		core.LogAudit("COUNTRY_CHANGE_DETECTED", data["username"], clientIP, details)
		h.invalidateSession(token, redisKey, data["username"], clientIP)
		return false
	}

	return true
}

// sessionUAMatches runs the dual-layer device check (User-Agent Client Hints
// with a lenient User-Agent parser fallback). On a mismatch it invalidates the
// session and returns false.
func (h *AuthHandler) sessionUAMatches(c echo.Context, token, redisKey string, data map[string]string, clientIP string) bool {
	chPlatform := c.Request().Header.Get("Sec-CH-UA-Platform")
	chMobile := c.Request().Header.Get("Sec-CH-UA-Mobile")
	chModel := c.Request().Header.Get("Sec-CH-UA-Model")

	storedPlatform := data["ua_ch_platform"]
	storedMobile := data["ua_ch_mobile"]
	storedModel := data["ua_ch_model"]

	normalizeCH := func(val string) string { return strings.Trim(val, `"`) }

	uaIsValid := true
	useClientHints := false

	// If session HAS Hints, we enforce binding if the current request also HAS Hints.
	// If the current request has NO hints but the session DOES, we fall back to UA matching
	// unless we want to be extremely strict (which might break on proxy header stripping).
	//
	// A hint is only compared when it is present on BOTH the stored session and the
	// current request. A hint that is absent on the current request is NOT a mismatch:
	// high-entropy hints (notably Sec-CH-UA-Model) are delivered inconsistently. They are
	// sent to rauth's own origin at login (it advertises Accept-CH/Critical-CH), but the
	// /rauthvalidate auth_request subrequest carries the headers the client sent to the
	// protected app, which usually does not request Client Hints. Treating the missing
	// model hint as a mismatch invalidated every mobile session on the next validation
	// (e.g. stored model "SM-S921B" vs an empty current model), causing a login loop.
	if storedPlatform != "" || storedMobile != "" || storedModel != "" {
		if chPlatform != "" || chMobile != "" || chModel != "" {
			useClientHints = true
			if storedPlatform != "" && chPlatform != "" && normalizeCH(storedPlatform) != normalizeCH(chPlatform) {
				uaIsValid = false
			}
			if uaIsValid && storedMobile != "" && chMobile != "" && normalizeCH(storedMobile) != normalizeCH(chMobile) {
				uaIsValid = false
			}
			if uaIsValid && storedModel != "" && chModel != "" && normalizeCH(storedModel) != normalizeCH(chModel) {
				uaIsValid = false
			}
		}
	}

	if !useClientHints {
		// Fallback to lenient User-Agent parser matching.
		uaIsValid = core.IsUserAgentCompatible(data["user_agent"], c.Request().UserAgent())
	}

	if uaIsValid {
		return true
	}

	details := map[string]interface{}{
		"use_ch":              useClientHints,
		"stored_ua":           data["user_agent"],
		"current_ua":          c.Request().UserAgent(),
		"stored_ch_platform":  storedPlatform,
		"current_ch_platform": chPlatform,
		"stored_ch_model":     storedModel,
		"current_ch_model":    chModel,
	}
	slog.Warn("Session validation failed due to User-Agent/Client-Hint mismatch, invalidating session",
		"username", data["username"], "use_ch", useClientHints,
		"stored_ua", data["user_agent"], "current_ua", c.Request().UserAgent(),
		"stored_ch_platform", storedPlatform, "current_ch_platform", chPlatform,
		"stored_ch_model", storedModel, "current_ch_model", chModel,
	)
	core.LogAudit("USER_AGENT_MISMATCH_INVALIDATED", data["username"], clientIP, details)
	h.invalidateSession(token, redisKey, data["username"], clientIP)
	return false
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

	// Success! Reset per-user penalties
	core.ResetRateLimit("login_fail_user:" + username)
	core.ResetRateLimit("login_post_ip:" + clientIP)

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
	core.LogAudit("LOGIN_FAILED", username, clientIP, nil)
	core.LoginFailedTotal.Inc()

	if username != "" {
		core.CheckRateLimit("login_fail_user:"+username, h.Cfg.RateLimitLoginFailUserMax, h.Cfg.RateLimitLoginFailUserDecay)
	}

	// 4. Track FAILED attempts from IP across different users
	if !core.HasActiveSessions(clientIP) {
		if !core.CheckRateLimit("login_fail_ip:"+clientIP, h.Cfg.RateLimitLoginFailIPMax, h.Cfg.RateLimitLoginFailIPDecay) {
			slog.Warn("Global IP failure rate limit exceeded", "ip", clientIP)
			return c.Render(http.StatusTooManyRequests, "login.html", map[string]interface{}{"error": "Too many failed attempts from your network. Please try again later.", "csrf": c.Get("csrf"), "rd": getRD(c)})
		}
	}

	return c.Render(http.StatusOK, "login.html", map[string]interface{}{"error": "Invalid credentials", "csrf": c.Get("csrf"), "rd": getRD(c)})
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

	core.ResetRateLimit("login_post_ip:" + clientIP)
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

	if !core.HasActiveSessions(clientIP) {
		if !core.CheckRateLimit("login_fail_ip:"+clientIP, h.Cfg.RateLimitLoginFailIPMax, h.Cfg.RateLimitLoginFailIPDecay) {
			return c.Render(http.StatusTooManyRequests, "login.html", map[string]interface{}{"error": "Too many failed attempts. Please try again later.", "csrf": c.Get("csrf"), "display2fa": true, "rd": getRD(c)})
		}
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
	secret := core.Decrypt2FASecret(userRecord.TwoFactor, h.Cfg.ServerSecret)

	if secret == "" {
		core.TokenDB.Del(core.Ctx, "pending_2fa:"+pendingToken)
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	if core.IsRateLimitExceeded("2fa_fail_user:"+username, h.Cfg.RateLimitLoginFailUserMax) {
		return c.Render(http.StatusTooManyRequests, "login.html", map[string]interface{}{"error": "Too many failed attempts. Please try again later.", "csrf": c.Get("csrf"), "display2fa": true, "rd": c.QueryParam("rd")})
	}

	totpOK := totp.Validate(code, secret)
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
		encryptedSecret := core.Encrypt2FASecret(secret, h.Cfg.ServerSecret)
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

		core.ResetRateLimit("login_post_ip:" + clientIP)
		core.ResetRateLimit("login_fail_user:" + username)
		core.ResetRateLimit("2fa_fail_user:" + username)
		core.LogAudit("2FA_SETUP_SUCCESS", username, clientIP, nil)
		return h.issueToken(c, username)
	}

	// Penalize failed setup attempts
	core.CheckRateLimit("2fa_fail_user:"+username, h.Cfg.RateLimitLoginFailUserMax, h.Cfg.RateLimitLoginFailUserDecay)

	if !core.HasActiveSessions(clientIP) {
		if !core.CheckRateLimit("login_fail_ip:"+clientIP, h.Cfg.RateLimitLoginFailIPMax, h.Cfg.RateLimitLoginFailIPDecay) {
			return c.Render(http.StatusTooManyRequests, "setup_2fa.html", map[string]interface{}{"error": "Too many failed attempts. Please try again later.", "csrf": c.Get("csrf"), "rd": getRD(c)})
		}
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

	// Reset all relevant rate limits on success
	core.ResetRateLimit("login_post_ip:" + clientIP)
	core.ResetRateLimit("login_fail_user:" + username)
	core.ResetRateLimit("login_fail_ip:" + clientIP)

	redirect := core.ValidateRedirectURL(getRD(c), "/rauthprofile", username, h.Cfg)
	return c.Redirect(http.StatusFound, redirect)
}
