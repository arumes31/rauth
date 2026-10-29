package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
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
	rateLimitKey := "validate:" + core.RateLimitIP(clientIP)

	cookie, err := c.Cookie("X-rauth-authtoken")
	if err != nil {
		return h.denyOrBypass(c, rateLimitKey, true)
	}

	token, err := core.DecryptToken(cookie.Value, h.Cfg.ServerSecret)
	if err != nil || token == "" {
		return h.denyOrBypass(c, rateLimitKey, true)
	}

	redisKey := "X-rauth-authtoken=" + token
	data, err := core.TokenDB.HGetAll(core.Ctx, redisKey).Result()
	if err != nil || len(data) == 0 || data["status"] != "valid" {
		return h.denyOrBypass(c, rateLimitKey, true)
	}

	// Reject sessions of deleted accounts or ones issued before the user's last
	// credential change (see core.BumpAuthGeneration). The session is left to
	// expire rather than deleted: SessionAuthorized also fails closed on a
	// transient Redis error, which must not destroy a valid session.
	if !core.SessionAuthorized(data) {
		return h.denyOrBypass(c, rateLimitKey, true)
	}

	// Session is present: reset the per-IP validate throttle.
	core.ResetRateLimit(rateLimitKey)

	if !core.SessionBindingValid(h.Cfg, c.Request(), token, redisKey, data, clientIP) {
		return h.denyOrBypass(c, rateLimitKey, false)
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

	// A token already rotated away is in its grace period: point the client at
	// its successor instead of refreshing or rotating it again, so a replayed
	// old cookie can neither keep itself alive nor fork new sessions.
	if successor := data["rotated_to"]; successor != "" {
		if data["ip"] == clientIP {
			if encrypted, err := core.EncryptToken(successor, h.Cfg.ServerSecret); err == nil {
				h.setSessionCookie(c, encrypted, time.Duration(h.Cfg.TokenValidityMinutes)*time.Minute)
			}
		}
		return c.NoContent(http.StatusOK)
	}

	// Refresh the session/cookie expiry when the client IP is unchanged.
	if data["ip"] == clientIP {
		validity := time.Duration(h.Cfg.TokenValidityMinutes) * time.Minute

		// Optional: Automatic Token Rotation
		// If rotation is enabled and the token is older than the threshold,
		// issue a new token and retire the old one.
		now := time.Now().Unix()
		createdAt, _ := strconv.ParseInt(data["created_at"], 10, 64)
		if h.Cfg.TokenRotationMinutes > 0 && now-createdAt > int64(h.Cfg.TokenRotationMinutes)*60 {
			newToken, ok := h.rotateSession(token, data["username"], clientIP, now, validity)
			if !ok {
				// Another request rotated it first, it was terminated meanwhile,
				// or Redis failed: leave the old token as it is. Refreshing it
				// would undo a retirement that happened after the read above.
				return c.NoContent(http.StatusOK)
			}
			if encrypted, err := core.EncryptToken(newToken, h.Cfg.ServerSecret); err == nil {
				cookie.Value = encrypted
				token = newToken
				slog.Debug("Session token rotated", "user", data["username"], "ip", clientIP)
			}
		}

		core.RefreshSession(token, validity)
		h.setSessionCookie(c, cookie.Value, validity)
	}

	return c.NoContent(http.StatusOK)
}

// rotationGrace is how long a rotated-away token keeps resolving to its
// successor, covering concurrent auth_request subrequests at the rotation moment.
const rotationGrace = 30 * time.Second

// rotateSession copies the session to a new token and retires the old one: the
// old hash records its successor (so it is never rotated or refreshed again)
// and expires after rotationGrace. Both happen in one Redis script that also
// requires the old session to still exist and not be rotated yet. It reports
// the new token on success.
func (h *AuthHandler) rotateSession(oldToken, username, clientIP string, now int64, validity time.Duration) (string, bool) {
	newTokenBytes := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(newTokenBytes); err != nil {
		return "", false
	}
	newToken := hex.EncodeToString(newTokenBytes)

	rotated, err := core.RotateSession(oldToken, newToken, username, clientIP, now, validity, rotationGrace)
	if err != nil {
		slog.Error("Failed to rotate session", "user", username, "error", err)
		return "", false
	}
	return newToken, rotated
}

// setSessionCookie writes the domain-wide session cookie.
func (h *AuthHandler) setSessionCookie(c echo.Context, value string, validity time.Duration) {
	writeSessionCookie(c, h.Cfg, value, validity)
}

// writeSessionCookie writes the domain-wide session cookie.
func writeSessionCookie(c echo.Context, cfg *core.Config, value string, validity time.Duration) {
	c.SetCookie(&http.Cookie{
		Name:     "X-rauth-authtoken",
		Value:    value,
		Path:     "/",
		Domain:   cfg.CookieDomains[0],
		Expires:  time.Now().Add(validity),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// denyOrBypass is used for every path where /rauthvalidate would reject the
// request. If an auth bypass rule matches the originally requested host and
// URI, the request is allowed anonymously instead (200 with empty identity
// headers); otherwise it is rejected, optionally through the validate rate limit.
func (h *AuthHandler) denyOrBypass(c echo.Context, rateLimitKey string, rateLimit bool) error {
	if rule, ok := h.matchBypass(c); ok {
		core.AuthBypassTotal.Inc()
		slog.Debug("Forward-auth request allowed by bypass rule", "rule", rule.Rule, "ip", c.RealIP())
		hdr := c.Response().Header()
		hdr.Set("X-RAuth-User", "")
		hdr.Set("X-RAuth-Groups", "")
		hdr.Set("X-RAuth-Admin", "0")
		hdr.Set("X-RAuth-Anonymous", "1")
		return c.NoContent(http.StatusOK)
	}
	if rateLimit {
		return h.rateLimitedUnauthorized(c, rateLimitKey)
	}
	return c.NoContent(http.StatusUnauthorized)
}

// matchBypass checks the auth bypass rules against the host and URI the
// reverse proxy reports for the original request. Those headers are only
// honoured from TRUSTED_PROXIES or, when that list is empty (legacy smart
// mode), from private/loopback peers, so a client reaching rauth directly
// over a public address cannot pick a bypassed host.
func (h *AuthHandler) matchBypass(c echo.Context) (core.BypassRule, bool) {
	if !core.HasBypassRules() {
		return core.BypassRule{}, false
	}
	req := c.Request()
	peer, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		peer = req.RemoteAddr
	}
	if len(h.Cfg.TrustedProxies) > 0 {
		if !h.Cfg.IsIPAllowed(peer, h.Cfg.TrustedProxies) {
			return core.BypassRule{}, false
		}
	} else if ip := net.ParseIP(peer); ip == nil || (!ip.IsPrivate() && !ip.IsLoopback()) {
		return core.BypassRule{}, false
	}
	return core.MatchBypass(req.Header.Get(h.Cfg.AuthBypassHostHeader), req.Header.Get(h.Cfg.AuthBypassURIHeader))
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
	ipBucket := core.RateLimitIP(clientIP)
	slog.Debug("Login attempt", "ip", clientIP, "method", c.Request().Method)

	// 1. Basic IP Throttling for ALL requests (GET/POST)
	// Fast-path read-only check to prevent large payload parsing if already throttled.
	if core.IsRateLimitExceeded("login_access:"+ipBucket, h.Cfg.RateLimitLoginAccessMax) {
		slog.Warn("General login access rate limit exceeded (fast-path)", "ip", clientIP)
		return c.Render(http.StatusTooManyRequests, "login.html", map[string]interface{}{"error": "Too many requests. Please wait a minute.", "csrf": c.Get("csrf"), "rd": c.QueryParam("rd")})
	}

	// Delegate 2FA verification before consuming this handler's rate-limit
	// budget: Verify2FA applies the same IP throttles itself, so checking here
	// too would double-count every 2FA attempt submitted via the login form.
	if c.Request().Method == http.MethodPost && c.FormValue("action") == "verify_2fa" {
		return h.Verify2FA(c)
	}

	if !core.CheckRateLimit("login_access:"+ipBucket, h.Cfg.RateLimitLoginAccessMax, h.Cfg.RateLimitLoginAccessDecay) {
		slog.Warn("General login access rate limit exceeded", "ip", clientIP)
		return c.Render(http.StatusTooManyRequests, "login.html", map[string]interface{}{"error": "Too many requests. Please wait a minute.", "csrf": c.Get("csrf"), "rd": getRD(c)})
	}

	if c.Request().Method == http.MethodGet {
		return c.Render(http.StatusOK, "login.html", map[string]interface{}{"csrf": c.Get("csrf"), "rd": getRD(c)})
	}

	// 2. Strict Throttling for POST (Authentication Attempts)
	if !core.CheckRateLimit("login_post_ip:"+ipBucket, h.Cfg.RateLimitLoginMax, h.Cfg.RateLimitLoginDecay) {
		slog.Warn("Login POST rate limit exceeded", "ip", clientIP)
		return c.Render(http.StatusTooManyRequests, "login.html", map[string]interface{}{"error": fmt.Sprintf("Too many login attempts from this IP (%s).", clientIP), "csrf": c.Get("csrf"), "rd": getRD(c)})
	}

	username := strings.TrimSpace(c.FormValue("username"))

	// 3. Per-User Throttling
	if throttled, err := h.checkUserThrottling(c, username); throttled {
		return err
	}

	// Read the generation before the credentials and carry it through the
	// pending token into the session: a password reset or 2FA reset that
	// commits in between leaves everything this login issues stale (see
	// core.RevokeAuth), instead of re-stamping old proof with the new value.
	authGen, err := core.AuthGeneration(username)
	if err != nil {
		slog.Error("Failed to read auth generation at login", "user", username, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal Server Error")
	}

	password := c.FormValue("password")
	userRecord, valid := h.verifyCredentials(username, password)

	if !valid {
		return h.handleAuthFailure(c, username)
	}

	// Success! Reset the per-user penalty for this account only. IP-scoped
	// counters are deliberately left alone: resetting them on success would let
	// an attacker holding any valid account clear their own throttle.
	core.ResetRateLimit(loginFailUserKey(username, clientIP))

	// Check if 2FA is enabled
	if userRecord.TwoFactor != "" {
		return h.initiate2FASession(c, username, authGen)
	}

	// Force 2FA Setup for new users (or users without 2FA)
	return h.initiate2FASetupSession(c, username, authGen)
}

// loginFailUserKey scopes the per-account password lockout to the client's IP
// bucket. A global per-username lock let any anonymous client keep a named
// account (including the root admin) locked out indefinitely; scoping it to
// the source means failures only lock out the network producing them, while
// the per-IP failure budget and bcrypt+2FA bound distributed guessing.
func loginFailUserKey(username, clientIP string) string {
	return "login_fail_user:" + username + "@" + core.RateLimitIP(clientIP)
}

func (h *AuthHandler) checkUserThrottling(c echo.Context, username string) (bool, error) {
	clientIP := c.RealIP()
	if username != "" && core.IsRateLimitExceeded(loginFailUserKey(username, clientIP), h.Cfg.RateLimitLoginFailUserMax) {
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
	return core.CheckRateLimit("login_fail_ip:"+core.RateLimitIP(clientIP), limit, h.Cfg.RateLimitLoginFailIPDecay)
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
		core.CheckRateLimit(loginFailUserKey(username, clientIP), h.Cfg.RateLimitLoginFailUserMax, h.Cfg.RateLimitLoginFailUserDecay)
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
	if exists, err := core.UserExists(username); err != nil || !exists {
		core.LogAudit("LOGIN_FAILED", "", clientIP, map[string]interface{}{"attempted_username": username})
		return
	}
	core.LogAudit("LOGIN_FAILED", username, clientIP, nil)
}

func (h *AuthHandler) initiate2FASession(c echo.Context, username, authGen string) error {
	tempToken := h.issueTempToken(username, authGen)
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

func (h *AuthHandler) initiate2FASetupSession(c echo.Context, username, authGen string) error {
	setupToken := h.issueSetupToken(username, authGen)
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
	ipBucket := core.RateLimitIP(clientIP)
	if core.IsRateLimitExceeded("login_access:"+ipBucket, h.Cfg.RateLimitLoginAccessMax) {
		ctx := map[string]interface{}{"error": "Too many requests. Please wait a minute.", "csrf": c.Get("csrf"), "rd": c.QueryParam("rd")}
		for k, v := range extraContext {
			ctx[k] = v
		}
		return c.Render(http.StatusTooManyRequests, template, ctx)
	}
	if !core.CheckRateLimit("login_access:"+ipBucket, h.Cfg.RateLimitLoginAccessMax, h.Cfg.RateLimitLoginAccessDecay) {
		ctx := map[string]interface{}{"error": "Too many requests. Please wait a minute.", "csrf": c.Get("csrf"), "rd": getRD(c)}
		for k, v := range extraContext {
			ctx[k] = v
		}
		return c.Render(http.StatusTooManyRequests, template, ctx)
	}
	if !core.CheckRateLimit("login_post_ip:"+ipBucket, h.Cfg.RateLimitLoginMax, h.Cfg.RateLimitLoginDecay) {
		ctx := map[string]interface{}{"error": fmt.Sprintf("Too many attempts from this IP (%s). Please try again later.", clientIP), "csrf": c.Get("csrf"), "rd": getRD(c)}
		for k, v := range extraContext {
			ctx[k] = v
		}
		return c.Render(http.StatusTooManyRequests, template, ctx)
	}
	return nil
}

// validatePendingToken resolves a pending 2FA/setup cookie to its username,
// token and the auth generation the first factor was checked under.
func (h *AuthHandler) validatePendingToken(c echo.Context, cookieName, prefix string) (string, string, string, error) {
	cookie, err := c.Cookie(cookieName)
	if err != nil {
		return "", "", "", err
	}
	token, err := core.DecryptToken(cookie.Value, h.Cfg.ServerSecret)
	if err != nil {
		return "", "", "", err
	}
	value, err := core.TokenDB.Get(core.Ctx, prefix+":"+token).Result()
	if err != nil {
		return "", "", "", err
	}
	// A pending token issued before the user's last credential change (password
	// change, 2FA reset, deletion) is dead even if its TTL has not run out.
	username, gen, current := core.ResolvePendingToken(value)
	if !current {
		core.TokenDB.Del(core.Ctx, prefix+":"+token, "pending_setup_secret:"+token)
		return "", "", "", errStalePendingToken
	}
	return username, token, gen, nil
}

var errStalePendingToken = errors.New("pending token predates a credential change")

func (h *AuthHandler) handle2FASuccess(c echo.Context, username, clientIP, pendingToken, authGen string, usedRecovery bool, userRecord *core.User) error {
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

	core.ResetRateLimit(loginFailUserKey(username, clientIP))
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

	return h.issueToken(c, username, authGen)
}

// reserve2FAAttempt atomically counts a second-factor attempt against the
// user's budget before the code is checked, so concurrent guesses cannot
// overshoot it (a check-then-increment window could). Success resets it.
func (h *AuthHandler) reserve2FAAttempt(username string) bool {
	exceeded, _, _ := core.ReserveRateLimitAttempt("2fa_fail_user:"+username, h.Cfg.RateLimitLoginFailUserMax, h.Cfg.RateLimitLoginFailUserDecay)
	return !exceeded
}

func (h *AuthHandler) handle2FAFailure(c echo.Context, username, clientIP string) error {
	core.LogAudit("2FA_FAILED", username, clientIP, nil)

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
	username, pendingToken, authGen, err := h.validatePendingToken(c, "rauth_2fa_pending", "pending_2fa")
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	userRecord, _ := core.GetUser(username)
	if userRecord.TwoFactor == "" {
		core.TokenDB.Del(core.Ctx, "pending_2fa:"+pendingToken)
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	if !h.reserve2FAAttempt(username) {
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
		return h.handle2FASuccess(c, username, clientIP, pendingToken, authGen, usedRecovery, &userRecord)
	}

	return h.handle2FAFailure(c, username, clientIP)
}

func (h *AuthHandler) Setup2FA(c echo.Context) error {
	username, setupToken, _, err := h.validatePendingToken(c, "rauth_setup_pending", "pending_setup")
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

	username, setupToken, authGen, err := h.validatePendingToken(c, "rauth_setup_pending", "pending_setup")
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	secret, err := core.TokenDB.Get(core.Ctx, "pending_setup_secret:"+setupToken).Result()
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthsetup2fa")
	}

	// Enrollment eligibility was decided when the setup token was issued; re-check
	// it now. The account must still exist and still have no second factor, so a
	// stale setup token can never replace a TOTP enrolled in the meantime or
	// write into a deleted (or recreated) account.
	userRecord, err := core.GetUser(username)
	if err != nil || userRecord.TwoFactor != "" {
		core.TokenDB.Del(core.Ctx, "pending_setup:"+setupToken, "pending_setup_secret:"+setupToken)
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	if !h.reserve2FAAttempt(username) {
		return c.Render(http.StatusTooManyRequests, "setup_2fa.html", map[string]interface{}{"error": "Too many failed attempts. Please try again later.", "csrf": c.Get("csrf"), "rd": c.QueryParam("rd")})
	}

	code := c.FormValue("totp_code")
	// Verify the code against the temporary secret, and burn it so the
	// enrollment code cannot be replayed on /verify-2fa within its window.
	if totp.Validate(code, secret) && !core.TOTPCodeReused(username, code) {
		// Save to user profile (encrypted)
		encryptedSecret, err := core.Encrypt2FASecret(secret, h.Cfg.ServerSecret)
		if err != nil {
			slog.Error("Failed to encrypt 2FA secret", "error", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Internal Server Error")
		}
		stored, err := core.SetSecondFactorIfUnset(username, encryptedSecret, authGen)
		if err != nil {
			slog.Error("Failed to save 2FA secret", "error", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Database Error")
		}
		if !stored {
			// Lost a race with another enrollment, the account vanished, or a
			// credential reset revoked this enrollment while it ran.
			core.TokenDB.Del(core.Ctx, "pending_setup:"+setupToken, "pending_setup_secret:"+setupToken)
			return c.Redirect(http.StatusFound, "/rauthlogin")
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
		if userRecord.Email != "" {
			device := core.FormatDevice(c.Request().UserAgent(),
				c.Request().Header.Get("Sec-CH-UA-Platform"),
				c.Request().Header.Get("Sec-CH-UA-Mobile"),
				c.Request().Header.Get("Sec-CH-UA-Model"))
			go core.Send2FAModifiedNotification(core.TwoFactorNotificationOptions{Email: userRecord.Email, Username: username, Action: "Enabled", IP: clientIP, Device: device})
		}

		core.ResetRateLimit(loginFailUserKey(username, clientIP))
		core.ResetRateLimit("2fa_fail_user:" + username)
		core.LogAudit("2FA_SETUP_SUCCESS", username, clientIP, nil)
		return h.issueToken(c, username, authGen)
	}

	// The failed attempt was already counted by reserve2FAAttempt.
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

func (h *AuthHandler) issueTempToken(username, authGen string) string {
	b := make([]byte, pendingTokenBytes)
	if _, err := rand.Read(b); err != nil {
		slog.Error("Failed to generate random temp token", "error", err)
		return ""
	}
	token := hex.EncodeToString(b)
	core.TokenDB.Set(core.Ctx, "pending_2fa:"+token, core.PendingTokenValue(username, authGen), 5*time.Minute)
	return token
}

func (h *AuthHandler) issueSetupToken(username, authGen string) string {
	b := make([]byte, pendingTokenBytes)
	if _, err := rand.Read(b); err != nil {
		slog.Error("Failed to generate random setup token", "error", err)
		return ""
	}
	token := hex.EncodeToString(b)
	core.TokenDB.Set(core.Ctx, "pending_setup:"+token, core.PendingTokenValue(username, authGen), 10*time.Minute)
	return token
}

// issueToken creates the authenticated session at the end of a login. authGen
// is the generation the login's first factor was checked under; it is stamped
// as is, so a revocation during the login leaves the session invalid.
func (h *AuthHandler) issueToken(c echo.Context, username, authGen string) error {
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

	validity := time.Duration(h.Cfg.TokenValidityMinutes) * time.Minute
	err = core.StoreSession(token, username, clientIP, map[string]interface{}{
		"status":         "valid",
		"ip":             clientIP,
		"username":       username,
		"country":        country,
		"groups":         userRecord.Groups,
		"is_admin":       userRecord.IsAdmin,
		"auth_gen":       authGen,
		"user_agent":     c.Request().UserAgent(),
		"ua_ch_platform": c.Request().Header.Get("Sec-CH-UA-Platform"),
		"ua_ch_mobile":   c.Request().Header.Get("Sec-CH-UA-Mobile"),
		"ua_ch_model":    c.Request().Header.Get("Sec-CH-UA-Model"),
		"created_at":     time.Now().Unix(),
	}, validity)
	if err != nil {
		slog.Error("Failed to store token in Redis", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal Server Error")
	}

	// Send Login Notification Email (Asynchronous)
	if userRecord.Email != "" {
		device := core.FormatDevice(c.Request().UserAgent(),
			c.Request().Header.Get("Sec-CH-UA-Platform"),
			c.Request().Header.Get("Sec-CH-UA-Mobile"),
			c.Request().Header.Get("Sec-CH-UA-Model"))
		go core.SendLoginNotification(userRecord.Email, username, clientIP, country, device)
	}

	h.setSessionCookie(c, encrypted, validity)

	core.LogAudit("LOGIN_SUCCESS", username, clientIP, map[string]interface{}{"country": country})
	core.LoginSuccessTotal.Inc()

	// Reset the per-user penalty on success. IP-scoped counters are not reset
	// so a successful login cannot be used to clear an IP's failure budget.
	core.ResetRateLimit(loginFailUserKey(username, clientIP))

	redirect := core.ValidateRedirectURL(getRD(c), "/rauthprofile", username, h.Cfg)
	return c.Redirect(http.StatusFound, redirect)
}
