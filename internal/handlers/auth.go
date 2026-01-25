package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"rauth/internal/core"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type AuthHandler struct {
	Cfg *core.Config
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

	data, err := core.TokenDB.HGetAll(core.Ctx, "X-rauth-authtoken="+token).Result()
	if err != nil || len(data) == 0 || data["status"] != "valid" {
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	return c.Redirect(http.StatusFound, "/rauthprofile")
}

func (h *AuthHandler) Validate(c echo.Context) error {
	clientIP := c.RealIP()
	if !core.CheckRateLimit("validate:"+clientIP, 100, 60) {
		return c.NoContent(http.StatusTooManyRequests)
	}

	cookie, err := c.Cookie("X-rauth-authtoken")
	if err != nil {
		return c.NoContent(http.StatusUnauthorized)
	}

	token, err := core.DecryptToken(cookie.Value, h.Cfg.ServerSecret)
	if err != nil || token == "" {
		return c.NoContent(http.StatusUnauthorized)
	}

	redisKey := "X-rauth-authtoken=" + token
	data, err := core.TokenDB.HGetAll(core.Ctx, redisKey).Result()
	if err != nil || len(data) == 0 || data["status"] != "valid" {
		return c.NoContent(http.StatusUnauthorized)
	}

	// Geo-check
	currentCountry := core.GetCountryCode(clientIP)
	if !h.Cfg.IsCountryAllowed(currentCountry) {
		slog.Warn("Access from blocked country", "country", currentCountry, "ip", clientIP)
		core.LogAudit("BLOCKED_COUNTRY_ACCESS", data["username"], clientIP, map[string]interface{}{"country": currentCountry})
		core.TokenDB.Del(core.Ctx, redisKey)
		return c.NoContent(http.StatusUnauthorized)
	}

	if data["country"] != "unknown" && currentCountry != "unknown" && data["country"] != currentCountry {
		core.LogAudit("COUNTRY_CHANGE_DETECTED", data["username"], clientIP, map[string]interface{}{"old": data["country"], "new": currentCountry, "current_ip": clientIP})
		// Expire instant if country changes
		core.TokenDB.Del(core.Ctx, redisKey)
		return c.NoContent(http.StatusUnauthorized)
	}

	// User-Agent check (Fingerprinting)
	if data["user_agent"] != c.Request().UserAgent() {
		slog.Warn("User-Agent change detected", "username", data["username"], "old", data["user_agent"], "new", c.Request().UserAgent())
		core.LogAudit("USER_AGENT_CHANGE_DETECTED", data["username"], clientIP, map[string]interface{}{"old": data["user_agent"], "new": c.Request().UserAgent()})
		// We could expire here, but let's be less aggressive for now and just log it unless it's a critical app.
		// For RAuth, safety first: let's expire if UA changes significantly?
		// Actually, let's just log for now to avoid false positives with browser updates.
	}

	c.Response().Header().Set("X-RAuth-User", data["username"])

	// Refresh if IP is unchanged
	if data["ip"] == clientIP {
		validity := time.Duration(h.Cfg.TokenValidityMinutes) * time.Minute
		core.TokenDB.Expire(core.Ctx, redisKey, validity)
		
		// Update cookie expiration
		newCookie := &http.Cookie{
			Name:     "X-rauth-authtoken",
			Value:    cookie.Value,
			Path:     "/",
			Domain:   h.Cfg.CookieDomains[0],
			Expires:  time.Now().Add(validity),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		}
		c.SetCookie(newCookie)
	}

	return c.NoContent(http.StatusOK)
}

func (h *AuthHandler) Login(c echo.Context) error {
	clientIP := c.RealIP()
	slog.Debug("Login attempt", "ip", clientIP, "method", c.Request().Method)
	if !core.CheckRateLimit("login_ip:"+clientIP, 10, 300) {
		slog.Warn("Rate limit exceeded", "ip", clientIP)
		return c.Render(http.StatusTooManyRequests, "login.html", map[string]interface{}{"error": fmt.Sprintf("Too many attempts from this IP (%s).", clientIP), "csrf": c.Get("csrf")})
	}

	if c.Request().Method == http.MethodGet {
		return c.Render(http.StatusOK, "login.html", map[string]interface{}{"csrf": c.Get("csrf"), "rd": c.QueryParam("rd")})
	}

	if c.FormValue("action") == "verify_2fa" {
		return h.Verify2FA(c)
	}

	username := strings.TrimSpace(c.FormValue("username"))
	password := c.FormValue("password")

	userRecord, err := core.GetUser(username)
	
	// Constant time password check to prevent username enumeration
	var valid bool
	if err == nil {
		valid = core.CheckPasswordHash(password, userRecord.Password)
	} else {
		// Dummy hash to simulate work
		core.CheckPasswordHash(password, "$2a$12$ce88271ea06248da6b12669ef405f18a52c193fcced142ee27")
		valid = false
	}

	if !valid {
		core.LogAudit("LOGIN_FAILED", username, clientIP, nil)
		core.LoginFailedTotal.Inc()
		return c.Render(http.StatusOK, "login.html", map[string]interface{}{"error": "Invalid credentials", "csrf": c.Get("csrf")})
	}

	// Check if 2FA is enabled
	if userRecord.TwoFactor != "" {
		// Issue a temporary short-lived session for 2FA verification
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
			"rd":         c.QueryParam("rd"),
		})
	}

	// Force 2FA Setup for new users (or users without 2FA)
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
	if rd := c.QueryParam("rd"); rd != "" {
		redirectURL += "?rd=" + url.QueryEscape(rd)
	}
	return c.Redirect(http.StatusFound, redirectURL)
}

func (h *AuthHandler) Verify2FA(c echo.Context) error {
	clientIP := c.RealIP()
	if !core.CheckRateLimit("login_ip:"+clientIP, 10, 300) {
		return c.Render(http.StatusTooManyRequests, "login.html", map[string]interface{}{"error": fmt.Sprintf("Too many attempts from this IP (%s). Please try again later.", clientIP), "csrf": c.Get("csrf"), "display2fa": true})
	}

	code := c.FormValue("totp_code")
	pendingCookie, err := c.Cookie("rauth_2fa_pending")
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	pendingToken, err := core.DecryptToken(pendingCookie.Value, h.Cfg.ServerSecret)
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	username, err := core.TokenDB.Get(core.Ctx, "pending_2fa:"+pendingToken).Result()
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	userRecord, _ := core.GetUser(username)
	secret := core.Decrypt2FASecret(userRecord.TwoFactor, h.Cfg.ServerSecret)
	if totp.Validate(code, secret) {
		core.TokenDB.Del(core.Ctx, "pending_2fa:"+pendingToken)
		// Clear pending cookie
		c.SetCookie(&http.Cookie{Name: "rauth_2fa_pending", MaxAge: -1, Path: "/", HttpOnly: true, Secure: true})
		core.ResetRateLimit("login_ip:" + c.RealIP())
		return h.issueToken(c, username)
	}

	core.LogAudit("2FA_FAILED", username, c.RealIP(), nil)
	return c.Render(http.StatusOK, "login.html", map[string]interface{}{
		"display2fa": true,
		"error":      "Invalid 2FA code",
		"csrf":       c.Get("csrf"),
	})
}

func (h *AuthHandler) Setup2FA(c echo.Context) error {
	cookie, err := c.Cookie("rauth_setup_pending")
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	setupToken, err := core.DecryptToken(cookie.Value, h.Cfg.ServerSecret)
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	username, err := core.TokenDB.Get(core.Ctx, "pending_setup:"+setupToken).Result()
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
		"rd":     c.QueryParam("rd"),
	})
}

func (h *AuthHandler) CompleteSetup2FA(c echo.Context) error {
	clientIP := c.RealIP()
	if !core.CheckRateLimit("login_ip:"+clientIP, 10, 300) {
		return c.Render(http.StatusTooManyRequests, "setup_2fa.html", map[string]interface{}{"error": fmt.Sprintf("Too many attempts from this IP (%s). Please try again later.", clientIP), "csrf": c.Get("csrf")})
	}

	cookie, err := c.Cookie("rauth_setup_pending")
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}
	
	setupToken, err := core.DecryptToken(cookie.Value, h.Cfg.ServerSecret)
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	username, err := core.TokenDB.Get(core.Ctx, "pending_setup:"+setupToken).Result()
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	secret, err := core.TokenDB.Get(core.Ctx, "pending_setup_secret:"+setupToken).Result()
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthsetup2fa")
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
		c.SetCookie(&http.Cookie{Name: "rauth_setup_pending", MaxAge: -1, Path: "/", HttpOnly: true, Secure: true})

		// Send notification email
		userRecord, _ := core.GetUser(username)
		if userRecord.Email != "" {
			go core.Send2FAModifiedNotification(userRecord.Email, username, "Enabled", c.RealIP())
		}

		core.ResetRateLimit("login_ip:" + c.RealIP())
		core.LogAudit("2FA_SETUP_SUCCESS", username, c.RealIP(), nil)
		return h.issueToken(c, username)
	}

	return c.Render(http.StatusOK, "setup_2fa.html", map[string]interface{}{
		"secret": secret,
		"error":  "Invalid code. Please try again.",
		"csrf":   c.Get("csrf"),
	})
}

func (h *AuthHandler) issueTempToken(username string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		slog.Error("Failed to generate random temp token", "error", err)
		return ""
	}
	token := hex.EncodeToString(b)
	core.TokenDB.Set(core.Ctx, "pending_2fa:"+token, username, 5*time.Minute)
	return token
}

func (h *AuthHandler) issueSetupToken(username string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		slog.Error("Failed to generate random setup token", "error", err)
		return ""
	}
	token := hex.EncodeToString(b)
	core.TokenDB.Set(core.Ctx, "pending_setup:"+token, username, 10*time.Minute)
	return token
}

func (h *AuthHandler) issueToken(c echo.Context, username string) error {
	tokenBytes := make([]byte, 32)
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

	redisKey := "X-rauth-authtoken=" + token
	err = core.TokenDB.HSet(core.Ctx, redisKey, map[string]interface{}{
		"status":     "valid",
		"ip":         clientIP,
		"username":   username,
		"country":    country,
		"user_agent": c.Request().UserAgent(),
		"created_at": time.Now().Unix(),
	}).Err()
	if err != nil {
		slog.Error("Failed to store token in Redis", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal Server Error")
	}

	validity := time.Duration(h.Cfg.TokenValidityMinutes) * time.Minute
	core.TokenDB.Expire(core.Ctx, redisKey, validity)

	// Send Login Notification Email (Asynchronous)
	userRecord, _ := core.GetUser(username)
	if userRecord.Email != "" {
		go core.SendLoginNotification(userRecord.Email, username, clientIP, country)
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

	redirect := c.QueryParam("rd")
	if redirect != "" {
		// Prevent protocol-relative redirects (e.g., //evil.com)
		if strings.HasPrefix(redirect, "//") {
			slog.Warn("Protocol-relative redirect attempted", "url", redirect, "user", username)
			redirect = "/rauthprofile"
		} else {
			parsedURL, err := url.Parse(redirect)
			if err != nil {
				redirect = "/rauthprofile"
			} else if parsedURL.IsAbs() {
				if !h.Cfg.IsAllowedHost(parsedURL.Hostname()) {
					slog.Warn("Unsafe absolute redirect attempted", "host", parsedURL.Hostname(), "user", username)
					redirect = "/rauthprofile"
				}
			} else {
				// Relative URL - ensure it starts with / and not // (checked above)
				if !strings.HasPrefix(redirect, "/") {
					redirect = "/" + redirect
				}
			}
		}
	}
	if redirect == "" {
		redirect = "/rauthprofile"
	}
	return c.Redirect(http.StatusFound, redirect)
}
