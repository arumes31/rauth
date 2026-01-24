package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"rauth/internal/core"
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
	if err != nil {
		return c.NoContent(http.StatusUnauthorized)
	}

	redisKey := "X-rauth-authtoken=" + token
	data, err := core.TokenDB.HGetAll(core.Ctx, redisKey).Result()
	if err != nil || len(data) == 0 || data["status"] != "valid" {
		return c.NoContent(http.StatusUnauthorized)
	}

	// Geo-check
	currentCountry := core.GetCountryCode(clientIP)
	if data["country"] != "unknown" && currentCountry != "unknown" && data["country"] != currentCountry {
		core.LogAudit("COUNTRY_CHANGE_DETECTED", data["username"], clientIP, map[string]interface{}{"old": data["country"], "new": currentCountry, "current_ip": clientIP})
		// Expire instant if country changes
		core.TokenDB.Del(core.Ctx, redisKey)
		return c.NoContent(http.StatusUnauthorized)
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
	if c.FormValue("action") == "verify_2fa" {
		return h.Verify2FA(c)
	}

	username := c.FormValue("username")
	password := c.FormValue("password")
	clientIP := c.RealIP()

	if !core.CheckRateLimit("login_ip:"+clientIP, 10, 300) {
		return c.Render(http.StatusOK, "login.html", map[string]interface{}{"error": "Too many attempts from this IP."})
	}

	userData, err := core.UserDB.HGetAll(core.Ctx, "user:"+username).Result()
	if err != nil || len(userData) == 0 || !core.CheckPasswordHash(password, userData["password"]) {
		core.LogAudit("LOGIN_FAILED", username, clientIP, nil)
		return c.Render(http.StatusOK, "login.html", map[string]interface{}{"error": "Invalid credentials", "csrf": c.Get("csrf")})
	}

	// Check if 2FA is enabled
	if userData["2fa_secret"] != "" {
		// Issue a temporary short-lived session for 2FA verification
		tempToken := h.issueTempToken(username)
		cookie := &http.Cookie{
			Name:     "rauth_2fa_pending",
			Value:    tempToken,
			Path:     "/",
			HttpOnly: true,
			Expires:  time.Now().Add(5 * time.Minute),
		}
		c.SetCookie(cookie)
		return c.Render(http.StatusOK, "login.html", map[string]interface{}{
			"display2fa": true,
			"username":   username,
			"csrf":       c.Get("csrf"),
		})
	}

	// Force 2FA Setup for new users (or users without 2FA)
	setupToken := h.issueSetupToken(username)
	c.SetCookie(&http.Cookie{
		Name:     "rauth_setup_pending",
		Value:    setupToken,
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Now().Add(10 * time.Minute),
	})
	return c.Redirect(http.StatusFound, "/rauthsetup2fa")
}

func (h *AuthHandler) Verify2FA(c echo.Context) error {
	code := c.FormValue("totp_code")
	pendingCookie, err := c.Cookie("rauth_2fa_pending")
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	username, err := core.TokenDB.Get(core.Ctx, "pending_2fa:"+pendingCookie.Value).Result()
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	userData, _ := core.UserDB.HGetAll(core.Ctx, "user:"+username).Result()
	if totp.Validate(code, userData["2fa_secret"]) {
		core.TokenDB.Del(core.Ctx, "pending_2fa:"+pendingCookie.Value)
		// Clear pending cookie
		c.SetCookie(&http.Cookie{Name: "rauth_2fa_pending", MaxAge: -1})
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
	username, err := core.TokenDB.Get(core.Ctx, "pending_setup:"+cookie.Value).Result()
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
	core.TokenDB.Set(core.Ctx, "pending_setup_secret:"+cookie.Value, key.Secret(), 5*time.Minute)

	return c.Render(http.StatusOK, "setup_2fa.html", map[string]interface{}{
		"secret": key.Secret(),
		"csrf":   c.Get("csrf"),
	})
}

func (h *AuthHandler) CompleteSetup2FA(c echo.Context) error {
	cookie, err := c.Cookie("rauth_setup_pending")
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}
	
	username, err := core.TokenDB.Get(core.Ctx, "pending_setup:"+cookie.Value).Result()
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	secret, err := core.TokenDB.Get(core.Ctx, "pending_setup_secret:"+cookie.Value).Result()
	if err != nil {
		return c.Redirect(http.StatusFound, "/rauthsetup2fa")
	}

	code := c.FormValue("totp_code")
	// Verify the code against the temporary secret
	if totp.Validate(code, secret) {
		// Save to user profile
		err = core.UserDB.HSet(core.Ctx, "user:"+username, "2fa_secret", secret).Err()
		if err != nil {
			slog.Error("Failed to save 2FA secret", "error", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Database Error")
		}
		
		// Cleanup
		core.TokenDB.Del(core.Ctx, "pending_setup:"+cookie.Value)
		core.TokenDB.Del(core.Ctx, "pending_setup_secret:"+cookie.Value)
		c.SetCookie(&http.Cookie{Name: "rauth_setup_pending", MaxAge: -1})

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

	redisKey := "X-rauth-authtoken=" + token
	err = core.TokenDB.HSet(core.Ctx, redisKey, map[string]interface{}{
		"status":     "valid",
		"ip":         clientIP,
		"username":   username,
		"country":    country,
		"created_at": time.Now().Unix(),
	}).Err()
	if err != nil {
		slog.Error("Failed to store token in Redis", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal Server Error")
	}
	
	validity := time.Duration(h.Cfg.TokenValidityMinutes) * time.Minute
	core.TokenDB.Expire(core.Ctx, redisKey, validity)

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
	
	redirect := c.QueryParam("rd")
	if redirect != "" && !h.Cfg.IsAllowedHost(redirect) {
		slog.Warn("Unsafe redirect attempted", "host", redirect, "user", username)
		redirect = "/"
	}
	if redirect == "" { redirect = "/rauthprofile" }
	return c.Redirect(http.StatusFound, redirect)
}
