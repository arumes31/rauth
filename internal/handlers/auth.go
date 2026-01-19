package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"rauth/internal/core"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp/totp"
)

type AuthHandler struct {
	Cfg *core.Config
}

func (h *AuthHandler) Validate(c echo.Context) error {
	clientIP := c.RealIP()
	if !core.CheckRateLimit("validate:"+clientIP, 100, 60) {
		return c.NoContent(http.StatusTooManyRequests)
	}

	cookie, err := c.Cookie("X-rcloudauth-authtoken")
	if err != nil {
		return c.NoContent(http.StatusUnauthorized)
	}

	token, err := core.DecryptToken(cookie.Value, h.Cfg.ServerSecret)
	if err != nil {
		return c.NoContent(http.StatusUnauthorized)
	}

	data, err := core.TokenDB.HGetAll(core.Ctx, "X-rcloudauth-authtoken="+token).Result()
	if err != nil || len(data) == 0 || data["status"] != "valid" {
		return c.NoContent(http.StatusUnauthorized)
	}

	// Geo-check
	currentCountry := core.GetCountryCode(clientIP)
	if data["country"] != "unknown" && currentCountry != "unknown" && data["country"] != currentCountry {
		core.LogAudit("COUNTRY_CHANGE_DETECTED", data["username"], clientIP, map[string]interface{}{"old": data["country"], "new": currentCountry})
		return c.NoContent(http.StatusUnauthorized)
	}

	return c.NoContent(http.StatusOK)
}

func (h *AuthHandler) Login(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	clientIP := c.RealIP()

	if !core.CheckRateLimit("login_ip:"+clientIP, 10, 300) {
		return c.Render(http.StatusOK, "login.html", map[string]interface{}{"error": "Too many attempts."})
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

	core.ResetRateLimit("login_ip:" + clientIP)
	return h.issueToken(c, username)
}

func (h *AuthHandler) Verify2FA(c echo.Context) error {
	code := c.FormValue("totp_code")
	pendingCookie, err := c.Cookie("rauth_2fa_pending")
	if err != nil {
		return c.Redirect(http.StatusFound, "/login")
	}

	username, err := core.TokenDB.Get(core.Ctx, "pending_2fa:"+pendingCookie.Value).Result()
	if err != nil {
		return c.Redirect(http.StatusFound, "/login")
	}

	userData, _ := core.UserDB.HGetAll(core.Ctx, "user:"+username).Result()
	if totp.Validate(code, userData["2fa_secret"]) {
		core.TokenDB.Del(core.Ctx, "pending_2fa:"+pendingCookie.Value)
		// Clear pending cookie
		c.SetCookie(&http.Cookie{Name: "rauth_2fa_pending", MaxAge: -1})
		return h.issueToken(c, username)
	}

	core.LogAudit("2FA_FAILED", username, c.RealIP(), nil)
	return c.Render(http.StatusOK, "login.html", map[string]interface{}{
		"display2fa": true,
		"error":      "Invalid 2FA code",
		"csrf":       c.Get("csrf"),
	})
}

func (h *AuthHandler) issueTempToken(username string) string {
	b := make([]byte, 16)
	rand.Read(b)
	token := hex.EncodeToString(b)
	core.TokenDB.Set(core.Ctx, "pending_2fa:"+token, username, 5*time.Minute)
	return token
}

func (h *AuthHandler) issueToken(c echo.Context, username string) error {
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	encrypted, _ := core.EncryptToken(token, h.Cfg.ServerSecret)
	clientIP := c.RealIP()
	country := core.GetCountryCode(clientIP)

	redisKey := "X-rcloudauth-authtoken=" + token
	core.TokenDB.HSet(core.Ctx, redisKey, map[string]interface{}{
		"status":     "valid",
		"ip":         clientIP,
		"username":   username,
		"country":    country,
		"created_at": time.Now().Unix(),
	})
	
	validity := time.Duration(h.Cfg.TokenValidityMinutes) * time.Minute
	core.TokenDB.Expire(core.Ctx, redisKey, validity)

	cookie := &http.Cookie{
		Name:     "X-rcloudauth-authtoken",
		Value:    encrypted,
		Path:     "/",
		Domain:   h.Cfg.CookieDomain,
		Expires:  time.Now().Add(validity),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	c.SetCookie(cookie)

	core.LogAudit("LOGIN_SUCCESS", username, clientIP, map[string]interface{}{"country": country})
	
	redirect := c.QueryParam("rd")
	if redirect == "" { redirect = "/" }
	return c.Redirect(http.StatusFound, redirect)
}
