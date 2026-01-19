package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"rauth/internal/core"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

type AuthHandler struct {
	Cfg *core.Config
}

func (h *AuthHandler) Validate(c echo.Context) error {
	clientIP := c.RealIP()
	
	// Global Rate Limit for Validation (prevent flood)
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

	redisKey := "X-rcloudauth-authtoken=" + token
	data, err := core.TokenDB.HGetAll(core.Ctx, redisKey).Result()
	if err != nil || len(data) == 0 {
		return c.NoContent(http.StatusUnauthorized)
	}

	if data["status"] != "valid" {
		return c.NoContent(http.StatusUnauthorized)
	}

	// Geo-check: If country changed since issuance, require fresh login (or 2FA)
	currentCountry := core.GetCountryCode(clientIP)
	if data["country"] != "unknown" && currentCountry != "unknown" && data["country"] != currentCountry {
		core.LogAudit("COUNTRY_CHANGE_DETECTED", data["username"], clientIP, map[string]interface{}{
			"old": data["country"],
			"new": currentCountry,
		})
		// In a real app, we might redirect to 2FA here. For now, we invalidate.
		return c.NoContent(http.StatusUnauthorized)
	}

	// RBAC check
	requiredGroup := c.Request().Header.Get("X-RAuth-Required-Group")
	if requiredGroup != "" {
		userData, _ := core.UserDB.HGetAll(core.Ctx, "user:"+data["username"]).Result()
		groups := strings.Split(userData["groups"], ",")
		found := false
		for _, g := range groups {
			if strings.TrimSpace(g) == requiredGroup {
				found = true
				break
			}
		}
		if !found {
			return c.String(http.StatusForbidden, "Missing group "+requiredGroup)
		}
	}

	return c.NoContent(http.StatusOK)
}

func (h *AuthHandler) Login(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	clientIP := c.RealIP()

	// Rate limit login attempts per IP
	if !core.CheckRateLimit("login_ip:"+clientIP, 10, 300) {
		return c.Render(http.StatusOK, "login.html", map[string]interface{}{
			"error": "Too many attempts from this IP. Please wait.",
		})
	}

	userData, err := core.UserDB.HGetAll(core.Ctx, "user:"+username).Result()
	if err != nil || len(userData) == 0 {
		core.LogAudit("LOGIN_FAILED", username, clientIP, map[string]interface{}{"reason": "user_not_found"})
		return c.Render(http.StatusOK, "login.html", map[string]interface{}{
			"error": "Invalid credentials",
		})
	}

	if !core.CheckPasswordHash(password, userData["password"]) {
		core.LogAudit("LOGIN_FAILED", username, clientIP, map[string]interface{}{"reason": "invalid_password"})
		return c.Render(http.StatusOK, "login.html", map[string]interface{}{
			"error": "Invalid credentials",
		})
	}

	// Success
	core.ResetRateLimit("login_ip:" + clientIP)
	return h.issueToken(c, username)
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
	core.TokenDB.SAdd(core.Ctx, "user_sessions:"+username, token)

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
	if redirect == "" {
		redirect = "/"
	}
	return c.Redirect(http.StatusFound, redirect)
}