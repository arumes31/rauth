package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"rauth/internal/core"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"strings"
)

// consumeInviteScript atomically reads and deletes an invite, returning its
// email and remaining TTL in milliseconds so the invite can be restored with
// its original expiry if account creation fails.
var consumeInviteScript = redis.NewScript(`
local email = redis.call("GET", KEYS[1])
if not email then
	return false
end
local ttl = redis.call("PTTL", KEYS[1])
redis.call("DEL", KEYS[1])
return {email, ttl}
`)

// consumeInvite atomically claims an invite token so concurrent redemptions
// of the same token cannot each create an account.
func consumeInvite(token string) (string, time.Duration, error) {
	res, err := consumeInviteScript.Run(core.Ctx, core.InviteDB, []string{"invite:" + token}).Slice()
	if err != nil {
		return "", 0, err
	}
	if len(res) != 2 {
		return "", 0, redis.Nil
	}
	email, _ := res[0].(string)
	ttlMs, _ := res[1].(int64)
	if email == "" {
		return "", 0, redis.Nil
	}
	return email, time.Duration(ttlMs) * time.Millisecond, nil
}

// restoreInvite puts a claimed invite back after an internal failure.
func restoreInvite(token, email string, ttl time.Duration) {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	core.InviteDB.Set(core.Ctx, "invite:"+token, email, ttl)
}

type InviteHandler struct {
	Cfg *core.Config
}

func (h *InviteHandler) Create(c echo.Context) error {
	email := strings.TrimSpace(c.FormValue("email"))
	if err := core.ValidateEmail(email); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Generate token
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to generate invitation token")
	}
	token := hex.EncodeToString(b)

	// Store token with email (24h expiry)
	core.InviteDB.Set(core.Ctx, "invite:"+token, email, 24*time.Hour)

	inviteURL := h.Cfg.PublicURL + "/rauthredeem?token=" + token

	// The token/URL is returned to the (admin-only) caller to share manually;
	// delivery is intentionally out of band rather than emailed by this endpoint.
	return c.JSON(http.StatusOK, map[string]string{
		"token": token,
		"url":   inviteURL,
	})
}

func (h *InviteHandler) RedeemPage(c echo.Context) error {
	token := c.QueryParam("token")
	if token == "" {
		return c.Redirect(http.StatusFound, "/rauthlogin")
	}

	email, err := core.InviteDB.Get(core.Ctx, "invite:"+token).Result()
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "Invalid or expired invitation")
	}

	return c.Render(http.StatusOK, "redeem.html", map[string]interface{}{
		"token": token,
		"email": email,
		"csrf":  c.Get("csrf"),
	})
}

func (h *InviteHandler) Redeem(c echo.Context) error {
	clientIP := c.RealIP()
	if core.IsRateLimitExceeded("reg_ip:"+clientIP, h.Cfg.RateLimitRegistrationMax) {
		return echo.NewHTTPError(http.StatusTooManyRequests, fmt.Sprintf("Too many registration attempts from this IP (%s)", clientIP))
	}
	if !core.CheckRateLimit("reg_ip:"+clientIP, h.Cfg.RateLimitRegistrationMax, h.Cfg.RateLimitRegistrationDecay) {
		return echo.NewHTTPError(http.StatusTooManyRequests, fmt.Sprintf("Too many registration attempts from this IP (%s)", clientIP))
	}

	token := c.FormValue("token")
	username := c.FormValue("username")
	password := c.FormValue("password")

	email, err := core.InviteDB.Get(core.Ctx, "invite:"+token).Result()
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "Invalid or expired invitation")
	}

	if err := core.ValidateUsername(username); err != nil {
		return h.renderRedeemError(c, http.StatusBadRequest, token, email, err.Error())
	}
	if err := core.ValidatePassword(password, h.Cfg); err != nil {
		return h.renderRedeemError(c, http.StatusBadRequest, token, email, err.Error())
	}

	// Claim the invite atomically before creating the user, so a token can
	// only ever be redeemed once even under concurrent requests.
	email, ttl, err := consumeInvite(token)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "Invalid or expired invitation")
	}

	// Create User
	err = core.CreateUser(username, password, email, false, "")
	if err != nil {
		// Keep the invite usable so the user can retry.
		restoreInvite(token, email, ttl)
		if strings.Contains(err.Error(), "already exists") {
			return h.renderRedeemError(c, http.StatusConflict, token, email, "Username already taken")
		}
		// Internal failure (e.g. storage error): keep the invite usable and
		// report it as such instead of a misleading conflict.
		return h.renderRedeemError(c, http.StatusInternalServerError, token, email, "Failed to create account. Please try again.")
	}

	core.LogAudit("USER_INVITE_REDEEMED", username, c.RealIP(), map[string]interface{}{"email": email})

	return c.Redirect(http.StatusFound, "/rauthlogin?success=account_created")
}

// renderRedeemError re-renders the redemption form with an error message. The
// form is a plain HTML POST, so a JSON body here would replace the page with
// raw JSON and strand the user.
func (h *InviteHandler) renderRedeemError(c echo.Context, status int, token, email, msg string) error {
	return c.Render(status, "redeem.html", map[string]interface{}{
		"token": token,
		"email": email,
		"error": msg,
		"csrf":  c.Get("csrf"),
	})
}
