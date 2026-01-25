package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"rauth/internal/core"
	"time"

	"github.com/labstack/echo/v4"
)

type InviteHandler struct {
	Cfg *core.Config
}

func (h *InviteHandler) Create(c echo.Context) error {
	email := c.FormValue("email")
	if email == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Email is required")
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
	
	// If email config exists, we could send it here. 
	// For now, return it so the admin can copy-paste.
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
	token := c.FormValue("token")
	username := c.FormValue("username")
	password := c.FormValue("password")

	email, err := core.InviteDB.Get(core.Ctx, "invite:"+token).Result()
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "Invalid or expired invitation")
	}

	if err := core.ValidatePassword(password, h.Cfg); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// Create User
	err = core.CreateUser(username, password, email, false, "")
	if err != nil {
		return c.JSON(http.StatusConflict, map[string]string{"error": "Username already taken"})
	}

	// Cleanup token
	core.InviteDB.Del(core.Ctx, "invite:"+token)

	core.LogAudit("USER_INVITE_REDEEMED", username, c.RealIP(), map[string]interface{}{"email": email})

	return c.Redirect(http.StatusFound, "/rauthlogin?success=account_created")
}
