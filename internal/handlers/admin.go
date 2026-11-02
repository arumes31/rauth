package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"rauth/internal/core"
	"rauth/internal/eventstore"
	"strings"

	"github.com/labstack/echo/v4"
)

type RequestEventSource interface {
	Epoch() string
	After(context.Context, uint64, string) (eventstore.Batch, error)
}

type AdminHandler struct {
	RequestEvents    RequestEventSource
	Cfg              *core.Config
	ReadPolicyStatus func(context.Context) (any, error)
}

func (h *AdminHandler) Dashboard(c echo.Context) error {
	users, err := core.ListUsers()
	if err != nil {
		slog.Error("Failed to list users", "error", err)
	}

	sessionPage, err := core.ListManagedSessions(c.Request().Context(), "", "", c.QueryParam("session_cursor"), 200)
	if err != nil {
		return sessionManagementError(err)
	}
	sessions := sessionPage.Sessions
	prepareSessionViews(sessions)

	// Fetch Audit Logs
	logs, err := core.RecentAuditLogs(100)
	if err != nil {
		slog.Error("Failed to fetch audit logs", "error", err)
	}

	// The Public Access unlock asks for TOTP if the admin has it, otherwise
	// the current password.
	adminHas2FA := false
	if adminName, ok := c.Get("username").(string); ok {
		if rec, err := core.GetUser(adminName); err == nil {
			adminHas2FA = rec.TwoFactor != ""
		}
	}

	feeds, feedErr := core.ListIPFeeds(c.Request().Context())
	if feedErr != nil {
		slog.Error("Failed to list IP feeds", "error", feedErr)
	}
	rules := bypassRuleViews()
	userViews, stats := buildAdminView(users, sessions, logs, rules)

	return c.Render(http.StatusOK, "management.html", map[string]interface{}{
		"username":         c.Get("username"),
		"cluster_enabled":  h.ReadPolicyStatus != nil,
		"root_user":        h.Cfg.InitialUser,
		"users":            userViews,
		"stats":            stats,
		"sessions":         sessions,
		"session_next":     sessionPage.Next,
		"session_paged":    sessionPage.Next != "" || c.QueryParam("session_cursor") != "",
		"logs":             logs,
		"csrf":             c.Get("csrf"),
		"bypass_rules":     rules,
		"policy_countries": core.PolicyCountries(),
		"ip_feeds":         feeds,
		"bypass_host_hdr":  h.Cfg.AuthBypassHostHeader,
		"bypass_uri_hdr":   h.Cfg.AuthBypassURIHeader,
		"admin_has_2fa":    adminHas2FA,
		"bypass_unlock_m":  bypassUnlockMinutes(c),
	})
}

func (h *AdminHandler) CreateUser(c echo.Context) error {
	user := strings.TrimSpace(c.FormValue("new_username"))
	pass := c.FormValue("new_password")
	email := strings.TrimSpace(c.FormValue("new_email"))
	isAdmin := c.FormValue("is_admin") == "on"

	if user == "" || pass == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username and password are required")
	}

	if err := core.ValidateUsername(user); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if _, err := core.GetUser(user); err == nil {
		return echo.NewHTTPError(http.StatusConflict, "User already exists")
	}

	if email != "" {
		if err := core.ValidateEmail(email); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
	}

	if err := core.ValidatePassword(pass, h.Cfg); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if isAdmin {
		if herr := h.requireAdminStepUp(c); herr != nil {
			return herr
		}
	}

	if err := core.CreateUser(user, pass, email, isAdmin, ""); err != nil {
		slog.Warn("Failed to create user", "user", user, "error", err)
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Send Welcome Email (Asynchronous)
	if email != "" {
		go core.SendAccountCreatedNotification(email, user)
	}

	slog.Info("User created by admin", "admin", c.Get("username"), "user", user)
	core.LogAudit("ADMIN_CREATE_USER", c.Get("username").(string), c.RealIP(), map[string]interface{}{"target": user})
	return c.Redirect(http.StatusFound, "/rauthmgmt?success=user_created")
}

func (h *AdminHandler) DeleteUser(c echo.Context) error {
	target := strings.TrimSpace(c.FormValue("username"))
	if target == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username is required")
	}

	if err := core.ValidateUsername(target); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// INITIAL_USER identifies the bootstrap administrator, even when renamed
	// from the default "admin" in the deployment configuration.
	if target == h.Cfg.InitialUser {
		return echo.NewHTTPError(http.StatusForbidden, "Cannot delete the root administrator")
	}

	if _, err := core.GetUser(target); err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}

	admin := c.Get("username").(string)
	if target == admin {
		return echo.NewHTTPError(http.StatusBadRequest, "Cannot delete yourself")
	}

	if err := core.DeleteUser(target); err != nil {
		slog.Error("Failed to delete user", "user", target, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete user")
	}

	slog.Info("User deleted by admin", "admin", admin, "user", target)
	core.LogAudit("ADMIN_DELETE_USER", admin, c.RealIP(), map[string]interface{}{"target": target})
	return c.Redirect(http.StatusFound, "/rauthmgmt?success=user_deleted")
}

func (h *AdminHandler) ResetUser2FA(c echo.Context) error {
	target := strings.TrimSpace(c.FormValue("username"))
	if target == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username is required")
	}

	if err := core.ValidateUsername(target); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	targetRecord, err := core.GetUser(target)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}

	admin := c.Get("username").(string)
	if target == admin {
		return echo.NewHTTPError(http.StatusBadRequest, "Cannot reset your own 2FA via management. Use profile settings.")
	}

	if herr := h.guardRootAdmin(target, admin); herr != nil {
		return herr
	}
	if targetRecord.IsAdmin == "1" {
		if herr := h.requireAdminStepUp(c); herr != nil {
			return herr
		}
	}

	// Reset every second factor (TOTP, recovery codes, passkeys) and revoke
	// every session and pending login of this user in one transaction.
	if _, err := core.ResetSecondFactors(target); err != nil {
		slog.Error("Failed to reset 2FA for user", "user", target, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to reset 2FA")
	}
	sweepUserSessions(target)

	slog.Info("2FA reset by admin", "admin", admin, "user", target)
	core.LogAudit("ADMIN_RESET_2FA", admin, c.RealIP(), map[string]interface{}{"target": target})
	return c.Redirect(http.StatusFound, "/rauthmgmt?success=2fa_reset")
}

func (h *AdminHandler) ChangeUserPassword(c echo.Context) error {
	target := strings.TrimSpace(c.FormValue("username"))
	if target == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username is required")
	}

	if err := core.ValidateUsername(target); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	targetRecord, err := core.GetUser(target)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}
	newPass := c.FormValue("new_password")
	if newPass == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Password is required")
	}

	admin := c.Get("username").(string)
	if target == admin {
		return echo.NewHTTPError(http.StatusBadRequest, "Cannot change your own password via management. Use profile settings.")
	}
	if herr := h.guardRootAdmin(target, admin); herr != nil {
		return herr
	}

	if err := core.ValidatePassword(newPass, h.Cfg); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if targetRecord.IsAdmin == "1" {
		if herr := h.requireAdminStepUp(c); herr != nil {
			return herr
		}
	}

	hash, err := core.HashPassword(newPass)
	if err != nil {
		slog.Error("Failed to hash new password for user", "user", target, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal Server Error")
	}

	// Security Hardening: the new password commits together with revoking
	// every session and pending login of this user, including a half-finished
	// 2FA setup started with the old password.
	if _, err := core.SetPassword(target, hash); err != nil {
		slog.Error("Failed to update user password", "user", target, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update password")
	}
	sweepUserSessions(target)

	slog.Info("Password changed by admin", "admin", admin, "user", target)
	core.LogAudit("ADMIN_CHANGE_PASSWORD", admin, c.RealIP(), map[string]interface{}{"target": target})
	return c.Redirect(http.StatusFound, "/rauthmgmt?success=password_changed")
}

func (h *AdminHandler) UpdateUserEmail(c echo.Context) error {
	target := strings.TrimSpace(c.FormValue("username"))
	if target == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username is required")
	}

	if err := core.ValidateUsername(target); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if _, err := core.GetUser(target); err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}
	newEmail := strings.TrimSpace(c.FormValue("new_email"))
	if newEmail == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Email is required")
	}

	if err := core.ValidateEmail(newEmail); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	admin := c.Get("username").(string)
	if herr := h.guardRootAdmin(target, admin); herr != nil {
		return herr
	}
	if err := core.UpdateUser(target, map[string]interface{}{"email": newEmail}); err != nil {
		slog.Error("Failed to update user email", "user", target, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update email")
	}

	slog.Info("User email updated by admin", "admin", admin, "user", target, "email", newEmail)
	core.LogAudit("ADMIN_UPDATE_EMAIL", admin, c.RealIP(), map[string]interface{}{"target": target, "email": newEmail})
	return c.Redirect(http.StatusFound, "/rauthmgmt?success=email_updated")
}

func (h *AdminHandler) InvalidateSession(c echo.Context) error {
	token := c.FormValue("token")
	if token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Token is required")
	}
	admin := c.Get("username").(string)

	if _, err := core.RevokeManagedSession(c.Request().Context(), token, ""); err != nil {
		return sessionManagementError(err)
	}
	slog.Info("Session invalidated by admin", "admin", admin)
	core.LogAudit("ADMIN_INVALIDATE_SESSION", admin, c.RealIP(), nil)

	return c.Redirect(http.StatusFound, "/rauthmgmt?success=session_terminated")
}

// requireAdminStepUp re-authenticates the acting administrator (TOTP code, or
// password without TOTP) before an action that hands out administrator
// credentials: creating an administrator, or resetting another
// administrator's password or 2FA. Otherwise a hijacked admin session could
// mint an administrator whose credentials it controls and use them for
// actions that demand fresh proof, such as unlocking Public Access.
func (h *AdminHandler) requireAdminStepUp(c echo.Context) *echo.HTTPError {
	admin := c.Get("username").(string)
	return verifyStepUp(h.Cfg, admin, c.FormValue("otp_code"), c.FormValue("current_password"))
}

// guardRootAdmin stops other administrators from taking over the bootstrap
// (INITIAL_USER) account by resetting its credentials or its notification
// e-mail. The root administrator manages its own account from the profile page.
func (h *AdminHandler) guardRootAdmin(target, admin string) error {
	if target == h.Cfg.InitialUser && admin != h.Cfg.InitialUser {
		return echo.NewHTTPError(http.StatusForbidden, "Only the root administrator can change the root administrator account")
	}
	return nil
}

// sweepUserSessions deletes a user's indexed sessions after a revocation. The
// generation bump (core.RevokeAuth) already made every session and pending
// token invalid, including ones the index misses; the sweep just removes the
// indexed ones from Redis right away.
func sweepUserSessions(username string) {
	if err := core.InvalidateUserSessions(username); err != nil {
		slog.Warn("Session index sweep failed", "user", username, "error", err)
	}
}

func (h *AdminHandler) PolicyStatus(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	if h.ReadPolicyStatus == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Policy confirmations unavailable")
	}
	status, err := h.ReadPolicyStatus(c.Request().Context())
	if err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Policy confirmations unavailable")
	}
	return c.JSON(http.StatusOK, status)
}
