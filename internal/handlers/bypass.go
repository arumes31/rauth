package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"rauth/internal/core"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

// bypassUnlockTTL is how long one step-up keeps the Public Access tab
// unlocked for the admin session that performed it.
const bypassUnlockTTL = 15 * time.Minute

// bypassUnlockKey is the TokenDB key marking a session as unlocked for bypass
// rule changes. It is bound to the session token, so another session (or a
// stolen cookie from before the step-up) does not inherit it.
func bypassUnlockKey(token string) string { return "bypass_unlock:" + token }

// BypassRuleView is what the admin dashboard renders for a bypass rule.
type BypassRuleView struct {
	core.BypassRule
	Scope string
}

func bypassRuleViews() []BypassRuleView {
	rules := core.ListBypassRules()
	views := make([]BypassRuleView, len(rules))
	for i, r := range rules {
		views[i] = BypassRuleView{BypassRule: r, Scope: core.DescribeBypassRule(r)}
	}
	return views
}

// bypassUnlockRemaining returns how long the current session stays unlocked
// for bypass rule changes (0 when locked).
func bypassUnlockRemaining(c echo.Context) time.Duration {
	token, _ := c.Get("token").(string)
	if token == "" {
		return 0
	}
	ttl, err := core.TokenDB.TTL(core.Ctx, bypassUnlockKey(token)).Result()
	if err != nil || ttl <= 0 {
		return 0
	}
	return ttl
}

// bypassUnlockMinutes is the remaining unlock time rounded up to whole
// minutes for the dashboard (0 when locked).
func bypassUnlockMinutes(c echo.Context) int {
	ttl := bypassUnlockRemaining(c)
	if ttl <= 0 {
		return 0
	}
	return int((ttl + time.Minute - 1) / time.Minute)
}

// requireBypassUnlock rejects bypass rule changes unless this session passed
// the step-up recently. Opening an application to anonymous access is high
// impact, so a hijacked admin session alone cannot do it.
func requireBypassUnlock(c echo.Context) *echo.HTTPError {
	if bypassUnlockRemaining(c) <= 0 {
		return echo.NewHTTPError(http.StatusForbidden, "Public access management is locked. Unlock it with your 2FA code (or password) first.")
	}
	return nil
}

// UnlockBypass verifies a step-up (TOTP code, or current password for admins
// without TOTP) once and unlocks bypass rule changes for this session.
func (h *AdminHandler) UnlockBypass(c echo.Context) error {
	admin := c.Get("username").(string)
	token, _ := c.Get("token").(string)
	if token == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Session required")
	}
	if herr := verifyStepUp(h.Cfg, admin, c.FormValue("otp_code"), c.FormValue("current_password")); herr != nil {
		return herr
	}
	if err := core.TokenDB.Set(core.Ctx, bypassUnlockKey(token), admin, bypassUnlockTTL).Err(); err != nil {
		slog.Error("Failed to store bypass unlock", "admin", admin, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to unlock")
	}
	core.LogAudit("ADMIN_BYPASS_UNLOCK", admin, c.RealIP(), map[string]interface{}{"minutes": int(bypassUnlockTTL.Minutes())})
	return c.Redirect(http.StatusFound, "/rauthmgmt?success=bypass_unlocked#bypass")
}

// LockBypass ends the unlock early.
func (h *AdminHandler) LockBypass(c echo.Context) error {
	if token, _ := c.Get("token").(string); token != "" {
		core.TokenDB.Del(core.Ctx, bypassUnlockKey(token))
	}
	return c.Redirect(http.StatusFound, "/rauthmgmt?success=bypass_locked#bypass")
}

// AddBypassRule creates a UI-managed auth bypass rule (unlock required,
// audit-logged).
func (h *AdminHandler) AddBypassRule(c echo.Context) error {
	admin := c.Get("username").(string)
	if herr := requireBypassUnlock(c); herr != nil {
		return herr
	}

	rule, err := core.AddBypassRule(c.FormValue("rule"), c.FormValue("action"), c.FormValue("note"), admin)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	slog.Warn("Auth bypass rule added", "admin", admin, "rule", rule.Rule, "action", rule.Action)
	core.LogAudit("ADMIN_BYPASS_RULE_ADD", admin, c.RealIP(), map[string]interface{}{"rule": rule.Rule, "action": rule.Action, "scope": core.DescribeBypassRule(rule)})
	return c.Redirect(http.StatusFound, "/rauthmgmt?success=bypass_added#bypass")
}

// UpdateBypassRule edits a UI-managed auth bypass rule (unlock required,
// audit-logged with the before and after state).
func (h *AdminHandler) UpdateBypassRule(c echo.Context) error {
	admin := c.Get("username").(string)
	if herr := requireBypassUnlock(c); herr != nil {
		return herr
	}

	old, rule, err := core.UpdateBypassRule(c.FormValue("original_rule"), c.FormValue("rule"), c.FormValue("action"), c.FormValue("note"), admin)
	if errors.Is(err, core.ErrBypassNotFound) {
		return echo.NewHTTPError(http.StatusNotFound, err.Error())
	} else if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	slog.Warn("Auth bypass rule updated", "admin", admin, "old_rule", old.Rule, "old_action", old.Action, "rule", rule.Rule, "action", rule.Action)
	core.LogAudit("ADMIN_BYPASS_RULE_UPDATE", admin, c.RealIP(), map[string]interface{}{
		"old_rule": old.Rule, "old_action": old.Action,
		"rule": rule.Rule, "action": rule.Action, "scope": core.DescribeBypassRule(rule),
	})
	return c.Redirect(http.StatusFound, "/rauthmgmt?success=bypass_updated#bypass")
}

// DeleteBypassRule removes a UI-managed auth bypass rule (also unlock gated,
// so a hijacked admin session cannot silently reshape access either way).
func (h *AdminHandler) DeleteBypassRule(c echo.Context) error {
	admin := c.Get("username").(string)
	if herr := requireBypassUnlock(c); herr != nil {
		return herr
	}

	raw := strings.TrimSpace(c.FormValue("rule"))
	existed, err := core.DeleteBypassRule(raw)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if !existed {
		return echo.NewHTTPError(http.StatusNotFound, core.ErrBypassNotFound.Error())
	}

	slog.Warn("Auth bypass rule removed", "admin", admin, "rule", raw)
	core.LogAudit("ADMIN_BYPASS_RULE_DELETE", admin, c.RealIP(), map[string]interface{}{"rule": raw})
	return c.Redirect(http.StatusFound, "/rauthmgmt?success=bypass_deleted#bypass")
}
