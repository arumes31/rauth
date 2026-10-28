package handlers

import (
	"log/slog"
	"net/http"
	"rauth/internal/core"
	"strings"

	"github.com/labstack/echo/v4"
)

// bypassRuleView is what the admin dashboard renders for a bypass rule.
type bypassRuleView struct {
	core.BypassRule
	Scope string
}

func bypassRuleViews() []bypassRuleView {
	rules := core.ListBypassRules()
	views := make([]bypassRuleView, len(rules))
	for i, r := range rules {
		views[i] = bypassRuleView{BypassRule: r, Scope: core.DescribeBypassRule(r)}
	}
	return views
}

// AddBypassRule creates a UI-managed auth bypass rule. Opening an application
// to anonymous access is high impact, so it requires a fresh step-up (TOTP
// code, or current password for admins without TOTP) on top of the admin
// session, and is audit-logged.
func (h *AdminHandler) AddBypassRule(c echo.Context) error {
	admin := c.Get("username").(string)
	if herr := verifyStepUp(h.Cfg, admin, c.FormValue("otp_code"), c.FormValue("current_password")); herr != nil {
		return herr
	}

	rule, err := core.AddBypassRule(c.FormValue("rule"), c.FormValue("note"), admin)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	slog.Warn("Auth bypass rule added", "admin", admin, "rule", rule.Rule)
	core.LogAudit("ADMIN_BYPASS_RULE_ADD", admin, c.RealIP(), map[string]interface{}{"rule": rule.Rule, "scope": core.DescribeBypassRule(rule)})
	return c.Redirect(http.StatusFound, "/rauthmgmt?success=bypass_added#bypass")
}

// DeleteBypassRule removes a UI-managed auth bypass rule (also step-up gated,
// so a hijacked admin session cannot silently reshape access either way).
func (h *AdminHandler) DeleteBypassRule(c echo.Context) error {
	admin := c.Get("username").(string)
	if herr := verifyStepUp(h.Cfg, admin, c.FormValue("otp_code"), c.FormValue("current_password")); herr != nil {
		return herr
	}

	raw := strings.TrimSpace(c.FormValue("rule"))
	existed, err := core.DeleteBypassRule(raw)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if !existed {
		return echo.NewHTTPError(http.StatusNotFound, "Rule not found (rules from AUTH_BYPASS_RULES can only be changed in the environment)")
	}

	slog.Warn("Auth bypass rule removed", "admin", admin, "rule", raw)
	core.LogAudit("ADMIN_BYPASS_RULE_DELETE", admin, c.RealIP(), map[string]interface{}{"rule": raw})
	return c.Redirect(http.StatusFound, "/rauthmgmt?success=bypass_deleted#bypass")
}
