package handlers

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/require"
	"rauth/internal/core"
)

func TestSessionManagementReportsBackendFailure(t *testing.T) {
	setupHandlersTest(t)
	seedAccount(t, "management-user")
	require.NoError(t, core.TokenDB.Close())
	e := echo.New()
	e.Renderer = &mockRenderer{}
	profile := &ProfileHandler{Cfg: &core.Config{}}
	admin := &AdminHandler{Cfg: &core.Config{}}
	for _, test := range []struct {
		name, path string
		handler    echo.HandlerFunc
	}{
		{"profile list", "/rauthprofile", profile.Show},
		{"admin list", "/rauthmgmt", admin.Dashboard},
		{"profile revoke", "/rauthprofile/session/terminate", profile.TerminateSession},
		{"admin revoke", "/rauthmgmt/session/invalidate", admin.InvalidateSession},
		{"revoke others", "/rauthprofile/session/terminate-others", profile.TerminateAllOtherSessions},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, _ := createTestContext(e, http.MethodPost, test.path, url.Values{"token": {"missing-session"}})
			c.Set("username", "management-user")
			c.Set("token", "current-session")
			err := test.handler(c)
			require.Error(t, err)
			httpErr, ok := err.(*echo.HTTPError)
			require.True(t, ok)
			require.Equal(t, http.StatusServiceUnavailable, httpErr.Code)
		})
	}
}

func TestCommittedCredentialChangesKeepAuditWhenSessionEnds(t *testing.T) {
	setupHandlersTest(t)
	core.SetBcryptCost(4)
	t.Cleanup(func() { core.SetBcryptCost(12) })
	require.NoError(t, core.CreateUser("changed-user", "OldPassword123!", "", false, ""))
	h := &ProfileHandler{Cfg: &core.Config{MinPasswordLength: 8}}
	e := echo.New()
	c, _ := createTestContext(e, http.MethodPost, "/rauthprofile/password", url.Values{"current_password": {"OldPassword123!"}, "new_password": {"NewPassword123!"}, "confirm_password": {"NewPassword123!"}})
	c.Set("username", "changed-user")
	c.Set("token", "expired-caller")
	err := h.ChangePassword(c)
	require.Error(t, err)
	require.Equal(t, http.StatusUnauthorized, err.(*echo.HTTPError).Code)
	rec, err := core.GetUser("changed-user")
	require.NoError(t, err)
	require.True(t, core.CheckPasswordHash("NewPassword123!", rec.Password))
	c, _ = createTestContext(e, http.MethodPost, "/rauthprofile/2fa/disable", nil)
	c.Set("username", "changed-user")
	c.Set("token", "expired-caller")
	err = h.DisableTOTP(c)
	require.Error(t, err)
	require.Equal(t, http.StatusUnauthorized, err.(*echo.HTTPError).Code)
	logs, err := core.UserAuditLogs("changed-user", 20)
	require.NoError(t, err)
	actions := map[string]bool{}
	for _, entry := range logs {
		actions[entry.Action] = true
	}
	require.True(t, actions["USER_CHANGE_PASSWORD"])
	require.True(t, actions["USER_DISABLE_TOTP"])
}
