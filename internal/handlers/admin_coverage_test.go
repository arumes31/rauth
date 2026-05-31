package handlers

import (
	"net/http"
	"net/url"
	"rauth/internal/core"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func adminTestCfg() *core.Config {
	return &core.Config{
		MinPasswordLength:         8,
		RateLimitLoginFailUserMax: 1000,
	}
}

func TestAdminHandler_ResetUser2FA(t *testing.T) {
	setupHandlersTest(t)
	h := &AdminHandler{Cfg: adminTestCfg()}
	e := echo.New()

	t.Run("Empty username", func(t *testing.T) {
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/reset2fa", url.Values{})
		c.Set("username", "admin")
		err := h.ResetUser2FA(c)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code)
	})

	t.Run("Cannot reset own 2FA", func(t *testing.T) {
		f := url.Values{}
		f.Set("username", "admin")
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/reset2fa", f)
		c.Set("username", "admin")
		err := h.ResetUser2FA(c)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code)
	})

	t.Run("Reset other user 2FA", func(t *testing.T) {
		core.UserDB.HSet(core.Ctx, "user:victim", map[string]interface{}{
			"username":   "victim",
			"2fa_secret": "enc:something",
		})
		f := url.Values{}
		f.Set("username", "victim")
		c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/reset2fa", f)
		c.Set("username", "admin")
		err := h.ResetUser2FA(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		secret, _ := core.UserDB.HGet(core.Ctx, "user:victim", "2fa_secret").Result()
		assert.Equal(t, "", secret)
	})
}

func TestAdminHandler_ChangeUserPassword(t *testing.T) {
	setupHandlersTest(t)
	h := &AdminHandler{Cfg: adminTestCfg()}
	e := echo.New()

	t.Run("Missing fields", func(t *testing.T) {
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/password", url.Values{})
		c.Set("username", "admin")
		err := h.ChangeUserPassword(c)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code)
	})

	t.Run("Cannot change own password", func(t *testing.T) {
		f := url.Values{}
		f.Set("username", "admin")
		f.Set("new_password", "SecurePass123!")
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/password", f)
		c.Set("username", "admin")
		err := h.ChangeUserPassword(c)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code)
	})

	t.Run("Weak password rejected", func(t *testing.T) {
		f := url.Values{}
		f.Set("username", "victim")
		f.Set("new_password", "short")
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/password", f)
		c.Set("username", "admin")
		err := h.ChangeUserPassword(c)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code)
	})

	t.Run("Valid password change", func(t *testing.T) {
		core.UserDB.HSet(core.Ctx, "user:victim2", "username", "victim2")
		f := url.Values{}
		f.Set("username", "victim2")
		f.Set("new_password", "SecurePass123!")
		c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/password", f)
		c.Set("username", "admin")
		err := h.ChangeUserPassword(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		hash, _ := core.UserDB.HGet(core.Ctx, "user:victim2", "password").Result()
		assert.True(t, core.CheckPasswordHash("SecurePass123!", hash))
	})
}

func TestAdminHandler_UpdateUserEmail(t *testing.T) {
	setupHandlersTest(t)
	h := &AdminHandler{Cfg: adminTestCfg()}
	e := echo.New()

	t.Run("Missing fields", func(t *testing.T) {
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/email", url.Values{})
		c.Set("username", "admin")
		err := h.UpdateUserEmail(c)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code)
	})

	t.Run("Invalid email", func(t *testing.T) {
		f := url.Values{}
		f.Set("username", "victim")
		f.Set("new_email", "not-an-email")
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/email", f)
		c.Set("username", "admin")
		err := h.UpdateUserEmail(c)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code)
	})

	t.Run("Valid email update", func(t *testing.T) {
		core.UserDB.HSet(core.Ctx, "user:victim3", "username", "victim3")
		f := url.Values{}
		f.Set("username", "victim3")
		f.Set("new_email", "updated@example.com")
		c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/email", f)
		c.Set("username", "admin")
		err := h.UpdateUserEmail(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		email, _ := core.UserDB.HGet(core.Ctx, "user:victim3", "email").Result()
		assert.Equal(t, "updated@example.com", email)
	})
}
