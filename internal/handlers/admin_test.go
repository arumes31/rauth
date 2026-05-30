package handlers

import (
	"net/http"
	"net/url"
	"rauth/internal/core"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestAdminHandler_Dashboard(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{
		RateLimitLoginMax:         1000,
		RateLimitLoginDecay:       60,
		RateLimitLoginAccessMax:   1000,
		RateLimitLoginFailUserMax: 1000,
		RateLimitLoginFailIPMax:   1000,
	}
	h := &AdminHandler{Cfg: cfg}
	e := echo.New()
	e.Renderer = &mockRenderer{}

	t.Run("Access Dashboard", func(t *testing.T) {
		c, rec := createTestContext(e, http.MethodGet, "/rauthmgmt", nil)
		c.Set("username", "admin")

		err := h.Dashboard(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestAdminHandler_InvalidateSession(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{
		RateLimitLoginMax:         1000,
		RateLimitLoginDecay:       60,
		RateLimitLoginAccessMax:   1000,
		RateLimitLoginFailUserMax: 1000,
		RateLimitLoginFailIPMax:   1000,
	}
	h := &AdminHandler{Cfg: cfg}
	e := echo.New()

	t.Run("Invalidate active session", func(t *testing.T) {
		token := "session-to-kill"
		core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+token, "username", "victim")

		f := make(url.Values)
		f.Set("token", token)
		c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/session/invalidate", f)
		c.Set("username", "admin")

		err := h.InvalidateSession(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		exists := core.TokenDB.Exists(core.Ctx, "X-rauth-authtoken="+token).Val()
		assert.Equal(t, int64(0), exists)
	})
}

func TestAdminHandler_CreateUser(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{
		MinPasswordLength:         8,
		RateLimitLoginMax:         1000,
		RateLimitLoginDecay:       60,
		RateLimitLoginAccessMax:   1000,
		RateLimitLoginFailUserMax: 1000,
		RateLimitLoginFailIPMax:   1000,
	}
	h := &AdminHandler{Cfg: cfg}
	e := echo.New()

	t.Run("Create valid user", func(t *testing.T) {
		f := make(url.Values)
		f.Set("new_username", "brandnew")
		f.Set("new_password", "SecurePass123!")
		f.Set("new_email", "new@example.com")

		c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/create", f)
		c.Set("username", "admin")

		err := h.CreateUser(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		exists := core.UserDB.Exists(core.Ctx, "user:brandnew").Val()
		assert.Equal(t, int64(1), exists)
	})

	t.Run("Create user - invalid password", func(t *testing.T) {
		f := make(url.Values)
		f.Set("new_username", "invalid")
		f.Set("new_password", "short")

		c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/create", f)
		c.Set("username", "admin")

		err := h.CreateUser(c)
		// It returns 400 Bad Request if password is too short
		if err != nil {
			if he, ok := err.(*echo.HTTPError); ok {
				assert.Equal(t, http.StatusBadRequest, he.Code)
			}
		} else {
			assert.Equal(t, http.StatusBadRequest, rec.Code)
		}

		exists := core.UserDB.Exists(core.Ctx, "user:invalid").Val()
		assert.Equal(t, int64(0), exists)
	})

	t.Run("Create user - duplicate", func(t *testing.T) {
		core.UserDB.HSet(core.Ctx, "user:duplicate", "username", "duplicate")

		f := make(url.Values)
		f.Set("new_username", "duplicate")
		f.Set("new_password", "SecurePass123!")

		c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/create", f)
		c.Set("username", "admin")

		err := h.CreateUser(c)
		if err != nil {
			if he, ok := err.(*echo.HTTPError); ok {
				assert.Equal(t, http.StatusBadRequest, he.Code)
			}
		} else {
			assert.Equal(t, http.StatusBadRequest, rec.Code)
		}
	})
}

func TestAdminHandler_DeleteUser(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{
		RateLimitLoginMax:         1000,
		RateLimitLoginDecay:       60,
		RateLimitLoginAccessMax:   1000,
		RateLimitLoginFailUserMax: 1000,
		RateLimitLoginFailIPMax:   1000,
	}
	h := &AdminHandler{Cfg: cfg}
	e := echo.New()

	t.Run("Delete other user", func(t *testing.T) {
		core.UserDB.HSet(core.Ctx, "user:victim", "username", "victim")
		core.UserDB.SAdd(core.Ctx, "users", "victim")

		f := make(url.Values)
		f.Set("username", "victim")
		c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/delete", f)
		c.Set("username", "admin")

		err := h.DeleteUser(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		exists := core.UserDB.Exists(core.Ctx, "user:victim").Val()
		assert.Equal(t, int64(0), exists)
	})

	t.Run("Delete self - should fail", func(t *testing.T) {
		core.UserDB.HSet(core.Ctx, "user:admin", "username", "admin")

		f := make(url.Values)
		f.Set("username", "admin")
		c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/delete", f)
		c.Set("username", "admin")

		err := h.DeleteUser(c)
		if err != nil {
			if he, ok := err.(*echo.HTTPError); ok {
				assert.Equal(t, http.StatusBadRequest, he.Code)
			}
		} else {
			assert.Equal(t, http.StatusBadRequest, rec.Code)
		}

		exists := core.UserDB.Exists(core.Ctx, "user:admin").Val()
		assert.Equal(t, int64(1), exists)
	})
}
func TestAdminHandler_CreateUser_InvalidUsername(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{
		MinPasswordLength:      8,
		RequirePasswordUpper:   true,
		RequirePasswordLower:   true,
		RequirePasswordNumber:  true,
		RequirePasswordSpecial: true,
	}
	h := &AdminHandler{Cfg: cfg}
	e := echo.New()

	testCases := []struct {
		name     string
		username string
		expected string
	}{
		{"TooShort", "ab", "username must be between 3 and 32 characters long"},
		{"TooLong", "thisusernameiswaytoolongtoobeallowedbyrauth", "username must be between 3 and 32 characters long"},
		{"InvalidChars", "user!name", "username can only contain alphanumeric characters, dots, underscores, and hyphens"},
		{"Spaces", "user name", "username can only contain alphanumeric characters, dots, underscores, and hyphens"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := make(url.Values)
			f.Set("new_username", tc.username)
			f.Set("new_password", "Password123!")
			c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/create", f)
			c.Set("username", "admin")

			err := h.CreateUser(c)
			if err != nil {
				if he, ok := err.(*echo.HTTPError); ok {
					assert.Equal(t, http.StatusBadRequest, he.Code)
					assert.Contains(t, he.Message, tc.expected)
				} else {
					t.Errorf("expected echo.HTTPError, got %T", err)
				}
			} else {
				assert.Equal(t, http.StatusBadRequest, rec.Code)
			}
		})
	}
}

func TestAdminHandler_ExtendedValidation(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{
		MinPasswordLength:      8,
		RequirePasswordUpper:   true,
		RequirePasswordLower:   true,
		RequirePasswordNumber:  true,
		RequirePasswordSpecial: true,
	}
	h := &AdminHandler{Cfg: cfg}
	e := echo.New()

	t.Run("DeleteUser - NonExistent", func(t *testing.T) {
		f := make(url.Values)
		f.Set("username", "no-such-user")
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/delete", f)
		c.Set("username", "admin")

		err := h.DeleteUser(c)
		if he, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusNotFound, he.Code)
		} else {
			t.Errorf("expected 404 error, got %v", err)
		}
	})

	t.Run("ResetUser2FA - Success", func(t *testing.T) {
		core.UserDB.HSet(core.Ctx, "user:victim", "username", "victim", "2fa_secret", "secret")
		core.UserDB.SAdd(core.Ctx, "users", "victim")

		f := make(url.Values)
		f.Set("username", " victim ") // Testing TrimSpace
		c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/reset2fa", f)
		c.Set("username", "admin")

		err := h.ResetUser2FA(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		user, _ := core.GetUser("victim")
		assert.Empty(t, user.TwoFactor)
	})

	t.Run("ChangeUserPassword - InvalidUsername", func(t *testing.T) {
		f := make(url.Values)
		f.Set("username", "user!name")
		f.Set("new_password", "Password123!")
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/password", f)
		c.Set("username", "admin")

		err := h.ChangeUserPassword(c)
		if he, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusBadRequest, he.Code)
			assert.Contains(t, he.Message, "can only contain alphanumeric")
		} else {
			t.Errorf("expected 400 error, got %v", err)
		}
	})

	t.Run("UpdateUserEmail - Success", func(t *testing.T) {
		core.UserDB.HSet(core.Ctx, "user:victim", "username", "victim", "email", "old@example.com")

		f := make(url.Values)
		f.Set("username", "victim")
		f.Set("new_email", "new@example.com")
		c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/email", f)
		c.Set("username", "admin")

		err := h.UpdateUserEmail(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		user, _ := core.GetUser("victim")
		assert.Equal(t, "new@example.com", user.Email)
	})
}
