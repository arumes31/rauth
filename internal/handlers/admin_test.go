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

func TestAdminHandler_ResetUser2FA(t *testing.T) {
	setupHandlersTest(t)
	h := &AdminHandler{Cfg: &core.Config{}}
	e := echo.New()

	core.UserDB.HSet(core.Ctx, "user:testuser", "2fa_secret", "secret_value")

	t.Run("Reset successful", func(t *testing.T) {
		f := make(url.Values)
		f.Set("username", "testuser")
		c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/reset-2fa", f)
		c.Set("username", "admin")

		err := h.ResetUser2FA(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		val, _ := core.UserDB.HGet(core.Ctx, "user:testuser", "2fa_secret").Result()
		assert.Equal(t, "", val)
	})

	t.Run("Missing username", func(t *testing.T) {
		f := make(url.Values)
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/reset-2fa", f)
		c.Set("username", "admin")

		err := h.ResetUser2FA(c)
		assert.Error(t, err)
		if he, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusBadRequest, he.Code)
		}
	})

	t.Run("Reset self not allowed", func(t *testing.T) {
		f := make(url.Values)
		f.Set("username", "admin")
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/reset-2fa", f)
		c.Set("username", "admin")

		err := h.ResetUser2FA(c)
		assert.Error(t, err)
		if he, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusBadRequest, he.Code)
		}
	})
}

func TestAdminHandler_ChangeUserPassword(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{
		MinPasswordLength: 8,
	}
	h := &AdminHandler{Cfg: cfg}
	e := echo.New()

	core.UserDB.HSet(core.Ctx, "user:testuser", "password", "old_hash")

	t.Run("Change password successful", func(t *testing.T) {
		f := make(url.Values)
		f.Set("username", "testuser")
		f.Set("new_password", "NewPass123!")
		c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/change-password", f)
		c.Set("username", "admin")

		err := h.ChangeUserPassword(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		newHash, _ := core.UserDB.HGet(core.Ctx, "user:testuser", "password").Result()
		assert.NotEqual(t, "old_hash", newHash)
		assert.True(t, core.CheckPasswordHash("NewPass123!", newHash))
	})

	t.Run("Missing parameters", func(t *testing.T) {
		f := make(url.Values)
		f.Set("username", "testuser")
		// Missing new_password
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/change-password", f)
		c.Set("username", "admin")

		err := h.ChangeUserPassword(c)
		assert.Error(t, err)
		if he, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusBadRequest, he.Code)
		}
	})

	t.Run("Change self not allowed", func(t *testing.T) {
		f := make(url.Values)
		f.Set("username", "admin")
		f.Set("new_password", "NewPass123!")
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/change-password", f)
		c.Set("username", "admin")

		err := h.ChangeUserPassword(c)
		assert.Error(t, err)
		if he, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusBadRequest, he.Code)
		}
	})

	t.Run("Invalid password format", func(t *testing.T) {
		f := make(url.Values)
		f.Set("username", "testuser")
		f.Set("new_password", "short")
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/change-password", f)
		c.Set("username", "admin")

		err := h.ChangeUserPassword(c)
		assert.Error(t, err)
		if he, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusBadRequest, he.Code)
		}
	})
}

func TestAdminHandler_UpdateUserEmail(t *testing.T) {
	setupHandlersTest(t)
	h := &AdminHandler{Cfg: &core.Config{}}
	e := echo.New()

	core.UserDB.HSet(core.Ctx, "user:testuser", "email", "old@example.com")

	t.Run("Update email successful", func(t *testing.T) {
		f := make(url.Values)
		f.Set("username", "testuser")
		f.Set("new_email", "new@example.com")
		c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/update-email", f)
		c.Set("username", "admin")

		err := h.UpdateUserEmail(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		val, _ := core.UserDB.HGet(core.Ctx, "user:testuser", "email").Result()
		assert.Equal(t, "new@example.com", val)
	})

	t.Run("Missing parameters", func(t *testing.T) {
		f := make(url.Values)
		f.Set("username", "testuser")
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/update-email", f)
		c.Set("username", "admin")

		err := h.UpdateUserEmail(c)
		assert.Error(t, err)
		if he, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusBadRequest, he.Code)
		}
	})

	t.Run("Invalid email format", func(t *testing.T) {
		f := make(url.Values)
		f.Set("username", "testuser")
		f.Set("new_email", "not-an-email")
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/update-email", f)
		c.Set("username", "admin")

		err := h.UpdateUserEmail(c)
		assert.Error(t, err)
		if he, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusBadRequest, he.Code)
		}
	})
}
