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

func TestAdminHandler_RobustValidation(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{
		MinPasswordLength: 8,
	}
	h := &AdminHandler{Cfg: cfg}
	e := echo.New()

	// Seed an admin and a regular user
	core.UserDB.HSet(core.Ctx, "user:admin", "username", "admin")
	core.UserDB.SAdd(core.Ctx, "users", "admin")
	core.UserDB.HSet(core.Ctx, "user:victim", "username", "victim")
	core.UserDB.SAdd(core.Ctx, "users", "victim")

	t.Run("UpdateUserEmail Table", func(t *testing.T) {
		testCases := []struct {
			name     string
			target   string
			email    string
			expected int
		}{
			{"Success", "victim", "new@example.com", http.StatusFound},
			{"InvalidFormat", "victim", "not-an-email", http.StatusBadRequest},
			{"NonExistent", "nonexistent", "valid@example.com", http.StatusBadRequest},
			{"InvalidUsernameFormat", "user!name", "valid@example.com", http.StatusBadRequest},
			{"EmptyEmail", "victim", "", http.StatusBadRequest},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				f := make(url.Values)
				f.Set("username", tc.target)
				f.Set("new_email", tc.email)
				c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/update-email", f)
				c.Set("username", "admin")

				err := h.UpdateUserEmail(c)
				if err != nil {
					if he, ok := err.(*echo.HTTPError); ok {
						assert.Equal(t, tc.expected, he.Code)
					}
				} else {
					assert.Equal(t, tc.expected, rec.Code)
				}
			})
		}
	})

	t.Run("DeleteUser Table", func(t *testing.T) {
		// Re-seed victim just in case
		core.UserDB.HSet(core.Ctx, "user:victim", "username", "victim", "uid", "v-uid")
		core.UserDB.SAdd(core.Ctx, "users", "victim")

		testCases := []struct {
			name     string
			target   string
			expected int
		}{
			{"Success", "victim", http.StatusFound},
			{"NonExistent", "nobody", http.StatusBadRequest},
			{"InvalidFormat", "bad!user", http.StatusBadRequest},
			{"DeleteSelf", "admin", http.StatusBadRequest},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				f := make(url.Values)
				f.Set("username", tc.target)
				c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/delete", f)
				c.Set("username", "admin")

				err := h.DeleteUser(c)
				if err != nil {
					if he, ok := err.(*echo.HTTPError); ok {
						assert.Equal(t, tc.expected, he.Code)
					}
				} else {
					assert.Equal(t, tc.expected, rec.Code)
				}
			})
		}
	})

	t.Run("ResetUser2FA Table", func(t *testing.T) {
		core.UserDB.HSet(core.Ctx, "user:victim", "username", "victim")
		core.UserDB.SAdd(core.Ctx, "users", "victim")

		testCases := []struct {
			name     string
			target   string
			expected int
		}{
			{"Success", "victim", http.StatusFound},
			{"NonExistent", "nobody", http.StatusBadRequest},
			{"ResetSelf", "admin", http.StatusBadRequest},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				f := make(url.Values)
				f.Set("username", tc.target)
				c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/reset-2fa", f)
				c.Set("username", "admin")

				err := h.ResetUser2FA(c)
				if err != nil {
					if he, ok := err.(*echo.HTTPError); ok {
						assert.Equal(t, tc.expected, he.Code)
					}
				} else {
					assert.Equal(t, tc.expected, rec.Code)
				}
			})
		}
	})

	t.Run("ChangeUserPassword Table", func(t *testing.T) {
		core.UserDB.HSet(core.Ctx, "user:victim", "username", "victim")
		core.UserDB.SAdd(core.Ctx, "users", "victim")

		testCases := []struct {
			name     string
			target   string
			pass     string
			expected int
		}{
			{"Success", "victim", "NewSecurePass123!", http.StatusFound},
			{"WeakPassword", "victim", "short", http.StatusBadRequest},
			{"NonExistent", "nobody", "NewSecurePass123!", http.StatusBadRequest},
			{"ChangeSelf", "admin", "NewSecurePass123!", http.StatusBadRequest},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				f := make(url.Values)
				f.Set("username", tc.target)
				f.Set("new_password", tc.pass)
				c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/change-password", f)
				c.Set("username", "admin")

				err := h.ChangeUserPassword(c)
				if err != nil {
					if he, ok := err.(*echo.HTTPError); ok {
						assert.Equal(t, tc.expected, he.Code)
					}
				} else {
					assert.Equal(t, tc.expected, rec.Code)
				}
			})
		}
	})
}
