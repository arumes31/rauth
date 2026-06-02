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
	cfg := &core.Config{}
	h := &AdminHandler{Cfg: cfg}
	e := echo.New()

	testCases := []struct {
		name         string
		targetUser   string
		setupDB      func()
		expectError  bool
		expectedCode int
		verify       func(t *testing.T)
	}{
		{
			name:       "Reset other user 2FA",
			targetUser: "victim",
			setupDB: func() {
				core.UserDB.HSet(core.Ctx, "user:victim", "username", "victim", "2fa_secret", "secret")
			},
			expectError:  false,
			expectedCode: http.StatusFound,
			verify: func(t *testing.T) {
				val := core.UserDB.HGet(core.Ctx, "user:victim", "2fa_secret").Val()
				assert.Equal(t, "", val)
			},
		},
		{
			name:       "Reset self 2FA",
			targetUser: "admin",
			setupDB: func() {
				core.UserDB.HSet(core.Ctx, "user:admin", "username", "admin", "2fa_secret", "secret")
			},
			expectError:  true,
			expectedCode: http.StatusBadRequest,
			verify: func(t *testing.T) {
				val := core.UserDB.HGet(core.Ctx, "user:admin", "2fa_secret").Val()
				assert.Equal(t, "secret", val)
			},
		},
		{
			name:         "Missing username",
			targetUser:   "",
			setupDB:      func() {},
			expectError:  true,
			expectedCode: http.StatusBadRequest,
			verify:       func(t *testing.T) {},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setupDB()
			f := make(url.Values)
			if tc.targetUser != "" {
				f.Set("username", tc.targetUser)
			}
			c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/reset2fa", f)
			c.Set("username", "admin")

			err := h.ResetUser2FA(c)
			if tc.expectError {
				if err != nil {
					if he, ok := err.(*echo.HTTPError); ok {
						assert.Equal(t, tc.expectedCode, he.Code)
					}
				} else {
					assert.Equal(t, tc.expectedCode, rec.Code)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedCode, rec.Code)
			}
			tc.verify(t)
		})
	}
}

func TestAdminHandler_ChangeUserPassword(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{
		MinPasswordLength: 8,
	}
	h := &AdminHandler{Cfg: cfg}
	e := echo.New()

	testCases := []struct {
		name         string
		targetUser   string
		newPass      string
		setupDB      func()
		expectError  bool
		expectedCode int
		verify       func(t *testing.T)
	}{
		{
			name:       "Change other user password",
			targetUser: "victim",
			newPass:    "NewSecurePass123!",
			setupDB: func() {
				core.UserDB.HSet(core.Ctx, "user:victim", "username", "victim", "password", "oldhash")
			},
			expectError:  false,
			expectedCode: http.StatusFound,
			verify: func(t *testing.T) {
				val := core.UserDB.HGet(core.Ctx, "user:victim", "password").Val()
				assert.NotEqual(t, "oldhash", val)
				assert.NotEmpty(t, val)
			},
		},
		{
			name:       "Change self password",
			targetUser: "admin",
			newPass:    "NewSecurePass123!",
			setupDB: func() {
				core.UserDB.HSet(core.Ctx, "user:admin", "username", "admin", "password", "oldhash")
			},
			expectError:  true,
			expectedCode: http.StatusBadRequest,
			verify: func(t *testing.T) {
				val := core.UserDB.HGet(core.Ctx, "user:admin", "password").Val()
				assert.Equal(t, "oldhash", val)
			},
		},
		{
			name:         "Missing username or password",
			targetUser:   "victim",
			newPass:      "",
			setupDB:      func() {},
			expectError:  true,
			expectedCode: http.StatusBadRequest,
			verify:       func(t *testing.T) {},
		},
		{
			name:         "Invalid new password",
			targetUser:   "victim",
			newPass:      "short",
			setupDB:      func() {},
			expectError:  true,
			expectedCode: http.StatusBadRequest,
			verify:       func(t *testing.T) {},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setupDB()
			f := make(url.Values)
			if tc.targetUser != "" {
				f.Set("username", tc.targetUser)
			}
			if tc.newPass != "" {
				f.Set("new_password", tc.newPass)
			}
			c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/password", f)
			c.Set("username", "admin")

			err := h.ChangeUserPassword(c)
			if tc.expectError {
				if err != nil {
					if he, ok := err.(*echo.HTTPError); ok {
						assert.Equal(t, tc.expectedCode, he.Code)
					}
				} else {
					assert.Equal(t, tc.expectedCode, rec.Code)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedCode, rec.Code)
			}
			tc.verify(t)
		})
	}
}

func TestAdminHandler_UpdateUserEmail(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{}
	h := &AdminHandler{Cfg: cfg}
	e := echo.New()

	testCases := []struct {
		name         string
		targetUser   string
		newEmail     string
		setupDB      func()
		expectError  bool
		expectedCode int
		verify       func(t *testing.T)
	}{
		{
			name:       "Update user email",
			targetUser: "victim",
			newEmail:   "new@example.com",
			setupDB: func() {
				core.UserDB.HSet(core.Ctx, "user:victim", "username", "victim", "email", "old@example.com")
			},
			expectError:  false,
			expectedCode: http.StatusFound,
			verify: func(t *testing.T) {
				val := core.UserDB.HGet(core.Ctx, "user:victim", "email").Val()
				assert.Equal(t, "new@example.com", val)
			},
		},
		{
			name:       "Invalid email",
			targetUser: "victim",
			newEmail:   "invalid-email",
			setupDB: func() {
				core.UserDB.HSet(core.Ctx, "user:victim", "username", "victim", "email", "old@example.com")
			},
			expectError:  true,
			expectedCode: http.StatusBadRequest,
			verify: func(t *testing.T) {
				val := core.UserDB.HGet(core.Ctx, "user:victim", "email").Val()
				assert.Equal(t, "old@example.com", val)
			},
		},
		{
			name:         "Missing username or email",
			targetUser:   "victim",
			newEmail:     "",
			setupDB:      func() {},
			expectError:  true,
			expectedCode: http.StatusBadRequest,
			verify:       func(t *testing.T) {},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setupDB()
			f := make(url.Values)
			if tc.targetUser != "" {
				f.Set("username", tc.targetUser)
			}
			if tc.newEmail != "" {
				f.Set("new_email", tc.newEmail)
			}
			c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/email", f)
			c.Set("username", "admin")

			err := h.UpdateUserEmail(c)
			if tc.expectError {
				if err != nil {
					if he, ok := err.(*echo.HTTPError); ok {
						assert.Equal(t, tc.expectedCode, he.Code)
					}
				} else {
					assert.Equal(t, tc.expectedCode, rec.Code)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedCode, rec.Code)
			}
			tc.verify(t)
		})
	}
}
