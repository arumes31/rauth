package handlers

import (
	"net/http"
	"net/url"
	"rauth/internal/core"
	"rauth/internal/middleware"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdminHandler_Dashboard(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{
		InitialUser:               "owner",
		RateLimitLoginMax:         1000,
		RateLimitLoginDecay:       60,
		RateLimitLoginAccessMax:   1000,
		RateLimitLoginFailUserMax: 1000,
		RateLimitLoginFailIPMax:   1000,
	}
	h := &AdminHandler{Cfg: cfg}
	e := echo.New()
	renderer := &mockRenderer{}
	e.Renderer = renderer

	t.Run("Access Dashboard", func(t *testing.T) {
		c, rec := createTestContext(e, http.MethodGet, "/rauthmgmt", nil)
		c.Set("username", "admin")

		err := h.Dashboard(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		data, ok := renderer.LastData.(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "owner", data["root_user"])
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

		exists := userExistsN(t, "brandnew")
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

		exists := userExistsN(t, "invalid")
		assert.Equal(t, int64(0), exists)
	})

	t.Run("Create user - duplicate", func(t *testing.T) {
		seedUserFields(t, "duplicate", map[string]interface{}{"username": "duplicate"})

		f := make(url.Values)
		f.Set("new_username", "duplicate")
		f.Set("new_password", "SecurePass123!")

		c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/create", f)
		c.Set("username", "admin")

		err := h.CreateUser(c)
		if err != nil {
			if he, ok := err.(*echo.HTTPError); ok {
				assert.Equal(t, http.StatusConflict, he.Code)
			}
		} else {
			assert.Equal(t, http.StatusConflict, rec.Code)
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
		seedUserFields(t, "victim", map[string]interface{}{"username": "victim"})

		f := make(url.Values)
		f.Set("username", "victim")
		c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/delete", f)
		c.Set("username", "admin")

		err := h.DeleteUser(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		exists := userExistsN(t, "victim")
		assert.Equal(t, int64(0), exists)
	})

	t.Run("Delete self - should fail", func(t *testing.T) {
		seedUserFields(t, "admin", map[string]interface{}{"username": "admin"})

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

		exists := userExistsN(t, "admin")
		assert.Equal(t, int64(1), exists)
	})
}

func TestAdminHandler_DeleteUserPermissions(t *testing.T) {
	cases := []struct {
		name        string
		root        string
		actor       string
		actorAdmin  string
		target      string
		targetAdmin string
		wantStatus  int
	}{
		{"delete user", "admin", "operator", "1", "member", "0", http.StatusFound},
		{"delete another admin", "admin", "operator", "1", "peeradmin", "1", http.StatusFound},
		{"root deletes another admin", "admin", "admin", "1", "peeradmin", "1", http.StatusFound},
		{"protect default root", "admin", "operator", "1", "admin", "1", http.StatusForbidden},
		{"protect configured root", "owner", "operator", "1", "owner", "1", http.StatusForbidden},
		{"protect root with surrounding whitespace", "owner", "operator", "1", " owner ", "1", http.StatusForbidden},
		{"root cannot delete itself", "owner", "owner", "1", "owner", "1", http.StatusForbidden},
		{"non-root admin cannot delete itself", "owner", "operator", "1", "operator", "1", http.StatusBadRequest},
		{"default name is deletable with custom root", "owner", "operator", "1", "admin", "1", http.StatusFound},
		{"non-admin cannot delete users", "admin", "member", "0", "victim", "0", http.StatusForbidden},
		{"non-admin cannot delete admins", "admin", "member", "0", "peeradmin", "1", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupHandlersTest(t)
			target := strings.TrimSpace(tc.target)
			seedUserFields(t, tc.actor, map[string]interface{}{"is_admin": tc.actorAdmin})
			seedUserFields(t, target, map[string]interface{}{"is_admin": tc.targetAdmin})
			require.NoError(t, core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken=target-session", "username", target, "status", "valid").Err())
			core.AddSessionIndex(target, "target-session")
			h := &AdminHandler{Cfg: &core.Config{InitialUser: tc.root}}
			e := echo.New()
			c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/delete", url.Values{"username": {tc.target}})
			c.Set("username", tc.actor)
			if err := middleware.AdminMiddleware(h.DeleteUser)(c); err != nil {
				e.HTTPErrorHandler(err, c)
			}
			require.Equal(t, tc.wantStatus, rec.Code)
			wantExists := int64(1)
			if tc.wantStatus == http.StatusFound {
				wantExists = 0
				assert.Equal(t, "/rauthmgmt?success=user_deleted", rec.Header().Get(echo.HeaderLocation))
			}
			assert.Equal(t, wantExists, userExistsN(t, target))
			assert.Equal(t, wantExists == 1, (userExistsN(t, target) == 1))
			assert.Equal(t, wantExists, core.TokenDB.Exists(core.Ctx, "X-rauth-authtoken=target-session").Val())
		})
	}
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

func TestAdminHandler_ChangeUserPassword_Full(t *testing.T) {
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

	t.Run("Success", func(t *testing.T) {
		// Seed user
		seedUserFields(t, "targetuser", map[string]interface{}{"username": "targetuser", "password": "oldhash"})

		// Create a dummy session for the user
		sessionToken := "target_session_token"
		core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+sessionToken, "username", "targetuser")
		core.TokenDB.SAdd(core.Ctx, "user_sessions:targetuser", sessionToken)

		f := make(url.Values)
		f.Set("username", "targetuser")
		f.Set("new_password", "NewStrongPass1!")

		c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/user/op", f)
		c.Set("username", "adminuser")

		err := h.ChangeUserPassword(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/rauthmgmt?success=password_changed", rec.Header().Get("Location"))

		// Verify the password was updated
		newHash := userField(t, "targetuser", "password")
		assert.NotEqual(t, "oldhash", newHash)
		assert.True(t, core.CheckPasswordHash("NewStrongPass1!", newHash))

		// Verify the session was invalidated
		exists, _ := core.TokenDB.Exists(core.Ctx, "X-rauth-authtoken="+sessionToken).Result()
		assert.Equal(t, int64(0), exists, "Session should be invalidated")
	})

	t.Run("Missing Username", func(t *testing.T) {
		f := make(url.Values)
		f.Set("username", "")
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/op", f)
		c.Set("username", "adminuser")

		err := h.ChangeUserPassword(c)
		he := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusBadRequest, he.Code)
		assert.Contains(t, he.Message.(string), "Username is required")
	})

	t.Run("Invalid Username", func(t *testing.T) {
		f := make(url.Values)
		f.Set("username", "ab")
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/op", f)
		c.Set("username", "adminuser")

		err := h.ChangeUserPassword(c)
		he := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusBadRequest, he.Code)
		assert.Contains(t, he.Message.(string), "username must be between 3 and 32 characters long")
	})

	t.Run("User Not Found", func(t *testing.T) {
		f := make(url.Values)
		f.Set("username", "notfound")
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/op", f)
		c.Set("username", "adminuser")

		err := h.ChangeUserPassword(c)
		he := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusNotFound, he.Code)
		assert.Contains(t, he.Message.(string), "User not found")
	})

	t.Run("Missing Password", func(t *testing.T) {
		seedUserFields(t, "exists", map[string]interface{}{"username": "exists"})

		f := make(url.Values)
		f.Set("username", "exists")
		f.Set("new_password", "")
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/op", f)
		c.Set("username", "adminuser")

		err := h.ChangeUserPassword(c)
		he := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusBadRequest, he.Code)
		assert.Contains(t, he.Message.(string), "Password is required")
	})

	t.Run("Change Own Password", func(t *testing.T) {
		seedUserFields(t, "adminuser", map[string]interface{}{"username": "adminuser"})

		f := make(url.Values)
		f.Set("username", "adminuser")
		f.Set("new_password", "Secure123!")
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/op", f)
		c.Set("username", "adminuser")

		err := h.ChangeUserPassword(c)
		he := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusBadRequest, he.Code)
		assert.Contains(t, he.Message.(string), "Cannot change your own password")
	})

	t.Run("Weak Password", func(t *testing.T) {
		f := make(url.Values)
		f.Set("username", "exists")
		f.Set("new_password", "weak")
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/op", f)
		c.Set("username", "adminuser")

		err := h.ChangeUserPassword(c)
		he := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusBadRequest, he.Code)
		assert.Contains(t, he.Message.(string), "password must be at least")
	})
}

func TestAdminHandler_UserOperations_Validation(t *testing.T) {
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

	// Seed some users
	seedUserFields(t, "exists", map[string]interface{}{"username": "exists"})
	seedUserFields(t, "adminuser", map[string]interface{}{"username": "adminuser"})

	testCases := []struct {
		name         string
		method       string
		handler      func(echo.Context) error
		username     string
		extraKey     string
		extraValue   string
		expectedCode int
		expectedMsg  string
	}{
		// DeleteUser
		{"Delete_InvalidFormat", "POST", h.DeleteUser, "ab", "", "", http.StatusBadRequest, "username must be between 3 and 32 characters long"},
		{"Delete_NotFound", "POST", h.DeleteUser, "notfound", "", "", http.StatusNotFound, "User not found"},
		{"Delete_Self", "POST", h.DeleteUser, "adminuser", "", "", http.StatusBadRequest, "Cannot delete yourself"},

		// ResetUser2FA
		{"Reset2FA_InvalidFormat", "POST", h.ResetUser2FA, "ab", "", "", http.StatusBadRequest, "username must be between 3 and 32 characters long"},
		{"Reset2FA_NotFound", "POST", h.ResetUser2FA, "notfound", "", "", http.StatusNotFound, "User not found"},
		{"Reset2FA_Self", "POST", h.ResetUser2FA, "adminuser", "", "", http.StatusBadRequest, "Cannot reset your own 2FA"},

		// ChangeUserPassword
		{"ChangePass_InvalidFormat", "POST", h.ChangeUserPassword, "ab", "new_password", "Secure123!", http.StatusBadRequest, "username must be between 3 and 32 characters long"},
		{"ChangePass_NotFound", "POST", h.ChangeUserPassword, "notfound", "new_password", "Secure123!", http.StatusNotFound, "User not found"},
		{"ChangePass_MissingPass", "POST", h.ChangeUserPassword, "exists", "new_password", "", http.StatusBadRequest, "Password is required"},
		{"ChangePass_WeakPass", "POST", h.ChangeUserPassword, "exists", "new_password", "weak", http.StatusBadRequest, "password must be at least"},
		{"ChangePass_Self", "POST", h.ChangeUserPassword, "adminuser", "new_password", "Secure123!", http.StatusBadRequest, "Cannot change your own password"},

		// UpdateUserEmail
		{"UpdateEmail_InvalidFormat", "POST", h.UpdateUserEmail, "ab", "new_email", "new@example.com", http.StatusBadRequest, "username must be between 3 and 32 characters long"},
		{"UpdateEmail_NotFound", "POST", h.UpdateUserEmail, "notfound", "new_email", "new@example.com", http.StatusNotFound, "User not found"},
		{"UpdateEmail_MissingEmail", "POST", h.UpdateUserEmail, "exists", "new_email", "", http.StatusBadRequest, "Email is required"},
		{"UpdateEmail_InvalidEmail", "POST", h.UpdateUserEmail, "exists", "new_email", "invalid", http.StatusBadRequest, "invalid email format"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := make(url.Values)
			f.Set("username", tc.username)
			if tc.extraKey != "" {
				f.Set(tc.extraKey, tc.extraValue)
			}

			c, rec := createTestContext(e, tc.method, "/rauthmgmt/user/op", f)
			c.Set("username", "adminuser")

			err := tc.handler(c)
			if err != nil {
				if he, ok := err.(*echo.HTTPError); ok {
					assert.Equal(t, tc.expectedCode, he.Code)
					assert.Contains(t, he.Message.(string), tc.expectedMsg)
				} else {
					t.Errorf("expected echo.HTTPError, got %T", err)
				}
			} else {
				assert.Equal(t, tc.expectedCode, rec.Code)
			}
		})
	}
}
