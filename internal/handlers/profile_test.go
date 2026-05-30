package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"rauth/internal/core"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestProfileHandler_Show(t *testing.T) {
	setupHandlersTest(t)
	h := &ProfileHandler{Cfg: &core.Config{}}
	e := echo.New()
	e.Renderer = &mockRenderer{}

	t.Run("View Profile", func(t *testing.T) {
		c, rec := createTestContext(e, http.MethodGet, "/rauthprofile", nil)
		c.Set("username", "profileuser")
		c.Set("token", "testtoken")

		err := h.Show(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("Logs are filtered by username", func(t *testing.T) {
		core.LogAudit("MY_ACTION", "profileuser", "1.1.1.1", nil)
		core.LogAudit("OTHER_ACTION", "otheruser", "2.2.2.2", nil)

		c, _ := createTestContext(e, http.MethodGet, "/rauthprofile", nil)
		c.Set("username", "profileuser")
		c.Set("token", "testtoken")

		renderer := &mockRenderer{}
		e.Renderer = renderer

		err := h.Show(c)
		assert.NoError(t, err)

		data := renderer.LastData.(map[string]interface{})
		logs := data["logs"].([]core.AuditLog)

		for _, log := range logs {
			assert.Equal(t, "profileuser", log.Username)
			assert.NotEqual(t, "OTHER_ACTION", log.Action)
		}
	})
}

func TestProfileHandler_TerminateSession(t *testing.T) {
	setupHandlersTest(t)
	h := &ProfileHandler{Cfg: &core.Config{}}
	e := echo.New()

	t.Run("Successfully terminate own session", func(t *testing.T) {
		token := "my-session-token"
		core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+token, "username", "profileuser")

		f := make(url.Values)
		f.Set("token", token)

		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/session/terminate", f)
		c.Set("username", "profileuser")

		err := h.TerminateSession(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		// Verify session is gone
		exists, _ := core.TokenDB.Exists(core.Ctx, "X-rauth-authtoken="+token).Result()
		assert.Equal(t, int64(0), exists)
	})

	t.Run("Fail to terminate others session", func(t *testing.T) {
		token := "others-session-token"
		core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+token, "username", "otheruser")

		f := make(url.Values)
		f.Set("token", token)

		c, _ := createTestContext(e, http.MethodPost, "/rauthprofile/session/terminate", f)
		c.Set("username", "profileuser")

		err := h.TerminateSession(c)
		assert.Error(t, err)
		echoErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusForbidden, echoErr.Code)
	})
}

func TestProfileHandler_ChangePassword(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{
		MinPasswordLength: 8,
		CookieDomains:     []string{"example.com"},
	}
	h := &ProfileHandler{Cfg: cfg}
	e := echo.New()

	password := "oldpassword"
	hash, _ := core.HashPassword(password)
	core.UserDB.HSet(core.Ctx, "user:passuser", "password", hash)

	t.Run("Successful password change", func(t *testing.T) {
		f := make(url.Values)
		f.Set("current_password", password)
		f.Set("new_password", "NewSecure123!")
		f.Set("confirm_password", "NewSecure123!")

		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/password", f)
		c.Set("username", "passuser")

		err := h.ChangePassword(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		// Verify new password
		newData, _ := core.UserDB.HGet(core.Ctx, "user:passuser", "password").Result()
		assert.True(t, core.CheckPasswordHash("NewSecure123!", newData))
	})

	t.Run("Incorrect current password", func(t *testing.T) {
		f := make(url.Values)
		f.Set("current_password", "wrong")
		f.Set("new_password", "NewSecure123!")
		f.Set("confirm_password", "NewSecure123!")

		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/password", f)
		c.Set("username", "passuser")

		err := h.ChangePassword(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var resp map[string]string
		err = json.Unmarshal(rec.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Contains(t, resp["error"], "incorrect")
	})

	t.Run("Password mismatch", func(t *testing.T) {
		f := make(url.Values)
		f.Set("current_password", password)
		f.Set("new_password", "NewSecure123!")
		f.Set("confirm_password", "mismatch")

		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/password", f)
		c.Set("username", "passuser")

		err := h.ChangePassword(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestProfileHandler_RenamePasskey(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{}
	h := &ProfileHandler{Cfg: cfg}
	e := echo.New()

	tests := []struct {
		name         string
		id           string
		nickname     string
		expectedCode int
	}{
		{"Rename successful", "cred123", "new_nick", http.StatusFound},
		{"Rename missing id", "", "new_nick", http.StatusBadRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := make(url.Values)
			if tc.id != "" {
				f.Set("id", tc.id)
			}
			f.Set("nickname", tc.nickname)

			c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/passkey/rename", f)
			c.Set("username", "profileuser")

			err := h.RenamePasskey(c)
			if err != nil {
				if he, ok := err.(*echo.HTTPError); ok {
					assert.Equal(t, tc.expectedCode, he.Code)
				} else {
					t.Errorf("expected echo.HTTPError")
				}
			} else {
				assert.Equal(t, tc.expectedCode, rec.Code)
			}
		})
	}
}

func TestProfileHandler_RevokePasskey(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{}
	h := &ProfileHandler{Cfg: cfg}
	e := echo.New()

	tests := []struct {
		name         string
		id           string
		expectedCode int
	}{
		{"Revoke successful", "cred123", http.StatusFound},
		{"Revoke missing id", "", http.StatusBadRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := make(url.Values)
			if tc.id != "" {
				f.Set("id", tc.id)
			}
			c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/passkey/revoke", f)
			c.Set("username", "profileuser")

			err := h.RevokePasskey(c)
			if err != nil {
				if he, ok := err.(*echo.HTTPError); ok {
					assert.Equal(t, tc.expectedCode, he.Code)
				} else {
					t.Errorf("expected echo.HTTPError")
				}
			} else {
				assert.Equal(t, tc.expectedCode, rec.Code)
			}
		})
	}
}

func TestProfileHandler_DisableTOTP(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{}
	h := &ProfileHandler{Cfg: cfg}
	e := echo.New()

	core.UserDB.HSet(core.Ctx, "user:totpuser", "username", "totpuser")

	t.Run("Disable TOTP successful", func(t *testing.T) {
		f := make(url.Values)

		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/disable-totp", f)
		c.Set("username", "totpuser")

		err := h.DisableTOTP(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
	})
}

func TestProfileHandler_TerminateAllOtherSessions(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{}
	h := &ProfileHandler{Cfg: cfg}
	e := echo.New()

	t.Run("Terminate all other sessions", func(t *testing.T) {
		f := make(url.Values)
		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/session/terminate-others", f)
		c.Set("username", "multiuser")
		c.Set("token", "current-token")

		err := h.TerminateAllOtherSessions(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
	})
}

func TestProfileHandler_validateTOTP(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{
		RateLimitLoginFailUserMax: 100,
	}
	h := &ProfileHandler{Cfg: cfg}

	tests := []struct {
		name         string
		code         string
		expectedCode int
	}{
		{"Empty code", "", http.StatusBadRequest},
		{"Invalid code", "123456", http.StatusBadRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := h.validateTOTP("totpuser", tc.code, "enc-secret")
			assert.NotNil(t, err)
			assert.Equal(t, tc.expectedCode, err.Code)
		})
	}
}
