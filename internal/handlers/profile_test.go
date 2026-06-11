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

	t.Run("Keeps current session, invalidates others", func(t *testing.T) {
		hash, _ := core.HashPassword(password)
		core.UserDB.HSet(core.Ctx, "user:passuser2", "password", hash)
		core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken=cur", "status", "valid", "username", "passuser2")
		core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken=other", "status", "valid", "username", "passuser2")
		core.AddSessionIndex("passuser2", "cur")
		core.AddSessionIndex("passuser2", "other")

		f := make(url.Values)
		f.Set("current_password", password)
		f.Set("new_password", "NewSecure123!")
		f.Set("confirm_password", "NewSecure123!")

		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/password", f)
		c.Set("username", "passuser2")
		c.Set("token", "cur")

		err := h.ChangePassword(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		curExists, _ := core.TokenDB.Exists(core.Ctx, "X-rauth-authtoken=cur").Result()
		otherExists, _ := core.TokenDB.Exists(core.Ctx, "X-rauth-authtoken=other").Result()
		assert.EqualValues(t, 1, curExists, "current session must survive a password change")
		assert.EqualValues(t, 0, otherExists, "other sessions must be invalidated")
	})
}


func TestProfileHandler_GenerateRecoveryCodes(t *testing.T) {
	setupHandlersTest(t)
	h := &ProfileHandler{Cfg: &core.Config{ServerSecret: "01234567890123456789012345678901"}}
	e := echo.New()

	t.Run("Generate recovery codes missing 2fa", func(t *testing.T) {
		core.UserDB.Del(core.Ctx, "user:profileuser")

		f := make(url.Values)
		f.Set("otp_code", "123456")

		c, _ := createTestContext(e, http.MethodPost, "/rauthprofile/recovery", f)
		c.Set("username", "profileuser")

		err := h.GenerateRecoveryCodes(c)
		assert.Error(t, err)
		he, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, he.Code)
	})
}

func TestProfileHandler_RenamePasskey(t *testing.T) {
	setupHandlersTest(t)
	h := &ProfileHandler{Cfg: &core.Config{}}
	e := echo.New()

	t.Run("Rename passkey successfully", func(t *testing.T) {
		f := make(url.Values)
		f.Set("id", "dGVzdGlk")
		f.Set("nickname", "New Name")

		c, _ := createTestContext(e, http.MethodPost, "/rauthprofile/passkeys/rename", f)
		c.Set("username", "profileuser")

		// Pre-populate credential properly mapped
        core.UserDB.HSet(core.Ctx, "user:profileuser:webauthn_creds_v2", "dGVzdGlk", `{"id":"dGVzdGlk","publicKey":"","attestationType":"","authenticator":{"aaguid":"","signCount":0,"cloneWarning":false}}`)


		err := h.RenamePasskey(c)
		assert.NoError(t, err)
	})
}

func TestProfileHandler_RevokePasskey(t *testing.T) {
	setupHandlersTest(t)
	h := &ProfileHandler{Cfg: &core.Config{}}
	e := echo.New()

	t.Run("Revoke passkey successfully", func(t *testing.T) {
		f := make(url.Values)
		f.Set("id", "dGVzdGlk")

		c, _ := createTestContext(e, http.MethodPost, "/rauthprofile/passkeys/revoke", f)
		c.Set("username", "profileuser")

		core.UserDB.HSet(core.Ctx, "user:profileuser:webauthn_creds_v2", "dGVzdGlk", `{"id":"dGVzdGlk","publicKey":"","attestationType":"","authenticator":{"aaguid":"","signCount":0,"cloneWarning":false}}`)

		err := h.RevokePasskey(c)
		assert.NoError(t, err)
	})
}

func TestProfileHandler_DisableTOTP(t *testing.T) {
	setupHandlersTest(t)
	h := &ProfileHandler{Cfg: &core.Config{}}
	e := echo.New()

	t.Run("Disable TOTP missing secret", func(t *testing.T) {
		core.UserDB.Del(core.Ctx, "user:profileuser")

		f := make(url.Values)
		f.Set("otp_code", "123456")

		c, _ := createTestContext(e, http.MethodPost, "/rauthprofile/2fa/disable", f)
		c.Set("username", "profileuser")

		err := h.DisableTOTP(c)
		assert.NoError(t, err)
	})
}

func TestProfileHandler_TerminateAllOtherSessions(t *testing.T) {
	setupHandlersTest(t)
	h := &ProfileHandler{Cfg: &core.Config{}}
	e := echo.New()

	t.Run("Terminate other sessions successfully", func(t *testing.T) {
        pwd := "SecurePass123!"
        hashedPwd, _ := core.HashPassword(pwd)

		f := make(url.Values)
		f.Set("password", pwd)

		c, _ := createTestContext(e, http.MethodPost, "/rauthprofile/sessions/terminate", f)
		c.Set("username", "profileuser")
		c.Set("token", "currenttoken")

		core.UserDB.HSet(core.Ctx, "user:profileuser", "password", string(hashedPwd))
		core.TokenDB.SAdd(core.Ctx, "user_sessions:profileuser", "currenttoken", "othertoken")
		core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken=othertoken", "status", "valid")

		err := h.TerminateAllOtherSessions(c)
		assert.NoError(t, err)

		assert.False(t, core.TokenDB.SIsMember(core.Ctx, "user_sessions:profileuser", "othertoken").Val())
		assert.True(t, core.TokenDB.SIsMember(core.Ctx, "user_sessions:profileuser", "currenttoken").Val())
	})
}

func TestProfileHandler_validateTOTP(t *testing.T) {
	setupHandlersTest(t)
	h := &ProfileHandler{Cfg: &core.Config{}}

	t.Run("Missing OTP", func(t *testing.T) {
		err := h.validateTOTP("user", "", "secret")
		assert.Error(t, err)
	})
}
