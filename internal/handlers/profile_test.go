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
	h := &ProfileHandler{Cfg: &core.Config{}}
	e := echo.New()

	core.UserDB.Del(core.Ctx, "user:testuser:webauthn_creds")
	core.UserDB.RPush(core.Ctx, "user:testuser:webauthn_creds", `{"ID":"AQID","Nickname":"oldname"}`)

	t.Run("Rename successful", func(t *testing.T) {
		f := make(url.Values)
		f.Set("id", "010203") // Hex for AQID base64
		f.Set("nickname", "newname")
		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/passkey/rename", f)
		c.Set("username", "testuser")

		err := h.RenamePasskey(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		credsJSON, _ := core.UserDB.LRange(core.Ctx, "user:testuser:webauthn_creds", 0, -1).Result()
		assert.Contains(t, credsJSON[0], "newname")
	})

	t.Run("Missing parameters", func(t *testing.T) {
		f := make(url.Values)
		f.Set("id", "010203")
		// Missing nickname
		c, _ := createTestContext(e, http.MethodPost, "/rauthprofile/passkey/rename", f)
		c.Set("username", "testuser")

		err := h.RenamePasskey(c)
		assert.Error(t, err)
		if he, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusBadRequest, he.Code)
		}
	})
}

func TestProfileHandler_RevokePasskey(t *testing.T) {
	setupHandlersTest(t)
	h := &ProfileHandler{Cfg: &core.Config{}}
	e := echo.New()

	core.UserDB.Del(core.Ctx, "user:testuser:webauthn_creds")
	core.UserDB.RPush(core.Ctx, "user:testuser:webauthn_creds", `{"ID":"AQID","Nickname":"key1"}`)
	core.UserDB.RPush(core.Ctx, "user:testuser:webauthn_creds", `{"ID":"BAUG","Nickname":"key2"}`)

	t.Run("Revoke successful", func(t *testing.T) {
		f := make(url.Values)
		f.Set("id", "010203")
		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/passkey/revoke", f)
		c.Set("username", "testuser")

		err := h.RevokePasskey(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		credsJSON, _ := core.UserDB.LRange(core.Ctx, "user:testuser:webauthn_creds", 0, -1).Result()
		assert.Equal(t, 1, len(credsJSON))
		assert.NotContains(t, credsJSON[0], "010203")
		assert.Contains(t, credsJSON[0], "BAUG")
	})

	t.Run("Missing parameter", func(t *testing.T) {
		f := make(url.Values)
		c, _ := createTestContext(e, http.MethodPost, "/rauthprofile/passkey/revoke", f)
		c.Set("username", "testuser")

		err := h.RevokePasskey(c)
		assert.Error(t, err)
		if he, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusBadRequest, he.Code)
		}
	})
}

func TestProfileHandler_DisableTOTP(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{
		ServerSecret:              "testsecret1234567890123456789012",
		RateLimitLoginFailUserMax: 1000,
	}
	h := &ProfileHandler{Cfg: cfg}
	e := echo.New()

	secret := "JBSWY3DPEHPK3PXP" // Valid base32 secret
	encryptedSecret := core.Encrypt2FASecret(secret, cfg.ServerSecret)

	core.UserDB.HSet(core.Ctx, "user:testuser", "2fa_secret", encryptedSecret)
	core.UserDB.HSet(core.Ctx, "user:nototp", "2fa_secret", "")

	t.Run("Disable successful with no TOTP configured", func(t *testing.T) {
		f := make(url.Values)
		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/disable-totp", f)
		c.Set("username", "nototp")

		err := h.DisableTOTP(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
	})

	t.Run("Disable fails without code when TOTP is configured", func(t *testing.T) {
		f := make(url.Values)
		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/disable-totp", f)
		c.Set("username", "testuser")

		err := h.DisableTOTP(c)
		assert.NoError(t, err) // JSON error response, not echo error
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("Disable fails with invalid code", func(t *testing.T) {
		f := make(url.Values)
		f.Set("otp_code", "000000")
		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/disable-totp", f)
		c.Set("username", "testuser")

		err := h.DisableTOTP(c)
		assert.NoError(t, err) // JSON error response
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestProfileHandler_TerminateAllOtherSessions(t *testing.T) {
	setupHandlersTest(t)
	h := &ProfileHandler{Cfg: &core.Config{}}
	e := echo.New()

	core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken=current_token", "username", "testuser")
	core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken=other_token", "username", "testuser")
	core.TokenDB.SAdd(core.Ctx, "user_sessions:testuser", "current_token", "other_token")

	t.Run("Terminate other sessions", func(t *testing.T) {
		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/session/terminate-others", nil)
		c.Set("username", "testuser")
		c.Set("token", "current_token")

		err := h.TerminateAllOtherSessions(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		members, _ := core.TokenDB.SMembers(core.Ctx, "user_sessions:testuser").Result()
		assert.Contains(t, members, "current_token")
		assert.NotContains(t, members, "other_token")

		exists1, _ := core.TokenDB.Exists(core.Ctx, "X-rauth-authtoken=current_token").Result()
		assert.Equal(t, int64(1), exists1)

		exists2, _ := core.TokenDB.Exists(core.Ctx, "X-rauth-authtoken=other_token").Result()
		assert.Equal(t, int64(0), exists2)
	})
}

func TestProfileHandler_validateTOTP(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{
		ServerSecret:              "testsecret1234567890123456789012",
		RateLimitLoginFailUserMax: 3,
	}
	h := &ProfileHandler{Cfg: cfg}

	secret := "JBSWY3DPEHPK3PXP"
	encryptedSecret := core.Encrypt2FASecret(secret, cfg.ServerSecret)

	t.Run("Missing code", func(t *testing.T) {
		err := h.validateTOTP("testuser", "", encryptedSecret)
		assert.NotNil(t, err)
		assert.Equal(t, http.StatusBadRequest, err.Code)
	})

	t.Run("Rate limit exceeded", func(t *testing.T) {
		core.RateLimitDB.Set(core.Ctx, "rate_limit:2fa_fail_user:limiteduser", 4, 0)
		err := h.validateTOTP("limiteduser", "123456", encryptedSecret)
		assert.NotNil(t, err)
		assert.Equal(t, http.StatusTooManyRequests, err.Code)
	})
}
