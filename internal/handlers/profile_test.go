package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"rauth/internal/core"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp/totp"
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

func TestProfileHandler_DisableTOTP(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{
		ServerSecret: "32byte-secret-key-for-testing-!!",
	}
	h := &ProfileHandler{Cfg: cfg}
	e := echo.New()

	key, _ := totp.Generate(totp.GenerateOpts{
		Issuer:      "RAuth",
		AccountName: "testuser@example.com",
	})
	secret := key.Secret()
	encryptedSecret := core.Encrypt2FASecret(secret, cfg.ServerSecret)

	core.UserDB.HSet(core.Ctx, "user:totpuser", map[string]interface{}{
		"username":   "totpuser",
		"2fa_secret": encryptedSecret,
	})

	t.Run("Successfully disable TOTP", func(t *testing.T) {
		code, _ := totp.GenerateCode(secret, time.Now())

		f := make(url.Values)
		f.Set("otp_code", code)

		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/disable-totp", f)
		c.Set("username", "totpuser")

		err := h.DisableTOTP(c)
		assert.NoError(t, err)

		// The handler returns a redirect wrapped in a redirect method. Check rec.Code or err
		assert.Equal(t, http.StatusFound, rec.Code)

		// Verify TOTP is disabled
		userData, _ := core.UserDB.HGetAll(core.Ctx, "user:totpuser").Result()
		assert.Equal(t, "", userData["2fa_secret"])
	})

	t.Run("Fail with invalid code", func(t *testing.T) {
		// Reset TOTP secret
		core.UserDB.HSet(core.Ctx, "user:totpuser", "2fa_secret", encryptedSecret)

		f := make(url.Values)
		f.Set("otp_code", "000000")

		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/disable-totp", f)
		c.Set("username", "totpuser")

		err := h.DisableTOTP(c)
		assert.NoError(t, err) // It returns c.JSON() which returns nil error but sets HTTP status
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("Success when TOTP is already disabled", func(t *testing.T) {
		core.UserDB.HSet(core.Ctx, "user:totpuser", "2fa_secret", "")

		f := make(url.Values)
		// No code provided

		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/disable-totp", f)
		c.Set("username", "totpuser")

		err := h.DisableTOTP(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
	})
}
