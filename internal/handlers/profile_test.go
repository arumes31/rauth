package handlers

import (
	"github.com/pquerna/otp/totp"
	"time"

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

func TestProfileHandler_GenerateRecoveryCodes(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{
		ServerSecret: "test-server-secret-key-1234567890",
	}
	h := &ProfileHandler{Cfg: cfg}
	e := echo.New()
	e.Renderer = &mockRenderer{}

	// Setup a user with TOTP
	username := "recoveryuser"

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "rauth",
		AccountName: username,
	})
	assert.NoError(t, err)

	secret := key.Secret()
	encryptedSecret := core.Encrypt2FASecret(secret, cfg.ServerSecret)

	core.UserDB.HSet(core.Ctx, "user:"+username, "password", "hashedpass", "2fa_secret", encryptedSecret)

	t.Run("Generate successful", func(t *testing.T) {
		code, _ := totp.GenerateCode(secret, time.Now())
		f := make(url.Values)
		f.Set("otp_code", code)

		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/recovery-codes", f)
		c.Set("username", username)

		err := h.GenerateRecoveryCodes(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

		// Check renderer
		renderer := e.Renderer.(*mockRenderer)
		data := renderer.LastData.(map[string]interface{})

		assert.Equal(t, username, data["username"])
		codes, ok := data["codes"].([]string)
		assert.True(t, ok)
		assert.Len(t, codes, 10)

		// Check DB
		dbCodes, _ := core.UserDB.SMembers(core.Ctx, "user:"+username+":recovery_codes").Result()
		assert.Len(t, dbCodes, 10)
	})

	t.Run("Missing OTP code", func(t *testing.T) {
		f := make(url.Values)

		c, _ := createTestContext(e, http.MethodPost, "/rauthprofile/recovery-codes", f)
		c.Set("username", username)

		err := h.GenerateRecoveryCodes(c)
		assert.Error(t, err)

		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
		assert.Contains(t, httpErr.Message, "2FA code required")
	})

	t.Run("Invalid OTP code", func(t *testing.T) {
		f := make(url.Values)
		f.Set("otp_code", "000000")

		c, _ := createTestContext(e, http.MethodPost, "/rauthprofile/recovery-codes", f)
		c.Set("username", username)

		err := h.GenerateRecoveryCodes(c)
		assert.Error(t, err)

		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
		assert.Contains(t, httpErr.Message, "Invalid 2FA code")
	})

	t.Run("Reused OTP code", func(t *testing.T) {
		code, _ := totp.GenerateCode(secret, time.Now())

		// First use
		f1 := make(url.Values)
		f1.Set("otp_code", code)
		c1, _ := createTestContext(e, http.MethodPost, "/rauthprofile/recovery-codes", f1)
		c1.Set("username", username)
		_ = h.GenerateRecoveryCodes(c1)

		// Second use
		f2 := make(url.Values)
		f2.Set("otp_code", code)
		c2, _ := createTestContext(e, http.MethodPost, "/rauthprofile/recovery-codes", f2)
		c2.Set("username", username)

		err := h.GenerateRecoveryCodes(c2)
		assert.Error(t, err)

		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
		assert.Contains(t, httpErr.Message, "already used")
	})

	t.Run("TOTP not enabled", func(t *testing.T) {
		core.UserDB.HSet(core.Ctx, "user:nototp", "password", "hashedpass")

		f := make(url.Values)
		f.Set("otp_code", "123456")

		c, _ := createTestContext(e, http.MethodPost, "/rauthprofile/recovery-codes", f)
		c.Set("username", "nototp")

		err := h.GenerateRecoveryCodes(c)
		assert.Error(t, err)

		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
		assert.Contains(t, httpErr.Message, "Enable TOTP before")
	})

	t.Run("User not found", func(t *testing.T) {
		f := make(url.Values)
		f.Set("otp_code", "123456")

		c, _ := createTestContext(e, http.MethodPost, "/rauthprofile/recovery-codes", f)
		c.Set("username", "nonexistent")

		err := h.GenerateRecoveryCodes(c)
		assert.Error(t, err)

		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
		assert.Contains(t, httpErr.Message, "Enable TOTP before") // HGetAll on non-existent returns empty map
	})
}
