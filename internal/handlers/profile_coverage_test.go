package handlers

import (
	"net/http"
	"net/url"
	"rauth/internal/core"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testTOTPSecret = "JBSWY3DPEHPK3PXP"

// profileTestCfg returns a config with a server secret and sane rate-limit
// values so validateTOTP's rate-limit guard does not trip on the first attempt.
func profileTestCfg() *core.Config {
	return &core.Config{
		ServerSecret:                "test-server-secret",
		MinPasswordLength:           8,
		RateLimitLoginFailUserMax:   5,
		RateLimitLoginFailUserDecay: 60,
	}
}

// seedTOTPUser stores a user with an encrypted TOTP secret and returns a valid
// current code for that secret.
func seedTOTPUser(t *testing.T, cfg *core.Config, username string) string {
	t.Helper()
	enc := core.Encrypt2FASecret(testTOTPSecret, cfg.ServerSecret)
	core.UserDB.HSet(core.Ctx, "user:"+username, map[string]interface{}{
		"username":   username,
		"2fa_secret": enc,
		"email":      username + "@example.com",
	})
	code, err := totp.GenerateCode(testTOTPSecret, time.Now())
	require.NoError(t, err)
	return code
}

func TestProfileHandler_GenerateRecoveryCodes(t *testing.T) {
	setupHandlersTest(t)
	cfg := profileTestCfg()
	h := &ProfileHandler{Cfg: cfg}
	e := echo.New()
	e.Renderer = &mockRenderer{}

	t.Run("No TOTP enabled returns 400", func(t *testing.T) {
		core.UserDB.HSet(core.Ctx, "user:no2fa", "username", "no2fa")
		c, _ := createTestContext(e, http.MethodPost, "/rauthprofile/recovery", nil)
		c.Set("username", "no2fa")

		err := h.GenerateRecoveryCodes(c)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code)
	})

	t.Run("Valid code generates codes", func(t *testing.T) {
		code := seedTOTPUser(t, cfg, "recuser")
		f := url.Values{}
		f.Set("otp_code", code)
		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/recovery", f)
		c.Set("username", "recuser")

		err := h.GenerateRecoveryCodes(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

		// Recovery codes were persisted.
		assert.Greater(t, core.CountRecoveryCodes("recuser"), int64(0))
	})

	t.Run("Reused code is rejected", func(t *testing.T) {
		code := seedTOTPUser(t, cfg, "reuser")
		f := url.Values{}
		f.Set("otp_code", code)

		c1, _ := createTestContext(e, http.MethodPost, "/rauthprofile/recovery", f)
		c1.Set("username", "reuser")
		require.NoError(t, h.GenerateRecoveryCodes(c1))

		// Second submission of the same code is blocked by replay protection.
		c2, _ := createTestContext(e, http.MethodPost, "/rauthprofile/recovery", f)
		c2.Set("username", "reuser")
		err := h.GenerateRecoveryCodes(c2)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code)
	})
}

func TestProfileHandler_validateTOTP(t *testing.T) {
	setupHandlersTest(t)
	cfg := profileTestCfg()
	h := &ProfileHandler{Cfg: cfg}
	enc := core.Encrypt2FASecret(testTOTPSecret, cfg.ServerSecret)

	t.Run("Empty code", func(t *testing.T) {
		err := h.validateTOTP("u", "", enc)
		require.NotNil(t, err)
		assert.Equal(t, http.StatusBadRequest, err.Code)
	})

	t.Run("Invalid code", func(t *testing.T) {
		err := h.validateTOTP("u", "000000", enc)
		require.NotNil(t, err)
		assert.Equal(t, http.StatusBadRequest, err.Code)
	})

	t.Run("Valid code", func(t *testing.T) {
		code, _ := totp.GenerateCode(testTOTPSecret, time.Now())
		err := h.validateTOTP("validu", code, enc)
		assert.Nil(t, err)
	})
}

func TestProfileHandler_RenamePasskey(t *testing.T) {
	setupHandlersTest(t)
	h := &ProfileHandler{Cfg: profileTestCfg()}
	e := echo.New()

	t.Run("Missing fields returns 400", func(t *testing.T) {
		c, _ := createTestContext(e, http.MethodPost, "/rauthprofile/passkey/rename", url.Values{})
		c.Set("username", "pk")
		err := h.RenamePasskey(c)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code)
	})

	t.Run("Valid rename redirects", func(t *testing.T) {
		f := url.Values{}
		f.Set("id", "deadbeef")
		f.Set("nickname", "My Key")
		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/passkey/rename", f)
		c.Set("username", "pk")
		err := h.RenamePasskey(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
	})
}

func TestProfileHandler_RevokePasskey(t *testing.T) {
	setupHandlersTest(t)
	h := &ProfileHandler{Cfg: profileTestCfg()}
	e := echo.New()

	t.Run("Missing id returns 400", func(t *testing.T) {
		c, _ := createTestContext(e, http.MethodPost, "/rauthprofile/passkey/revoke", url.Values{})
		c.Set("username", "pk")
		err := h.RevokePasskey(c)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code)
	})

	t.Run("Valid revoke redirects and notifies", func(t *testing.T) {
		core.UserDB.HSet(core.Ctx, "user:pkuser", map[string]interface{}{
			"username": "pkuser",
			"email":    "pkuser@example.com",
		})
		f := url.Values{}
		f.Set("id", "deadbeef")
		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/passkey/revoke", f)
		c.Set("username", "pkuser")
		err := h.RevokePasskey(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
	})
}

func TestProfileHandler_DisableTOTP(t *testing.T) {
	setupHandlersTest(t)
	cfg := profileTestCfg()
	h := &ProfileHandler{Cfg: cfg}
	e := echo.New()

	t.Run("Invalid code returns JSON error", func(t *testing.T) {
		seedTOTPUser(t, cfg, "dis1")
		f := url.Values{}
		f.Set("otp_code", "000000")
		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/totp/disable", f)
		c.Set("username", "dis1")
		err := h.DisableTOTP(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("Valid code disables TOTP", func(t *testing.T) {
		code := seedTOTPUser(t, cfg, "dis2")
		f := url.Values{}
		f.Set("otp_code", code)
		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/totp/disable", f)
		c.Set("username", "dis2")
		err := h.DisableTOTP(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		secret, _ := core.UserDB.HGet(core.Ctx, "user:dis2", "2fa_secret").Result()
		assert.Equal(t, "", secret)
	})
}

func TestProfileHandler_TerminateAllOtherSessions(t *testing.T) {
	setupHandlersTest(t)
	h := &ProfileHandler{Cfg: profileTestCfg()}
	e := echo.New()

	core.AddSessionIndex("multiuser", "keep")
	core.AddSessionIndex("multiuser", "drop")
	core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken=keep", "username", "multiuser")
	core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken=drop", "username", "multiuser")

	c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/sessions/terminate-all", nil)
	c.Set("username", "multiuser")
	c.Set("token", "keep")

	err := h.TerminateAllOtherSessions(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, rec.Code)

	exists, _ := core.TokenDB.Exists(core.Ctx, "X-rauth-authtoken=drop").Result()
	assert.Equal(t, int64(0), exists)
}
