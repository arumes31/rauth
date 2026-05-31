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

func TestProfileHandler_Show_WithSessions(t *testing.T) {
	setupHandlersTest(t)
	h := &ProfileHandler{Cfg: profileTestCfg()}
	e := echo.New()
	renderer := &mockRenderer{}
	e.Renderer = renderer

	username := "showuser"
	core.UserDB.HSet(core.Ctx, "user:"+username, map[string]interface{}{
		"username": username,
		"email":    "show@example.com",
		"groups":   "default",
		"is_admin": "1",
	})

	// A live session that should be rendered.
	core.AddSessionIndex(username, "live-token")
	core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken=live-token", map[string]interface{}{
		"username":   username,
		"ip":         "10.0.0.9",
		"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		"status":     "valid",
	})
	core.TokenDB.Expire(core.Ctx, "X-rauth-authtoken=live-token", time.Hour)

	// A stale index entry whose token no longer exists -> pruned in the loop.
	core.AddSessionIndex(username, "stale-token")

	c, rec := createTestContext(e, http.MethodGet, "/rauthprofile", nil)
	c.Set("username", username)
	c.Set("token", "live-token")

	err := h.Show(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	data := renderer.LastData.(map[string]interface{})
	sessions := data["sessions"].([]map[string]string)
	require.Len(t, sessions, 1)
	assert.Equal(t, "1", sessions[0]["is_current"])
	assert.NotEmpty(t, sessions[0]["friendly_ua"])

	// Stale index entry was cleaned up.
	members, _ := core.TokenDB.SMembers(core.Ctx, "user_sessions:"+username).Result()
	assert.NotContains(t, members, "stale-token")
}

func TestProfileHandler_ChangePassword_2FA(t *testing.T) {
	setupHandlersTest(t)
	cfg := profileTestCfg()
	cfg.CookieDomains = []string{"example.com"}
	h := &ProfileHandler{Cfg: cfg}
	e := echo.New()

	password := "oldpassword"
	hash, _ := core.HashPassword(password)
	enc := core.Encrypt2FASecret(testTOTPSecret, cfg.ServerSecret)
	core.UserDB.HSet(core.Ctx, "user:2fauser", map[string]interface{}{
		"username":   "2fauser",
		"password":   hash,
		"2fa_secret": enc,
		"email":      "2fauser@example.com",
	})

	t.Run("Valid password change with 2FA", func(t *testing.T) {
		code, _ := totp.GenerateCode(testTOTPSecret, time.Now())
		f := url.Values{}
		f.Set("current_password", password)
		f.Set("new_password", "NewSecure123!")
		f.Set("confirm_password", "NewSecure123!")
		f.Set("otp_code", code)

		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/password", f)
		c.Set("username", "2fauser")

		err := h.ChangePassword(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
	})

	t.Run("Wrong 2FA code rejected", func(t *testing.T) {
		f := url.Values{}
		f.Set("current_password", "NewSecure123!") // password from prior subtest
		f.Set("new_password", "AnotherPass123!")
		f.Set("confirm_password", "AnotherPass123!")
		f.Set("otp_code", "000000")

		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/password", f)
		c.Set("username", "2fauser")

		err := h.ChangePassword(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestProfileHandler_ChangePassword_RateLimited(t *testing.T) {
	setupHandlersTest(t)
	cfg := profileTestCfg()
	cfg.RateLimitLoginFailUserMax = 1
	cfg.CookieDomains = []string{"example.com"}
	h := &ProfileHandler{Cfg: cfg}
	e := echo.New()

	hash, _ := core.HashPassword("oldpassword")
	core.UserDB.HSet(core.Ctx, "user:rluser", map[string]interface{}{
		"username": "rluser",
		"password": hash,
	})

	// Exhaust the per-user failed-login budget so the next attempt is throttled.
	core.CheckRateLimit("login_fail_user:rluser", cfg.RateLimitLoginFailUserMax, cfg.RateLimitLoginFailUserDecay)

	f := url.Values{}
	f.Set("current_password", "whatever")
	f.Set("new_password", "NewSecure123!")
	f.Set("confirm_password", "NewSecure123!")
	c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/password", f)
	c.Set("username", "rluser")

	err := h.ChangePassword(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
}
