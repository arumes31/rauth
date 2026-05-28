package handlers

import (
	"net/http"
	"net/url"
	"os"
	"rauth/internal/core"
	"testing"
	"time"
	"net/smtp"

	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/redis/go-redis/v9"
)

func TestCompleteSetup2FA_Extended(t *testing.T) {
	cfg := &core.Config{
		ServerSecret:              "32byte-secret-key-for-testing-!!",
		CookieDomains:             []string{"example.com"},
		TokenValidityMinutes:      60,
		RateLimitLoginMax:         1000,
		RateLimitLoginDecay:       60,
		RateLimitLoginAccessMax:   1000,
		RateLimitLoginFailUserMax: 1000,
		RateLimitLoginFailIPMax:   5,
		RateLimitLoginFailIPDecay: 60,
	}
	h := &AuthHandler{Cfg: cfg}
	e := echo.New()
	e.Renderer = &mockRenderer{}

	setupPending := func(username, setupToken, secret string) string {
		encryptedToken, _ := core.EncryptToken(setupToken, cfg.ServerSecret)
		core.TokenDB.Set(core.Ctx, "pending_setup:"+setupToken, username, 10*time.Minute)
		core.TokenDB.Set(core.Ctx, "pending_setup_secret:"+setupToken, secret, 5*time.Minute)
		return encryptedToken
	}

	t.Run("Success with Email Notification", func(t *testing.T) {
		setupHandlersTest(t)
		username := "emailuser"
		setupToken := "token-email"
		secret := "JBSWY3DPEHPK3PXP"
		encryptedToken := setupPending(username, setupToken, secret)

		core.UserDB.HSet(core.Ctx, "user:"+username, map[string]interface{}{
			"username": username,
			"email":    "user@example.com",
		})

		// Mock email and bypass check
		assert.NoError(t, os.Setenv("SMTP_HOST", "mock"))
		defer func() { assert.NoError(t, os.Unsetenv("SMTP_HOST")) }()

		var emailSentCount int
		origSendMail := core.TestingSendMail
		core.TestingSendMail = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
			emailSentCount++
			return nil
		}
		defer func() { core.TestingSendMail = origSendMail }()

		code, _ := totp.GenerateCode(secret, time.Now())
		f := make(url.Values)
		f.Set("totp_code", code)

		c, rec := createTestContext(e, http.MethodPost, "/rauthsetup2fa", f)
		c.Request().AddCookie(&http.Cookie{Name: "rauth_setup_pending", Value: encryptedToken})

		err := h.CompleteSetup2FA(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		time.Sleep(100 * time.Millisecond)
		assert.GreaterOrEqual(t, emailSentCount, 1)
	})

	t.Run("Database Error saving 2FA secret", func(t *testing.T) {
		setupHandlersTest(t)
		username := "dbuser"
		setupToken := "token-db"
		secret := "JBSWY3DPEHPK3PXP"
		encryptedToken := setupPending(username, setupToken, secret)

		core.UserDB.HSet(core.Ctx, "user:"+username, "username", username)

		origUserDB := core.UserDB
		core.UserDB = redis.NewClient(&redis.Options{Addr: "localhost:1", MaxRetries: -1})
		defer func() { core.UserDB = origUserDB }()

		code, _ := totp.GenerateCode(secret, time.Now())
		f := make(url.Values)
		f.Set("totp_code", code)

		c, rec := createTestContext(e, http.MethodPost, "/rauthsetup2fa", f)
		c.Request().AddCookie(&http.Cookie{Name: "rauth_setup_pending", Value: encryptedToken})

		err := h.CompleteSetup2FA(c)
		if err != nil {
			he, ok := err.(*echo.HTTPError)
			if ok {
				assert.Equal(t, http.StatusInternalServerError, he.Code)
			} else {
				t.Errorf("Expected HTTPError, got %T", err)
			}
		} else {
			assert.Equal(t, http.StatusInternalServerError, rec.Code)
		}
	})

	t.Run("Failed TOTP - Rate Limit Exceeded (no active sessions)", func(t *testing.T) {
		setupHandlersTest(t)
		username := "rluser"
		setupToken := "token-rl"
		secret := "JBSWY3DPEHPK3PXP"
		encryptedToken := setupPending(username, setupToken, secret)
		clientIP := "1.2.3.4"

		core.RateLimitDB.Set(core.Ctx, "rate_limit:login_fail_ip:"+clientIP, cfg.RateLimitLoginFailIPMax, 0)

		f := make(url.Values)
		f.Set("totp_code", "000000")

		c, rec := createTestContext(e, http.MethodPost, "/rauthsetup2fa", f)
		c.Request().Header.Set(echo.HeaderXRealIP, clientIP)
		c.Request().AddCookie(&http.Cookie{Name: "rauth_setup_pending", Value: encryptedToken})

		err := h.CompleteSetup2FA(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		assert.Contains(t, e.Renderer.(*mockRenderer).LastData.(map[string]interface{})["error"], "Too many failed attempts")
	})
}
