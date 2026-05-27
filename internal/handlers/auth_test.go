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
)

func TestAuthHandler_Root(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{ServerSecret: "32byte-secret-key-for-testing-!!"}
	h := &AuthHandler{Cfg: cfg}
	e := echo.New()

	t.Run("Redirect to login when no cookie", func(t *testing.T) {
		c, rec := createTestContext(e, http.MethodGet, "/", nil)

		err := h.Root(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/rauthlogin", rec.Header().Get("Location"))
	})
}

func TestAuthHandler_Login(t *testing.T) {
	setupHandlersTest(t)

	cfg := &core.Config{
		ServerSecret:              "32byte-secret-key-for-testing-!!",
		CookieDomains:             []string{"example.com"},
		TokenValidityMinutes:      60,
		RateLimitLoginMax:         1000,
		RateLimitLoginDecay:       300,
		RateLimitLoginAccessMax:   1000,
		RateLimitLoginFailUserMax: 1000,
		RateLimitLoginFailIPMax:   1000,
	}
	h := &AuthHandler{Cfg: cfg}
	e := echo.New()

	// Mock renderer
	e.Renderer = &mockRenderer{}

	// Create test user
	password := "testpass"
	hash, _ := core.HashPassword(password)
	core.UserDB.HSet(core.Ctx, "user:testuser", map[string]interface{}{
		"username": "testuser",
		"password": hash,
	})

	t.Run("Successful login", func(t *testing.T) {
		f := make(url.Values)
		f.Set("username", "testuser")
		f.Set("password", "testpass")

		c, rec := createTestContext(e, http.MethodPost, "/rauthlogin", f)

		err := h.Login(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.NotEmpty(t, rec.Header().Get("Set-Cookie"))
	})

	t.Run("Failed login - wrong password", func(t *testing.T) {
		f := make(url.Values)
		f.Set("username", "testuser")
		f.Set("password", "wrongpass")

		c, rec := createTestContext(e, http.MethodPost, "/rauthlogin", f)

		err := h.Login(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("Rate limit exceeded", func(t *testing.T) {
		clientIP := "192.168.1.100"
		// Temporarily set limit low for this subtest
		oldMax := h.Cfg.RateLimitLoginMax
		h.Cfg.RateLimitLoginMax = 10
		defer func() { h.Cfg.RateLimitLoginMax = oldMax }()

		core.RateLimitDB.Set(core.Ctx, "rate_limit:login_post_ip:"+clientIP, 11, 0)

		f := make(url.Values)
		f.Set("username", "testuser")
		f.Set("password", "testpass")

		c, rec := createTestContext(e, http.MethodPost, "/rauthlogin", f)
		c.Request().Header.Set(echo.HeaderXRealIP, clientIP)

		err := h.Login(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	})

	t.Run("Login triggers 2FA session", func(t *testing.T) {
		// Create user with 2FA enabled
		password := "testpass"
		hash, _ := core.HashPassword(password)
		core.UserDB.HSet(core.Ctx, "user:2fauser", map[string]interface{}{
			"username":   "2fauser",
			"password":   hash,
			"2fa_secret": "JBSWY3DPEHPK3PXP",
		})

		f := make(url.Values)
		f.Set("username", "2fauser")
		f.Set("password", "testpass")

		c, rec := createTestContext(e, http.MethodPost, "/rauthlogin", f)

		err := h.Login(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		// Should set rauth_2fa_pending cookie
		cookies := rec.Result().Cookies()
		found := false
		for _, ck := range cookies {
			if ck.Name == "rauth_2fa_pending" {
				found = true
				break
			}
		}
		assert.True(t, found)

		// Check renderer data
		renderer := e.Renderer.(*mockRenderer)
		data := renderer.LastData.(map[string]interface{})
		assert.True(t, data["display2fa"].(bool))
		assert.Equal(t, "2fauser", data["username"])
	})

	t.Run("Login triggers 2FA setup session with rd", func(t *testing.T) {
		// User with no 2FA
		password := "testpass"
		hash, _ := core.HashPassword(password)
		core.UserDB.HSet(core.Ctx, "user:newuser", map[string]interface{}{
			"username": "newuser",
			"password": hash,
		})

		rd := "/after-setup"
		f := make(url.Values)
		f.Set("username", "newuser")
		f.Set("password", "testpass")

		c, rec := createTestContext(e, http.MethodPost, "/rauthlogin?rd="+url.QueryEscape(rd), f)

		err := h.Login(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Contains(t, rec.Header().Get("Location"), "/rauthsetup2fa")
		assert.Contains(t, rec.Header().Get("Location"), "rd="+url.QueryEscape(rd))
	})

}

func TestAuthHandler_Validate(t *testing.T) {
	setupHandlersTest(t)

	cfg := &core.Config{
		ServerSecret:              "32byte-secret-key-for-testing-!!",
		CookieDomains:             []string{"example.com"},
		TokenValidityMinutes:      60,
		RateLimitLoginMax:         1000,
		RateLimitLoginDecay:       60,
		RateLimitValidateMax:      1000,
		RateLimitValidateDecay:    60,
		RateLimitLoginAccessMax:   1000,
		RateLimitLoginFailUserMax: 1000,
		RateLimitLoginFailIPMax:   1000,
	}
	h := &AuthHandler{Cfg: cfg}
	e := echo.New()

	t.Run("Valid token", func(t *testing.T) {
		token := "valid-token"
		encrypted, _ := core.EncryptToken(token, cfg.ServerSecret)

		core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+token, map[string]interface{}{
			"status":   "valid",
			"username": "testuser",
			"ip":       "127.0.0.1",
			"country":  "unknown",
		})

		c, rec := createTestContext(e, http.MethodGet, "/rauthvalidate", nil)
		c.Request().AddCookie(&http.Cookie{Name: "X-rauth-authtoken", Value: encrypted})

		err := h.Validate(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "testuser", rec.Header().Get("X-RAuth-User"))
	})

	t.Run("Geo-check failure", func(t *testing.T) {
		token := "geo-token"
		encrypted, _ := core.EncryptToken(token, cfg.ServerSecret)

		core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+token, map[string]interface{}{
			"status":   "valid",
			"username": "testuser",
			"ip":       "1.1.1.1",
			"country":  "DE",
		})

		clientIP := "8.8.8.8"
		core.GeoCache.Put(clientIP, "US")

		c, rec := createTestContext(e, http.MethodGet, "/rauthvalidate", nil)
		c.Request().Header.Set(echo.HeaderXRealIP, clientIP)
		c.Request().AddCookie(&http.Cookie{Name: "X-rauth-authtoken", Value: encrypted})

		err := h.Validate(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("User-Agent mismatch invalidates session", func(t *testing.T) {
		token := "ua-token"
		encrypted, _ := core.EncryptToken(token, cfg.ServerSecret)

		redisKey := "X-rauth-authtoken=" + token
		core.TokenDB.HSet(core.Ctx, redisKey, map[string]interface{}{
			"status":     "valid",
			"username":   "testuser",
			"ip":         "127.0.0.1",
			"country":    "unknown",
			"user_agent": "Mozilla/5.0 (Original Browser)",
		})

		c, rec := createTestContext(e, http.MethodGet, "/rauthvalidate", nil)
		c.Request().Header.Set("User-Agent", "Mozilla/5.0 (Attacker Browser)")
		c.Request().AddCookie(&http.Cookie{Name: "X-rauth-authtoken", Value: encrypted})

		err := h.Validate(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)

		// Verify session was deleted from Redis
		exists, _ := core.TokenDB.Exists(core.Ctx, redisKey).Result()
		assert.Equal(t, int64(0), exists)
	})
}

func TestAuthHandler_CompleteSetup2FA(t *testing.T) {

	cfg := &core.Config{
		ServerSecret:              "32byte-secret-key-for-testing-!!",
		CookieDomains:             []string{"example.com"},
		TokenValidityMinutes:      60,
		RateLimitLoginMax:         1000,
		RateLimitLoginDecay:       60,
		RateLimitValidateMax:      1000,
		RateLimitValidateDecay:    60,
		RateLimitLoginAccessMax:   1000,
		RateLimitLoginAccessDecay: 60,
		RateLimitLoginFailUserMax: 1000,
		RateLimitLoginFailIPMax:   1000,
		RateLimitLoginFailIPDecay: 60,
	}
	h := &AuthHandler{Cfg: cfg}
	e := echo.New()
	e.Renderer = &mockRenderer{}

	// Helper to setup a valid pending session
	setupPending := func(username, setupToken, secret string) string {
		encryptedToken, _ := core.EncryptToken(setupToken, cfg.ServerSecret)
		core.TokenDB.Set(core.Ctx, "pending_setup:"+setupToken, username, 10*time.Minute)
		core.TokenDB.Set(core.Ctx, "pending_setup_secret:"+setupToken, secret, 5*time.Minute)
		return encryptedToken
	}

	t.Run("login_access rate limit", func(t *testing.T) {
		setupHandlersTest(t)
		clientIP := "1.2.3.4"
		core.RateLimitDB.Set(core.Ctx, "rate_limit:login_access:"+clientIP, cfg.RateLimitLoginAccessMax+1, 0)

		c, rec := createTestContext(e, http.MethodPost, "/rauthsetup2fa", nil)
		c.Request().Header.Set(echo.HeaderXRealIP, clientIP)

		err := h.CompleteSetup2FA(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		assert.Contains(t, e.Renderer.(*mockRenderer).LastData.(map[string]interface{})["error"], "Too many requests")
	})

	t.Run("login_post_ip rate limit", func(t *testing.T) {
		setupHandlersTest(t)
		clientIP := "1.2.3.4"
		core.RateLimitDB.Set(core.Ctx, "rate_limit:login_post_ip:"+clientIP, cfg.RateLimitLoginMax+1, 0)

		c, rec := createTestContext(e, http.MethodPost, "/rauthsetup2fa", nil)
		c.Request().Header.Set(echo.HeaderXRealIP, clientIP)

		err := h.CompleteSetup2FA(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		assert.Contains(t, e.Renderer.(*mockRenderer).LastData.(map[string]interface{})["error"], "Too many attempts from this IP")
	})

	t.Run("Missing cookie", func(t *testing.T) {
		setupHandlersTest(t)
		c, rec := createTestContext(e, http.MethodPost, "/rauthsetup2fa", nil)
		err := h.CompleteSetup2FA(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/rauthlogin", rec.Header().Get("Location"))
	})

	t.Run("Invalid cookie decryption", func(t *testing.T) {
		setupHandlersTest(t)
		c, rec := createTestContext(e, http.MethodPost, "/rauthsetup2fa", nil)
		c.Request().AddCookie(&http.Cookie{Name: "rauth_setup_pending", Value: "garbage"})
		err := h.CompleteSetup2FA(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/rauthlogin", rec.Header().Get("Location"))
	})

	t.Run("Missing pending_setup in Redis", func(t *testing.T) {
		setupHandlersTest(t)
		setupToken := "valid-looking-token"
		encrypted, _ := core.EncryptToken(setupToken, cfg.ServerSecret)
		c, rec := createTestContext(e, http.MethodPost, "/rauthsetup2fa", nil)
		c.Request().AddCookie(&http.Cookie{Name: "rauth_setup_pending", Value: encrypted})

		err := h.CompleteSetup2FA(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/rauthlogin", rec.Header().Get("Location"))
	})

	t.Run("Missing pending_setup_secret in Redis", func(t *testing.T) {
		setupHandlersTest(t)
		username := "user1"
		setupToken := "token1"
		encrypted, _ := core.EncryptToken(setupToken, cfg.ServerSecret)
		core.TokenDB.Set(core.Ctx, "pending_setup:"+setupToken, username, 10*time.Minute)

		c, rec := createTestContext(e, http.MethodPost, "/rauthsetup2fa", nil)
		c.Request().AddCookie(&http.Cookie{Name: "rauth_setup_pending", Value: encrypted})

		err := h.CompleteSetup2FA(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/rauthsetup2fa", rec.Header().Get("Location"))
	})

	t.Run("2fa_fail_user rate limit", func(t *testing.T) {
		setupHandlersTest(t)
		username := "user1"
		setupToken := "token1"
		secret := "JBSWY3DPEHPK3PXP"
		encrypted := setupPending(username, setupToken, secret)

		core.RateLimitDB.Set(core.Ctx, "rate_limit:2fa_fail_user:"+username, cfg.RateLimitLoginFailIPMax+1, 0)

		c, rec := createTestContext(e, http.MethodPost, "/rauthsetup2fa", nil)
		c.Request().AddCookie(&http.Cookie{Name: "rauth_setup_pending", Value: encrypted})

		err := h.CompleteSetup2FA(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		assert.Contains(t, e.Renderer.(*mockRenderer).LastData.(map[string]interface{})["error"], "Too many failed attempts")
	})

	t.Run("Invalid TOTP code", func(t *testing.T) {
		setupHandlersTest(t)
		username := "user1"
		setupToken := "token1"
		secret := "JBSWY3DPEHPK3PXP"
		encrypted := setupPending(username, setupToken, secret)

		f := make(url.Values)
		f.Set("totp_code", "000000")
		c, rec := createTestContext(e, http.MethodPost, "/rauthsetup2fa", f)
		c.Request().AddCookie(&http.Cookie{Name: "rauth_setup_pending", Value: encrypted})

		err := h.CompleteSetup2FA(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, e.Renderer.(*mockRenderer).LastData.(map[string]interface{})["error"], "Invalid code")

		// Verify penalization (login_fail_ip should be incremented)
		clientIP := "127.0.0.1"
		count, _ := core.RateLimitDB.Get(core.Ctx, "rate_limit:login_fail_ip:"+clientIP).Int()
		assert.Equal(t, 1, count)
	})

	t.Run("Successful TOTP Setup", func(t *testing.T) {
		setupHandlersTest(t)
		username := "setupuser"
		setupToken := "setup-token-abc"
		secret := "JBSWY3DPEHPK3PXP"
		encryptedToken := setupPending(username, setupToken, secret)

		code, _ := totp.GenerateCode(secret, time.Now())

		f := make(url.Values)
		f.Set("totp_code", code)

		c, rec := createTestContext(e, http.MethodPost, "/rauthsetup2fa", f)
		c.Request().AddCookie(&http.Cookie{Name: "rauth_setup_pending", Value: encryptedToken})

		err := h.CompleteSetup2FA(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		saved, _ := core.UserDB.HGet(core.Ctx, "user:"+username, "2fa_secret").Result()
		decrypted := core.Decrypt2FASecret(saved, cfg.ServerSecret)
		assert.Equal(t, secret, decrypted)

		// Verify cleanup
		exists, _ := core.TokenDB.Exists(core.Ctx, "pending_setup:"+setupToken).Result()
		assert.Equal(t, int64(0), exists)
	})
}

func TestAuthHandler_InvalidateSessionIntegration(t *testing.T) {
	setupHandlersTest(t)

	cfg := &core.Config{
		ServerSecret:              "32byte-secret-key-for-testing-!!",
		CookieDomains:             []string{"example.com"},
		TokenValidityMinutes:      60,
		RateLimitLoginMax:         1000,
		RateLimitLoginDecay:       60,
		RateLimitValidateMax:      1000,
		RateLimitValidateDecay:    60,
		RateLimitLoginAccessMax:   1000,
		RateLimitLoginFailUserMax: 1000,
		RateLimitLoginFailIPMax:   1000,
	}
	h := &AuthHandler{Cfg: cfg}
	adminH := &AdminHandler{Cfg: cfg}
	e := echo.New()

	username := "sessionuser"
	core.UserDB.HSet(core.Ctx, "user:"+username, map[string]interface{}{"is_admin": "0", "username": username})

	// 1. Issue token
	rawToken := "integration-token-xyz"
	encrypted, _ := core.EncryptToken(rawToken, cfg.ServerSecret)

	// REDIS KEY MUST BE: X-rauth-authtoken= + token
	redisKey := "X-rauth-authtoken=" + rawToken
	core.TokenDB.HSet(core.Ctx, redisKey, map[string]interface{}{
		"status":   "valid",
		"username": username,
		"ip":       "127.0.0.1",
		"country":  "unknown",
	})

	// 2. Verify it is valid
	c1, rec1 := createTestContext(e, http.MethodGet, "/rauthvalidate", nil)
	c1.Request().AddCookie(&http.Cookie{Name: "X-rauth-authtoken", Value: encrypted})

	err := h.Validate(c1)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec1.Code)

	// 3. Admin invalidates it
	f := make(url.Values)
	f.Set("token", rawToken)
	c2, rec2 := createTestContext(e, http.MethodPost, "/rauthmgmt/session/invalidate", f)
	c2.Set("username", "admin")

	err = adminH.InvalidateSession(c2)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusFound, rec2.Code)

	// 4. Verify it is now invalid
	c3, rec3 := createTestContext(e, http.MethodGet, "/rauthvalidate", nil)
	c3.Request().AddCookie(&http.Cookie{Name: "X-rauth-authtoken", Value: encrypted})

	err = h.Validate(c3)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, rec3.Code)
}

func TestAuthHandler_Setup2FA(t *testing.T) {
	setupHandlersTest(t)

	cfg := &core.Config{
		ServerSecret: "32byte-secret-key-for-testing-!!",
	}
	h := &AuthHandler{Cfg: cfg}
	e := echo.New()
	e.Renderer = &mockRenderer{}

	t.Run("Redirect to login when cookie is missing", func(t *testing.T) {
		c, rec := createTestContext(e, http.MethodGet, "/rauthsetup2fa", nil)

		err := h.Setup2FA(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/rauthlogin", rec.Header().Get("Location"))
	})

	t.Run("Redirect to login when cookie is invalid", func(t *testing.T) {
		c, rec := createTestContext(e, http.MethodGet, "/rauthsetup2fa", nil)
		c.Request().AddCookie(&http.Cookie{Name: "rauth_setup_pending", Value: "invalid-token"})

		err := h.Setup2FA(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/rauthlogin", rec.Header().Get("Location"))
	})

	t.Run("Redirect to login when token is not in DB", func(t *testing.T) {
		setupToken := "missing-token"
		encryptedToken, _ := core.EncryptToken(setupToken, cfg.ServerSecret)

		c, rec := createTestContext(e, http.MethodGet, "/rauthsetup2fa", nil)
		c.Request().AddCookie(&http.Cookie{Name: "rauth_setup_pending", Value: encryptedToken})

		err := h.Setup2FA(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/rauthlogin", rec.Header().Get("Location"))
	})

	t.Run("Successful 2FA Setup page rendering", func(t *testing.T) {
		username := "setupuser"
		setupToken := "valid-setup-token"
		encryptedToken, _ := core.EncryptToken(setupToken, cfg.ServerSecret)
		core.TokenDB.Set(core.Ctx, "pending_setup:"+setupToken, username, 10*time.Minute)

		c, rec := createTestContext(e, http.MethodGet, "/rauthsetup2fa", nil)
		c.Request().AddCookie(&http.Cookie{Name: "rauth_setup_pending", Value: encryptedToken})

		err := h.Setup2FA(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		// Check if secret was generated and stored
		secret, err := core.TokenDB.Get(core.Ctx, "pending_setup_secret:"+setupToken).Result()
		assert.NoError(t, err)
		assert.NotEmpty(t, secret)

		// Check renderer data
		renderer := e.Renderer.(*mockRenderer)
		data := renderer.LastData.(map[string]interface{})
		assert.Equal(t, secret, data["secret"])
	})

	t.Run("Setup2FA handles rd parameter", func(t *testing.T) {
		username := "setupuser"
		setupToken := "valid-setup-token-rd"
		encryptedToken, _ := core.EncryptToken(setupToken, cfg.ServerSecret)
		core.TokenDB.Set(core.Ctx, "pending_setup:"+setupToken, username, 10*time.Minute)

		rd := "/custom-redirect"
		c, rec := createTestContext(e, http.MethodGet, "/rauthsetup2fa?rd="+url.QueryEscape(rd), nil)
		c.Request().AddCookie(&http.Cookie{Name: "rauth_setup_pending", Value: encryptedToken})

		err := h.Setup2FA(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		renderer := e.Renderer.(*mockRenderer)
		data := renderer.LastData.(map[string]interface{})
		assert.Equal(t, rd, data["rd"])
	})

}
