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

	cfg := &core.Config{
		ServerSecret: "32byte-secret-key-for-testing-!!",
		CookieDomains: []string{"example.com"},
		TokenValidityMinutes: 60,
		RateLimitLoginMax: 10,
		RateLimitLoginDecay: 300,
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
		core.RateLimitDB.Set(core.Ctx, "rate_limit:login_ip:"+clientIP, 11, 0)

		f := make(url.Values)
		f.Set("username", "testuser")
		f.Set("password", "testpass")

		c, rec := createTestContext(e, http.MethodPost, "/rauthlogin", f)
		c.Request().Header.Set(echo.HeaderXRealIP, clientIP)

		err := h.Login(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	})
}

func TestAuthHandler_Validate(t *testing.T) {
	setupHandlersTest(t)

	cfg := &core.Config{
		ServerSecret: "32byte-secret-key-for-testing-!!",
		CookieDomains: []string{"example.com"},
		TokenValidityMinutes: 60,
	}
	h := &AuthHandler{Cfg: cfg}
	e := echo.New()

	t.Run("Valid token", func(t *testing.T) {
		token := "valid-token"
		encrypted, _ := core.EncryptToken(token, cfg.ServerSecret)
		
		core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+token, map[string]interface{}{
			"status": "valid",
			"username": "testuser",
			"ip": "127.0.0.1",
			"country": "unknown",
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
}

func TestAuthHandler_CompleteSetup2FA(t *testing.T) {
	setupHandlersTest(t)

	cfg := &core.Config{
		ServerSecret:  "32byte-secret-key-for-testing-!!",
		CookieDomains: []string{"example.com"},
		TokenValidityMinutes: 60,
	}
	h := &AuthHandler{Cfg: cfg}
	e := echo.New()
	e.Renderer = &mockRenderer{}

	// Setup pending user
	username := "setupuser"
	setupToken := "setup-token-abc"
	encryptedToken, _ := core.EncryptToken(setupToken, cfg.ServerSecret)
	secret := "JBSWY3DPEHPK3PXP" 
	core.TokenDB.Set(core.Ctx, "pending_setup:"+setupToken, username, 10*time.Minute)
	core.TokenDB.Set(core.Ctx, "pending_setup_secret:"+setupToken, secret, 5*time.Minute)

	t.Run("Valid TOTP Setup", func(t *testing.T) {
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
	})
}

func TestAuthHandler_InvalidateSessionIntegration(t *testing.T) {
	setupHandlersTest(t)

	cfg := &core.Config{
		ServerSecret: "32byte-secret-key-for-testing-!!",
		CookieDomains: []string{"example.com"},
		TokenValidityMinutes: 60,
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
		"status": "valid",
		"username": username,
		"ip": "127.0.0.1",
		"country": "unknown",
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
