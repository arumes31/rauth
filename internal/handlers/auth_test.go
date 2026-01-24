package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"rauth/internal/core"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

type mockRenderer struct{}

func (m *mockRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return nil
}

func TestAuthHandler_Login(t *testing.T) {
	s := miniredis.RunT(t)
	core.UserDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.RateLimitDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.AuditDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

	cfg := &core.Config{
		ServerSecret: "32byte-secret-key-for-testing-!!",
		CookieDomains: []string{"example.com"},
		TokenValidityMinutes: 60,
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

		req := httptest.NewRequest(http.MethodPost, "/rauthlogin", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.Login(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.NotEmpty(t, rec.Header().Get("Set-Cookie"))
	})

	t.Run("Failed login - wrong password", func(t *testing.T) {
		f := make(url.Values)
		f.Set("username", "testuser")
		f.Set("password", "wrongpass")

		req := httptest.NewRequest(http.MethodPost, "/rauthlogin", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Note: Login returns OK (to render the page with error) or Redirect
		err := h.Login(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code) // Renders login.html
	})

	t.Run("Rate limit exceeded", func(t *testing.T) {
		clientIP := "192.168.1.100"
		core.RateLimitDB.Set(core.Ctx, "rate_limit:login_ip:"+clientIP, 11, 0)

		f := make(url.Values)
		f.Set("username", "testuser")
		f.Set("password", "testpass")

		req := httptest.NewRequest(http.MethodPost, "/rauthlogin", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderXRealIP, clientIP)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.Login(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		// We can't easily check the rendered content without a full renderer mock,
		// but we know it should return 200 and not 302.
	})
}

func TestAuthHandler_Validate(t *testing.T) {
	s := miniredis.RunT(t)
	core.TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.RateLimitDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

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
			"ip": "1.1.1.1",
			"country": "unknown",
		})

		req := httptest.NewRequest(http.MethodGet, "/rauthvalidate", nil)
		req.Header.Set(echo.HeaderXRealIP, "1.1.1.1")
		req.AddCookie(&http.Cookie{Name: "X-rauth-authtoken", Value: encrypted})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

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
			"country":  "DE", // Stored country is DE
		})

		// Mock the current IP's country in GeoCache
		clientIP := "8.8.8.8"
		core.GeoCacheLock.Lock()
		core.GeoCache[clientIP] = "US"
		core.GeoCacheLock.Unlock()

		req := httptest.NewRequest(http.MethodGet, "/rauthvalidate", nil)
		req.Header.Set(echo.HeaderXRealIP, clientIP)
		req.AddCookie(&http.Cookie{Name: "X-rauth-authtoken", Value: encrypted})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.Validate(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("Token expired in Redis", func(t *testing.T) {
		token := "expired-token"
		encrypted, _ := core.EncryptToken(token, cfg.ServerSecret)
		// Don't set in Redis

		req := httptest.NewRequest(http.MethodGet, "/rauthvalidate", nil)
		req.AddCookie(&http.Cookie{Name: "X-rauth-authtoken", Value: encrypted})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.Validate(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("Unauthorized - no cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/rauthvalidate", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.Validate(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

func TestAuthHandler_Validate_Refresh(t *testing.T) {
	s := miniredis.RunT(t)
	core.TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.RateLimitDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

	cfg := &core.Config{
		ServerSecret: "32byte-secret-key-for-testing-!!",
		CookieDomains: []string{"example.com"},
		TokenValidityMinutes: 10,
	}
	h := &AuthHandler{Cfg: cfg}
	e := echo.New()

	t.Run("Refresh token TTL", func(t *testing.T) {
		token := "refresh-token"
		encrypted, _ := core.EncryptToken(token, cfg.ServerSecret)
		clientIP := "1.2.3.4"
		
		core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+token, map[string]interface{}{
			"status": "valid",
			"username": "refresher",
			"ip": clientIP,
			"country": "unknown",
		})
		core.TokenDB.Expire(core.Ctx, "X-rauth-authtoken="+token, 1*time.Minute)

		req := httptest.NewRequest(http.MethodGet, "/rauthvalidate", nil)
		req.Header.Set(echo.HeaderXRealIP, clientIP)
		req.AddCookie(&http.Cookie{Name: "X-rauth-authtoken", Value: encrypted})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.Validate(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		// Check TTL increased (should be around 10 minutes now)
		ttl := core.TokenDB.TTL(core.Ctx, "X-rauth-authtoken="+token).Val()
		assert.True(t, ttl > 9*time.Minute)
	})
}

func TestAuthHandler_CompleteSetup2FA(t *testing.T) {
	s := miniredis.RunT(t)
	core.UserDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.RateLimitDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

	cfg := &core.Config{
		ServerSecret:  "32byte-secret-key-for-testing-!!",
		CookieDomains: []string{"example.com"},
	}
	h := &AuthHandler{Cfg: cfg}
	e := echo.New()
	e.Renderer = &mockRenderer{}

	// Setup pending user
	username := "setupuser"
	setupToken := "setup-token-abc"
	secret := "JBSWY3DPEHPK3PXP" // Example Base32 secret
	core.TokenDB.Set(core.Ctx, "pending_setup:"+setupToken, username, 10*time.Minute)
	core.TokenDB.Set(core.Ctx, "pending_setup_secret:"+setupToken, secret, 5*time.Minute)

	t.Run("Valid TOTP Setup", func(t *testing.T) {
		code, _ := totp.GenerateCode(secret, time.Now())

		f := make(url.Values)
		f.Set("totp_code", code)

		req := httptest.NewRequest(http.MethodPost, "/rauthsetup2fa", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		req.AddCookie(&http.Cookie{Name: "rauth_setup_pending", Value: setupToken})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.CompleteSetup2FA(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		// Verify secret saved
		saved, _ := core.UserDB.HGet(core.Ctx, "user:"+username, "2fa_secret").Result()
		assert.Equal(t, secret, saved)
	})
}

func TestAuthHandler_Logout(t *testing.T) {
	cfg := &core.Config{CookieDomains: []string{"example.com"}}
	h := &AuthHandler{Cfg: cfg}

	t.Run("Logout placeholder", func(t *testing.T) {
		// Placeholder for future logout test if moved to handler
		assert.NotNil(t, h)
	})
}

func TestAuthHandler_IssueToken_Redirect(t *testing.T) {
	s := miniredis.RunT(t)
	core.TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.AuditDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

	cfg := &core.Config{
		ServerSecret: "32byte-secret-key-for-testing-!!",
		CookieDomains: []string{"example.com"},
		AllowedHosts: []string{"trusted.com"},
	}
	h := &AuthHandler{Cfg: cfg}
	e := echo.New()

	t.Run("Safe redirect", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/rauthlogin?rd=http://trusted.com/app", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.issueToken(c, "testuser")
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "http://trusted.com/app", rec.Header().Get("Location"))
	})

	t.Run("Unsafe redirect", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/rauthlogin?rd=http://evil.com/phish", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.issueToken(c, "testuser")
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		// Should fall back to root
		assert.Equal(t, "/", rec.Header().Get("Location"))
	})
}
