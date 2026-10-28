package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"rauth/internal/core"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBruteForceProtection(t *testing.T) {
	setupHandlersTest(t)

	cfg := &core.Config{
		ServerSecret:                "32byte-secret-key-for-testing-!!",
		CookieDomains:               []string{"example.com"},
		RateLimitLoginMax:           100,
		RateLimitLoginDecay:         300,
		RateLimitValidateMax:        100,
		RateLimitValidateDecay:      60,
		RateLimitLoginAccessMax:     1000,
		RateLimitLoginFailUserMax:   5,
		RateLimitLoginFailUserDecay: 300,
		RateLimitLoginFailIPMax:     20,
		RateLimitLoginFailIPDecay:   600,
	}
	h := &AuthHandler{Cfg: cfg}
	e := echo.New()
	renderer := &mockRenderer{}
	e.Renderer = renderer

	// Setup user
	seedUserFields(t, "bruteuser", map[string]interface{}{"password": "$2a$12$nothing"})

	t.Run("Login IP Brute Force", func(t *testing.T) {
		clientIP := "1.2.3.4"
		core.ResetRateLimit("login_post_ip:" + clientIP)

		for i := 0; i < 102; i++ {
			f := url.Values{}
			f.Set("username", fmt.Sprintf("user_ip_%d", i)) // Different user to only test IP limit
			f.Set("password", "wrong")

			c, rec := createTestContext(e, http.MethodPost, "/rauthlogin", f)
			c.Request().Header.Set(echo.HeaderXRealIP, clientIP)

			err := h.Login(c)
			assert.NoError(t, err)

			if i >= 100 {
				assert.Equal(t, http.StatusTooManyRequests, rec.Code)
				data := renderer.LastData.(map[string]interface{})
				assert.Contains(t, data["error"], "Too many login attempts from this IP")
			}
		}
	})

	t.Run("Account Lockout Protection", func(t *testing.T) {
		username := "lockeduser"
		clientIP := "1.1.1.1"
		core.ResetRateLimit("login_fail_user:" + username)
		core.ResetRateLimit("login_post_ip:" + clientIP)

		for i := 0; i < 6; i++ {
			f := url.Values{}
			f.Set("username", username)
			f.Set("password", "wrong")

			c, rec := createTestContext(e, http.MethodPost, "/rauthlogin", f)
			c.Request().Header.Set(echo.HeaderXRealIP, clientIP)

			err := h.Login(c)
			assert.NoError(t, err)

			if i >= 5 {
				assert.Equal(t, http.StatusTooManyRequests, rec.Code)
				data := renderer.LastData.(map[string]interface{})
				assert.Contains(t, data["error"], "account is temporarily locked")
			}
		}
	})

	t.Run("Global IP Failure Protection", func(t *testing.T) {
		clientIP := "2.2.2.2"
		core.ResetRateLimit("login_fail_ip:" + clientIP)
		core.ResetRateLimit("login_post_ip:" + clientIP)

		// Set login_post_ip high enough so we hit login_fail_ip first
		oldMax := h.Cfg.RateLimitLoginMax
		h.Cfg.RateLimitLoginMax = 100
		defer func() { h.Cfg.RateLimitLoginMax = oldMax }()

		for i := 0; i < 22; i++ {
			f := url.Values{}
			f.Set("username", fmt.Sprintf("user_global_%d", i))
			f.Set("password", "wrong")

			c, rec := createTestContext(e, http.MethodPost, "/rauthlogin", f)
			c.Request().Header.Set(echo.HeaderXRealIP, clientIP)

			err := h.Login(c)
			assert.NoError(t, err)

			if i >= 20 {
				assert.Equal(t, http.StatusTooManyRequests, rec.Code)
				data := renderer.LastData.(map[string]interface{})
				assert.Contains(t, data["error"], "Too many failed attempts from your network")
			}
		}
	})

	t.Run("Validate Rate Limiting", func(t *testing.T) {
		clientIP := "5.6.7.8"
		core.ResetRateLimit("validate:" + clientIP)
		for i := 0; i < h.Cfg.RateLimitValidateMax+5; i++ {
			c, rec := createTestContext(e, http.MethodGet, "/rauthvalidate", nil)
			c.Request().Header.Set(echo.HeaderXRealIP, clientIP)

			err := h.Validate(c)
			assert.NoError(t, err)

			if i >= h.Cfg.RateLimitValidateMax {
				assert.Equal(t, http.StatusTooManyRequests, rec.Code)
			}
		}
	})

	t.Run("Independent Rate Limits", func(t *testing.T) {
		clientIP := "10.10.10.10"
		rateLimitKeyLogin := "rate_limit:login_post_ip:" + clientIP
		rateLimitKeyValidate := "rate_limit:validate:" + clientIP

		// 1. Max out login rate limit
		core.RateLimitDB.Set(core.Ctx, rateLimitKeyLogin, h.Cfg.RateLimitLoginMax, 0)

		// 2. Verify login is blocked
		f := url.Values{}
		f.Set("username", "bruteuser")
		f.Set("password", "wrong")
		cLogin, recLogin := createTestContext(e, http.MethodPost, "/rauthlogin", f)
		cLogin.Request().Header.Set(echo.HeaderXRealIP, clientIP)
		err := h.Login(cLogin)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusTooManyRequests, recLogin.Code)

		// 3. Verify validation is NOT blocked (uses a different key)
		cVal, recVal := createTestContext(e, http.MethodGet, "/rauthvalidate", nil)
		cVal.Request().Header.Set(echo.HeaderXRealIP, clientIP)
		err = h.Validate(cVal)
		assert.NoError(t, err)
		assert.NotEqual(t, http.StatusTooManyRequests, recVal.Code)

		// Cleanup
		core.RateLimitDB.Del(core.Ctx, rateLimitKeyLogin)
		core.RateLimitDB.Del(core.Ctx, rateLimitKeyValidate)
	})

	t.Run("2FA Brute Force Protection", func(t *testing.T) {
		pendingToken := "brute-2fa-token"
		encryptedToken, _ := core.EncryptToken(pendingToken, cfg.ServerSecret)
		core.TokenDB.Set(core.Ctx, "pending_2fa:"+pendingToken, "bruteuser", 5*time.Minute)
		seedUserFields(t, "bruteuser", map[string]interface{}{"2fa_secret": "JBSWY3DPEHPK3PXP"})

		clientIP := "9.9.9.9"
		core.ResetRateLimit("login_post_ip:" + clientIP)
		core.ResetRateLimit("login_fail_ip:" + clientIP)
		core.ResetRateLimit("2fa_fail_user:bruteuser")

		for i := 0; i < 22; i++ {
			f := url.Values{}
			f.Set("action", "verify_2fa")
			f.Set("totp_code", "123456")

			c, rec := createTestContext(e, http.MethodPost, "/rauthlogin", f)
			c.Request().Header.Set(echo.HeaderXRealIP, clientIP)
			c.Request().AddCookie(&http.Cookie{Name: "rauth_2fa_pending", Value: encryptedToken})

			err := h.Login(c)
			assert.NoError(t, err)

			if i >= 20 {
				assert.Equal(t, http.StatusTooManyRequests, rec.Code)
				data := renderer.LastData.(map[string]interface{})
				assert.Contains(t, data["error"], "Too many failed attempts")
			}
		}
	})
}

func TestSuccessfulLoginDoesNotResetIPCounters(t *testing.T) {
	setupHandlersTest(t)

	cfg := &core.Config{
		ServerSecret:                "32byte-secret-key-for-testing-!!",
		CookieDomains:               []string{"example.com"},
		RateLimitLoginMax:           100,
		RateLimitLoginDecay:         300,
		RateLimitLoginAccessMax:     1000,
		RateLimitLoginAccessDecay:   60,
		RateLimitLoginFailUserMax:   5,
		RateLimitLoginFailUserDecay: 300,
		RateLimitLoginFailIPMax:     20,
		RateLimitLoginFailIPDecay:   600,
	}
	h := &AuthHandler{Cfg: cfg}
	e := echo.New()
	e.Renderer = &mockRenderer{}

	require.NoError(t, core.CreateUser("sprayer", "Correct-Horse-1", "", false, ""))
	clientIP := "203.0.113.10"

	// One failed attempt against another (unknown) account from this IP.
	f := url.Values{"username": {"victim"}, "password": {"guess"}}
	c, _ := createTestContext(e, http.MethodPost, "/rauthlogin", f)
	c.Request().Header.Set(echo.HeaderXRealIP, clientIP)
	require.NoError(t, h.Login(c))

	// A successful login with the attacker's own account must not wipe the
	// IP-scoped counters.
	f = url.Values{"username": {"sprayer"}, "password": {"Correct-Horse-1"}}
	c, _ = createTestContext(e, http.MethodPost, "/rauthlogin", f)
	c.Request().Header.Set(echo.HeaderXRealIP, clientIP)
	require.NoError(t, h.Login(c))

	failIP, err := core.RateLimitDB.Get(core.Ctx, "rate_limit:login_fail_ip:"+clientIP).Int()
	require.NoError(t, err)
	assert.Equal(t, 1, failIP)
	postIP, err := core.RateLimitDB.Get(core.Ctx, "rate_limit:login_post_ip:"+clientIP).Int()
	require.NoError(t, err)
	assert.Equal(t, 2, postIP)

	// The failed attempt for an unknown account must not create a per-user
	// audit list for the attacker-chosen name.
	exists := int64(userAuditCount(t, "victim"))
	assert.Equal(t, int64(0), exists)
}
