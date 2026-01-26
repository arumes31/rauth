package handlers

import (
	"net/http"
	"net/url"
	"rauth/internal/core"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestBruteForceProtection(t *testing.T) {
	setupHandlersTest(t)

	cfg := &core.Config{
		ServerSecret: "32byte-secret-key-for-testing-!!",
		CookieDomains: []string{"example.com"},
		RateLimitLoginMax: 10,
		RateLimitLoginDecay: 300,
		RateLimitValidateMax: 100,
		RateLimitValidateDecay: 60,
	}
	h := &AuthHandler{Cfg: cfg}
	e := echo.New()
	renderer := &mockRenderer{}
	e.Renderer = renderer

	// Setup user
	core.UserDB.HSet(core.Ctx, "user:bruteuser", "password", "$2a$12$nothing") 

	t.Run("Login IP Brute Force", func(t *testing.T) {
		clientIP := "1.2.3.4"
		
		for i := 0; i < 12; i++ {
			f := url.Values{}
			f.Set("username", "bruteuser")
			f.Set("password", "wrong")
			
			c, _ := createTestContext(e, http.MethodPost, "/rauthlogin", f)
			c.Request().Header.Set(echo.HeaderXRealIP, clientIP)
			
			err := h.Login(c)
			assert.NoError(t, err)
			
			if i >= 10 {
				data := renderer.LastData.(map[string]interface{})
				assert.Contains(t, data["error"], "Too many attempts", "Should trigger rate limit at 11th attempt")
			}
		}
	})

	t.Run("Validate Rate Limiting", func(t *testing.T) {
		clientIP := "5.6.7.8"
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
		rateLimitKeyLogin := "rate_limit:login_ip:" + clientIP
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

	t.Run("2FA Brute Force Protection (Currently Vulnerable)", func(t *testing.T) {
		pendingToken := "brute-2fa-token"
		encryptedToken, _ := core.EncryptToken(pendingToken, cfg.ServerSecret)
		core.TokenDB.Set(core.Ctx, "pending_2fa:"+pendingToken, "bruteuser", 5*time.Minute)
		core.UserDB.HSet(core.Ctx, "user:bruteuser", "2fa_secret", "JBSWY3DPEHPK3PXP")

		clientIP := "9.9.9.9"
		for i := 0; i < 5; i++ {
			f := url.Values{}
			f.Set("action", "verify_2fa")
			f.Set("totp_code", "123456")
			
			c, rec := createTestContext(e, http.MethodPost, "/rauthlogin", f)
			c.Request().Header.Set(echo.HeaderXRealIP, clientIP)
			c.Request().AddCookie(&http.Cookie{Name: "rauth_2fa_pending", Value: encryptedToken})
			
			err := h.Login(c)
			assert.NoError(t, err)
			// If it returns 200 OK with data, it means it's not rate limited
			assert.Equal(t, http.StatusOK, rec.Code) 
		}
	})
}