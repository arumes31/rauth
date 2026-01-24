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
			
			h.Login(c)
			
			if i >= 10 {
				data := renderer.LastData.(map[string]interface{})
				assert.Contains(t, data["error"], "Too many attempts", "Should trigger rate limit at 11th attempt")
			}
		}
	})

	t.Run("Validate Rate Limiting", func(t *testing.T) {
		clientIP := "5.6.7.8"
		for i := 0; i < 105; i++ {
			c, rec := createTestContext(e, http.MethodGet, "/rauthvalidate", nil)
			c.Request().Header.Set(echo.HeaderXRealIP, clientIP)
			
			h.Validate(c)
			
			if i >= 100 {
				assert.Equal(t, http.StatusTooManyRequests, rec.Code)
			}
		}
	})
	
	t.Run("2FA Brute Force Protection (Currently Vulnerable)", func(t *testing.T) {
		pendingToken := "brute-2fa-token"
		core.TokenDB.Set(core.Ctx, "pending_2fa:"+pendingToken, "bruteuser", 5*time.Minute)
		core.UserDB.HSet(core.Ctx, "user:bruteuser", "2fa_secret", "JBSWY3DPEHPK3PXP")

		clientIP := "9.9.9.9"
		for i := 0; i < 5; i++ {
			f := url.Values{}
			f.Set("action", "verify_2fa")
			f.Set("totp_code", "123456")
			
			c, rec := createTestContext(e, http.MethodPost, "/rauthlogin", f)
			c.Request().Header.Set(echo.HeaderXRealIP, clientIP)
			c.Request().AddCookie(&http.Cookie{Name: "rauth_2fa_pending", Value: pendingToken})
			
			h.Login(c)
			// If it returns 200 OK with data, it means it's not rate limited
			assert.Equal(t, http.StatusOK, rec.Code) 
		}
	})
}