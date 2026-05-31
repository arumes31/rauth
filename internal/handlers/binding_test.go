package handlers

import (
	"net/http"
	"net/http/httptest"
	"rauth/internal/core"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

func TestHardwareBinding_Coverage(t *testing.T) {
	s := miniredis.RunT(t)
	core.TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.UserDB = core.TokenDB
	core.RateLimitDB = core.TokenDB
	core.AuditDB = core.TokenDB

	cfg := &core.Config{
		TokenValidityMinutes: 10,
		CookieDomains:        []string{"example.com"},
		ServerSecret:         "12345678901234567890123456789012",
	}
	h := &AuthHandler{Cfg: cfg}

	setupSession := func(platform, mobile, model string) (*http.Cookie, string) {
		token := "binding-token-" + platform
		redisKey := "X-rauth-authtoken=" + token
		core.TokenDB.HSet(core.Ctx, redisKey, map[string]interface{}{
			"status":         "valid",
			"username":       "alice",
			"ip":             "127.0.0.1",
			"country":        "Internal",
			"user_agent":     "Mozilla/5.0",
			"ua_ch_platform": platform,
			"ua_ch_mobile":   mobile,
			"ua_ch_model":    model,
		})
		encrypted, _ := core.EncryptToken(token, cfg.ServerSecret)
		return &http.Cookie{Name: "X-rauth-authtoken", Value: encrypted}, redisKey
	}

	t.Run("Binding Success - Exact Match", func(t *testing.T) {
		cookie, _ := setupSession("Windows", "0", "PC")
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/rauthvalidate", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Sec-CH-UA-Platform", "Windows")
		req.Header.Set("Sec-CH-UA-Mobile", "0")
		req.Header.Set("Sec-CH-UA-Model", "PC")
		req.AddCookie(cookie)
		req.RemoteAddr = "127.0.0.1:1234"
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.Validate(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("Binding Failure - Model Mismatch", func(t *testing.T) {
		cookie, _ := setupSession("Android", "?1", "Pixel 6")
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/rauthvalidate", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Sec-CH-UA-Platform", "Android")
		req.Header.Set("Sec-CH-UA-Model", "iPhone") // Attacker spoofing model
		req.AddCookie(cookie)
		req.RemoteAddr = "127.0.0.1:1234"
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.Validate(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("Binding Success - Fallback if no request hints", func(t *testing.T) {
		cookie, _ := setupSession("Android", "?1", "Pixel 6")
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/rauthvalidate", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0") // No CH headers
		req.AddCookie(cookie)
		req.RemoteAddr = "127.0.0.1:1234"
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.Validate(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}
