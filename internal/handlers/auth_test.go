package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"rauth/internal/core"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/labstack/echo/v4"
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
		
		core.TokenDB.HSet(core.Ctx, "X-rcloudauth-authtoken="+token, map[string]interface{}{
			"status": "valid",
			"username": "testuser",
			"ip": "127.0.0.1",
			"country": "Internal",
		})

		req := httptest.NewRequest(http.MethodGet, "/rauthvalidate", nil)
		req.AddCookie(&http.Cookie{Name: "X-rcloudauth-authtoken", Value: encrypted})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.Validate(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
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
