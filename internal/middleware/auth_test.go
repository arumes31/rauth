package middleware

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

func TestAuthMiddleware(t *testing.T) {
	s := miniredis.RunT(t)
	core.TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.UserDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

	e := echo.New()
	cfg := &core.Config{ServerSecret: "32byte-secret-key-for-testing-!!" }

	handler := AuthMiddleware(cfg)(func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	t.Run("Redirect if no cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/rauthprofile", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Contains(t, rec.Header().Get("Location"), "/rauthlogin")
	})

	t.Run("Success with valid token", func(t *testing.T) {
		token := "valid-test-token"
		encrypted, _ := core.EncryptToken(token, cfg.ServerSecret)
		
		core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+token, map[string]interface{}{
			"status": "valid",
			"username": "testuser",
			"groups": "admin",
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "X-rauth-authtoken", Value: encrypted})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "testuser", c.Get("username"))
		assert.Equal(t, "testuser", rec.Header().Get("X-Rauth-User"))
	})
}

func TestAdminMiddleware(t *testing.T) {
	s := miniredis.RunT(t)
	core.UserDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

	e := echo.New()
	handler := AdminMiddleware(func(c echo.Context) error {
		return c.String(http.StatusOK, "Admin OK")
	})

	t.Run("Forbidden if not admin", func(t *testing.T) {
		core.UserDB.HSet(core.Ctx, "user:normal", map[string]interface{}{"is_admin": "0"})
		
		req := httptest.NewRequest(http.MethodGet, "/rauthmgmt", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "normal")

		err := handler(c)
		he, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusForbidden, he.Code)
	})

	t.Run("Success if admin", func(t *testing.T) {
		core.UserDB.HSet(core.Ctx, "user:admin", map[string]interface{}{"is_admin": "1"})
		
		req := httptest.NewRequest(http.MethodGet, "/rauthmgmt", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "admin")

		err := handler(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}
