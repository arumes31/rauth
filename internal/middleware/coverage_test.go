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
	"github.com/stretchr/testify/require"
)

func TestAuthMiddleware_Coverage(t *testing.T) {
	s := miniredis.RunT(t)
	core.TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.UserDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

	e := echo.New()
	cfg := &core.Config{ServerSecret: "32byte-secret-key-for-testing-!!"}
	handler := AuthMiddleware(cfg)(func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	t.Run("Undecryptable cookie redirects to login", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/rauthprofile", nil)
		req.AddCookie(&http.Cookie{Name: "X-rauth-authtoken", Value: "not-base64!!"})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		err := handler(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/rauthlogin", rec.Header().Get("Location"))
	})

	t.Run("Invalid status redirects to login", func(t *testing.T) {
		token := "invalid-status-token"
		enc, _ := core.EncryptToken(token, cfg.ServerSecret)
		core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+token, map[string]interface{}{
			"status":   "expired",
			"username": "u",
		})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "X-rauth-authtoken", Value: enc})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		err := handler(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
	})

	t.Run("Legacy session falls back to user hash for admin status", func(t *testing.T) {
		token := "legacy-admin-token"
		enc, _ := core.EncryptToken(token, cfg.ServerSecret)
		// Token lacks is_admin (legacy); the user hash supplies it.
		core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+token, map[string]interface{}{
			"status":   "valid",
			"username": "legacyadmin",
			"groups":   "admins",
		})
		core.UserDB.HSet(core.Ctx, "user:legacyadmin", map[string]interface{}{"is_admin": "1"})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "X-rauth-authtoken", Value: enc})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		err := handler(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "1", rec.Header().Get("X-RAuth-Admin"))
	})

	t.Run("Unknown admin status defaults to 0", func(t *testing.T) {
		token := "no-admin-token"
		enc, _ := core.EncryptToken(token, cfg.ServerSecret)
		// Neither token nor user hash carry is_admin -> defaults to "0".
		core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+token, map[string]interface{}{
			"status":   "valid",
			"username": "ghostuser",
		})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "X-rauth-authtoken", Value: enc})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		err := handler(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "0", rec.Header().Get("X-RAuth-Admin"))
	})
}

func TestAdminMiddleware_Coverage(t *testing.T) {
	s := miniredis.RunT(t)
	core.UserDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

	e := echo.New()
	handler := AdminMiddleware(func(c echo.Context) error {
		return c.String(http.StatusOK, "Admin OK")
	})

	t.Run("No username in context redirects to login", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/rauthmgmt", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		err := handler(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
	})

	t.Run("Admin status resolved from context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/rauthmgmt", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "ctxadmin")
		c.Set("is_admin", "1") // already resolved by AuthMiddleware; no HGet needed
		err := handler(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("Missing user hash treated as non-admin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/rauthmgmt", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "nouserhash") // no user:nouserhash key -> redis.Nil -> "0"
		err := handler(c)
		he, ok := err.(*echo.HTTPError)
		require.True(t, ok)
		assert.Equal(t, http.StatusForbidden, he.Code)
	})
}
