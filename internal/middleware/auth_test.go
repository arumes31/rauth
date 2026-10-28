package middleware

import (
	"net/http"
	"net/http/httptest"
	"rauth/internal/core"
	"rauth/internal/pgtest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

func TestAuthMiddleware(t *testing.T) {
	s := miniredis.RunT(t)
	core.TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	usePG(t)
	assert.NoError(t, core.PutUser(core.User{Username: "testuser"}))

	e := echo.New()
	cfg := &core.Config{ServerSecret: "32byte-secret-key-for-testing-!!"}

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
		assert.Equal(t, "/rauthlogin?rd=%2Frauthprofile", rec.Header().Get("Location"))
	})

	t.Run("Success with valid token", func(t *testing.T) {
		token := "valid-test-token"
		encrypted, _ := core.EncryptToken(token, cfg.ServerSecret)

		core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+token, map[string]interface{}{
			"status":   "valid",
			"username": "testuser",
			"groups":   "admin",
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "X-rauth-authtoken", Value: encrypted})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "testuser", c.Get("username"))
		assert.Equal(t, "testuser", rec.Header().Get("X-RAuth-User"))
	})

	t.Run("Redirect and invalidate on device mismatch", func(t *testing.T) {
		token := "bound-test-token"
		encrypted, _ := core.EncryptToken(token, cfg.ServerSecret)

		core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+token, map[string]interface{}{
			"status":     "valid",
			"username":   "testuser",
			"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		})

		req := httptest.NewRequest(http.MethodGet, "/rauthprofile", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1")
		req.AddCookie(&http.Cookie{Name: "X-rauth-authtoken", Value: encrypted})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/rauthlogin", rec.Header().Get("Location"))
		exists, _ := core.TokenDB.Exists(core.Ctx, "X-rauth-authtoken="+token).Result()
		assert.Equal(t, int64(0), exists, "a session failing device binding must be invalidated")
	})
}

func TestAdminMiddleware(t *testing.T) {
	usePG(t)

	e := echo.New()
	handler := AdminMiddleware(func(c echo.Context) error {
		return c.String(http.StatusOK, "Admin OK")
	})

	t.Run("Forbidden if not admin", func(t *testing.T) {
		assert.NoError(t, core.PutUser(core.User{Username: "normal", IsAdmin: "0"}))

		req := httptest.NewRequest(http.MethodGet, "/rauthmgmt", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "normal")

		err := handler(c)
		he, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusForbidden, he.Code)
	})

	t.Run("Demotion applies despite admin flag stamped in session", func(t *testing.T) {
		assert.NoError(t, core.PutUser(core.User{Username: "demoted", IsAdmin: "0"}))

		req := httptest.NewRequest(http.MethodGet, "/rauthmgmt", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "demoted")
		c.Set("is_admin", "1")

		err := handler(c)
		he, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusForbidden, he.Code)
	})

	t.Run("Success if admin", func(t *testing.T) {
		assert.NoError(t, core.PutUser(core.User{Username: "admin", IsAdmin: "1"}))

		req := httptest.NewRequest(http.MethodGet, "/rauthmgmt", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "admin")

		err := handler(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func usePG(t *testing.T) {
	t.Helper()
	core.PG = pgtest.Open(t, core.Migrate)
	pgtest.Reset(t, core.PG)
}
