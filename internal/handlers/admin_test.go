package handlers

import (
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

func TestAdminHandler_Dashboard(t *testing.T) {
	s := miniredis.RunT(t)
	core.UserDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.AuditDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

	h := &AdminHandler{Cfg: &core.Config{}}
	e := echo.New()
	e.Renderer = &mockRenderer{}

	t.Run("Access Dashboard", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/rauthmgmt", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "admin")

		err := h.Dashboard(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestAdminHandler_InvalidateSession(t *testing.T) {
	s := miniredis.RunT(t)
	core.TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.AuditDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

	h := &AdminHandler{Cfg: &core.Config{}}
	e := echo.New()

	t.Run("Invalidate active session", func(t *testing.T) {
		token := "session-to-kill"
		redisKey := "X-rauth-authtoken=" + token
		core.TokenDB.HSet(core.Ctx, redisKey, map[string]interface{}{"status": "valid"})

		f := make(url.Values)
		f.Set("token", token)

		req := httptest.NewRequest(http.MethodPost, "/rauthmgmt/session/invalidate", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "admin")

		err := h.InvalidateSession(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		// Verify it's gone from Redis
		exists, _ := core.TokenDB.Exists(core.Ctx, redisKey).Result()
		assert.Equal(t, int64(0), exists)
	})
}

func TestAdminHandler_CreateUser(t *testing.T) {
	s := miniredis.RunT(t)
	core.UserDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.AuditDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

	h := &AdminHandler{Cfg: &core.Config{MinPasswordLength: 8}}
	e := echo.New()

	t.Run("Create valid user", func(t *testing.T) {
		f := make(url.Values)
		f.Set("new_username", "brandnew")
		f.Set("new_password", "very-secure-pass-123!")
		f.Set("new_email", "new@test.com")
		f.Set("is_admin", "on")

		req := httptest.NewRequest(http.MethodPost, "/rauthmgmt/user/create", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "admin")

		err := h.CreateUser(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		// Verify user exists
		userData, err := core.UserDB.HGetAll(core.Ctx, "user:brandnew").Result()
		assert.NoError(t, err)
		assert.Equal(t, "brandnew", userData["username"])
		assert.Equal(t, "1", userData["is_admin"])
	})

	t.Run("Create user - invalid password", func(t *testing.T) {
		f := make(url.Values)
		f.Set("new_username", "invaliduser")
		f.Set("new_password", "short")

		req := httptest.NewRequest(http.MethodPost, "/rauthmgmt/user/create", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "admin")

		err := h.CreateUser(c)
		assert.Error(t, err)
		he, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, he.Code)
	})

	t.Run("Create user - duplicate", func(t *testing.T) {
		core.CreateUser("duplicate", "pass12345!", "test@test.com", false, "")

		f := make(url.Values)
		f.Set("new_username", "duplicate")
		f.Set("new_password", "pass12345!")

		req := httptest.NewRequest(http.MethodPost, "/rauthmgmt/user/create", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "admin")

		err := h.CreateUser(c)
		assert.Error(t, err)
		he, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, he.Code)
	})
}

func TestAdminHandler_DeleteUser(t *testing.T) {
	s := miniredis.RunT(t)
	core.UserDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.AuditDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

	h := &AdminHandler{Cfg: &core.Config{}}
	e := echo.New()

	core.UserDB.HSet(core.Ctx, "user:victim", map[string]interface{}{"username": "victim"})

	t.Run("Delete other user", func(t *testing.T) {
		f := make(url.Values)
		f.Set("username", "victim")

		req := httptest.NewRequest(http.MethodPost, "/rauthmgmt/user/delete", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "admin")

		err := h.DeleteUser(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		exists, _ := core.UserDB.Exists(core.Ctx, "user:victim").Result()
		assert.Equal(t, int64(0), exists)
	})

	t.Run("Delete self - should fail", func(t *testing.T) {
		f := make(url.Values)
		f.Set("username", "admin")

		req := httptest.NewRequest(http.MethodPost, "/rauthmgmt/user/delete", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "admin")

		err := h.DeleteUser(c)
		assert.Error(t, err)
		he, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, he.Code)
	})
}
