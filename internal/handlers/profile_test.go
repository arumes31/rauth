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

func TestProfileHandler_Show(t *testing.T) {
	s := miniredis.RunT(t)
	core.UserDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.AuditDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

	h := &ProfileHandler{Cfg: &core.Config{}}
	e := echo.New()
	e.Renderer = &mockRenderer{}

	// Create test user
	username := "profileuser"
	core.UserDB.HSet(core.Ctx, "user:"+username, map[string]interface{}{
		"email":    "profile@test.com",
		"is_admin": "0",
	})

	t.Run("View Profile", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/rauthprofile", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", username)

		err := h.Show(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestProfileHandler_ChangePassword(t *testing.T) {
	s := miniredis.RunT(t)
	core.UserDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.AuditDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

	cfg := &core.Config{
		MinPasswordLength: 8,
	}
	h := &ProfileHandler{Cfg: cfg}
	e := echo.New()

	username := "passuser"
	oldPass := "oldpassword123!"
	newPass := "newpassword456!"
	hash, _ := core.HashPassword(oldPass)
	core.UserDB.HSet(core.Ctx, "user:"+username, map[string]interface{}{
		"password": hash,
	})

	t.Run("Successful password change", func(t *testing.T) {
		f := make(url.Values)
		f.Set("current_password", oldPass)
		f.Set("new_password", newPass)
		f.Set("confirm_password", newPass)

		req := httptest.NewRequest(http.MethodPost, "/rauthprofile/password", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", username)

		err := h.ChangePassword(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Contains(t, rec.Header().Get("Location"), "success=1")

		// Verify password updated in Redis
		userData, _ := core.UserDB.HGetAll(core.Ctx, "user:"+username).Result()
		assert.True(t, core.CheckPasswordHash(newPass, userData["password"]))
	})

	t.Run("Incorrect current password", func(t *testing.T) {
		f := make(url.Values)
		f.Set("current_password", "wrongpass")
		f.Set("new_password", "some-new-pass")
		f.Set("confirm_password", "some-new-pass")

		req := httptest.NewRequest(http.MethodPost, "/rauthprofile/password", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", username)

		err := h.ChangePassword(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("Password mismatch", func(t *testing.T) {
		f := make(url.Values)
		f.Set("current_password", oldPass)
		f.Set("new_password", "newpass123")
		f.Set("confirm_password", "mismatch")

		req := httptest.NewRequest(http.MethodPost, "/rauthprofile/password", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", username)

		err := h.ChangePassword(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}
