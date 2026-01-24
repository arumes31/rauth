package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"rauth/internal/core"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestProfileHandler_Show(t *testing.T) {
	setupHandlersTest(t)
	h := &ProfileHandler{Cfg: &core.Config{}}
	e := echo.New()
	e.Renderer = &mockRenderer{}

	t.Run("View Profile", func(t *testing.T) {
		c, rec := createTestContext(e, http.MethodGet, "/rauthprofile", nil)
		c.Set("username", "profileuser")

		err := h.Show(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("Logs are filtered by username", func(t *testing.T) {
		core.LogAudit("MY_ACTION", "profileuser", "1.1.1.1", nil)
		core.LogAudit("OTHER_ACTION", "otheruser", "2.2.2.2", nil)

		c, _ := createTestContext(e, http.MethodGet, "/rauthprofile", nil)
		c.Set("username", "profileuser")

		renderer := &mockRenderer{}
		e.Renderer = renderer

		err := h.Show(c)
		assert.NoError(t, err)

		data := renderer.LastData.(map[string]interface{})
		logs := data["logs"].([]core.AuditLog)
		
		for _, log := range logs {
			assert.Equal(t, "profileuser", log.Username)
			assert.NotEqual(t, "OTHER_ACTION", log.Action)
		}
	})
}

func TestProfileHandler_ChangePassword(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{
		MinPasswordLength: 8,
		CookieDomains: []string{"example.com"},
	}
	h := &ProfileHandler{Cfg: cfg}
	e := echo.New()

	password := "oldpassword"
	hash, _ := core.HashPassword(password)
	core.UserDB.HSet(core.Ctx, "user:passuser", "password", hash)

	t.Run("Successful password change", func(t *testing.T) {
		f := make(url.Values)
		f.Set("current_password", password)
		f.Set("new_password", "NewSecure123!")
		f.Set("confirm_password", "NewSecure123!")

		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/password", f)
		c.Set("username", "passuser")

		err := h.ChangePassword(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)

		// Verify new password
		newData, _ := core.UserDB.HGet(core.Ctx, "user:passuser", "password").Result()
		assert.True(t, core.CheckPasswordHash("NewSecure123!", newData))
	})

	t.Run("Incorrect current password", func(t *testing.T) {
		f := make(url.Values)
		f.Set("current_password", "wrong")
		f.Set("new_password", "NewSecure123!")
		f.Set("confirm_password", "NewSecure123!")

		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/password", f)
		c.Set("username", "passuser")

		err := h.ChangePassword(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		
		var resp map[string]string
		json.Unmarshal(rec.Body.Bytes(), &resp)
		assert.Contains(t, resp["error"], "incorrect")
	})

	t.Run("Password mismatch", func(t *testing.T) {
		f := make(url.Values)
		f.Set("current_password", password)
		f.Set("new_password", "NewSecure123!")
		f.Set("confirm_password", "mismatch")

		c, rec := createTestContext(e, http.MethodPost, "/rauthprofile/password", f)
		c.Set("username", "passuser")

		err := h.ChangePassword(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}
