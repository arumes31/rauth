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

func TestInviteHandler_Create(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{PublicURL: "http://localhost:8080"}
	h := &InviteHandler{Cfg: cfg}
	e := echo.New()

	t.Run("Successful invite creation", func(t *testing.T) {
		f := make(url.Values)
		f.Set("email", "test@example.com")

		c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/invite", f)
		err := h.Create(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var resp map[string]string
		err = json.Unmarshal(rec.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.NotEmpty(t, resp["token"])
		assert.Contains(t, resp["url"], "/rauthredeem?token="+resp["token"])

		// Verify token in DB
		email, err := core.InviteDB.Get(core.Ctx, "invite:"+resp["token"]).Result()
		assert.NoError(t, err)
		assert.Equal(t, "test@example.com", email)
	})

	t.Run("Missing email", func(t *testing.T) {
		f := make(url.Values)
		c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/invite", f)
		err := h.Create(c)

		assert.Error(t, err)
		he, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, he.Code)
		assert.Equal(t, "Email is required", he.Message)
	})
}

func TestInviteHandler_RedeemPage(t *testing.T) {
	setupHandlersTest(t)
	h := &InviteHandler{}
	e := echo.New()
	mockR := &mockRenderer{}
	e.Renderer = mockR

	t.Run("Valid token", func(t *testing.T) {
		token := "valid-token"
		email := "test@example.com"
		core.InviteDB.Set(core.Ctx, "invite:"+token, email, 0)

		c, rec := createTestContext(e, http.MethodGet, "/rauthredeem?token="+token, nil)
		err := h.RedeemPage(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		data := mockR.LastData.(map[string]interface{})
		assert.Equal(t, token, data["token"])
		assert.Equal(t, email, data["email"])
	})

	t.Run("Missing token", func(t *testing.T) {
		c, rec := createTestContext(e, http.MethodGet, "/rauthredeem", nil)
		err := h.RedeemPage(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/rauthlogin", rec.Header().Get("Location"))
	})

	t.Run("Invalid token", func(t *testing.T) {
		c, _ := createTestContext(e, http.MethodGet, "/rauthredeem?token=invalid", nil)
		err := h.RedeemPage(c)

		assert.Error(t, err)
		he, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusNotFound, he.Code)
	})
}

func TestInviteHandler_Redeem(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{
		PasswordMinLength: 8,
		ServerSecret:      "32byte-secret-key-for-testing-!!",
	}
	h := &InviteHandler{Cfg: cfg}
	e := echo.New()

	t.Run("Successful redemption", func(t *testing.T) {
		token := "redeem-token"
		email := "test@example.com"
		core.InviteDB.Set(core.Ctx, "invite:"+token, email, 0)

		f := make(url.Values)
		f.Set("token", token)
		f.Set("username", "newuser")
		f.Set("password", "strongpassword123")

		c, rec := createTestContext(e, http.MethodPost, "/rauthredeem", f)
		err := h.Redeem(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/rauthlogin?success=account_created", rec.Header().Get("Location"))

		// Verify user created
		exists, _ := core.UserDB.Exists(core.Ctx, "user:newuser").Result()
		assert.Equal(t, int64(1), exists)

		// Verify token deleted
		exists, _ = core.InviteDB.Exists(core.Ctx, "invite:"+token).Result()
		assert.Equal(t, int64(0), exists)
	})

	t.Run("Invalid token", func(t *testing.T) {
		f := make(url.Values)
		f.Set("token", "invalid")
		f.Set("username", "newuser2")
		f.Set("password", "strongpassword123")

		c, _ := createTestContext(e, http.MethodPost, "/rauthredeem", f)
		err := h.Redeem(c)

		assert.Error(t, err)
		he, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusNotFound, he.Code)
	})

	t.Run("Weak password", func(t *testing.T) {
		token := "weak-pass-token"
		email := "test2@example.com"
		core.InviteDB.Set(core.Ctx, "invite:"+token, email, 0)

		f := make(url.Values)
		f.Set("token", token)
		f.Set("username", "newuser3")
		f.Set("password", "weak")

		c, rec := createTestContext(e, http.MethodPost, "/rauthredeem", f)
		err := h.Redeem(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("Username already taken", func(t *testing.T) {
		token := "taken-user-token"
		email := "test3@example.com"
		core.InviteDB.Set(core.Ctx, "invite:"+token, email, 0)

		core.UserDB.HSet(core.Ctx, "user:existinguser", "username", "existinguser")

		f := make(url.Values)
		f.Set("token", token)
		f.Set("username", "existinguser")
		f.Set("password", "strongpassword123")

		c, rec := createTestContext(e, http.MethodPost, "/rauthredeem", f)
		err := h.Redeem(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusConflict, rec.Code)
	})
}
