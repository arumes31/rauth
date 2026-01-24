package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"rauth/internal/core"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

func TestWebAuthnHandlers(t *testing.T) {
	s := miniredis.RunT(t)
	defer s.Close()

	core.TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.UserDB = core.TokenDB

	cfg := &core.Config{
		CookieDomains: []string{"localhost"},
		ServerSecret:  "testsecret1234567890123456789012",
	}
	core.InitWebAuthn(cfg)

	h := &WebAuthnHandler{Cfg: cfg}
	e := echo.New()

	t.Run("BeginRegistration_Unauthorized", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/webauthn/register/begin", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.BeginRegistration(c)
		if assert.Error(t, err) {
			he, ok := err.(*echo.HTTPError)
			assert.True(t, ok)
			assert.Equal(t, http.StatusUnauthorized, he.Code)
		}
	})

	t.Run("BeginRegistration_Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/webauthn/register/begin", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "testuser")

		if assert.NoError(t, h.BeginRegistration(c)) {
			assert.Equal(t, http.StatusOK, rec.Code)
			var options map[string]interface{}
			err := json.Unmarshal(rec.Body.Bytes(), &options)
			assert.NoError(t, err)
			assert.NotNil(t, options["publicKey"])
		}
	})

	t.Run("BeginLogin_NoUsername", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/webauthn/login/begin", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.BeginLogin(c)
		if assert.Error(t, err) {
			he, ok := err.(*echo.HTTPError)
			assert.True(t, ok)
			assert.Equal(t, http.StatusBadRequest, he.Code)
		}
	})

	t.Run("BeginLogin_Success", func(t *testing.T) {
		// Register a fake credential first
		cred := &webauthn.Credential{ID: []byte("credID"), PublicKey: []byte("pubKey")}
		core.SaveWebAuthnCredential("testuser", cred)

		req := httptest.NewRequest(http.MethodGet, "/webauthn/login/begin?username=testuser", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		if assert.NoError(t, h.BeginLogin(c)) {
			assert.Equal(t, http.StatusOK, rec.Code)
			var options map[string]interface{}
			err := json.Unmarshal(rec.Body.Bytes(), &options)
			assert.NoError(t, err)
			assert.NotNil(t, options["publicKey"])
		}
	})
}
