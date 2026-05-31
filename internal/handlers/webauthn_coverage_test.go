package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"rauth/internal/core"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parsedAssertion(userHandle []byte) *protocol.ParsedCredentialAssertionData {
	return &protocol.ParsedCredentialAssertionData{
		Response: protocol.ParsedAssertionResponse{
			UserHandle: userHandle,
		},
	}
}

func TestWebAuthnHandler_identifyWebAuthnUser(t *testing.T) {
	setupHandlersTest(t)
	h := &WebAuthnHandler{Cfg: &core.Config{}}
	e := echo.New()

	t.Run("UserHandle resolves via UID index", func(t *testing.T) {
		require.NoError(t, core.CreateUser("uiduser", "password123", "", false, ""))
		core.UserDB.Set(core.Ctx, "uid:handle-1", "uiduser", 0)

		c, _ := createTestContext(e, http.MethodPost, "/webauthn/login/finish", nil)
		username, userID, rec, err := h.identifyWebAuthnUser(c, parsedAssertion([]byte("handle-1")))
		require.NoError(t, err)
		assert.Equal(t, "uiduser", username)
		assert.Equal(t, []byte("handle-1"), userID)
		assert.Equal(t, "uiduser", rec.Username)
	})

	t.Run("UserHandle resolves via legacy username", func(t *testing.T) {
		require.NoError(t, core.CreateUser("legacyuser", "password123", "", false, ""))

		c, _ := createTestContext(e, http.MethodPost, "/webauthn/login/finish", nil)
		username, _, _, err := h.identifyWebAuthnUser(c, parsedAssertion([]byte("legacyuser")))
		require.NoError(t, err)
		assert.Equal(t, "legacyuser", username)
	})

	t.Run("Falls back to username query param", func(t *testing.T) {
		require.NoError(t, core.CreateUser("paramuser", "password123", "", false, ""))

		c, _ := createTestContext(e, http.MethodPost, "/webauthn/login/finish?username=paramuser", nil)
		username, userID, _, err := h.identifyWebAuthnUser(c, parsedAssertion(nil))
		require.NoError(t, err)
		assert.Equal(t, "paramuser", username)
		assert.NotEmpty(t, userID)
	})

	t.Run("Unidentifiable user returns 400", func(t *testing.T) {
		c, _ := createTestContext(e, http.MethodPost, "/webauthn/login/finish", nil)
		_, _, _, err := h.identifyWebAuthnUser(c, parsedAssertion(nil))
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code)
	})

	t.Run("Orphaned UID index returns user not found", func(t *testing.T) {
		// UID index points at a username with no user record.
		core.UserDB.Set(core.Ctx, "uid:orphan-handle", "ghostuser", 0)

		c, _ := createTestContext(e, http.MethodPost, "/webauthn/login/finish", nil)
		_, _, _, err := h.identifyWebAuthnUser(c, parsedAssertion([]byte("orphan-handle")))
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code)
	})
}

func TestWebAuthnHandler_getWebAuthnLoginSession(t *testing.T) {
	setupHandlersTest(t)
	h := &WebAuthnHandler{Cfg: &core.Config{}}
	e := echo.New()

	t.Run("Missing cookie returns 400", func(t *testing.T) {
		c, _ := createTestContext(e, http.MethodPost, "/webauthn/login/finish", nil)
		_, err := h.getWebAuthnLoginSession(c)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code)
	})

	t.Run("Cookie without redis session returns 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/webauthn/login/finish", nil)
		req.AddCookie(&http.Cookie{Name: "rauth_webauthn_session", Value: "nonexistent"})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_, err := h.getWebAuthnLoginSession(c)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code)
	})

	t.Run("Corrupt session JSON returns 500", func(t *testing.T) {
		core.TokenDB.Set(core.Ctx, "webauthn_login_session:corrupt", "{not-json", 0)
		req := httptest.NewRequest(http.MethodPost, "/webauthn/login/finish", nil)
		req.AddCookie(&http.Cookie{Name: "rauth_webauthn_session", Value: "corrupt"})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_, err := h.getWebAuthnLoginSession(c)
		require.Error(t, err)
		assert.Equal(t, http.StatusInternalServerError, err.(*echo.HTTPError).Code)
	})

	t.Run("Valid session is returned and consumed", func(t *testing.T) {
		sd := webauthn.SessionData{Challenge: "abc", UserID: []byte("uid")}
		raw, _ := json.Marshal(sd)
		core.TokenDB.Set(core.Ctx, "webauthn_login_session:good", raw, 0)
		req := httptest.NewRequest(http.MethodPost, "/webauthn/login/finish", nil)
		req.AddCookie(&http.Cookie{Name: "rauth_webauthn_session", Value: "good"})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		got, err := h.getWebAuthnLoginSession(c)
		require.NoError(t, err)
		assert.Equal(t, "abc", got.Challenge)
		// One-time use: the session key is deleted after retrieval.
		exists, _ := core.TokenDB.Exists(core.Ctx, "webauthn_login_session:good").Result()
		assert.Equal(t, int64(0), exists)
	})
}
