package handlers

import (
	"github.com/go-webauthn/webauthn/protocol"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"rauth/internal/core"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

func TestWebAuthnHandlers(t *testing.T) {
	s := miniredis.RunT(t)
	defer s.Close()

	core.TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.UserDB = core.TokenDB
	core.RateLimitDB = core.TokenDB

	cfg := &core.Config{
		CookieDomains:              []string{"localhost"},
		ServerSecret:               "testsecret1234567890123456789012",
		TokenValidityMinutes:       60,
		RateLimitLoginMax:          100,
		RateLimitLoginDecay:        60,
		RateLimitRegistrationMax:   100,
		RateLimitRegistrationDecay: 60,
		RateLimitLoginAccessMax:    1000,
		RateLimitLoginFailUserMax:  1000,
		RateLimitLoginFailIPMax:    1000,
	}
	err := core.InitWebAuthn(cfg)
	assert.NoError(t, err)

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
		_ = core.CreateUser("testuser", "password123", "test@example.com", false, "")
		req := httptest.NewRequest(http.MethodGet, "/webauthn/register/begin", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "testuser")

		if assert.NoError(t, h.BeginRegistration(c)) {
			assert.Equal(t, http.StatusOK, rec.Code)
			var options map[string]interface{}
			err := json.Unmarshal(rec.Body.Bytes(), &options)
			assert.NoError(t, err)
			assert.NotNil(t, options["challenge"])
		}
	})

	t.Run("BeginLogin_Nameless_Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/webauthn/login/begin", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		if assert.NoError(t, h.BeginLogin(c)) {
			assert.Equal(t, http.StatusOK, rec.Code)
			// Should set rauth_webauthn_session cookie
			cookies := rec.Result().Cookies()
			found := false
			for _, cookie := range cookies {
				if cookie.Name == "rauth_webauthn_session" {
					found = true
					break
				}
			}
			assert.True(t, found)
		}
	})

	t.Run("FinishLogin_MissingSession", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/webauthn/login/finish", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.FinishLogin(c)
		if assert.Error(t, err) {
			he, ok := err.(*echo.HTTPError)
			assert.True(t, ok)
			assert.Equal(t, http.StatusBadRequest, he.Code)
		}
	})

	// Regression: a passkey-issued session must stamp groups/is_admin and the
	// per-IP session index, matching the password-login path (issueToken), so
	// forward-auth forwards X-RAuth-Groups/X-RAuth-Admin and brute-force checks
	// (HasActiveSessions) can see passkey sessions.
	t.Run("issuePasskeyToken_StampsGroupsAdminAndIPIndex", func(t *testing.T) {
		core.AuditDB = core.TokenDB
		core.UserDB.HSet(core.Ctx, "user:passkeyuser", map[string]interface{}{
			"username": "passkeyuser",
			"groups":   "engineering,ops",
			"is_admin": "1",
		})
		userRecord, gerr := core.GetUser("passkeyuser")
		assert.NoError(t, gerr)

		req := httptest.NewRequest(http.MethodPost, "/webauthn/login/finish", nil)
		req.RemoteAddr = "203.0.113.7:12345"
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		assert.NoError(t, h.issuePasskeyToken(c, "passkeyuser", &userRecord))

		tokens, err := core.TokenDB.SMembers(core.Ctx, "ip_sessions:203.0.113.7").Result()
		assert.NoError(t, err)
		if assert.Len(t, tokens, 1) {
			data, err := core.TokenDB.HGetAll(core.Ctx, "X-rauth-authtoken="+tokens[0]).Result()
			assert.NoError(t, err)
			assert.Equal(t, "engineering,ops", data["groups"])
			assert.Equal(t, "1", data["is_admin"])
		}
	})
}


func TestWebAuthnHandler_identifyWebAuthnUser(t *testing.T) {
	setupHandlersTest(t)
	h := &WebAuthnHandler{Cfg: &core.Config{}}
	e := echo.New()

	t.Run("Identify missing both", func(t *testing.T) {
		parsedResponse := &protocol.ParsedCredentialAssertionData{
			Response: protocol.ParsedAssertionResponse{
				UserHandle: []byte{},
			},
		}

		c, _ := createTestContext(e, http.MethodPost, "/auth/webauthn/login/finish", nil)

		_, _, _, err := h.identifyWebAuthnUser(c, parsedResponse)
		assert.Error(t, err)
	})

	t.Run("Identify by usernameParam", func(t *testing.T) {
		// Mock user in DB
		core.UserDB.HSet(core.Ctx, "user:testuser", "username", "testuser", "uid", "test-uid")

		parsedResponse := &protocol.ParsedCredentialAssertionData{
			Response: protocol.ParsedAssertionResponse{
				UserHandle: []byte{},
			},
		}

		c, _ := createTestContext(e, http.MethodGet, "/auth/webauthn/login/finish?username=testuser", nil)

		username, userID, userRec, err := h.identifyWebAuthnUser(c, parsedResponse)
		assert.NoError(t, err)
		assert.Equal(t, "testuser", username)
		assert.Equal(t, []byte("test-uid"), userID)
		assert.NotNil(t, userRec)
	})
}
