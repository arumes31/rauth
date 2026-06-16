package handlers

import (
	"encoding/json"
	"github.com/go-webauthn/webauthn/protocol"
	"net/http"
	"net/http/httptest"
	"rauth/internal/core"
	"testing"
	"time"

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

	t.Run("BeginLogin_ExistingUser_Success", func(t *testing.T) {
		_ = core.CreateUser("beginloginuser", "password123", "login@example.com", false, "")

		// Setup a fake webauthn credential for the user to avoid "Found no credentials for user"
		// the go-webauthn/webauthn library requires credentials to exist for non-discoverable logins
		// webauthn struct is aliased or not imported, we can just use go-webauthn/webauthn if we add import
		// Since we just need to test BeginLogin without failing, we can bypass the error. Wait, BeginLogin returns 500 when error is returned.
		// Let's just create a credential via core.SaveWebAuthnCredential

		// Create mock credential to store
		credJSON := `{"ID":"ZmFrZS1pZA==","PublicKey":"YmFzZTY0a2V5","AttestationType":"none","Transport":[],"Flags":{"UserPresent":true,"UserVerified":true,"BackupEligible":false,"BackupState":false},"Authenticator":{"AAGUID":"AAAAAAAAAAAAAAAAAAAAAA==","SignCount":0,"CloneWarning":false,"Attachment":"platform"},"Attestation":null}`
		core.UserDB.HSet(core.Ctx, "user:beginloginuser:webauthn_creds_v2", "ZmFrZS1pZA==", credJSON)

		req := httptest.NewRequest(http.MethodGet, "/webauthn/login/begin?username=beginloginuser", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		if assert.NoError(t, h.BeginLogin(c)) {
			assert.Equal(t, http.StatusOK, rec.Code)
			var options map[string]interface{}
			err := json.Unmarshal(rec.Body.Bytes(), &options)
			assert.NoError(t, err)
			assert.NotNil(t, options["challenge"])

			// Verify session cookie was set
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

	t.Run("BeginLogin_NonExistentUser_DummySuccess", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/webauthn/login/begin?username=nonexistentuser", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.BeginLogin(c)
		if assert.Error(t, err) {
			he, ok := err.(*echo.HTTPError)
			assert.True(t, ok)
			assert.Equal(t, http.StatusInternalServerError, he.Code)
		} else {
			assert.Equal(t, http.StatusOK, rec.Code)
			var options map[string]interface{}
			err := json.Unmarshal(rec.Body.Bytes(), &options)
			assert.NoError(t, err)
			assert.Fail(t, "expected an error but got none")
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

	t.Run("FinishRegistration_RateLimitExceeded", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish", nil)
		req.RemoteAddr = "192.168.1.1:12345" // For clientIP
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		// Max out rate limit
		for i := 0; i < cfg.RateLimitRegistrationMax; i++ {
			core.CheckRateLimit("reg_ip:192.168.1.1", cfg.RateLimitRegistrationMax, cfg.RateLimitRegistrationDecay)
		}

		err := h.FinishRegistration(c)
		if assert.Error(t, err) {
			he, ok := err.(*echo.HTTPError)
			assert.True(t, ok)
			assert.Equal(t, http.StatusTooManyRequests, he.Code)
		}

		// Clear rate limit for other tests
		core.TokenDB.Del(core.Ctx, "reg_ip:192.168.1.1")
	})

	t.Run("FinishRegistration_Unauthorized", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.FinishRegistration(c)
		if assert.Error(t, err) {
			he, ok := err.(*echo.HTTPError)
			assert.True(t, ok)
			assert.Equal(t, http.StatusUnauthorized, he.Code)
		}
	})

	t.Run("FinishRegistration_UserNotFound", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "nonexistentuser")

		err := h.FinishRegistration(c)
		if assert.Error(t, err) {
			he, ok := err.(*echo.HTTPError)
			assert.True(t, ok)
			assert.Equal(t, http.StatusInternalServerError, he.Code)
			assert.Equal(t, "User not found", he.Message)
		}
	})

	t.Run("FinishRegistration_SessionExpired", func(t *testing.T) {
		_ = core.CreateUser("testuser2", "password123", "test2@example.com", false, "")
		req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "testuser2")

		err := h.FinishRegistration(c)
		if assert.Error(t, err) {
			he, ok := err.(*echo.HTTPError)
			assert.True(t, ok)
			assert.Equal(t, http.StatusBadRequest, he.Code)
			assert.Equal(t, "Session expired", he.Message)
		}
	})

	t.Run("FinishRegistration_WebAuthnError", func(t *testing.T) {
		_ = core.CreateUser("testuser4", "password123", "test4@example.com", false, "")

		// Valid JSON, but not matching what the webauthn library expects to correctly verify an empty request
		sessionJSON := `{"challenge":"aGVsbG8=","user_id":"dGVzdHVzZXI0","allowed_credentials":[],"userVerification":"preferred"}`
		core.TokenDB.Set(core.Ctx, "webauthn_reg:testuser4", sessionJSON, 5*time.Minute)

		req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "testuser4")

		err := h.FinishRegistration(c)
		if assert.Error(t, err) {
			he, ok := err.(*echo.HTTPError)
			assert.True(t, ok)
			assert.Equal(t, http.StatusBadRequest, he.Code)
		}
	})

	t.Run("FinishRegistration_InvalidSessionData", func(t *testing.T) {
		_ = core.CreateUser("testuser3", "password123", "test3@example.com", false, "")
		core.TokenDB.Set(core.Ctx, "webauthn_reg:testuser3", "invalid json", 0)
		req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "testuser3")

		err := h.FinishRegistration(c)
		if assert.Error(t, err) {
			he, ok := err.(*echo.HTTPError)
			assert.True(t, ok)
			assert.Equal(t, http.StatusInternalServerError, he.Code)
			assert.Equal(t, "Failed to parse session data", he.Message)
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
