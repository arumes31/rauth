package handlers

import (
	"encoding/json"
	"github.com/go-webauthn/webauthn/protocol"
	"net/http"
	"net/http/httptest"
	"net/url"
	"rauth/internal/core"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/labstack/echo/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebAuthnHandlers(t *testing.T) {
	s := miniredis.RunT(t)
	defer s.Close()

	core.TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	usePG(t)
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

	t.Run("BeginRegistration_RequiresStepUp", func(t *testing.T) {
		_ = core.CreateUser("testuser", "password123", "test@example.com", false, "")
		for _, pw := range []string{"", "wrongpassword"} {
			c, _ := createTestContext(e, http.MethodPost, "/webauthn/register/begin", url.Values{"current_password": {pw}})
			c.Set("username", "testuser")

			err := h.BeginRegistration(c)
			if assert.Error(t, err) {
				he, ok := err.(*echo.HTTPError)
				assert.True(t, ok)
				assert.Equal(t, http.StatusBadRequest, he.Code)
			}
		}
		keys, err := core.TokenDB.Keys(core.Ctx, "webauthn_reg:*").Result()
		require.NoError(t, err)
		assert.Empty(t, keys, "no registration challenge may be issued without step-up")
	})

	t.Run("BeginRegistration_Success", func(t *testing.T) {
		_ = core.CreateUser("testuser", "password123", "test@example.com", false, "")
		c, rec := createTestContext(e, http.MethodPost, "/webauthn/register/begin", url.Values{"current_password": {"password123"}})
		setRegistrationIdentity(t, c, "testuser")

		if assert.NoError(t, h.BeginRegistration(c)) {
			assert.Equal(t, http.StatusOK, rec.Code)
			var options map[string]interface{}
			err := json.Unmarshal(rec.Body.Bytes(), &options)
			assert.NoError(t, err)
			assert.NotNil(t, options["challenge"])
		}
	})

	t.Run("BeginRegistration_UserNotFound", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/webauthn/register/begin", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "nonexistentuser")

		err := h.BeginRegistration(c)
		if assert.Error(t, err) {
			he, ok := err.(*echo.HTTPError)
			assert.True(t, ok)
			assert.Equal(t, http.StatusInternalServerError, he.Code)
			assert.Equal(t, "User not found", he.Message)
		}
	})

	t.Run("BeginRegistration_WebAuthnError", func(t *testing.T) {
		_ = core.CreateUser("testuser_weberr", "password123", "test2@example.com", false, "")

		// Temporarily modify the WebAuthnInstance config to force an error
		originalRPID := core.WebAuthnInstance.Config.RPID
		core.WebAuthnInstance.Config.RPID = ""
		defer func() {
			core.WebAuthnInstance.Config.RPID = originalRPID
		}()

		c, _ := createTestContext(e, http.MethodPost, "/webauthn/register/begin", url.Values{"current_password": {"password123"}})
		setRegistrationIdentity(t, c, "testuser_weberr")

		err := h.BeginRegistration(c)
		if assert.Error(t, err) {
			he, ok := err.(*echo.HTTPError)
			assert.True(t, ok)
			assert.Equal(t, http.StatusInternalServerError, he.Code)
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

	// Unknown accounts, accounts without passkeys and enrolled accounts must
	// all get a 200 with one allowed credential, so the response does not
	// reveal which one a username is. The dummy credential is stable per name.
	t.Run("BeginLogin_ByName_DoesNotRevealAccount", func(t *testing.T) {
		seedUserFields(t, "nokeys", map[string]interface{}{"username": "nokeys"})
		seedUserFields(t, "haskey", map[string]interface{}{"username": "haskey"})
		require.NoError(t, core.SaveWebAuthnCredential("haskey", &webauthn.Credential{ID: []byte("real-key")}, mustGen(t, "haskey")))

		allowed := func(name string) []interface{} {
			req := httptest.NewRequest(http.MethodGet, "/webauthn/login/begin?username="+name, nil)
			rec := httptest.NewRecorder()
			require.NoError(t, h.BeginLogin(e.NewContext(req, rec)))
			require.Equal(t, http.StatusOK, rec.Code, name)
			var body struct {
				AllowCredentials []interface{} `json:"allowCredentials"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			return body.AllowCredentials
		}
		for _, name := range []string{"ghost", "nokeys", "haskey"} {
			assert.Len(t, allowed(name), 1, name)
		}
		assert.Equal(t, allowed("ghost"), allowed("ghost"), "the dummy credential must be stable")
		assert.NotEqual(t, allowed("ghost"), allowed("nokeys"))
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

		req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		setRegistrationIdentity(t, c, "testuser4")
		seedRegistrationProof(t, c, cfg, "testuser4", sessionJSON, false)

		err := h.FinishRegistration(c)
		if assert.Error(t, err) {
			he, ok := err.(*echo.HTTPError)
			assert.True(t, ok)
			assert.Equal(t, http.StatusBadRequest, he.Code)
		}
	})

	t.Run("FinishRegistration_InvalidSessionData", func(t *testing.T) {
		_ = core.CreateUser("testuser3", "password123", "test3@example.com", false, "")

		req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		setRegistrationIdentity(t, c, "testuser3")
		seedRegistrationProof(t, c, cfg, "testuser3", "", true)

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
		seedUserFields(t, "passkeyuser", map[string]interface{}{
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

		assert.NoError(t, h.issuePasskeyToken(c, "passkeyuser", &userRecord, mustGen(t, "passkeyuser")))

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
		seedUserFields(t, "testuser", map[string]interface{}{"username": "testuser", "uid": "0f8e2c1a-3b4d-4e5f-8a6b-7c9d0e1f2a3b"})

		parsedResponse := &protocol.ParsedCredentialAssertionData{
			Response: protocol.ParsedAssertionResponse{
				UserHandle: []byte{},
			},
		}

		c, _ := createTestContext(e, http.MethodGet, "/auth/webauthn/login/finish?username=testuser", nil)

		username, userID, userRec, err := h.identifyWebAuthnUser(c, parsedResponse)
		assert.NoError(t, err)
		assert.Equal(t, "testuser", username)
		assert.Equal(t, []byte("0f8e2c1a-3b4d-4e5f-8a6b-7c9d0e1f2a3b"), userID)
		assert.NotNil(t, userRec)
	})
}

func setRegistrationIdentity(t *testing.T, c *echo.Context, user string) {
	t.Helper()
	gen, err := core.AuthGeneration(user)
	require.NoError(t, err)
	c.Set("username", user)
	c.Set("auth_gen", gen)
	c.Set("token", strings.Repeat("browser-token-", 4))
	token := c.Get("token").(string)
	require.NoError(t, core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+token, "username", user, "status", "valid", "auth_gen", gen).Err())
	require.NoError(t, core.TokenDB.Expire(core.Ctx, "X-rauth-authtoken="+token, time.Hour).Err())
}
func seedRegistrationProof(t *testing.T, c *echo.Context, cfg *core.Config, user, sessionJSON string, corrupt bool) string {
	t.Helper()
	gen, _ := c.Get("auth_gen").(string)
	tok, _ := c.Get("token").(string)
	id := core.GenerateRandomString(32)
	body := []byte("invalid json")
	if !corrupt {
		var session webauthn.SessionData
		require.NoError(t, json.Unmarshal([]byte(sessionJSON), &session))
		var err error
		binding, bindingErr := core.RegistrationSessionBinding(c.Request().Context(), tok, cfg.ServerSecret)
		require.NoError(t, bindingErr)
		body, err = json.Marshal(registrationProof{Session: session, Username: user, Generation: gen, BrowserBinding: binding})
		require.NoError(t, err)
	}
	require.NoError(t, core.StoreAuthArtifact(core.PasskeyRegistration, id, body, user, gen, 5*time.Minute))
	c.Request().AddCookie(&http.Cookie{Name: registrationCookie, Value: id})
	return id
}
func TestRegistrationProofBoundToBrowserAndGeneration(t *testing.T) {
	s := miniredis.RunT(t)
	core.TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	core.RateLimitDB = core.TokenDB
	usePG(t)
	require.NoError(t, core.CreateUser("proof-user", "Password123", "", false, ""))
	cfg := &core.Config{ServerSecret: strings.Repeat("s", 32), RateLimitRegistrationMax: 100, RateLimitRegistrationDecay: 60}
	h := &WebAuthnHandler{Cfg: cfg}
	e := echo.New()
	c, _ := createTestContext(e, http.MethodPost, "/webauthn/register/finish", nil)
	setRegistrationIdentity(t, c, "proof-user")
	id := seedRegistrationProof(t, c, cfg, "proof-user", `{"challenge":"aGVsbG8=","user_id":"dGVzdA=="}`, false)
	wrong, _ := createTestContext(e, http.MethodPost, "/webauthn/register/finish", nil)
	setRegistrationIdentity(t, wrong, "proof-user")
	other := strings.Repeat("other-browser", 4)
	require.NoError(t, core.StoreSession(other, "proof-user", "127.0.0.1", map[string]interface{}{"username": "proof-user", "status": "valid", "auth_gen": wrong.Get("auth_gen")}, time.Hour))
	wrong.Set("token", other)
	// This must reach the distinct-browser comparison, not fail because the
	// second session is absent or belongs to a different account/generation.
	otherBinding, bindingErr := core.RegistrationSessionBinding(wrong.Request().Context(), other, cfg.ServerSecret)
	require.NoError(t, bindingErr)
	originalBinding, bindingErr := core.RegistrationSessionBinding(c.Request().Context(), c.Get("token").(string), cfg.ServerSecret)
	require.NoError(t, bindingErr)
	require.NotEqual(t, originalBinding, otherBinding)
	wrong.Request().AddCookie(&http.Cookie{Name: registrationCookie, Value: id})
	err := h.FinishRegistration(wrong)
	require.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code)
	_, err = core.GetAuthArtifact(core.PasskeyRegistration, id)
	require.NoError(t, err, "a different browser cannot consume this proof")
	_, err = core.BumpAuthGeneration("proof-user")
	require.NoError(t, err)
	setRegistrationIdentity(t, c, "proof-user")
	err = h.FinishRegistration(c)
	require.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, err.(*echo.HTTPError).Code, "an old step-up cannot register a factor after credential reset")
}

func TestRegistrationProofSurvivesNormalSessionRotation(t *testing.T) {
	setupHandlersTest(t)
	core.SetBcryptCost(4)
	t.Cleanup(func() { core.SetBcryptCost(12) })
	user := "rotation-proof-user"
	require.NoError(t, core.CreateUser(user, "Password123!", "", false, ""))
	cfg := &core.Config{ServerSecret: strings.Repeat("s", 32), CookieDomains: []string{"localhost"}, RateLimitRegistrationMax: 100, RateLimitRegistrationDecay: 60}
	require.NoError(t, core.InitWebAuthn(cfg))
	h := &WebAuthnHandler{Cfg: cfg}
	e := echo.New()
	begin, rec := createTestContext(e, http.MethodPost, "/webauthn/register/begin", url.Values{"current_password": {"Password123!"}})
	setRegistrationIdentity(t, begin, user)
	old := begin.Get("token").(string)
	require.NoError(t, core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+old, "username", user, "status", "valid", "auth_gen", begin.Get("auth_gen")).Err())
	require.NoError(t, core.TokenDB.Expire(core.Ctx, "X-rauth-authtoken="+old, time.Hour).Err())
	require.NoError(t, h.BeginRegistration(begin))
	var challenge *http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == registrationCookie {
			challenge = cookie
		}
	}
	require.NotNil(t, challenge)
	next := strings.Repeat("rotated-browser-", 4)
	changed, err := core.RotateSession(old, next, user, "127.0.0.1", time.Now().Unix(), time.Hour, 30*time.Second)
	require.NoError(t, err)
	require.True(t, changed)
	finish, _ := createTestContext(e, http.MethodPost, "/webauthn/register/finish", nil)
	finish.Set("username", user)
	finish.Set("auth_gen", begin.Get("auth_gen"))
	finish.Set("token", next)
	finish.Request().AddCookie(challenge)
	// An invalid attestation still claims the matching one-use proof. A normal
	// cookie rotation must not strand the real browser before that stage.
	require.Error(t, h.FinishRegistration(finish))
	_, err = core.GetAuthArtifact(core.PasskeyRegistration, challenge.Value)
	require.ErrorIs(t, err, core.ErrAuthArtifactMissing, "normal session rotation must preserve this browser's registration binding")
}
