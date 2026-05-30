package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"rauth/internal/core"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
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
		err := core.CreateUser("testuser", "password123", "test@example.com", false, "")
		assert.NoError(t, err)
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
}

func TestWebAuthnHandler_identifyWebAuthnUser(t *testing.T) {
	setupHandlersTest(t)
	h := &WebAuthnHandler{Cfg: &core.Config{}}
	e := echo.New()

	err := core.CreateUser("knownuser", "pass", "email@example.com", false, "")
	assert.NoError(t, err)
	knownUserRecord, _ := core.GetUser("knownuser")
	uidBytes := []byte(knownUserRecord.UID)

	t.Run("Identify by Handle matching string UID index", func(t *testing.T) {
		core.UserDB.HSet(core.Ctx, "uid_index", string(uidBytes), "knownuser")

		req := httptest.NewRequest(http.MethodGet, "/?username=", nil)
		c := e.NewContext(req, httptest.NewRecorder())
		parsed := &protocol.ParsedCredentialAssertionData{
			Response: protocol.ParsedAssertionResponse{
				UserHandle: uidBytes,
			},
		}

		username, userID, user, err := h.identifyWebAuthnUser(c, parsed)
		assert.NoError(t, err)
		assert.Equal(t, "knownuser", username)
		assert.Equal(t, uidBytes, userID)
		assert.NotNil(t, user)
	})

	t.Run("Identify by Username Param fallback", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/?username=knownuser", nil)
		c := e.NewContext(req, httptest.NewRecorder())
		parsed := &protocol.ParsedCredentialAssertionData{
			Response: protocol.ParsedAssertionResponse{
				UserHandle: nil, // No handle provided by authenticator
			},
		}

		username, userID, user, err := h.identifyWebAuthnUser(c, parsed)
		assert.NoError(t, err)
		assert.Equal(t, "knownuser", username)
		assert.Equal(t, uidBytes, userID)
		assert.NotNil(t, user)
	})
}

func TestWebAuthnHandler_issuePasskeyToken(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{
		CookieDomains:        []string{"example.com"},
		ServerSecret:         "testsecret1234567890123456789012",
		TokenValidityMinutes: 60,
		AllowedCountries:     []string{"US"}, // Only US allowed
	}
	h := &WebAuthnHandler{Cfg: cfg}
	e := echo.New()

	err := core.CreateUser("passkeyuser", "pass", "email@example.com", false, "")
	assert.NoError(t, err)
	userRecord, _ := core.GetUser("passkeyuser")

	t.Run("Issue token successfully", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-For", "8.8.8.8") // US IP (mocked or handled by geo check)
		// We should mock GetCountryCode if needed, but it might return Internal for 127.0.0.1. Let's reset AllowedCountries to empty so it allows all to test success path first.
		h.Cfg.AllowedCountries = []string{}

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.issuePasskeyToken(c, "passkeyuser", &userRecord)
		assert.NoError(t, err)

		cookies := rec.Result().Cookies()
		foundAuthToken := false
		foundWebAuthnSessionClear := false
		for _, cookie := range cookies {
			if cookie.Name == "X-rauth-authtoken" {
				foundAuthToken = true
				assert.NotEmpty(t, cookie.Value)
			}
			if cookie.Name == "rauth_webauthn_session" {
				foundWebAuthnSessionClear = true
				assert.Equal(t, "", cookie.Value)
			}
		}
		assert.True(t, foundAuthToken)
		assert.True(t, foundWebAuthnSessionClear)
	})

	t.Run("Blocked by country", func(t *testing.T) {
		h.Cfg.AllowedCountries = []string{"US"}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-For", "127.0.0.1") // Loopback is Internal, not US
		req.RemoteAddr = "127.0.0.1:1234"
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.issuePasskeyToken(c, "passkeyuser", &userRecord)
		assert.Error(t, err)
		if he, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusForbidden, he.Code)
		}
	})
}
