package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"rauth/internal/core"
)

func responseCookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == name && cookie.MaxAge >= 0 {
			return cookie
		}
	}
	t.Fatalf("missing response cookie %s", name)
	return nil
}

func TestSelectedSQLRuntimeLogin2FARecoveryAndManagement(t *testing.T) {
	cfg := setupSQLRuntimeTest(t)
	core.SetBcryptCost(4)
	t.Cleanup(func() { core.SetBcryptCost(12) })
	const user = "sql-handler-user"
	const secret = "JBSWY3DPEHPK3PXP"
	require.NoError(t, core.CreateUser(user, "Password123!", "", true, secret))
	e := echo.New()
	renderer := &mockRenderer{}
	e.Renderer = renderer
	a, b := &AuthHandler{Cfg: cfg}, &AuthHandler{Cfg: cfg}
	login := func(handler *AuthHandler) *http.Cookie {
		c, rec := createTestContext(e, http.MethodPost, "/rauthlogin", url.Values{"username": {user}, "password": {"Password123!"}})
		require.NoError(t, handler.Login(c))
		require.Equal(t, http.StatusOK, rec.Code)
		return responseCookie(t, rec, "rauth_2fa_pending")
	}
	verify := func(handler *AuthHandler, pending *http.Cookie, proof string) *httptest.ResponseRecorder {
		c, rec := createTestContext(e, http.MethodPost, "/rauthlogin?action=verify_2fa", url.Values{"totp_code": {proof}})
		c.Request().AddCookie(pending)
		require.NoError(t, handler.Verify2FA(c))
		return rec
	}
	pending := login(a)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	completed := verify(b, pending, code)
	require.Equal(t, http.StatusFound, completed.Code)
	session := responseCookie(t, completed, "X-rauth-authtoken")
	token, err := core.DecryptToken(session.Value, cfg.ServerSecret)
	require.NoError(t, err)
	c, validated := createTestContext(e, http.MethodGet, "/rauthvalidate", nil)
	c.Request().AddCookie(session)
	require.NoError(t, a.Validate(c))
	assert.Equal(t, http.StatusOK, validated.Code)
	assert.Equal(t, user, validated.Header().Get("X-RAuth-User"))
	replay := verify(a, pending, code)
	assert.Equal(t, http.StatusFound, replay.Code)
	assert.Empty(t, replay.Result().Cookies(), "a consumed challenge cannot issue another session")
	replay = verify(a, login(b), code)
	assert.Equal(t, http.StatusUnauthorized, replay.Code, "TOTP replay is global across handler instances")
	recovery, err := core.GenerateRecoveryCodes(user)
	require.NoError(t, err)
	require.NotEmpty(t, recovery)
	recovered := verify(a, login(b), recovery[0])
	require.Equal(t, http.StatusFound, recovered.Code)
	responseCookie(t, recovered, "X-rauth-authtoken")
	assert.False(t, core.ConsumeRecoveryCode(user, recovery[0]), "recovery proof is single-use")
	profile := &ProfileHandler{Cfg: cfg}
	c, _ = createTestContext(e, http.MethodGet, "/rauthprofile", nil)
	c.Set("username", user)
	c.Set("token", token)
	require.NoError(t, profile.Show(c))
	data, err := json.Marshal(renderer.LastData)
	require.NoError(t, err)
	assert.NotContains(t, string(data), token)
	views := renderer.LastData.(map[string]interface{})["sessions"].([]map[string]string)
	require.Len(t, views, 2)
	var currentHandle string
	for _, view := range views {
		if view["is_current"] == "1" {
			currentHandle = view["handle"]
		}
	}
	require.NotEmpty(t, currentHandle)
	admin := &AdminHandler{Cfg: cfg}
	c, _ = createTestContext(e, http.MethodPost, "/rauthmgmt/session/invalidate", url.Values{"token": {currentHandle}})
	c.Set("username", user)
	require.NoError(t, admin.InvalidateSession(c))
	c, validated = createTestContext(e, http.MethodGet, "/rauthvalidate", nil)
	c.Request().AddCookie(session)
	require.NoError(t, b.Validate(c))
	assert.Equal(t, http.StatusUnauthorized, validated.Code)
	require.Nil(t, core.TokenDB)
	require.Nil(t, core.RateLimitDB)
	require.Nil(t, core.InviteDB)
}
