package handlers

import (
	"net/http"
	"net/url"
	"rauth/internal/core"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetBypassRules(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		core.SetEnvBypassRules(nil)
		core.UserDB.Del(core.Ctx, "auth_bypass_rules")
		_ = core.ReloadBypassRules()
	})
}

func bypassTestConfig() *core.Config {
	return &core.Config{
		ServerSecret:           "32byte-secret-key-for-testing-!!",
		CookieDomains:          []string{"example.com"},
		TokenValidityMinutes:   60,
		RateLimitValidateMax:   1000,
		RateLimitValidateDecay: 60,
		AuthBypassHostHeader:   "X-Forwarded-Host",
		AuthBypassURIHeader:    "X-Forwarded-Uri",
	}
}

func validateWith(t *testing.T, h *AuthHandler, host, uri, remote string, cookie *http.Cookie) (int, http.Header) {
	t.Helper()
	c, rec := createTestContext(echo.New(), http.MethodGet, "/rauthvalidate", nil)
	if host != "" {
		c.Request().Header.Set("X-Forwarded-Host", host)
	}
	if uri != "" {
		c.Request().Header.Set("X-Forwarded-Uri", uri)
	}
	if remote != "" {
		c.Request().RemoteAddr = remote
	}
	if cookie != nil {
		c.Request().AddCookie(cookie)
	}
	require.NoError(t, h.Validate(c))
	return rec.Code, rec.Header()
}

func TestValidate_BypassRules(t *testing.T) {
	setupHandlersTest(t)
	resetBypassRules(t)
	core.SetEnvBypassRules([]string{"cloud.example.com", "web.example.com/webhook"})
	h := &AuthHandler{Cfg: bypassTestConfig()}

	t.Run("whole host is anonymous", func(t *testing.T) {
		code, hdr := validateWith(t, h, "cloud.example.com", "/index.php", "", nil)
		assert.Equal(t, http.StatusOK, code)
		assert.Equal(t, "1", hdr.Get("X-RAuth-Anonymous"))
		assert.Equal(t, "", hdr.Get("X-RAuth-User"))
		assert.Equal(t, "0", hdr.Get("X-RAuth-Admin"))
	})

	t.Run("path prefix and subpaths are anonymous", func(t *testing.T) {
		for _, uri := range []string{"/webhook", "/webhook/github?x=1"} {
			code, _ := validateWith(t, h, "web.example.com", uri, "", nil)
			assert.Equal(t, http.StatusOK, code, uri)
		}
	})

	t.Run("other paths still require auth", func(t *testing.T) {
		for _, uri := range []string{"/", "/admin", "/webhooks", "/webhook/../admin", "/webhook%2f..%2fadmin"} {
			code, _ := validateWith(t, h, "web.example.com", uri, "", nil)
			assert.Equal(t, http.StatusUnauthorized, code, uri)
		}
	})

	t.Run("missing headers require auth", func(t *testing.T) {
		code, _ := validateWith(t, h, "", "/webhook", "", nil)
		assert.Equal(t, http.StatusUnauthorized, code)
		code, _ = validateWith(t, h, "cloud.example.com", "", "", nil)
		assert.Equal(t, http.StatusUnauthorized, code)
	})

	t.Run("valid session keeps its identity", func(t *testing.T) {
		seedAccount(t, "testuser")
		token := "bypass-valid-token"
		core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+token, map[string]interface{}{
			"status": "valid", "username": "testuser", "ip": "127.0.0.1", "country": "unknown",
		})
		encrypted, _ := core.EncryptToken(token, h.Cfg.ServerSecret)
		code, hdr := validateWith(t, h, "cloud.example.com", "/", "", &http.Cookie{Name: "X-rauth-authtoken", Value: encrypted})
		assert.Equal(t, http.StatusOK, code)
		assert.Equal(t, "testuser", hdr.Get("X-RAuth-User"))
		assert.Empty(t, hdr.Get("X-RAuth-Anonymous"))
	})
}

func TestValidate_BypassTrustedProxies(t *testing.T) {
	setupHandlersTest(t)
	resetBypassRules(t)
	core.SetEnvBypassRules([]string{"cloud.example.com"})
	cfg := bypassTestConfig()
	cfg.TrustedProxies = []string{"10.0.0.0/8"}
	h := &AuthHandler{Cfg: cfg}

	code, _ := validateWith(t, h, "cloud.example.com", "/", "10.1.2.3:5000", nil)
	assert.Equal(t, http.StatusOK, code, "trusted proxy")

	code, _ = validateWith(t, h, "cloud.example.com", "/", "203.0.113.7:5000", nil)
	assert.Equal(t, http.StatusUnauthorized, code, "untrusted peer must not be able to claim a bypassed host")
}

func TestValidate_BypassSmartModePeers(t *testing.T) {
	setupHandlersTest(t)
	resetBypassRules(t)
	core.SetEnvBypassRules([]string{"cloud.example.com"})
	h := &AuthHandler{Cfg: bypassTestConfig()}

	for _, peer := range []string{"127.0.0.1:5000", "172.18.0.5:5000", "[::1]:5000"} {
		code, _ := validateWith(t, h, "cloud.example.com", "/", peer, nil)
		assert.Equal(t, http.StatusOK, code, peer)
	}
	code, _ := validateWith(t, h, "cloud.example.com", "/", "203.0.113.7:5000", nil)
	assert.Equal(t, http.StatusUnauthorized, code, "public peer without TRUSTED_PROXIES must not use bypass headers")
}

func TestAdminHandler_BypassRules(t *testing.T) {
	setupHandlersTest(t)
	resetBypassRules(t)
	hash, _ := core.HashPassword("AdminPass1!")
	core.UserDB.HSet(core.Ctx, "user:adminuser", "username", "adminuser", "password", hash)
	h := &AdminHandler{Cfg: &core.Config{RateLimitLoginFailUserMax: 1000, RateLimitLoginFailUserDecay: 60}}
	e := echo.New()

	postAs := func(token string, fn func(echo.Context) error, f url.Values) (int, string, error) {
		c, rec := createTestContext(e, http.MethodPost, "/rauthmgmt/bypass", f)
		c.Set("username", "adminuser")
		c.Set("token", token)
		err := fn(c)
		if he, ok := err.(*echo.HTTPError); ok {
			return he.Code, "", nil
		}
		return rec.Code, rec.Header().Get("Location"), err
	}
	post := func(fn func(echo.Context) error, f url.Values) (int, string, error) {
		return postAs("session-a", fn, f)
	}

	// Locked: every change is refused, even with a password in the form.
	code, _, err := post(h.AddBypassRule, url.Values{"rule": {"web.example.com/webhook"}, "current_password": {"AdminPass1!"}})
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, code, "locked")
	_, ok := core.MatchBypass("web.example.com", "/webhook")
	assert.False(t, ok)

	code, _, _ = post(h.UnlockBypass, url.Values{})
	assert.Equal(t, http.StatusBadRequest, code, "step-up required")
	code, _, _ = post(h.UnlockBypass, url.Values{"current_password": {"wrong"}})
	assert.Equal(t, http.StatusBadRequest, code, "wrong password")
	code, _, _ = postAs("", h.UnlockBypass, url.Values{"current_password": {"AdminPass1!"}})
	assert.Equal(t, http.StatusUnauthorized, code, "no session token")

	code, loc, err := post(h.UnlockBypass, url.Values{"current_password": {"AdminPass1!"}})
	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, code)
	assert.Equal(t, "/rauthmgmt?success=bypass_unlocked#bypass", loc)
	ttl := core.TokenDB.TTL(core.Ctx, "bypass_unlock:session-a").Val()
	assert.Greater(t, ttl, time.Duration(0))
	assert.LessOrEqual(t, ttl, bypassUnlockTTL)

	// Unlocked: several changes without further step-up.
	code, _, _ = post(h.AddBypassRule, url.Values{"rule": {"https://bad"}})
	assert.Equal(t, http.StatusBadRequest, code, "invalid rule")

	for _, f := range []url.Values{
		{"rule": {"app.example.com/"}},
		{"rule": {"app.example.com/example"}, "action": {"deny"}},
		{"rule": {"app.example.com/*"}, "note": {"rest is public"}},
	} {
		code, loc, err = post(h.AddBypassRule, f)
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, code, f.Get("rule"))
		assert.Equal(t, "/rauthmgmt?success=bypass_added#bypass", loc)
	}
	for uri, want := range map[string]bool{"/": true, "/foo": true, "/example": false, "/example/x": false} {
		_, ok = core.MatchBypass("app.example.com", uri)
		assert.Equal(t, want, ok, uri)
	}

	code, _, _ = post(h.AddBypassRule, url.Values{"rule": {"app.example.com/example"}})
	assert.Equal(t, http.StatusBadRequest, code, "duplicate")

	// Another session of the same admin is not unlocked.
	code, _, _ = postAs("session-b", h.DeleteBypassRule, url.Values{"rule": {"app.example.com/example"}})
	assert.Equal(t, http.StatusForbidden, code)

	code, loc, err = post(h.UpdateBypassRule, url.Values{"original_rule": {"app.example.com/example"}, "rule": {"app.example.com/example"}, "action": {"allow"}})
	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, code)
	assert.Equal(t, "/rauthmgmt?success=bypass_updated#bypass", loc)
	_, ok = core.MatchBypass("app.example.com", "/example")
	assert.True(t, ok)

	code, _, _ = post(h.UpdateBypassRule, url.Values{"original_rule": {"app.example.com/nope"}, "rule": {"app.example.com/x"}})
	assert.Equal(t, http.StatusNotFound, code)

	code, loc, err = post(h.DeleteBypassRule, url.Values{"rule": {"app.example.com/example"}})
	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, code)
	assert.Equal(t, "/rauthmgmt?success=bypass_deleted#bypass", loc)

	code, _, _ = post(h.DeleteBypassRule, url.Values{"rule": {"app.example.com/example"}})
	assert.Equal(t, http.StatusNotFound, code)

	// Lock ends the unlock immediately.
	code, loc, _ = post(h.LockBypass, url.Values{})
	assert.Equal(t, http.StatusFound, code)
	assert.Equal(t, "/rauthmgmt?success=bypass_locked#bypass", loc)
	code, _, _ = post(h.DeleteBypassRule, url.Values{"rule": {"app.example.com"}})
	assert.Equal(t, http.StatusForbidden, code)
}
