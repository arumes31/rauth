package handlers

import (
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
	rauthmiddleware "rauth/internal/middleware"
)

func ssoHTTPContext(e *echo.Echo, method, origin, path string, cookies ...*http.Cookie) (echo.Context, *httptest.ResponseRecorder) {
	c, rec := createTestContext(e, method, origin+path, nil)
	for _, cookie := range cookies {
		c.Request().AddCookie(cookie)
	}
	return c, rec
}
func ssoHTTPError(t *testing.T, err error, status int) {
	t.Helper()
	require.Error(t, err)
	var he *echo.HTTPError
	require.ErrorAs(t, err, &he)
	assert.Equal(t, status, he.Code)
}
func TestSSOHTTPPasswordAndTOTPOnDifferentNodesCrossDomainAndGlobalLogout(t *testing.T) {
	cfg := setupSQLRuntimeTest(t)
	cfg.SSOCanonicalOrigin = "https://auth.example.com"
	cfg.WebAuthnOrigins = []string{cfg.SSOCanonicalOrigin}
	cfg.SSOApplicationOrigins = []string{"https://app.other.test", "https://second.example.net"}
	require.NoError(t, cfg.ValidateSSO())
	core.SetBcryptCost(4)
	t.Cleanup(func() { core.SetBcryptCost(12) })
	const user = "sso-http-user"
	const secret = "JBSWY3DPEHPK3PXP"
	require.NoError(t, core.CreateUser(user, "Password123!", "", false, secret))
	e := echo.New()
	e.Renderer = &mockRenderer{}
	a, b := &AuthHandler{Cfg: cfg}, &AuthHandler{Cfg: cfg}
	const returnURI = "/remote.php/dav/files/admin/opaque%253bname;v=1?x=%25%3B"
	c, started := ssoHTTPContext(e, http.MethodGet, cfg.SSOApplicationOrigins[0], "/_rauth/start?rd="+url.QueryEscape(returnURI))
	require.NoError(t, a.SSOStart(c))
	require.Equal(t, http.StatusFound, started.Code)
	startURL, err := url.Parse(started.Header().Get("Location"))
	require.NoError(t, err)
	state := startURL.Query().Get("transaction")
	require.Len(t, state, 64)
	browser := responseCookie(t, started, ssoBrowserCookiePrefix+state)
	assert.Empty(t, browser.Domain)
	assert.True(t, browser.Secure)
	assert.True(t, browser.HttpOnly)
	assert.Equal(t, "/", browser.Path)
	// Authorization first prompts at the canonical origin, retaining its local rd
	// through password on A and TOTP on B.
	c, loginRedirect := ssoHTTPContext(e, http.MethodGet, cfg.SSOCanonicalOrigin, startURL.RequestURI())
	require.NoError(t, b.SSOAuthorize(c))
	require.Equal(t, http.StatusFound, loginRedirect.Code)
	loginURL, err := url.Parse(loginRedirect.Header().Get("Location"))
	require.NoError(t, err)
	c, password := createTestContext(e, http.MethodPost, cfg.SSOCanonicalOrigin+loginURL.RequestURI(), url.Values{"username": {user}, "password": {"Password123!"}})
	require.NoError(t, a.Login(c))
	require.Equal(t, http.StatusOK, password.Code)
	pending := responseCookie(t, password, "rauth_2fa_pending")
	proof, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	c, completed := createTestContext(e, http.MethodPost, cfg.SSOCanonicalOrigin+"/verify-2fa?rd="+url.QueryEscape(loginURL.Query().Get("rd")), url.Values{"totp_code": {proof}})
	c.Request().AddCookie(pending)
	require.NoError(t, b.Verify2FA(c))
	require.Equal(t, http.StatusFound, completed.Code)
	central := responseCookie(t, completed, "X-rauth-authtoken")
	assert.Empty(t, central.Domain, "canonical SSO login must not share a domain cookie with application backends")
	assert.Equal(t, startURL.RequestURI(), completed.Header().Get("Location"))
	c, authorized := ssoHTTPContext(e, http.MethodGet, cfg.SSOCanonicalOrigin, startURL.RequestURI(), central)
	require.NoError(t, a.SSOAuthorize(c))
	require.Equal(t, http.StatusFound, authorized.Code)
	callback, err := url.Parse(authorized.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "app.other.test", callback.Host)
	assert.Equal(t, "no-store", authorized.Header().Get("Cache-Control"))
	assert.Equal(t, "no-referrer", authorized.Header().Get("Referrer-Policy"))
	c, _ = ssoHTTPContext(e, http.MethodGet, cfg.SSOApplicationOrigins[0], callback.RequestURI())
	ssoHTTPError(t, b.SSOCallback(c), http.StatusBadRequest)
	wrongBrowser := *browser
	wrongBrowser.Value = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	c, _ = ssoHTTPContext(e, http.MethodGet, cfg.SSOApplicationOrigins[0], callback.RequestURI(), &wrongBrowser)
	ssoHTTPError(t, b.SSOCallback(c), http.StatusBadRequest)
	c, _ = ssoHTTPContext(e, http.MethodGet, cfg.SSOApplicationOrigins[1], callback.RequestURI(), browser)
	ssoHTTPError(t, b.SSOCallback(c), http.StatusBadRequest)
	c, _ = ssoHTTPContext(e, http.MethodGet, cfg.SSOApplicationOrigins[0], callback.RequestURI(), browser)
	c.Request().RemoteAddr = "203.0.113.55:49152"
	c.Request().Header.Set("X-Forwarded-Host", "app.other.test")
	ssoHTTPError(t, b.SSOCallback(c), http.StatusForbidden)
	c, accepted := ssoHTTPContext(e, http.MethodGet, cfg.SSOApplicationOrigins[0], callback.RequestURI(), browser)
	require.NoError(t, b.SSOCallback(c))
	require.Equal(t, http.StatusFound, accepted.Code)
	assert.Equal(t, returnURI, accepted.Header().Get("Location"))
	app := responseCookie(t, accepted, core.SSOAppCookie)
	assert.Empty(t, app.Domain)
	assert.True(t, app.Secure)
	assert.True(t, app.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, app.SameSite)
	c, _ = ssoHTTPContext(e, http.MethodGet, cfg.SSOApplicationOrigins[0], callback.RequestURI(), browser)
	ssoHTTPError(t, a.SSOCallback(c), http.StatusBadRequest)
	validate := func(handler *AuthHandler, host string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		c, rec := ssoHTTPContext(e, http.MethodGet, "https://local-worker.example", "/rauthvalidate", cookies...)
		c.Request().Header.Set(cfg.AuthBypassHostHeader, host)
		c.Request().Header.Set(cfg.AuthBypassURIHeader, returnURI)
		require.NoError(t, handler.Validate(c))
		return rec
	}
	valid := validate(a, "app.other.test", app)
	assert.Equal(t, http.StatusOK, valid.Code)
	assert.Equal(t, user, valid.Header().Get("X-RAuth-User"))
	assert.Equal(t, http.StatusUnauthorized, validate(b, "second.example.net", app).Code, "copied cookies cannot cross audiences")
	assert.Equal(t, http.StatusUnauthorized, validate(b, "app.other.test", central).Code, "a central domain cookie does not authorize an app directly")
	// Even renaming an app cookie cannot turn it into a canonical/profile cookie.
	copied := *app
	copied.Name = "X-rauth-authtoken"
	c, root := ssoHTTPContext(e, http.MethodGet, cfg.SSOCanonicalOrigin, "/", &copied)
	require.NoError(t, a.Root(c))
	assert.Equal(t, "/rauthlogin", root.Header().Get("Location"))
	c, profile := ssoHTTPContext(e, http.MethodGet, cfg.SSOCanonicalOrigin, "/rauthprofile", &copied)
	called := false
	require.NoError(t, rauthmiddleware.AuthMiddleware(cfg)(func(c echo.Context) error { called = true; return c.NoContent(http.StatusOK) })(c))
	assert.False(t, called)
	assert.Equal(t, http.StatusFound, profile.Code)
	// Exercise app-cookie rotation and ensure the refresh remains host-only.
	_, err = core.PG.Exec(core.Ctx, "UPDATE auth_sessions SET issued_at=clock_timestamp()-interval '2 minutes' WHERE audience=$1", cfg.SSOApplicationOrigins[0])
	require.NoError(t, err)
	cfg.TokenRotationMinutes = 1
	rotated := validate(b, "app.other.test", app)
	require.Equal(t, http.StatusOK, rotated.Code)
	replacement := responseCookie(t, rotated, core.SSOAppCookie)
	assert.Empty(t, replacement.Domain)
	assert.NotEqual(t, app.Value, replacement.Value)
	// A second domain reuses the central login without another password prompt.
	c, secondStart := ssoHTTPContext(e, http.MethodGet, cfg.SSOApplicationOrigins[1], "/_rauth/start?rd=/docs")
	require.NoError(t, b.SSOStart(c))
	secondURL, err := url.Parse(secondStart.Header().Get("Location"))
	require.NoError(t, err)
	secondBrowser := responseCookie(t, secondStart, ssoBrowserCookiePrefix+secondURL.Query().Get("transaction"))
	c, secondAuthorize := ssoHTTPContext(e, http.MethodGet, cfg.SSOCanonicalOrigin, secondURL.RequestURI(), central)
	require.NoError(t, b.SSOAuthorize(c))
	secondCallback, err := url.Parse(secondAuthorize.Header().Get("Location"))
	require.NoError(t, err)
	c, secondAccepted := ssoHTTPContext(e, http.MethodGet, cfg.SSOApplicationOrigins[1], secondCallback.RequestURI(), secondBrowser)
	require.NoError(t, a.SSOCallback(c))
	second := responseCookie(t, secondAccepted, core.SSOAppCookie)
	assert.Equal(t, http.StatusOK, validate(b, "second.example.net", second).Code)
	c, signedOut := ssoHTTPContext(e, http.MethodPost, cfg.SSOApplicationOrigins[1], "/_rauth/logout", second)
	require.NoError(t, a.SSOSignOut(c))
	assert.Equal(t, http.StatusFound, signedOut.Code)
	assert.Equal(t, http.StatusUnauthorized, validate(a, "app.other.test", replacement).Code)
	assert.Equal(t, http.StatusUnauthorized, validate(b, "second.example.net", second).Code)
	assert.Equal(t, http.StatusUnauthorized, validate(a, "auth.example.com", central).Code)
	require.Nil(t, core.TokenDB)
	require.Nil(t, core.InviteDB)
	require.Nil(t, core.RateLimitDB)
}
func TestSSORoutesRejectUnknownHostsAndUnsafeReturns(t *testing.T) {
	cfg := setupSQLRuntimeTest(t)
	cfg.SSOCanonicalOrigin = "https://auth.example.com"
	cfg.WebAuthnOrigins = []string{cfg.SSOCanonicalOrigin}
	cfg.SSOApplicationOrigins = []string{"https://app.other.test"}
	h := &AuthHandler{Cfg: cfg}
	e := echo.New()
	for _, target := range []string{"https://evil.example.org/_rauth/start", "https://sub.app.other.test/_rauth/start", "https://app.other.test/_rauth/start?rd=" + url.QueryEscape("//evil.test"), "https://app.other.test/_rauth/start?rd=" + url.QueryEscape("/%2fevil.test")} {
		c, _ := createTestContext(e, http.MethodGet, target, nil)
		require.Error(t, h.SSOStart(c), target)
	}
	c, started := ssoHTTPContext(e, http.MethodGet, cfg.SSOApplicationOrigins[0], "/_rauth/start?rd=/ignored")
	original := "/docs?q=one&second=%2525%3B&empty="
	c.Request().Header.Set("X-RAuth-Return-URI", original)
	require.NoError(t, h.SSOStart(c))
	target, err := url.Parse(started.Header().Get("Location"))
	require.NoError(t, err)
	state := target.Query().Get("transaction")
	binding := responseCookie(t, started, ssoBrowserCookiePrefix+state)
	// Use the authority directly for this transport-only test. The full browser
	// sequence is covered above; preserve the exact URI including all ampersands.
	require.NoError(t, core.CreateUser("sso-header-user", "Password123!", "", false, ""))
	c, issued := ssoHTTPContext(e, http.MethodGet, cfg.SSOCanonicalOrigin, "/rauthlogin")
	generation, err := core.AuthGeneration("sso-header-user")
	require.NoError(t, err)
	require.NoError(t, h.issueToken(c, "sso-header-user", generation))
	central := responseCookie(t, issued, "X-rauth-authtoken")
	c, authorized := ssoHTTPContext(e, http.MethodGet, cfg.SSOCanonicalOrigin, target.RequestURI(), central)
	require.NoError(t, h.SSOAuthorize(c))
	callback, err := url.Parse(authorized.Header().Get("Location"))
	require.NoError(t, err)
	c, accepted := ssoHTTPContext(e, http.MethodGet, cfg.SSOApplicationOrigins[0], callback.RequestURI(), binding)
	require.NoError(t, h.SSOCallback(c))
	assert.Equal(t, original, accepted.Header().Get("Location"))
	c, _ = ssoHTTPContext(e, http.MethodGet, cfg.SSOCanonicalOrigin, "/_rauth/authorize?transaction=invalid")
	ssoHTTPError(t, h.SSOAuthorize(c), http.StatusBadRequest)
	cfg.SSOCanonicalOrigin = ""
	c, _ = ssoHTTPContext(e, http.MethodGet, "https://app.other.test", "/_rauth/start")
	ssoHTTPError(t, h.SSOStart(c), http.StatusNotFound)
}
