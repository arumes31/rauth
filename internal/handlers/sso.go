package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/labstack/echo/v4"
	"rauth/internal/authstate"
	"rauth/internal/core"
)

const ssoBrowserCookiePrefix = "__Host-rauth-sso-"

func ssoHeaders(c echo.Context) {
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Referrer-Policy", "no-referrer")
	c.Response().Header().Set("Pragma", "no-cache")
}
func newSSOSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func ssoParam(c echo.Context, name string) (string, bool) {
	values := c.QueryParams()[name]
	if len(values) != 1 || len(values[0]) != 64 {
		return "", false
	}
	_, err := hex.DecodeString(values[0])
	return values[0], err == nil
}
func ssoFailure(err error) error {
	if errors.Is(err, authstate.ErrSSOInvalid) || errors.Is(err, authstate.ErrNotFound) || errors.Is(err, authstate.ErrStaleGeneration) {
		return echo.NewHTTPError(http.StatusBadRequest, "Login transfer is invalid or expired; start again from the application")
	}
	return echo.NewHTTPError(http.StatusServiceUnavailable, "Login transfer is temporarily unavailable; retry").SetInternal(err)
}
func (h *AuthHandler) ssoOrigin(c echo.Context, canonical bool) (string, error) {
	ssoHeaders(c)
	if h.Cfg.SSOCanonicalOrigin == "" {
		return "", echo.NewHTTPError(http.StatusNotFound)
	}
	origin, ok := h.Cfg.SSORequestOrigin(c.Request())
	if !ok {
		return "", echo.NewHTTPError(http.StatusForbidden, "Untrusted login transfer route")
	}
	if (canonical && origin != h.Cfg.SSOCanonicalOrigin) || (!canonical && !h.Cfg.SSOApplication(origin)) {
		return "", echo.NewHTTPError(http.StatusNotFound)
	}
	return origin, nil
}

// SSOStart must be reverse-proxied locally on the enrolled application's exact
// host. The per-transaction __Host cookie permits parallel tabs without sharing
// a broad domain cookie or putting the browser's binding in the URL.
func (h *AuthHandler) SSOStart(c echo.Context) error {
	origin, err := h.ssoOrigin(c, false)
	if err != nil {
		return err
	}
	returnURI := c.QueryParam("rd")
	// A named NPM error location can pass the untouched URI in an overwritten
	// header, avoiding lossy concatenation of an unescaped URI into a query.
	if original := c.Request().Header.Get("X-RAuth-Return-URI"); original != "" {
		returnURI = original
	}

	if returnURI == "" {
		returnURI = "/"
	}
	if !authstate.SSOLocalReturn(returnURI) {
		return ssoFailure(authstate.ErrSSOInvalid)
	}
	exceeded, _, err := core.ReserveRateLimitAttempt("sso_start:"+core.RateLimitIP(c.RealIP()), 30, 300)
	if err != nil {
		return ssoFailure(err)
	}
	if exceeded {
		return echo.NewHTTPError(http.StatusTooManyRequests, "Too many login transfers; retry later")
	}
	id, err := newSSOSecret()
	if err != nil {
		return ssoFailure(err)
	}
	browser, err := newSSOSecret()
	if err != nil {
		return ssoFailure(err)
	}
	if err = core.BeginSSO(c.Request().Context(), id, browser, origin, returnURI); err != nil {
		return ssoFailure(err)
	}
	c.SetCookie(&http.Cookie{Name: ssoBrowserCookiePrefix + id, Value: browser, Path: "/", MaxAge: int(authstate.SSOTransactionTTL / time.Second), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	return c.Redirect(http.StatusFound, h.Cfg.SSOCanonicalOrigin+"/_rauth/authorize?transaction="+id)
}

func (h *AuthHandler) ssoSession(c echo.Context, cookieName, audience string) (string, error) {
	cookie, err := c.Cookie(cookieName)
	if err != nil {
		return "", authstate.ErrNotFound
	}
	token, err := core.DecryptToken(cookie.Value, h.Cfg.ServerSecret)
	if err != nil || token == "" {
		return "", authstate.ErrNotFound
	}
	data, err := core.ReadAuthSession(c.Request().Context(), token)
	if err != nil {
		return "", err
	}
	if data["status"] != "valid" || !core.SessionAudienceValid(data, audience) {
		return "", authstate.ErrNotFound
	}
	ok, err := core.SessionAuthorization(c.Request().Context(), data)
	if err != nil {
		return "", err
	}
	if !ok || !core.SessionBindingValid(h.Cfg, c.Request(), token, "X-rauth-authtoken="+token, data, c.RealIP()) {
		return "", authstate.ErrNotFound
	}
	// The SQL store won't let retired grace tokens mint new authorizations.
	// Follow only the authoritative, encrypted successor of this valid session.
	if successor := data["rotated_to"]; successor != "" {
		next, err := core.ReadAuthSession(c.Request().Context(), successor)
		if err != nil {
			return "", err
		}
		if next["session_family"] != data["session_family"] || next["status"] != "valid" || next["rotated_to"] != "" || !core.SessionAudienceValid(next, audience) {
			return "", authstate.ErrNotFound
		}
		token = successor
	}
	return token, nil
}

func (h *AuthHandler) SSOAuthorize(c echo.Context) error {
	if _, err := h.ssoOrigin(c, true); err != nil {
		return err
	}
	id, ok := ssoParam(c, "transaction")
	if !ok {
		return ssoFailure(authstate.ErrSSOInvalid)
	}
	token, err := h.ssoSession(c, h.Cfg.SessionCookieName(), "")
	if errors.Is(err, authstate.ErrNotFound) {
		return c.Redirect(http.StatusFound, "/rauthlogin?rd="+url.QueryEscape("/_rauth/authorize?transaction="+id))
	}
	if err != nil {
		return ssoFailure(err)
	}
	code, err := newSSOSecret()
	if err != nil {
		return ssoFailure(err)
	}
	origin, err := core.AuthorizeSSO(c.Request().Context(), id, code, token)
	if err != nil {
		return ssoFailure(err)
	}
	if !h.Cfg.SSOApplication(origin) {
		return ssoFailure(authstate.ErrSSOInvalid)
	}
	return c.Redirect(http.StatusFound, origin+"/_rauth/callback?"+url.Values{"state": {id}, "code": {code}}.Encode())
}

func (h *AuthHandler) SSOCallback(c echo.Context) error {
	origin, err := h.ssoOrigin(c, false)
	if err != nil {
		return err
	}
	id, ok := ssoParam(c, "state")
	if !ok {
		return ssoFailure(authstate.ErrSSOInvalid)
	}
	code, ok := ssoParam(c, "code")
	if !ok {
		return ssoFailure(authstate.ErrSSOInvalid)
	}
	browser, err := c.Cookie(ssoBrowserCookiePrefix + id)
	if err != nil {
		return ssoFailure(authstate.ErrSSOInvalid)
	}
	token, err := newSSOSecret()
	if err != nil {
		return ssoFailure(err)
	}
	encrypted, err := core.EncryptToken(token, h.Cfg.ServerSecret)
	if err != nil {
		return ssoFailure(err)
	}
	validity := time.Duration(h.Cfg.TokenValidityMinutes) * time.Minute
	target, err := core.RedeemSSO(c.Request().Context(), id, code, browser.Value, origin, token, validity)
	if err != nil {
		return ssoFailure(err)
	}
	writeAppSessionCookie(c, encrypted, validity)
	c.SetCookie(&http.Cookie{Name: ssoBrowserCookiePrefix + id, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	return c.Redirect(http.StatusFound, target)
}

// SSOLogoutPage exposes the middleware's HttpOnly-cookie CSRF proof through a
// same-origin confirmation form. Legacy clients need this explicit token path;
// merely reading the confirmation page never revokes a session.
func (h *AuthHandler) SSOLogoutPage(c echo.Context) error {
	origin, err := h.ssoOrigin(c, false)
	if err != nil {
		return err
	}
	_, err = h.ssoSession(c, core.SSOAppCookie, origin)
	if errors.Is(err, authstate.ErrNotFound) {
		return echo.NewHTTPError(http.StatusUnauthorized, "Login required")
	}
	if err != nil {
		return ssoFailure(err)
	}
	csrf, ok := c.Get("csrf").(string)
	if !ok || csrf == "" {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Sign-out form is temporarily unavailable; retry")
	}
	return c.Render(http.StatusOK, "sso_logout.html", map[string]interface{}{"csrf": csrf})
}

// SSOSignOut revokes the common family before clearing this host's cookie.
// The route is POST-only and uses the same CSRF middleware as account mutations.
func (h *AuthHandler) SSOSignOut(c echo.Context) error {
	origin, err := h.ssoOrigin(c, false)
	if err != nil {
		return err
	}
	token, err := h.ssoSession(c, core.SSOAppCookie, origin)
	if errors.Is(err, authstate.ErrNotFound) {
		return echo.NewHTTPError(http.StatusUnauthorized, "Login required")
	}
	if err != nil {
		return ssoFailure(err)
	}
	if err = core.RevokeAuthSession(c.Request().Context(), token); err != nil {
		return ssoFailure(err)
	}
	c.SetCookie(&http.Cookie{Name: core.SSOAppCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	return c.Redirect(http.StatusFound, h.Cfg.SSOCanonicalOrigin+"/rauthlogin")
}
func writeAppSessionCookie(c echo.Context, value string, validity time.Duration) {
	c.SetCookie(&http.Cookie{Name: core.SSOAppCookie, Value: value, Path: "/", Expires: time.Now().Add(validity), MaxAge: int(validity / time.Second), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

// validationCookie selects a host-only app cookie only for an exactly enrolled
// forwarded target from a trusted proxy. Central tokens never become app tokens
// merely because COOKIE_DOMAIN also covers that application.
func (h *AuthHandler) validationCookie(c echo.Context) (string, string, error) {
	if h.Cfg.SSOCanonicalOrigin == "" {
		return h.Cfg.SessionCookieName(), "", nil
	}
	if !h.Cfg.IsTrustedProxyPeer(c.Request().RemoteAddr) {
		return "", "", authstate.ErrSSOInvalid
	}
	origin := "https://" + c.Request().Header.Get(h.Cfg.AuthBypassHostHeader)
	if origin == h.Cfg.SSOCanonicalOrigin {
		return h.Cfg.SessionCookieName(), "", nil
	}
	if !h.Cfg.SSOApplication(origin) {
		return "", "", authstate.ErrSSOInvalid
	}
	c.Set("session_cookie_name", core.SSOAppCookie)
	return core.SSOAppCookie, origin, nil
}
