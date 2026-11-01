package core

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"rauth/internal/authstate"
)

const SSOAppCookie = "__Host-rauth-session"
const SSOAuthCookie = "__Host-rauth-auth"

func (c *Config) ValidateSSO() error {
	if c.SSOCanonicalOrigin == "" && len(c.SSOApplicationOrigins) == 0 {
		return nil
	}
	mode, err := configuredAuthStateMode(c)
	if err != nil || mode != "postgres" {
		return errors.New("SSO requires the selected PostgreSQL authentication authority")
	}
	if !authstate.SSOOrigin(c.SSOCanonicalOrigin) || len(c.SSOApplicationOrigins) == 0 || len(c.SSOApplicationOrigins) > 1000 {
		return errors.New("SSO requires an exact HTTPS canonical origin and 1-1000 application origins")
	}
	// Do not derive a new passkey realm from application domains. The existing
	// RP ID and registered origins must already cover the canonical login.
	host := strings.TrimPrefix(c.SSOCanonicalOrigin, "https://")
	if len(c.CookieDomains) == 0 || !authstate.SSOOrigin("https://"+c.CookieDomains[0]) || (host != c.CookieDomains[0] && !strings.HasSuffix(host, "."+c.CookieDomains[0])) {
		return errors.New("SSO canonical origin must be within the existing WebAuthn RP ID (first COOKIE_DOMAIN)")
	}
	registered := false
	if len(c.WebAuthnOrigins) > 0 {
		for _, raw := range c.WebAuthnOrigins {
			origin := strings.TrimSuffix(strings.TrimSpace(raw), "/")
			if !strings.HasPrefix(origin, "http://") && !strings.HasPrefix(origin, "https://") {
				origin = "https://" + origin
			}
			if origin == c.SSOCanonicalOrigin {
				registered = true
			}
		}
	} else {
		for _, allowed := range append(append([]string{}, c.CookieDomains...), c.AllowedHosts...) {
			if "https://"+allowed == c.SSOCanonicalOrigin {
				registered = true
			}
		}
	}
	if !registered {
		return errors.New("SSO canonical origin must be an existing allowed WebAuthn origin; retain the established RP identity")
	}
	seen := make(map[string]bool)
	for _, origin := range c.SSOApplicationOrigins {
		if !authstate.SSOOrigin(origin) || origin == c.SSOCanonicalOrigin || seen[origin] {
			return errors.New("SSO application origins must be distinct exact HTTPS DNS origins")
		}
		seen[origin] = true
	}
	return nil
}
func (c *Config) SSOApplication(origin string) bool {
	if c.SSOCanonicalOrigin == "" {
		return false
	}
	for _, allowed := range c.SSOApplicationOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}

// SSORequestOrigin reads only Host, which the dedicated per-site proxy routes
// must overwrite. It never accepts a client-selected forwarded host or scheme.
func (c *Config) SSORequestOrigin(req *http.Request) (string, bool) {
	if !c.IsTrustedProxyPeer(req.RemoteAddr) {
		return "", false
	}
	origin := "https://" + strings.ToLower(req.Host)
	return origin, authstate.SSOOrigin(origin)
}
func ssoStore() (*authstate.PostgresSessions, error) {
	s, ok := securitySessions.(*authstate.PostgresSessions)
	if !ok || s == nil {
		return nil, errors.New("SSO authority is unavailable")
	}
	return s, nil
}
func BeginSSO(ctx context.Context, id, browser, origin, returnURI string) error {
	s, err := ssoStore()
	if err != nil {
		return err
	}
	return s.BeginSSO(ctx, id, browser, origin, returnURI)
}
func AuthorizeSSO(ctx context.Context, id, code, token string) (string, error) {
	s, err := ssoStore()
	if err != nil {
		return "", err
	}
	return s.AuthorizeSSO(ctx, id, code, token)
}
func RedeemSSO(ctx context.Context, id, code, browser, origin, token string, ttl time.Duration) (string, error) {
	s, err := ssoStore()
	if err != nil {
		return "", err
	}
	return s.RedeemSSO(ctx, id, code, browser, origin, token, ttl)
}

// SessionAudienceValid keeps application tokens out of the canonical login,
// management/profile routes and other applications, even if a cookie is copied.
func SessionAudienceValid(data map[string]string, expected string) bool {
	return data["audience"] == expected
}

// SessionCookieDomain preserves legacy cookie scope until SSO is enabled. The
// passkey RP ID still comes from COOKIE_DOMAIN and must not change with scope.
func (c *Config) SessionCookieDomain() string {
	if c.SSOCanonicalOrigin != "" || len(c.CookieDomains) == 0 {
		return ""
	}
	return c.CookieDomains[0]
}

// SessionCookieName keeps broad-domain cookie planting out of the canonical SSO
// login. SSO never falls back to a sibling-settable legacy cookie name.
func (c *Config) SessionCookieName() string {
	if c.SSOCanonicalOrigin != "" {
		return SSOAuthCookie
	}
	return "X-rauth-authtoken"
}
