package handlers

import (
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/url"
	"rauth/internal/core"
	"testing"
)

func TestValidatePolicyAppliesBeforeAuthenticatedSession(t *testing.T) {
	setupHandlersTest(t)
	resetBypassRules(t)
	cfg := bypassTestConfig()
	h := &AuthHandler{Cfg: cfg}
	policy := core.RulePolicy{CountryMode: core.CountrySelected, AllowedCountries: []string{"AT"}}
	_, err := core.AddBypassRule("policy.example.com", "allow", "", "admin", policy)
	require.NoError(t, err)
	seedAccount(t, "alice")
	token := "policy-valid-token"
	core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+token, map[string]interface{}{"status": "valid", "username": "alice", "ip": "127.0.0.1", "country": "unknown"})
	encrypted, err := core.EncryptToken(token, cfg.ServerSecret)
	require.NoError(t, err)
	cookie := &http.Cookie{Name: "X-rauth-authtoken", Value: encrypted}
	for _, c := range []*http.Cookie{nil, cookie} {
		status, headers := validateWith(t, h, "policy.example.com", "/", "127.0.0.1:5000", c)
		assert.Equal(t, http.StatusForbidden, status)
		assert.Empty(t, headers.Get("X-RAuth-User"))
		assert.Empty(t, headers.Get("X-RAuth-Anonymous"))
	}
	policy.AllowPrivateNetworks = true
	_, _, err = core.UpdateBypassRule("policy.example.com", "policy.example.com", "allow", "", "admin", policy)
	require.NoError(t, err)
	status, headers := validateWith(t, h, "policy.example.com", "/", "127.0.0.1:5000", cookie)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "alice", headers.Get("X-RAuth-User"))
	status, _ = validateWith(t, h, "policy.example.com", "/", "203.0.113.2:5000", cookie)
	assert.Equal(t, http.StatusForbidden, status, "untrusted peers cannot select public policy")
	status, _ = validateWith(t, h, "policy.example.com", "/x%2f..", "127.0.0.1:5000", cookie)
	assert.Equal(t, http.StatusForbidden, status, "ambiguous target cannot skip policy using a cookie")
}

func TestBypassPolicyFormValidation(t *testing.T) {
	for _, fields := range []url.Values{
		{"policy_fields": {"1"}, "country_mode": {"selected"}},
		{"policy_fields": {"1"}, "country_mode": {"all"}, "allow_private_networks": {"forged"}},
		{"policy_fields": {"1"}, "country_mode": {"selected"}, "allowed_countries": {"XX"}},
	} {
		c, _ := createTestContext(echo.New(), http.MethodPost, "/", fields)
		_, err := bypassPolicyForm(c)
		assert.Error(t, err)
	}
	c, _ := createTestContext(echo.New(), http.MethodPost, "/", url.Values{"policy_fields": {"1"}, "country_mode": {"selected"}, "allowed_countries": {"AT", "DE"}})
	p, err := bypassPolicyForm(c)
	require.NoError(t, err)
	require.Len(t, p, 1)
	assert.Equal(t, []string{"AT", "DE"}, p[0].AllowedCountries)
}

func TestValidateRestrictedPolicyDoesNotLockOutOtherApplications(t *testing.T) {
	setupHandlersTest(t)
	resetBypassRules(t)
	_, err := core.AddBypassRule("policy.example.com", "allow", "", "admin", core.RulePolicy{CountryMode: core.CountrySelected, AllowedCountries: []string{"AT"}})
	require.NoError(t, err)
	seedAccount(t, "alice")
	cfg := bypassTestConfig()
	h := &AuthHandler{Cfg: cfg}
	token := "unrelated-policy-session"
	core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+token, map[string]interface{}{"status": "valid", "username": "alice", "ip": "127.0.0.1", "country": "unknown"})
	encrypted, err := core.EncryptToken(token, cfg.ServerSecret)
	require.NoError(t, err)
	cookie := &http.Cookie{Name: "X-rauth-authtoken", Value: encrypted}
	for _, tc := range []struct{ host, uri, peer string }{
		{"other.example.com", "/file%2f..", "127.0.0.1:5000"},
		{"", "", "127.0.0.1:5000"},
		{"other.example.com", "/", "203.0.113.7:5000"},
	} {
		status, headers := validateWith(t, h, tc.host, tc.uri, tc.peer, cookie)
		assert.Equal(t, http.StatusOK, status, tc.host+" "+tc.uri)
		assert.Equal(t, "alice", headers.Get("X-RAuth-User"))
	}
	status, _ := validateWith(t, h, "other.example.com", "/", "127.0.0.1:5000", nil)
	assert.Equal(t, http.StatusUnauthorized, status, "a restriction on another host must not open private applications")
}
