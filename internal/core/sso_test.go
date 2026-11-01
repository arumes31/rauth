package core

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSSOEnrollmentConfig(t *testing.T) {
	base := Config{CookieDomains: []string{"example.com"}, WebAuthnOrigins: []string{"https://auth.example.com"}, AuthStateMode: "postgres", SSOCanonicalOrigin: "https://auth.example.com", SSOApplicationOrigins: []string{"https://app.other.test"}}
	assert.NoError(t, base.ValidateSSO())
	assert.NoError(t, (&Config{}).ValidateSSO())
	assert.True(t, base.SSOApplication("https://app.other.test"))
	assert.False(t, base.SSOApplication("https://sub.app.other.test"))
	for _, change := range []func(*Config){func(c *Config) { c.AuthStateMode = "redis" }, func(c *Config) { c.SSOCanonicalOrigin = "" }, func(c *Config) { c.SSOApplicationOrigins = nil }, func(c *Config) { c.SSOApplicationOrigins = []string{c.SSOCanonicalOrigin} }, func(c *Config) { c.SSOApplicationOrigins = []string{"https://*.other.test"} }, func(c *Config) {
		c.SSOApplicationOrigins = []string{"https://app.other.test", "https://app.other.test"}
	}} {
		cfg := base
		change(&cfg)
		assert.Error(t, cfg.ValidateSSO())
	}
	assert.True(t, SessionAudienceValid(map[string]string{}, ""))
	assert.False(t, SessionAudienceValid(map[string]string{"audience": "https://app.other.test"}, ""))
}

func TestSSOPreservesPasskeyRealm(t *testing.T) {
	c := Config{AuthStateMode: "postgres", SSOCanonicalOrigin: "https://auth.example.com", SSOApplicationOrigins: []string{"https://app.other.test"}, CookieDomains: []string{"example.com"}, WebAuthnOrigins: []string{"https://auth.example.com"}}
	assert.NoError(t, c.ValidateSSO())
	c.CookieDomains = []string{"other.test"}
	assert.Error(t, c.ValidateSSO())
	c.CookieDomains = []string{"example.com"}
	c.WebAuthnOrigins = []string{"https://unrelated.example.com"}
	assert.Error(t, c.ValidateSSO())
	c.WebAuthnOrigins = nil
	c.AllowedHosts = []string{"auth.example.com"}
	assert.NoError(t, c.ValidateSSO())
}
