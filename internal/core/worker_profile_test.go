package core

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func workerProfileConfig() *Config {
	return &Config{AuthStateMode: "postgres", CookieDomains: []string{"example.test"}, SSOCanonicalOrigin: "https://login.example.test", SSOApplicationOrigins: []string{"https://app.other.test"}, WebAuthnOrigins: []string{"https://login.example.test"}, TrustedProxies: []string{"10.253.42.1"}, AuthBypassHostHeader: "X-Forwarded-Host", AuthBypassURIHeader: "X-Forwarded-Uri"}
}
func TestWorkerProfileIgnoresSecretsAndPhysicalLocations(t *testing.T) {
	cfg := workerProfileConfig()
	before, err := NodeSecurityFingerprint(cfg)
	require.NoError(t, err)
	cfg.ServerSecret = "private-cookie-secret"
	cfg.RedisPassword = "private-redis-password"
	cfg.PostgresURL = "postgres://user:private-password@db/auth"
	cfg.AuthStateKeyFile = "/private/keyring.json"
	cfg.InitialPassword = "private-initial-password"
	cfg.Initial2FASecret = "private-otp-key"
	cfg.SMTPPass = "private-smtp-password"
	cfg.MaxMindLicenseKey = "private-license"
	cfg.ListenAddr = "127.0.0.2:9000"
	cfg.ClusterConfigFile = "/mnt/usb1/rauth/config/node.json"
	cfg.MaxMindDBPath = "/mnt/usb1/rauth/geoip/database.mmdb"
	after, err := NodeSecurityFingerprint(cfg)
	require.NoError(t, err)
	assert.Equal(t, before, after)
	assert.True(t, policyHash(after))
}
func TestWorkerProfileIncludesTrustOriginsAndSecurityDelivery(t *testing.T) {
	changes := []func(*Config){func(c *Config) { c.TrustedProxies = []string{"10.253.42.2"} }, func(c *Config) { c.TrustCloudflareIP = true }, func(c *Config) { c.AllowedCountries = []string{"AT"} }, func(c *Config) { c.SSOApplicationOrigins = []string{"https://another.other.test"} }, func(c *Config) { c.CSRFTrustedOrigins = []string{"https://trusted.other.test"} }, func(c *Config) { c.SMTPHost = "mail.other.test" }, func(c *Config) { c.SMTPTLS = "none" }, func(c *Config) { c.TokenValidityMinutes = 30 }, func(c *Config) { c.RateLimitLoginMax = 1 }, func(c *Config) { c.WebAuthnRequireUserVerification = true }}
	baseline, err := NodeSecurityFingerprint(workerProfileConfig())
	require.NoError(t, err)
	for _, change := range changes {
		cfg := workerProfileConfig()
		change(cfg)
		hash, err := NodeSecurityFingerprint(cfg)
		require.NoError(t, err)
		assert.NotEqual(t, baseline, hash)
	}
	_, err = NodeSecurityFingerprint(nil)
	require.Error(t, err)
}
func TestWorkerPolicyOptionsRequireFrozenExplicitClusterConfiguration(t *testing.T) {
	cfg := workerProfileConfig()
	opts, err := WorkerPolicyOptionsForConfig(snapshotNode, cfg)
	require.NoError(t, err)
	assert.Equal(t, snapshotNode, opts.NodeID)
	assert.True(t, policyHash(opts.SecurityFingerprint))
	assert.False(t, opts.RequireGeoIP)
	for _, change := range []func(*Config){func(c *Config) { c.AuthStateMode = "redis" }, func(c *Config) { c.SSOCanonicalOrigin = "" }, func(c *Config) { c.CloudflareAutoUpdate = true }, func(c *Config) { c.TrustedProxies = nil }, func(c *Config) { c.TrustedProxies = []string{"10.0.0.0/8"} }, func(c *Config) { c.TrustedProxies = []string{"0.0.0.0"} }, func(c *Config) { c.AuthBypassURIHeader = "" }} {
		bad := workerProfileConfig()
		change(bad)
		_, err := WorkerPolicyOptionsForConfig(snapshotNode, bad)
		require.Error(t, err)
	}
	cfg.AllowedCountries = []string{"AT"}
	opts, err = WorkerPolicyOptionsForConfig(snapshotNode, cfg)
	require.NoError(t, err)
	assert.True(t, opts.RequireGeoIP)
	cfg.TrustedProxies = []string{"10.253.42.1/32", "fd7a:115c:a1e0::1/128"}
	_, err = WorkerPolicyOptionsForConfig(snapshotNode, cfg)
	require.NoError(t, err)
}

func TestWorkerPolicyOptionsRejectInvalidFrozenEdgeRanges(t *testing.T) {
	for _, ranges := range [][]string{nil, {"bad-prefix"}, {"198.51.100.1/24"}} {
		cfg := workerProfileConfig()
		cfg.TrustCloudflareIP = true
		cfg.CloudflareIPRanges = ranges
		_, err := WorkerPolicyOptionsForConfig(snapshotNode, cfg)
		require.Error(t, err)
	}
	cfg := workerProfileConfig()
	cfg.TrustCloudflareIP = true
	cfg.CloudflareIPRanges = []string{"198.51.100.0/24"}
	_, err := WorkerPolicyOptionsForConfig(snapshotNode, cfg)
	require.NoError(t, err)
}
