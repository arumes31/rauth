package core

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRulePolicyNormalization(t *testing.T) {
	p, err := NormalizeRulePolicy(RulePolicy{CountryMode: " SELECTED ", AllowedCountries: []string{"at", "DE", "AT"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"AT", "DE"}, p.AllowedCountries)
	assert.Equal(t, "Only AT, DE", p.CountrySummary())
	for _, bad := range []RulePolicy{
		{CountryMode: "selected"}, {CountryMode: "invalid"},
		{CountryMode: "selected", AllowedCountries: []string{"ZZ"}},
		{CountryMode: "selected", AllowedCountries: []string{"EU"}},
		{CountryMode: "selected", AllowedCountries: []string{"123"}},
	} {
		_, err := NormalizeRulePolicy(bad)
		assert.Error(t, err, "%+v", bad)
	}
	legacy, err := NormalizeRulePolicy(RulePolicy{})
	require.NoError(t, err)
	assert.Equal(t, CountryAll, legacy.CountryMode)
	assert.False(t, legacy.Restricted())
	assert.Greater(t, len(PolicyCountries()), 240)
}

func TestRulePolicyCountryDecisions(t *testing.T) {
	p := RulePolicy{CountryMode: CountrySelected, AllowedCountries: []string{"AT"}}
	cases := []struct {
		ip, country string
		allowed     bool
		reason      string
	}{
		{"8.8.8.8", "AT", true, ""},
		{"2001:4860:4860::8888", "AT", true, ""},
		{"::ffff:8.8.8.8", "AT", true, ""},
		{"8.8.8.8", "DE", false, "country_blocked"},
		{"8.8.8.8", "unknown", false, "country_blocked"},
		{"127.0.0.1", "AT", false, "country_blocked"},
		{"100.95.137.18", "AT", false, "country_blocked"},
		{"fd7a:115c:a1e0::1", "AT", false, "country_blocked"},
		{"bad", "AT", false, "invalid_client_ip"},
		{"fe80::1%eth0", "AT", false, "invalid_client_ip"},
	}
	for _, tc := range cases {
		d := p.Evaluate(tc.ip, tc.country)
		assert.Equal(t, tc.allowed, d.Allowed, tc.ip+" "+tc.country)
		assert.Equal(t, tc.reason, d.Reason)
	}
	p.AllowPrivateNetworks = true
	assert.True(t, p.Evaluate("100.95.137.18", "Tailscale").Allowed)
	assert.True(t, p.Evaluate("::ffff:192.168.1.3", "Internal").Allowed)
	assert.False(t, p.Evaluate("8.8.8.8", "unknown").Allowed)
	p.BlockedFeedIDs = []string{"missing"}
	assert.False(t, p.Evaluate("127.0.0.1", "Internal").Allowed, "a private exception never opens missing feed policy")
}

func TestRulePolicyWinningRuleNeverFallsThrough(t *testing.T) {
	t.Cleanup(func() { activeBypass.Store(&bypassSet{}) })
	broad, err := ParseBypassRule("app.example.com")
	require.NoError(t, err)
	narrow, err := ParseBypassRule("app.example.com/restricted")
	require.NoError(t, err)
	narrow.RulePolicy = RulePolicy{CountryMode: CountrySelected, AllowedCountries: []string{"AT"}}
	private, err := ParseBypassRule("!app.example.com/private")
	require.NoError(t, err)
	activeBypass.Store(&bypassSet{ui: []BypassRule{broad, narrow, private}})
	assert.True(t, HasRestrictedBypassRules())
	rule, found, err := SelectBypassRule("app.example.com", "/restricted/file")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, narrow.Rule, rule.Rule)
	assert.False(t, rule.Evaluate("8.8.8.8", "DE").Allowed)
	rule, found, err = SelectBypassRule("app.example.com", "/private")
	require.NoError(t, err)
	require.True(t, found)
	assert.False(t, rule.Allows())
	_, _, err = SelectBypassRule("app.example.com", "/restricted/x%252f.txt")
	assert.Error(t, err)
}

func TestRulePolicyPersistenceAndInvalidReload(t *testing.T) {
	newRegressionRedis(t)
	t.Cleanup(func() { activeBypass.Store(&bypassSet{}) })
	p := RulePolicy{CountryMode: CountrySelected, AllowedCountries: []string{"AT"}}
	_, err := AddBypassRule("policy.example.com", "allow", "test", "admin", p)
	require.NoError(t, err)
	rules := ListBypassRules()
	require.Len(t, rules, 1)
	assert.Equal(t, []string{"AT"}, rules[0].AllowedCountries)
	// Older callers must preserve restrictions rather than silently removing them.
	_, _, err = UpdateBypassRule("policy.example.com", "policy.example.com", "allow", "renamed note", "admin2")
	require.NoError(t, err)
	assert.Equal(t, []string{"AT"}, ListBypassRules()[0].AllowedCountries)
	_, err = PG.Exec(Ctx, `UPDATE bypass_rules SET meta='{"action":"allow","country_mode":"selected","allowed_countries":[]}' WHERE rule='policy.example.com'`)
	require.NoError(t, err)
	assert.Error(t, ReloadBypassRules())
	assert.Equal(t, []string{"AT"}, ListBypassRules()[0].AllowedCountries, "last complete policy survives malformed refresh")
}

func TestRulePolicySelectorIgnoresUnrelatedTargets(t *testing.T) {
	t.Cleanup(func() { activeBypass.Store(&bypassSet{}) })
	rule, err := ParseBypassRule("policy.example.com")
	require.NoError(t, err)
	rule.RulePolicy = RulePolicy{CountryMode: CountrySelected, AllowedCountries: []string{"AT"}}
	activeBypass.Store(&bypassSet{ui: []BypassRule{rule}})
	for _, host := range []string{"other.example.com", ""} {
		_, found, err := SelectBypassRule(host, "/file%2f..")
		assert.NoError(t, err)
		assert.False(t, found)
	}
	_, _, err = SelectBypassRule("policy.example.com", "/file%2f..")
	assert.Error(t, err)
	assert.True(t, HasRestrictedBypassRulesForHost("POLICY.example.com:443"))
	assert.False(t, HasRestrictedBypassRulesForHost("other.example.com"))
}

func TestPolicyCountriesExcludeObsoleteAliases(t *testing.T) {
	for _, code := range []string{"DD", "SU", "FX", "BU", "TP", "ZR"} {
		for _, option := range PolicyCountries() {
			assert.NotEqual(t, code, option.Code, "obsolete country aliases must not create duplicate checkbox entries")
		}
	}
}
