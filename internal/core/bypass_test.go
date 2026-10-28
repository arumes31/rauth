package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseBypassRule(t *testing.T) {
	valid := map[string]BypassRule{
		"cloud.example.com":        {Rule: "cloud.example.com", Host: "cloud.example.com"},
		" Cloud.Example.COM. ":     {Rule: "cloud.example.com", Host: "cloud.example.com"},
		"*.public.example.com":     {Rule: "*.public.example.com", Host: "public.example.com", Wildcard: true},
		"web.example.com/webhook":  {Rule: "web.example.com/webhook", Host: "web.example.com", Path: "/webhook"},
		"web.example.com/webhook/": {Rule: "web.example.com/webhook", Host: "web.example.com", Path: "/webhook"},
		"web.example.com/a//b":     {Rule: "web.example.com/a/b", Host: "web.example.com", Path: "/a/b"},
		"web.example.com/":         {Rule: "web.example.com", Host: "web.example.com"},
		"*.example.com/api/public": {Rule: "*.example.com/api/public", Host: "example.com", Wildcard: true, Path: "/api/public"},
	}
	for in, want := range valid {
		got, err := ParseBypassRule(in)
		require.NoError(t, err, in)
		assert.Equal(t, want.Rule, got.Rule, in)
		assert.Equal(t, want.Host, got.Host, in)
		assert.Equal(t, want.Wildcard, got.Wildcard, in)
		assert.Equal(t, want.Path, got.Path, in)
	}

	for _, in := range []string{
		"", "   ", "https://cloud.example.com", "cloud.example.com:8080", "*", "*.", "a.*.example.com",
		"foo_bar.example.com", "-bad.example.com", "web.example.com/../admin", "web.example.com/a/./b",
		"web.example.com/a%2fb", `web.example.com/a\b`, "web.example.com/a;b", "web.example.com/a?x=1",
		"10.0.0.1:80", "exa mple.com",
	} {
		_, err := ParseBypassRule(in)
		assert.Error(t, err, in)
	}
}

func TestSafeRequestPath(t *testing.T) {
	ok := map[string]string{
		"/":                         "/",
		"/webhook":                  "/webhook",
		"/webhook/":                 "/webhook",
		"/webhook/github?x=1&y=2":   "/webhook/github",
		"//webhook//github":         "/webhook/github",
		"/web%20hook":               "/web hook",
		"https://web.example.com/a": "/a",
		"http://host":               "/",
		"?only=query":               "/",
		"/admin?next=https://web.example.com/webhook": "/admin",
	}
	for in, want := range ok {
		got, valid := safeRequestPath(in)
		require.True(t, valid, in)
		assert.Equal(t, want, got, in)
	}

	for _, in := range []string{
		"", "webhook", "/webhook/../admin", "/webhook/./x", "/webhook/%2e%2e/admin", "/webhook%2f..%2fadmin",
		"/webhook%2Fadmin", `/webhook\..\admin`, "/webhook%5cadmin", "/webhook;jsessionid=1", "/webhook/%00",
		"/webhook/%zz", "/..", "/webhook/%2E", "/webhook/%252e%252e/admin", "/webhook%252f..%252fadmin",
		"/webhook/%25", "ftp://host/webhook",
	} {
		_, valid := safeRequestPath(in)
		assert.False(t, valid, in)
	}
}

func TestMatchBypass(t *testing.T) {
	t.Cleanup(func() { activeBypass.Store(&bypassSet{}) })
	SetEnvBypassRules([]string{"cloud.example.com", "web.example.com/webhook", "*.public.example.com", "not a rule"})

	cases := []struct {
		host, uri string
		want      bool
	}{
		{"cloud.example.com", "/", true},
		{"CLOUD.example.com:443", "/index.php/apps/files?dir=/", true},
		{"cloud.example.com.", "/x", true},
		{"cloud.example.com, proxy.internal", "/x", true},
		{"evilcloud.example.com", "/", false},
		{"cloud.example.com.evil.com", "/", false},
		{"web.example.com", "/webhook", true},
		{"web.example.com", "/webhook/github/push?sig=1", true},
		{"web.example.com", "/webhooks", false},
		{"web.example.com", "/webhook-admin", false},
		{"web.example.com", "/admin", false},
		{"web.example.com", "/", false},
		{"web.example.com", "/webhook/../admin", false},
		{"web.example.com", "/webhook/%2e%2e/admin", false},
		{"web.example.com", "/webhook%2f..%2fadmin", false},
		{"web.example.com", "/webhook;x=1", false},
		{"web.example.com", "/WEBHOOK", false},
		{"web.example.com", "/webhook/%252e%252e/admin", false},
		{"web.example.com", "/admin?x=http://web.example.com/webhook", false},
		{"web.example.com", "/admin#https://h/webhook", false},
		{"web.example.com", "/webhook?target=https://example.com/callback", true},
		{"web.example.com", "HTTPS://web.example.com/webhook/x", true},
		{"a.public.example.com", "/anything", true},
		{"a.b.public.example.com", "/anything", true},
		{"public.example.com", "/", false},
		{"", "/", false},
		{"cloud.example.com", "", false},
		{"bad_host", "/", false},
	}
	for _, tc := range cases {
		_, got := MatchBypass(tc.host, tc.uri)
		assert.Equal(t, tc.want, got, "host=%q uri=%q", tc.host, tc.uri)
	}
}

func TestBypassRuleStorage(t *testing.T) {
	newRegressionRedis(t)
	t.Cleanup(func() { activeBypass.Store(&bypassSet{}) })

	_, err := AddBypassRule("not a host!", "", "admin")
	assert.Error(t, err)

	r, err := AddBypassRule("Web.Example.com/webhook/", "GitHub hooks", "admin")
	require.NoError(t, err)
	assert.Equal(t, "web.example.com/webhook", r.Rule)
	_, ok := MatchBypass("web.example.com", "/webhook/x")
	assert.True(t, ok)

	rules := ListBypassRules()
	require.Len(t, rules, 1)
	assert.Equal(t, "ui", rules[0].Source)
	assert.Equal(t, "GitHub hooks", rules[0].Note)
	assert.Equal(t, "admin", rules[0].CreatedBy)

	// Another instance picks the rule up from Redis.
	activeBypass.Store(&bypassSet{})
	require.NoError(t, ReloadBypassRules())
	_, ok = MatchBypass("web.example.com", "/webhook")
	assert.True(t, ok)

	existed, err := DeleteBypassRule("web.example.com/webhook")
	require.NoError(t, err)
	assert.True(t, existed)
	_, ok = MatchBypass("web.example.com", "/webhook")
	assert.False(t, ok)

	existed, err = DeleteBypassRule("web.example.com/webhook")
	require.NoError(t, err)
	assert.False(t, existed)
}
