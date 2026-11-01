package core

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPFeedParserAndMatching(t *testing.T) {
	index, canonical, err := parseFeed([]byte("# example\n8.8.8.8\n8.8.8.8/32\n2001:4860::/32 # IPv6\n::ffff:1.1.1.1\n10.2.3.4/8\n"), false)
	require.NoError(t, err)
	assert.Equal(t, 4, index.count)
	assert.Contains(t, string(canonical), "10.0.0.0/8")
	for _, ip := range []string{"8.8.8.8", "::ffff:8.8.8.8", "1.1.1.1", "10.99.2.1", "2001:4860:1234::1"} {
		assert.True(t, index.contains(netip.MustParseAddr(ip)), ip)
	}
	for _, ip := range []string{"8.8.4.4", "2001:4861::1", "11.1.1.1"} {
		assert.False(t, index.contains(netip.MustParseAddr(ip)), ip)
	}
	for _, body := range []string{"", "<html>error</html>", "8.8.8.8 extra", "fe80::1%eth0", "::ffff:1.1.1.1/80", strings.Repeat("x", 5000)} {
		_, _, err := parseFeed([]byte(body), false)
		assert.Error(t, err)
	}
	empty, _, err := parseFeed(nil, true)
	require.NoError(t, err)
	assert.Equal(t, 0, empty.count)
	_, _, err = parseFeed(make([]byte, MaxFeedBytes+1), true)
	assert.Error(t, err)
}

type stubFeedResolver struct {
	addresses []netip.Addr
	err       error
}

func (s stubFeedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return s.addresses, s.err
}

type stubFeedDialer struct {
	calls []string
	conn  net.Conn
}

func (s *stubFeedDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	s.calls = append(s.calls, address)
	if s.conn != nil {
		return s.conn, nil
	}
	return nil, errors.New("offline")
}
func TestIPFeedFetchDestinationBoundary(t *testing.T) {
	for _, raw := range []string{"http://example.org/list", "https://user:password@example.org/list", "https://127.0.0.1/list", "https://100.100.100.200/list", "file:///etc/passwd", "https://[::ffff:192.168.1.1]/list", "https://[64:ff9b::a9fe:a9fe]/list", "https://example.org/#fragment"} {
		_, err := validateFeedURL(raw)
		assert.Error(t, err, raw)
	}
	_, err := validateFeedURL("https://example.org/list?format=ip")
	require.NoError(t, err)
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.1.2", "::1", "fd00::1", "fe80::1", "198.18.0.1", "64:ff9b::7f00:1", "2002:7f00:1::"} {
		assert.False(t, publicFeedAddress(netip.MustParseAddr(ip)), ip)
	}
	d := &stubFeedDialer{}
	dial := dialPublicFeed(stubFeedResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}}, d)
	_, err = dial(context.Background(), "tcp", "example.org:443")
	assert.Error(t, err)
	assert.Empty(t, d.calls, "mixed DNS must fail before any connection")
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	d = &stubFeedDialer{conn: a}
	dial = dialPublicFeed(stubFeedResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}, d)
	c, err := dial(context.Background(), "tcp", "example.org:443")
	require.NoError(t, err)
	assert.Equal(t, a, c)
	assert.Equal(t, []string{"8.8.8.8:443"}, d.calls, "dial only the validated address, without a second DNS lookup")
	client := newFeedClient()
	transport := client.Transport.(*http.Transport)
	assert.Nil(t, transport.Proxy)
	redirect, _ := http.NewRequest("GET", "https://127.0.0.1/private", nil)
	assert.Error(t, client.CheckRedirect(redirect, []*http.Request{{}}))
	redirect, _ = http.NewRequest("GET", "https://example.org/list", nil)
	assert.Error(t, client.CheckRedirect(redirect, []*http.Request{{}, {}, {}}))
}

type feedRoundTrip func(*http.Request) (*http.Response, error)

func (f feedRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func testFeedClient(body string) *http.Client {
	return &http.Client{Transport: feedRoundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
}
func TestIPFeedFetcherBoundsAndRedaction(t *testing.T) {
	ctx := context.Background()
	_, err := fetchIPFeed(ctx, testFeedClient(strings.Repeat("x", MaxFeedBytes+1)), "https://example.org/list")
	assert.Error(t, err)
	client := &http.Client{Transport: feedRoundTrip(func(r *http.Request) (*http.Response, error) { return nil, errors.New("sensitive query token") })}
	_, err = fetchIPFeed(ctx, client, "https://example.org/list?secret=hidden")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "hidden")
	assert.NotContains(t, err.Error(), "sensitive")
	f := IPFeed{SourceURL: "https://example.org/list?token=secret"}
	assert.Equal(t, "https://example.org/list", f.DisplayURL())
}
func TestIPFeedLifecycleRetainsLastGoodAndReferences(t *testing.T) {
	newRegressionRedis(t)
	t.Cleanup(func() {
		activeFeeds.Store(&feedSnapshot{indexes: map[string]*compiledIPFeed{}, versions: map[string]int64{}})
		activeBypass.Store(&bypassSet{})
	})
	ctx := context.Background()
	f, err := AddIPFeed(ctx, "Blocklist", "https://example.org/list", 60, "admin")
	require.NoError(t, err)
	policy := RulePolicy{CountryMode: CountrySelected, AllowedCountries: []string{"AT"}, AllowPrivateNetworks: true, BlockedFeedIDs: []string{f.ID}}
	_, err = AddBypassRule("app.example.com", "allow", "", "admin", policy)
	assert.Error(t, err, "unloaded feed cannot be attached")
	assert.Empty(t, ListBypassRules(), "failed attachment transaction must not publish a rule")
	body := "8.8.8.8\n1.1.1.1\n127.0.0.0/8\n2001:4860::/32"
	require.NoError(t, refreshIPFeed(ctx, f.ID, FeedRefreshOptions{}, testFeedClient(body)))
	f, err = GetIPFeed(ctx, f.ID)
	require.NoError(t, err)
	assert.True(t, f.Ready())
	assert.Equal(t, 4, f.EntryCount)
	_, err = AddBypassRule("app.example.com", "allow", "", "admin", policy)
	require.NoError(t, err)
	decision := policy.Evaluate("8.8.8.8", "AT")
	assert.False(t, decision.Allowed)
	assert.Equal(t, "ip_feed_blocked", decision.Reason)
	assert.Equal(t, f.ID, decision.FeedID)
	assert.False(t, policy.Evaluate("127.0.0.1", "Internal").Allowed, "feed block must precede private-network exception")
	assert.True(t, policy.Evaluate("9.9.9.9", "AT").Allowed)
	assert.False(t, policy.Evaluate("9.9.9.9", "DE").Allowed)
	assert.ErrorIs(t, DeleteIPFeed(ctx, f.ID), ErrIPFeedInUse)
	assert.ErrorIs(t, UpdateIPFeed(ctx, f.ID, "Disabled", "", 60, false, "admin"), ErrIPFeedInUse)
	for _, bad := range []string{"<html>offline</html>", "", "9.9.9.9"} {
		assert.Error(t, refreshIPFeed(ctx, f.ID, FeedRefreshOptions{}, testFeedClient(bad)))
		current, err := GetIPFeed(ctx, f.ID)
		require.NoError(t, err)
		assert.Equal(t, f.Version, current.Version)
		assert.NotEmpty(t, current.LastError)
		assert.False(t, policy.Evaluate("8.8.8.8", "AT").Allowed, "bad refresh cannot clear blocks")
	}
	require.NoError(t, refreshIPFeed(ctx, f.ID, FeedRefreshOptions{}, testFeedClient(body)))
	unchanged, _ := GetIPFeed(ctx, f.ID)
	assert.Equal(t, f.Version, unchanged.Version, "same payload does not churn versions")
	_, _, err = UpdateBypassRule("app.example.com", "app.example.com/new", "allow", "", "admin")
	require.NoError(t, err)
	feeds, err := ListIPFeeds(ctx)
	require.NoError(t, err)
	require.Len(t, feeds, 1)
	assert.Equal(t, []string{"app.example.com/new"}, feeds[0].Rules)
	_, err = DeleteBypassRule("app.example.com/new")
	require.NoError(t, err)
	require.NoError(t, DeleteIPFeed(ctx, f.ID))
	require.NoError(t, ReloadIPFeeds(ctx))
	assert.Equal(t, "ip_feed_unavailable", policy.Evaluate("9.9.9.9", "AT").Reason)
}
func TestIPFeedConcurrentEditAndExplicitReplacement(t *testing.T) {
	newRegressionRedis(t)
	t.Cleanup(func() {
		activeFeeds.Store(&feedSnapshot{indexes: map[string]*compiledIPFeed{}, versions: map[string]int64{}})
	})
	ctx := context.Background()
	f, err := AddIPFeed(ctx, "Feed", "https://example.org/old", 60, "admin")
	require.NoError(t, err)
	require.NoError(t, refreshIPFeed(ctx, f.ID, FeedRefreshOptions{}, testFeedClient("8.8.8.8\n1.1.1.1")))
	client := &http.Client{Transport: feedRoundTrip(func(r *http.Request) (*http.Response, error) {
		require.NoError(t, UpdateIPFeed(ctx, f.ID, "Feed", "https://example.org/new", 60, true, "admin"))
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("9.9.9.9\n4.4.4.4")), Request: r}, nil
	})}
	assert.Error(t, refreshIPFeed(ctx, f.ID, FeedRefreshOptions{}, client), "stale fetch cannot replace edited feed")
	old, err := GetIPFeed(ctx, f.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), old.Version)
	require.NoError(t, refreshIPFeed(ctx, f.ID, FeedRefreshOptions{AcceptEmpty: true}, testFeedClient("")))
	next, _ := GetIPFeed(ctx, f.ID)
	assert.Equal(t, 0, next.EntryCount)
	assert.Equal(t, int64(2), next.Version)
	_, err = PG.Exec(ctx, "UPDATE ip_feed_versions SET payload='corrupt' WHERE feed_id=$1 AND version=$2", f.ID, next.Version)
	require.NoError(t, err)
	activeFeeds.Store(&feedSnapshot{indexes: map[string]*compiledIPFeed{}, versions: map[string]int64{}})
	assert.Error(t, ReloadIPFeeds(ctx), "checksum must be verified before activation")
}
func BenchmarkIPFeedMatch(b *testing.B) {
	index, _, err := parseFeed([]byte("8.8.8.0/24\n2001:4860::/32"), false)
	if err != nil {
		b.Fatal(err)
	}
	address := netip.MustParseAddr("2001:4860:1111::1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		index.contains(address)
	}
}

func TestPolicyPreviewDoesNotFetchAndReportsWinningRule(t *testing.T) {
	t.Cleanup(func() { activeBypass.Store(&bypassSet{}) })
	r, err := ParseBypassRule("app.example.com/restricted")
	require.NoError(t, err)
	r.RulePolicy = RulePolicy{CountryMode: CountrySelected, AllowedCountries: []string{"AT"}}
	activeBypass.Store(&bypassSet{ui: []BypassRule{r}})
	p, err := PreviewURLPolicy("https://app.example.com/restricted?token=private", "127.0.0.1")
	require.NoError(t, err)
	assert.False(t, p.Allowed)
	assert.Equal(t, "country_blocked", p.Reason)
	assert.NotContains(t, p.URL, "private")
	p, err = PreviewURLPolicy("https://other.example.com/", "8.8.8.8")
	require.NoError(t, err)
	assert.True(t, p.Allowed)
	assert.False(t, p.Public)
	assert.Equal(t, "login_required", p.Reason)
	for _, raw := range []string{"file:///etc/passwd", "https://user:pass@app.example.com/", "invalid"} {
		_, err = PreviewURLPolicy(raw, "8.8.8.8")
		assert.Error(t, err)
	}
}
