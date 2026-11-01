package core

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultIPFeedBackfillInheritanceAndOptOut(t *testing.T) {
	newRegressionRedis(t)
	t.Cleanup(func() {
		activeFeeds.Store(&feedSnapshot{indexes: map[string]*compiledIPFeed{}, versions: map[string]int64{}})
		activeBypass.Store(&bypassSet{})
	})
	ctx := context.Background()
	_, err := AddBypassRule("legacy.example.com", "allow", "", "admin")
	require.NoError(t, err)
	_, err = AddBypassRule("private.example.com", "deny", "", "admin")
	require.NoError(t, err)
	_, err = AddBypassRule("optout.example.com", "allow", "", "admin", RulePolicy{DefaultFeedConfigured: true})
	require.NoError(t, err)
	require.NoError(t, EnsureDefaultIPFeed(ctx))
	require.NoError(t, ReloadIPFeeds(ctx))
	require.NoError(t, ReloadBypassRules())
	SetEnvBypassRules([]string{"env.example.com"})
	for _, host := range []string{"legacy.example.com", "env.example.com"} {
		rule, found, err := SelectBypassRule(host, "/")
		require.NoError(t, err)
		require.True(t, found)
		assert.Contains(t, rule.BlockedFeedIDs, DefaultIPFeedID)
		assert.Equal(t, "ip_feed_unavailable", rule.Evaluate("8.8.8.8", "AT").Reason, "pending default cannot create unrestricted startup")
	}
	private, found, err := SelectBypassRule("private.example.com", "/")
	require.NoError(t, err)
	require.True(t, found)
	assert.Empty(t, private.BlockedFeedIDs)
	optout, found, err := SelectBypassRule("optout.example.com", "/")
	require.NoError(t, err)
	require.True(t, found)
	assert.Empty(t, optout.BlockedFeedIDs)
	_, err = AddBypassRule("new.example.com", "allow", "", "admin")
	assert.Error(t, err, "pending default must be bootstrapped before attaching new inherited rules")
	require.NoError(t, refreshIPFeed(ctx, DefaultIPFeedID, FeedRefreshOptions{}, testFeedClient("8.8.8.8\n2001:4860::/32")))
	rule, err := AddBypassRule("new.example.com", "allow", "", "admin")
	require.NoError(t, err)
	assert.Contains(t, rule.BlockedFeedIDs, DefaultIPFeedID)
	_, err = AddBypassRule("wasprivate.example.com", "deny", "", "admin", RulePolicy{DefaultFeedConfigured: true})
	require.NoError(t, err)
	_, converted, err := UpdateBypassRule("wasprivate.example.com", "wasprivate.example.com", "allow", "", "legacy-admin")
	require.NoError(t, err)
	assert.Contains(t, converted.BlockedFeedIDs, DefaultIPFeedID)
	assert.Equal(t, "ip_feed_blocked", rule.Evaluate("8.8.8.8", "AT").Reason)
	assert.True(t, rule.Evaluate("9.9.9.9", "AT").Allowed)
	_, _, err = UpdateBypassRule("new.example.com", "new.example.com", "allow", "", "admin", RulePolicy{DefaultFeedConfigured: true})
	require.NoError(t, err)
	require.NoError(t, EnsureDefaultIPFeed(ctx))
	require.NoError(t, ReloadBypassRules())
	rule, _, _ = SelectBypassRule("new.example.com", "/")
	assert.Empty(t, rule.BlockedFeedIDs, "explicit admin opt-out survives restarts")
	assert.Error(t, DeleteIPFeed(ctx, DefaultIPFeedID))
	assert.Error(t, UpdateIPFeed(ctx, DefaultIPFeedID, "Default", "", 60, false, "admin"))
	assert.Error(t, UpdateIPFeed(ctx, DefaultIPFeedID, "Default", "https://other.example/list", 60, true, "admin"))
}
func TestDefaultIPFeedLive(t *testing.T) {
	if os.Getenv("RAUTH_TEST_DEFAULT_FEED_LIVE") != "1" {
		t.Skip("explicit live default-feed integration check")
	}
	newRegressionRedis(t)
	t.Cleanup(func() {
		activeFeeds.Store(&feedSnapshot{indexes: map[string]*compiledIPFeed{}, versions: map[string]int64{}})
		activeBypass.Store(&bypassSet{})
	})
	ctx := context.Background()
	require.NoError(t, EnsureDefaultIPFeed(ctx))
	require.NoError(t, RefreshIPFeed(ctx, DefaultIPFeedID, FeedRefreshOptions{}))
	feed, err := GetIPFeed(ctx, DefaultIPFeedID)
	require.NoError(t, err)
	assert.True(t, feed.Ready())
	assert.Greater(t, feed.EntryCount, 0)
	var body []byte
	require.NoError(t, PG.QueryRow(ctx, "SELECT payload FROM ip_feed_versions WHERE feed_id=$1 AND version=$2", feed.ID, feed.Version).Scan(&body))
	first := strings.Split(string(body), "\n")[0]
	prefix, err := netip.ParsePrefix(first)
	require.NoError(t, err)
	rule, err := AddBypassRule("default-live-test.example.com", "allow", "", "integration-test")
	require.NoError(t, err)
	assert.Equal(t, "ip_feed_blocked", rule.Evaluate(prefix.Addr().String(), "AT").Reason)
	t.Logf("Live default feed: ready=%v entries=%d version=%d canonical_bytes=%d", feed.Ready(), feed.EntryCount, feed.Version, len(body))
}

func TestDefaultIPFeedCannotBeDeletedWithAlternateUUIDSpelling(t *testing.T) {
	newRegressionRedis(t)
	require.NoError(t, EnsureDefaultIPFeed(context.Background()))
	for _, id := range []string{strings.ToUpper(DefaultIPFeedID), "{" + DefaultIPFeedID + "}", "urn:uuid:" + DefaultIPFeedID} {
		err := DeleteIPFeed(context.Background(), id)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "built-in default")
	}
	_, err := GetIPFeed(context.Background(), DefaultIPFeedID)
	require.NoError(t, err)
}
func TestIPFeedColdStartRetryIsPrompt(t *testing.T) {
	f := IPFeed{Enabled: true, Version: 0, RefreshMinutes: 60, LastAttempt: 1000}
	assert.False(t, ipFeedRefreshDue(f, 1059))
	assert.True(t, ipFeedRefreshDue(f, 1060), "a transient first-download failure must not block public URLs for an hour")
	f.Version = 1
	assert.False(t, ipFeedRefreshDue(f, 1060))
	assert.True(t, ipFeedRefreshDue(f, 4600), "loaded feeds retain their configured refresh interval")
	f.Enabled = false
	assert.False(t, ipFeedRefreshDue(f, 9999))
}

func TestDefaultIPFeedRespectsCatalogLimit(t *testing.T) {
	newRegressionRedis(t)
	t.Cleanup(func() {
		activeFeeds.Store(&feedSnapshot{indexes: map[string]*compiledIPFeed{}, versions: map[string]int64{}})
		activeBypass.Store(&bypassSet{})
	})
	ctx := context.Background()
	for i := 0; i < MaxIPFeeds; i++ {
		_, err := AddIPFeed(ctx, fmt.Sprintf("Custom %d", i), "https://feeds.example.com/list", 60, "admin")
		require.NoError(t, err)
	}
	_, err := AddBypassRule("legacy.example.com", "allow", "", "admin")
	require.NoError(t, err)
	require.ErrorContains(t, EnsureDefaultIPFeed(ctx), "make room")
	var count int
	require.NoError(t, PG.QueryRow(ctx, "SELECT count(*) FROM ip_feeds").Scan(&count))
	assert.Equal(t, MaxIPFeeds, count)
	require.NoError(t, ReloadBypassRules())
	rule, found, err := SelectBypassRule("legacy.example.com", "/")
	require.NoError(t, err)
	require.True(t, found)
	assert.Empty(t, rule.BlockedFeedIDs, "a failed bootstrap must not partially alter rules")
}
