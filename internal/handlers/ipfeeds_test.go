package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"rauth/internal/core"
	"testing"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPFeedAdminMutationsRequireUnlock(t *testing.T) {
	h := &AdminHandler{Cfg: bypassTestConfig()}
	for _, action := range []func(*echo.Context) error{h.AddIPFeed, h.UpdateIPFeed, h.DeleteIPFeed, h.RefreshIPFeed} {
		c, _ := createTestContext(echo.New(), http.MethodPost, "/rauthmgmt/ip-feeds", url.Values{})
		err := action(c)
		require.Error(t, err)
		he, ok := err.(*echo.HTTPError)
		require.True(t, ok)
		assert.Equal(t, 403, he.Code)
	}
}
func TestIPFeedAdminCreateUpdateDelete(t *testing.T) {
	setupHandlersTest(t)
	h := &AdminHandler{Cfg: bypassTestConfig()}
	core.TokenDB.Set(core.Ctx, bypassUnlockKey("feed-admin"), "admin", time.Minute)
	post := func(fn func(*echo.Context) error, form url.Values) (int, error) {
		c, r := createTestContext(echo.New(), http.MethodPost, "/rauthmgmt/ip-feeds", form)
		c.Set("token", "feed-admin")
		c.Set("username", "admin")
		err := fn(c)
		return r.Code, err
	}
	_, err := post(h.AddIPFeed, url.Values{"name": {"Test feed"}, "source_url": {"https://example.org/list?api_token=SECRET_SHOULD_NOT_RENDER"}, "refresh_minutes": {"60"}})
	require.NoError(t, err)
	feeds, err := core.ListIPFeeds(context.Background())
	require.NoError(t, err)
	require.Len(t, feeds, 1)
	assert.NotContains(t, feeds[0].DisplayURL(), "SECRET")
	_, err = post(h.UpdateIPFeed, url.Values{"feed_id": {feeds[0].ID}, "name": {"Renamed"}, "refresh_minutes": {"15"}, "enabled": {"on"}})
	require.NoError(t, err)
	feed, err := core.GetIPFeed(context.Background(), feeds[0].ID)
	require.NoError(t, err)
	assert.Equal(t, "Renamed", feed.Name)
	assert.Contains(t, feed.SourceURL, "api_token=", "blank URL must keep the original")
	_, err = post(h.DeleteIPFeed, url.Values{"feed_id": {feed.ID}})
	require.NoError(t, err)
	feeds, err = core.ListIPFeeds(context.Background())
	require.NoError(t, err)
	assert.Empty(t, feeds)
}
func TestValidateIPFeedBlocksValidSessions(t *testing.T) {
	setupHandlersTest(t)
	resetBypassRules(t)
	f, err := core.AddIPFeed(core.Ctx, "Deny loopback", "https://example.org/list", 60, "admin")
	require.NoError(t, err)
	payload := []byte("127.0.0.0/8")
	sum := sha256.Sum256(payload)
	_, err = core.PG.Exec(core.Ctx, "INSERT INTO ip_feed_versions(feed_id,version,checksum,payload,created_at) VALUES($1,1,$2,$3,1)", f.ID, hex.EncodeToString(sum[:]), payload)
	require.NoError(t, err)
	_, err = core.PG.Exec(core.Ctx, "UPDATE ip_feeds SET active_version=1,entry_count=1 WHERE id=$1", f.ID)
	require.NoError(t, err)
	require.NoError(t, core.ReloadIPFeeds(core.Ctx))
	p := core.RulePolicy{CountryMode: core.CountrySelected, AllowedCountries: []string{"AT"}, AllowPrivateNetworks: true, BlockedFeedIDs: []string{f.ID}}
	_, err = core.AddBypassRule("app.example.com", "allow", "", "admin", p)
	require.NoError(t, err)
	seedAccount(t, "alice")
	cfg := bypassTestConfig()
	h := &AuthHandler{Cfg: cfg}
	token := "feed-blocked-valid-session"
	core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+token, map[string]interface{}{"status": "valid", "username": "alice", "ip": "127.0.0.1", "country": "unknown"})
	encrypted, err := core.EncryptToken(token, cfg.ServerSecret)
	require.NoError(t, err)
	cookie := &http.Cookie{Name: "X-rauth-authtoken", Value: encrypted}
	for _, session := range []*http.Cookie{nil, cookie} {
		status, headers := validateWith(t, h, "app.example.com", "/", "127.0.0.1:5000", session)
		assert.Equal(t, 403, status)
		assert.Empty(t, headers.Get("X-RAuth-User"))
		assert.Empty(t, headers.Get("X-RAuth-Anonymous"))
	}
}
