package core

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestFeedRetentionAndWakeup(t *testing.T) {
	f := NewRequestFeed(3)
	initial := f.After(0)
	for i := 0; i < 5; i++ {
		f.Append(RequestEvent{URL: fmt.Sprintf("https://example.com/%d", i), Source: "2001:db8::1", Action: "bypass"})
	}
	select {
	case <-initial.Changed:
	default:
		t.Fatal("reader not notified")
	}
	b := f.After(0)
	require.Len(t, b.Events, 3)
	assert.Equal(t, uint64(3), b.Oldest)
	assert.Equal(t, uint64(5), b.Latest)
	assert.Equal(t, []uint64{3, 4, 5}, []uint64{b.Events[0].ID, b.Events[1].ID, b.Events[2].ID})
	require.Len(t, f.After(4).Events, 1)
	assert.Empty(t, f.After(5).Events)
	b.Events[0].URL = "changed by reader"
	assert.NotEqual(t, b.Events[0].URL, f.After(0).Events[0].URL, "snapshots must not alias history")
}

func TestRequestFeedConcurrentBoundedHistory(t *testing.T) {
	f := NewRequestFeed(RequestFeedCapacity)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				f.Append(RequestEvent{Source: "127.0.0.1", Action: "authenticated"})
				_ = f.After(0)
			}
		}()
	}
	wg.Wait()
	cursor := uint64(0)
	count := 0
	for {
		b := f.After(cursor)
		assert.LessOrEqual(t, len(b.Events), RequestFeedBatch)
		assert.Equal(t, uint64(601), b.Oldest)
		assert.Equal(t, uint64(1600), b.Latest)
		for _, e := range b.Events {
			require.Greater(t, e.ID, cursor)
			cursor = e.ID
			count++
		}
		if cursor == b.Latest {
			break
		}
	}
	assert.Equal(t, RequestFeedCapacity, count)
	assert.NotEqual(t, f.Epoch(), NewRequestFeed(3).Epoch())
}

func TestProtectedRequestURL(t *testing.T) {
	cases := []struct{ scheme, host, target, want string }{
		{"https", "cloud.example.com", "/files/ops;C?token=secret#fragment", "https://cloud.example.com/files/ops;C"},
		{"https", "cloud.example.com", "/files/ops%3BC?password=secret", "https://cloud.example.com/files/ops%3BC"},
		{"https", "cloud.example.com", "https://user:password@other.example.com/file?token=secret", "https://cloud.example.com/file"},
		{"http", "localhost:8080", "/", "http://localhost:8080/"},
		{"", "cloud.example.com", "/file", "https://cloud.example.com/file"},
		{"https", "user:password@cloud.example.com", "/file", "https://cloud.example.com/file"},
		{"https", "bad\r\nhost", "/file", ""},
		{"https", "cloud.example.com", "relative", ""},
		{"https", "", "/file", ""},
		{"https", "cloud.example.com", "/%zz", ""},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, ProtectedRequestURL(tc.scheme, tc.host, tc.target))
	}
	f := NewRequestFeed(1)
	f.Append(RequestEvent{URL: strings.Repeat("é", 3000), Source: "not-an-IP", Country: strings.Repeat("x", 100), Action: "untrusted"})
	e := f.After(0).Events[0]
	assert.Len(t, []rune(e.URL), 2048)
	assert.Len(t, e.Country, 32)
	assert.Equal(t, "unknown", e.Source)
	assert.Equal(t, "error", e.Action)
}

func TestTrustedProxyPeer(t *testing.T) {
	cfg := &Config{TrustedProxies: []string{"10.0.0.0/8"}}
	assert.True(t, cfg.IsTrustedProxyPeer("10.1.2.3:1234"))
	assert.False(t, cfg.IsTrustedProxyPeer("203.0.113.1:1234"))
	cfg.TrustedProxies = nil
	assert.True(t, cfg.IsTrustedProxyPeer("[::1]:1234"))
	assert.False(t, cfg.IsTrustedProxyPeer("invalid"))
}
