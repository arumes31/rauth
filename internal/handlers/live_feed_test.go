package handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"rauth/internal/core"
	"rauth/internal/eventstore"
	"rauth/internal/middleware"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readFeedEvent(t *testing.T, r *bufio.Reader) (kind, id string, data map[string]interface{}) {
	t.Helper()
	var raw string
	for {
		line, err := r.ReadString('\n')
		require.NoError(t, err)
		line = strings.TrimSuffix(line, "\n")
		if line == "" {
			if kind == "" {
				continue
			}
			require.NoError(t, json.Unmarshal([]byte(raw), &data))
			return
		}
		if strings.HasPrefix(line, "event: ") {
			kind = strings.TrimPrefix(line, "event: ")
		}
		if strings.HasPrefix(line, "id: ") {
			id = strings.TrimPrefix(line, "id: ")
		}
		if strings.HasPrefix(line, "data: ") {
			raw = strings.TrimPrefix(line, "data: ")
		}
	}
}

func feedTestServer(t *testing.T) (*httptest.Server, *http.Cookie) {
	return feedTestServerWithEvents(t, nil)
}
func feedTestServerWithEvents(t *testing.T, events RequestEventSource, configure ...func(*AdminHandler)) (*httptest.Server, *http.Cookie) {
	t.Helper()
	seedUserFields(t, "feedadmin", map[string]interface{}{"is_admin": "1"})
	cfg := bypassTestConfig()
	token := "feed-session"
	require.NoError(t, core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+token, map[string]interface{}{
		"username": "feedadmin", "status": "valid", "country": "unknown", "ip": "127.0.0.1", "user_agent": "Go-http-client/1.1", "auth_gen": mustGen(t, "feedadmin"),
	}).Err())
	encrypted, err := core.EncryptToken(token, cfg.ServerSecret)
	require.NoError(t, err)
	e := echo.New()
	h := &AdminHandler{Cfg: cfg, RequestEvents: events}
	for _, option := range configure {
		option(h)
	}
	e.GET("/rauthmgmt/live-feed", h.LiveFeed, middleware.AuthMiddleware(cfg), middleware.AdminMiddleware)
	for path, handler := range map[string]echo.HandlerFunc{"data": h.StatsData, "history": h.StatsHistory, "diagnostics": h.StatsDiagnostics, "stream": h.StatsStream, "operations": h.StatsOperations} {
		e.GET("/rauthmgmt/stats/"+path, handler, middleware.AuthMiddleware(cfg), middleware.AdminMiddleware)
	}
	srv := httptest.NewServer(e)
	t.Cleanup(srv.Close)
	return srv, &http.Cookie{Name: "X-rauth-authtoken", Value: encrypted}
}

func openFeed(t *testing.T, srv *httptest.Server, cookie *http.Cookie, cursor string, node ...string) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	t.Cleanup(cancel)
	target := srv.URL + "/rauthmgmt/live-feed"
	if len(node) > 0 {
		target += "?node=" + url.QueryEscape(node[0])
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	require.NoError(t, err)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if cursor != "" {
		req.Header.Set("Last-Event-ID", cursor)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestLiveFeedDeliveryReconnectAndReset(t *testing.T) {
	setupHandlersTest(t)
	previous := core.LiveRequests
	core.LiveRequests = core.NewRequestFeed(3)
	t.Cleanup(func() { core.LiveRequests = previous })
	srv, cookie := feedTestServer(t)
	for i := 0; i < 5; i++ {
		core.LiveRequests.Append(core.RequestEvent{URL: "https://cloud.example.com/file", Source: "127.0.0.1", Action: "bypass"})
	}
	resp := openFeed(t, srv, cookie, core.LiveRequests.Epoch()+":1")
	require.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	reader := bufio.NewReader(resp.Body)
	kind, _, _ := readFeedEvent(t, reader)
	require.Equal(t, "ready", kind)
	kind, _, data := readFeedEvent(t, reader)
	require.Equal(t, "gap", kind)
	assert.Equal(t, float64(1), data["dropped"])
	for i := 3; i <= 5; i++ {
		kind, id, data := readFeedEvent(t, reader)
		assert.Equal(t, "request", kind)
		assert.Equal(t, fmt.Sprintf("%s:%d", core.LiveRequests.Epoch(), i), id)
		assert.Equal(t, "bypass", data["action"])
	}
	core.LiveRequests.Append(core.RequestEvent{Source: "127.0.0.1", Action: "authenticated"})
	kind, id, _ := readFeedEvent(t, reader)
	assert.Equal(t, "request", kind)
	assert.True(t, strings.HasSuffix(id, ":6"))
	require.NoError(t, resp.Body.Close())
	resp = openFeed(t, srv, cookie, "old-instance:999")
	reader = bufio.NewReader(resp.Body)
	kind, _, _ = readFeedEvent(t, reader)
	assert.Equal(t, "reset", kind)
	require.NoError(t, resp.Body.Close())
}

func TestLiveFeedAccessEndsAfterSessionOrAdminRevocation(t *testing.T) {
	setupHandlersTest(t)
	for _, mode := range []string{"session", "admin", "generation"} {
		t.Run(mode, func(t *testing.T) {
			srv, cookie := feedTestServer(t)
			resp := openFeed(t, srv, cookie, "")
			require.Equal(t, 200, resp.StatusCode)
			reader := bufio.NewReader(resp.Body)
			kind, _, _ := readFeedEvent(t, reader)
			require.Equal(t, "ready", kind)
			revokedAt := time.Now()
			switch mode {
			case "session":
				require.NoError(t, core.TokenDB.Del(core.Ctx, "X-rauth-authtoken=feed-session").Err())
			case "admin":
				require.NoError(t, core.UpdateUser("feedadmin", map[string]interface{}{"is_admin": "0"}))
			case "generation":
				_, err := core.BumpAuthGeneration("feedadmin")
				require.NoError(t, err)
			}
			for {
				kind, _, _ = readFeedEvent(t, reader)
				if kind == "heartbeat" {
					continue
				}
				assert.Equal(t, "session-ended", kind)
				assert.Less(t, time.Since(revokedAt), 9*time.Second, "idle authorization rechecks must not skip the first heartbeat")
				break
			}
			require.NoError(t, resp.Body.Close())
		})
	}
}

func TestLiveFeedRequiresLiveAdministratorSession(t *testing.T) {
	setupHandlersTest(t)
	srv, cookie := feedTestServer(t)
	resp := openFeed(t, srv, nil, "")
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
	require.NoError(t, core.UpdateUser("feedadmin", map[string]interface{}{"is_admin": "0"}))
	resp = openFeed(t, srv, cookie, "")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
}

func TestFeedCursorAndConnectionBounds(t *testing.T) {
	for _, raw := range []string{"", "missing-colon", "x:-1", "x:18446744073709551616", strings.Repeat("x", 129)} {
		_, _, ok := feedCursor(raw)
		assert.False(t, ok, raw)
	}
	epoch, n, ok := feedCursor("instance:42")
	assert.True(t, ok)
	assert.Equal(t, "instance", epoch)
	assert.Equal(t, uint64(42), n)
	for i := 0; i < 3; i++ {
		require.True(t, acquireFeedStream("limit-test"))
		defer releaseFeedStream("limit-test")
	}
	assert.False(t, acquireFeedStream("limit-test"))
}

type durableFeedFixture struct {
	mu             sync.Mutex
	events         []core.RequestEvent
	latest, pruned uint64
	changed        chan struct{}
	err            error
	nodes          []string
}

func (*durableFeedFixture) Epoch() string { return "durable-epoch" }
func (f *durableFeedFixture) After(_ context.Context, cursor uint64, node string) (eventstore.Batch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return eventstore.Batch{}, f.err
	}
	f.nodes = append(f.nodes, node)
	out := eventstore.Batch{Events: []core.RequestEvent{}, Latest: f.latest, Next: f.latest, PrunedThrough: f.pruned, Changed: f.changed}
	if len(f.events) > 0 {
		out.Oldest = f.events[0].ID
	}
	for _, e := range f.events {
		if e.ID > cursor && (node == "" || e.NodeID == node) {
			out.Events = append(out.Events, e)
			if len(out.Events) == 100 {
				out.Next = e.ID
				break
			}
		}
	}
	return out, nil
}
func TestLiveFeedDurableSourceUsesProcessingNodeFilterAndSurvivesReconnect(t *testing.T) {
	setupHandlersTest(t)
	previous := core.LiveRequests
	core.LiveRequests = core.NewRequestFeed(3)
	defer func() { core.LiveRequests = previous }()
	core.LiveRequests.Append(core.RequestEvent{URL: "https://memory-only.example.test/decoy", Action: "bypass"})
	nodeA := "11111111-1111-4111-8111-111111111111"
	nodeB := "22222222-2222-4222-8222-222222222222"
	source := &durableFeedFixture{latest: 3, changed: make(chan struct{}), events: []core.RequestEvent{{ID: 1, NodeID: nodeA, NodeName: "worker-A", Kind: "decision", URL: "https://example.test/a", Source: "203.0.113.7", Action: "bypass"}, {ID: 2, NodeID: nodeB, NodeName: "worker-B", Kind: "decision", URL: "https://example.test/b", Action: "bypass"}, {ID: 3, NodeID: nodeA, NodeName: "worker-A", Kind: "decision", URL: "https://example.test/c", Action: "blocked"}}}
	srv, cookie := feedTestServerWithEvents(t, source)
	resp := openFeed(t, srv, cookie, "durable-epoch:0", nodeA)
	require.Equal(t, 200, resp.StatusCode)
	reader := bufio.NewReader(resp.Body)
	kind, _, _ := readFeedEvent(t, reader)
	require.Equal(t, "ready", kind)
	for _, want := range []string{"durable-epoch:1", "durable-epoch:3"} {
		kind, id, data := readFeedEvent(t, reader)
		require.Equal(t, "request", kind)
		require.Equal(t, want, id)
		require.Equal(t, "worker-A", data["node_name"])
		require.NotContains(t, data["url"], "memory-only")
	}
	require.NoError(t, resp.Body.Close())
	source.mu.Lock()
	source.events = append(source.events, core.RequestEvent{ID: 4, NodeID: nodeA, NodeName: "worker-A", Kind: "decision", Action: "authenticated"})
	source.latest = 4
	close(source.changed)
	source.changed = make(chan struct{})
	source.mu.Unlock()
	resp = openFeed(t, srv, cookie, "durable-epoch:3", nodeA)
	reader = bufio.NewReader(resp.Body)
	kind, _, _ = readFeedEvent(t, reader)
	require.Equal(t, "ready", kind)
	kind, id, _ := readFeedEvent(t, reader)
	require.Equal(t, "request", kind)
	require.Equal(t, "durable-epoch:4", id)
	require.NoError(t, resp.Body.Close())
	source.mu.Lock()
	defer source.mu.Unlock()
	for _, node := range source.nodes {
		require.Equal(t, nodeA, node)
	}
}
func TestLiveFeedConfiguredHistoryFailureDoesNotFallBackToMemory(t *testing.T) {
	setupHandlersTest(t)
	source := &durableFeedFixture{err: errors.New("synthetic storage failure")}
	srv, cookie := feedTestServerWithEvents(t, source)
	resp := openFeed(t, srv, cookie, "")
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NotContains(t, string(body), "synthetic")
	require.NoError(t, resp.Body.Close())
}
func TestLiveFeedForwardsDurableLossMarkersAndPruningNotice(t *testing.T) {
	setupHandlersTest(t)
	source := &durableFeedFixture{latest: 4, pruned: 2, changed: make(chan struct{}), events: []core.RequestEvent{{ID: 3, Kind: "gap", NodeName: "worker-A", UnknownLoss: true, UncleanTotal: 1}, {ID: 4, Kind: "decision", NodeName: "worker-A", Action: "bypass"}}}
	srv, cookie := feedTestServerWithEvents(t, source)
	resp := openFeed(t, srv, cookie, "durable-epoch:0")
	reader := bufio.NewReader(resp.Body)
	kind, _, _ := readFeedEvent(t, reader)
	require.Equal(t, "ready", kind)
	kind, _, data := readFeedEvent(t, reader)
	require.Equal(t, "gap", kind)
	require.Equal(t, "history_expired", data["reason"])
	kind, id, data := readFeedEvent(t, reader)
	require.Equal(t, "gap", kind)
	require.Equal(t, "durable-epoch:3", id)
	require.Equal(t, true, data["unknown_loss"])
	require.NoError(t, resp.Body.Close())
}
