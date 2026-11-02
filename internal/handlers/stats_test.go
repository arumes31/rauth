package handlers

import (
	"bufio"
	"context"
	"errors"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"rauth/internal/core"
	"rauth/internal/eventstore"
	"rauth/internal/hahealth"
	"testing"
	"time"
)

type statsFixture struct {
	durableFeedFixture
	fail bool
}

func (f *statsFixture) Statistics(_ context.Context, q eventstore.StatsQuery) (eventstore.StatsSnapshot, error) {
	if f.fail {
		return eventstore.StatsSnapshot{}, errors.New("private storage details must not escape")
	}
	return eventstore.StatsSnapshot{GeneratedAt: time.Now(), Query: q, Total: 7}, nil
}
func (*statsFixture) Decisions(context.Context, eventstore.StatsQuery) ([]core.RequestEvent, error) {
	return []core.RequestEvent{{URL: "https://example.test/path", Source: "192.0.2.5", NodeID: "11111111-1111-4111-8111-111111111111", NodeName: "worker", Kind: "decision"}}, nil
}
func (*statsFixture) Diagnostics(context.Context, string) (eventstore.Diagnostics, error) {
	return eventstore.Diagnostics{Complete: true}, nil
}
func statsGet(t *testing.T, base, path string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+"/rauthmgmt/stats/"+path, nil)
	require.NoError(t, err)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	client := &http.Client{Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}
func TestStatsEndpointsRequireAdministratorAndKeepFailuresPrivate(t *testing.T) {
	setupHandlersTest(t)
	fixture := &statsFixture{}
	srv, cookie := feedTestServerWithEvents(t, fixture)
	for _, path := range []string{"data", "history", "diagnostics?node=11111111-1111-4111-8111-111111111111", "stream"} {
		resp := statsGet(t, srv.URL, path, nil)
		require.Equal(t, http.StatusFound, resp.StatusCode)
		require.NoError(t, resp.Body.Close())
	}
	resp := statsGet(t, srv.URL, "data?range=5m&node=11111111-1111-4111-8111-111111111111", cookie)
	require.Equal(t, 200, resp.StatusCode)
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"total":7`)
	require.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	require.NoError(t, resp.Body.Close())
	resp = statsGet(t, srv.URL, "data?range=forever", cookie)
	require.Equal(t, 400, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
	fixture.fail = true
	resp = statsGet(t, srv.URL, "data", cookie)
	require.Equal(t, 503, resp.StatusCode)
	raw, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "private storage")
	require.NoError(t, resp.Body.Close())
	require.NoError(t, core.UpdateUser("feedadmin", map[string]interface{}{"is_admin": "0"}))
	for _, path := range []string{"data", "history", "diagnostics", "stream"} {
		resp = statsGet(t, srv.URL, path, cookie)
		require.Equal(t, 403, resp.StatusCode)
		require.NoError(t, resp.Body.Close())
	}
}
func TestStatsStreamRechecksRevokedAdminAndSharesFeedBudget(t *testing.T) {
	setupHandlersTest(t)
	srv, cookie := feedTestServerWithEvents(t, &statsFixture{})
	resp := statsGet(t, srv.URL, "stream?range=5m", cookie)
	require.Equal(t, 200, resp.StatusCode)
	reader := bufio.NewReader(resp.Body)
	kind, _, data := readFeedEvent(t, reader)
	require.Equal(t, "stats", kind)
	require.EqualValues(t, 7, data["total"])
	require.NoError(t, core.UpdateUser("feedadmin", map[string]interface{}{"is_admin": "0"}))
	for i := 0; i < 7; i++ {
		kind, _, _ = readFeedEvent(t, reader)
		if kind == "session-ended" {
			break
		}
	}
	require.Equal(t, "session-ended", kind)
	require.NoError(t, resp.Body.Close())
	require.NoError(t, core.UpdateUser("feedadmin", map[string]interface{}{"is_admin": "1"}))
	for i := 0; i < 3; i++ {
		require.True(t, acquireFeedStream("feedadmin"))
		defer releaseFeedStream("feedadmin")
	}
	resp = statsGet(t, srv.URL, "stream", cookie)
	require.Equal(t, 429, resp.StatusCode)
}
func TestStatsConfiguredButUnavailableDoesNotUseMemoryFeed(t *testing.T) {
	setupHandlersTest(t)
	srv, cookie := feedTestServerWithEvents(t, nil)
	resp := statsGet(t, srv.URL, "data", cookie)
	require.Equal(t, 503, resp.StatusCode)
}

func TestHAOperationsRemainAdministratorOnlyAndUnavailableTelemetryIsExplicit(t *testing.T) {
	setupHandlersTest(t)
	srv, cookie := feedTestServerWithEvents(t, &statsFixture{}, func(h *AdminHandler) {
		h.ReadHAStatus = func() hahealth.View {
			return hahealth.View{Configured: true, State: "unavailable", Fencing: "not_observed"}
		}
	})
	anonymous := statsGet(t, srv.URL, "operations", nil)
	require.Equal(t, 302, anonymous.StatusCode)
	require.NoError(t, anonymous.Body.Close())
	response := statsGet(t, srv.URL, "operations", cookie)
	require.Equal(t, 200, response.StatusCode)
	raw, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"ha_observation":{"configured":true`)
	require.Contains(t, string(raw), `"state":"unavailable"`)
	require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
	require.NoError(t, response.Body.Close())
	require.NoError(t, core.UpdateUser("feedadmin", map[string]interface{}{"is_admin": "0"}))
	denied := statsGet(t, srv.URL, "operations", cookie)
	require.Equal(t, 403, denied.StatusCode)
}
