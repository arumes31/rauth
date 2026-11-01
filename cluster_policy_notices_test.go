package main

import (
	"bufio"
	"context"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"rauth/internal/clusterpolicy"
	"rauth/internal/clustertransport"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func noticeIdentity(revision int64) clusterpolicy.Identity {
	return clusterpolicy.Identity{Revision: revision, SHA256: strings.Repeat("a", 64)}
}
func TestClusterPolicyNoticesCoalesceAndBoundConnections(t *testing.T) {
	h := newPolicyNoticeHub()
	_, first := h.after()
	h.publish(noticeIdentity(2))
	select {
	case <-first:
	default:
		t.Fatal("publication did not notify")
	}
	latest, next := h.after()
	assert.Equal(t, noticeIdentity(2), latest)
	h.publish(noticeIdentity(2))
	h.publish(noticeIdentity(1))
	h.publish(clusterpolicy.Identity{Revision: 3, SHA256: "invalid"})
	select {
	case <-next:
		t.Fatal("duplicate/old/invalid publication notified")
	default:
	}
	for i := 0; i < 64; i++ {
		require.True(t, h.acquire(strconv.Itoa(i)))
	}
	assert.False(t, h.acquire("0"))
	assert.False(t, h.acquire("overflow"))
	h.release("0")
	assert.True(t, h.acquire("overflow"))
}

type noticeBody struct {
	io.Reader
	closed bool
}

func (b *noticeBody) Close() error { b.closed = true; return nil }
func TestClusterPolicyNoticeReaderRejectsInvalidAndUnboundedFrames(t *testing.T) {
	good, _ := json.Marshal(noticeIdentity(1))
	frame := "event: policy\ndata: " + string(good) + "\n\n"
	for _, tc := range []struct {
		name, body string
		want       int
		fail       bool
	}{
		{"valid", ": heartbeat\n\n" + frame, 1, false},
		{"trailing JSON", "data: " + string(good) + " {}\n", 0, true},
		{"unknown fields", "data: {\"revision\":1,\"SHA256\":\"" + strings.Repeat("a", 64) + "\",\"lease\":true}\n", 0, true},
		{"invalid identity", "data: {\"Revision\":0,\"SHA256\":\"bad\"}\n", 0, true},
		{"oversized", strings.Repeat("x", 1025) + "\n", 0, true},
		{"notice flood", strings.Repeat(frame, 65), 64, true},
		{"line flood", strings.Repeat(": keepalive\n", 257), 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &noticeBody{Reader: strings.NewReader(tc.body)}
			calls := 0
			err := readPolicyNotices(&http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: body}, func() { calls++ })
			if tc.fail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.want, calls)
			assert.True(t, body.closed)
		})
	}
	for _, status := range []int{302, 403, 503} {
		body := &noticeBody{Reader: strings.NewReader(frame)}
		assert.Error(t, readPolicyNotices(&http.Response{StatusCode: status, Header: http.Header{}, Body: body}, func() { t.Fatal("denial must not notify") }))
		assert.True(t, body.closed)
	}
}
func TestClusterPolicyNoticesStreamImmediatelyAndRecheckRevocation(t *testing.T) {
	h := newPolicyNoticeHub()
	h.publish(noticeIdentity(1))
	var revoked atomic.Bool
	authorize := func(context.Context, clustertransport.Peer, clustertransport.Scope) error {
		if revoked.Load() {
			return clustertransport.ErrDenied
		}
		return nil
	}
	assigned := map[string]bool{"8120081d-2a31-419b-9d35-1b74f373b07e": true}
	gate, err := clustertransport.NewGate("4378060a-b9ce-446b-9bd6-e4b675f84b1d", authorize)
	require.NoError(t, err)
	protected, err := gate.Protect(clustertransport.PolicyRead, policyNoticeHandler(h, authorize, assigned))
	require.NoError(t, err)
	fixture := relayPrivateRequest(t, adminRelayEnvelope{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.TLS = fixture.TLS
		r.RemoteAddr = fixture.RemoteAddr
		protected.ServeHTTP(w, r)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, 200, response.StatusCode)
	reader := bufio.NewReader(response.Body)
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		if strings.HasPrefix(line, "data: ") {
			assert.Contains(t, line, "\"revision\":1")
			break
		}
	}
	revoked.Store(true)
	h.publish(noticeIdentity(2))
	rest, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.NotContains(t, string(rest), "\"revision\":2")
}
func TestClusterPolicyNoticesRequireExactScopeAndAssignedNode(t *testing.T) {
	for _, scope := range []clustertransport.Scope{clustertransport.PolicyRead, clustertransport.AdminRelay} {
		handler := relayGateFixture(t, scope, policyNoticeHandler(newPolicyNoticeHub(), func(context.Context, clustertransport.Peer, clustertransport.Scope) error { return nil }, map[string]bool{"8120081d-2a31-419b-9d35-1b74f373b07e": scope == clustertransport.AdminRelay}))
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, relayPrivateRequest(t, adminRelayEnvelope{}))
		assert.Equal(t, 403, out.Code)
	}
}
