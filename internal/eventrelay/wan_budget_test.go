package eventrelay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"rauth/internal/clustertransport"
	"rauth/internal/requestevent"
)

func TestReceiverAllowsWANCommitAndHonorsParentCancellation(t *testing.T) {
	node := uuid.NewString()
	e := event(node)
	store := &committer{write: func(ctx context.Context, _ string, events []requestevent.Event) ([]string, error) {
		select {
		case <-time.After(3100 * time.Millisecond):
			return []string{events[0].EventID}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	handler := gated(t, node, store, clustertransport.EventsWrite)
	require.Equal(t, http.StatusOK, invoke(handler, encoded([]requestevent.Event{e})).Code, "a committed WAN upload must survive the former three-second limit")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(encoded([]requestevent.Event{event(node)}))).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	started := time.Now()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.Less(t, time.Since(started), time.Second, "the larger event budget must not ignore caller cancellation")
	require.NotContains(t, rec.Body.String(), e.EventID, "failed commit must not acknowledge an event")
}

func TestSenderWaitsForWANCommitAndRetainsCanceledUpload(t *testing.T) {
	node := uuid.NewString()
	e := event(node)
	out := &box{live: []requestevent.Event{e}}
	client := clientFunc(func(r *http.Request) (*http.Response, error) {
		select {
		case <-time.After(5100 * time.Millisecond):
			return response(http.StatusOK, ackFor([]requestevent.Event{e})), nil
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	})
	sender, err := NewSender(out, client, "https://100.72.1.1:9443")
	require.NoError(t, err)
	require.NoError(t, sender.deliver(context.Background(), true), "sender must await a WAN commit beyond the former five-second limit")
	require.Empty(t, out.live)
	out.live = []requestevent.Event{e}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	require.Error(t, sender.deliver(ctx, true))
	require.Less(t, time.Since(started), time.Second)
	require.Len(t, out.live, 1, "cancellation must keep the durable upload pending")
	require.Equal(t, e.EventID, out.live[0].EventID)
}
