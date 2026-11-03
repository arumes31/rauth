package handlers

import (
	"bufio"
	"context"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"rauth/internal/core"
	"rauth/internal/eventstore"
)

type coldHistoryFeed struct {
	delayAt  string
	onLookup func()
	reads    atomic.Int32
	tails    atomic.Int32
	changed  chan struct{}
}

func (f *coldHistoryFeed) Epoch() string { return "cold-reader" }
func coldFeedWait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(2100 * time.Millisecond):
		return nil
	}
}
func (f *coldHistoryFeed) After(ctx context.Context, cursor uint64, _ string) (eventstore.Batch, error) {
	if f.reads.Add(1) == 1 && f.delayAt == "history" {
		if f.onLookup != nil {
			f.onLookup()
		}
		if err := coldFeedWait(ctx); err != nil {
			return eventstore.Batch{}, err
		}
	}
	batch := eventstore.Batch{Oldest: 1, Latest: 1, Next: 1, Changed: f.changed}
	if cursor == 0 {
		batch.Events = []core.RequestEvent{{ID: 1, URL: "https://example.com/cold", Source: "127.0.0.1", Action: "bypass"}}
	}
	return batch, nil
}
func (f *coldHistoryFeed) FeedStart(ctx context.Context, _ string, _ int) (uint64, error) {
	if f.tails.Add(1) == 1 && f.delayAt == "tail" {
		if f.onLookup != nil {
			f.onLookup()
		}
		if err := coldFeedWait(ctx); err != nil {
			return 0, err
		}
	}
	return 0, nil
}
func TestLiveFeedAllowsColdHistoryAndTail(t *testing.T) {
	for _, stage := range []string{"history", "tail"} {
		t.Run(stage, func(t *testing.T) {
			setupHandlersTest(t)
			events := &coldHistoryFeed{delayAt: stage, changed: make(chan struct{})}
			srv, cookie := feedTestServerWithEvents(t, events)
			response := openFeed(t, srv, cookie, "")
			defer func() { require.NoError(t, response.Body.Close()) }()
			require.Equal(t, 200, response.StatusCode)
			reader := bufio.NewReader(response.Body)
			kind, _, _ := readFeedEvent(t, reader)
			require.Equal(t, "ready", kind)
			kind, _, data := readFeedEvent(t, reader)
			require.Equal(t, "request", kind)
			require.Equal(t, "https://example.com/cold", data["url"])
		})
	}
}

func TestLiveFeedRevokedDuringColdSetupDisclosesNoEvents(t *testing.T) {
	for _, stage := range []string{"history", "tail"} {
		t.Run(stage, func(t *testing.T) {
			setupHandlersTest(t)
			revoked := make(chan error, 1)
			events := &coldHistoryFeed{delayAt: stage, changed: make(chan struct{}), onLookup: func() {
				revoked <- core.TokenDB.Del(core.Ctx, "X-rauth-authtoken=feed-session").Err()
			}}
			srv, cookie := feedTestServerWithEvents(t, events)
			response := openFeed(t, srv, cookie, "")
			defer func() { require.NoError(t, response.Body.Close()) }()
			require.NoError(t, <-revoked)
			require.Equal(t, 403, response.StatusCode)
			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			require.NotContains(t, string(body), "https://example.com/cold")
			require.False(t, strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream"))
		})
	}
}
