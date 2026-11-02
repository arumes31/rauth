package eventrelay

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"rauth/internal/clustertransport"
	"rauth/internal/requestevent"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func event(node string) requestevent.Event {
	e := requestevent.Decision(requestevent.Event{Time: time.Now().UTC(), URL: "https://example.test/document", Source: "8.8.8.8", Country: "US", Action: "bypass", Status: 200})
	e.EventID = uuid.NewString()
	e.NodeID = node
	e.NodeName = "worker"
	return e
}

type committer struct {
	calls atomic.Int32
	write func(context.Context, string, []requestevent.Event) ([]string, error)
}

func (c *committer) Ingest(ctx context.Context, node string, events []requestevent.Event) ([]string, error) {
	c.calls.Add(1)
	if c.write != nil {
		return c.write(ctx, node, events)
	}
	ids := make([]string, len(events))
	for i, e := range events {
		ids[i] = e.EventID
	}
	return ids, nil
}
func gated(t *testing.T, node string, store Committer, scope clustertransport.Scope) http.Handler {
	t.Helper()
	cluster := uuid.NewString()
	gate, err := clustertransport.NewGate(cluster, func(context.Context, clustertransport.Peer, clustertransport.Scope) error { return nil })
	require.NoError(t, err)
	receiver := Receiver(func() Committer { return store }, map[string]bool{node: true})
	handler, err := gate.Protect(scope, receiver)
	require.NoError(t, err)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uri, _ := clustertransport.NodeURI(cluster, node)
		now := time.Now()
		leaf := &x509.Certificate{Raw: []byte("synthetic-verified-leaf"), RawSubjectPublicKeyInfo: []byte("synthetic-node-key"), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), URIs: []*url.URL{uri}}
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
		r.RemoteAddr = "100.72.1.2:1234"
		handler.ServeHTTP(w, r)
	})
}
func invoke(handler http.Handler, raw string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, request)
	return rec
}
func encoded(events []requestevent.Event) string {
	raw, _ := json.Marshal(Envelope{Schema: 1, Events: events})
	return string(raw)
}
func TestReceiverUsesAuthorizedNodeAndRejectsOversizedOrSpoofedBatches(t *testing.T) {
	node := uuid.NewString()
	store := &committer{}
	handler := gated(t, node, store, clustertransport.EventsWrite)
	good := encoded([]requestevent.Event{event(node)})
	require.Equal(t, 200, invoke(handler, good).Code)
	require.EqualValues(t, 1, store.calls.Load())
	for _, raw := range []string{encoded([]requestevent.Event{event(uuid.NewString())}), `{"schema":1,"schema":1,"events":[]}`, `{"schema":1,"events":[` + strings.Repeat(`{},`, 100) + `{}]}`, strings.Replace(good, `"url":"https://example.test/document"`, `"url":"https://example.test/document?token=secret"`, 1), strings.Replace(good, `"schema":1`, `"schema":2`, 1), good + `{}`, strings.Replace(good, `"schema":1`, `"schema":1,"cookie":"secret"`, 1)} {
		require.Equal(t, 400, invoke(handler, raw).Code)
	}
	require.EqualValues(t, 1, store.calls.Load())
	require.Equal(t, 403, invoke(Receiver(func() Committer { return store }, map[string]bool{node: true}), good).Code)
	require.Equal(t, 403, invoke(gated(t, node, store, clustertransport.StatusRead), good).Code)
}
func TestReceiverDoesNotAcknowledgeBeforeCommitAndBoundsConcurrency(t *testing.T) {
	node := uuid.NewString()
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	store := &committer{write: func(ctx context.Context, _ string, events []requestevent.Event) ([]string, error) {
		entered <- struct{}{}
		select {
		case <-release:
			ids := make([]string, len(events))
			for i, e := range events {
				ids[i] = e.EventID
			}
			return ids, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	handler := gated(t, node, store, clustertransport.EventsWrite)
	raw := encoded([]requestevent.Event{event(node)})
	var wg sync.WaitGroup
	responses := make(chan int, 4)
	for range 4 {
		wg.Go(func() { responses <- invoke(handler, raw).Code })
	}
	for range 4 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("collector did not enter")
		}
	}
	require.Empty(t, responses)
	require.Equal(t, 429, invoke(handler, raw).Code)
	close(release)
	wg.Wait()
	for range 4 {
		require.Equal(t, 200, <-responses)
	}
}
func TestReceiverFailureAndPerNodeBudget(t *testing.T) {
	node := uuid.NewString()
	store := &committer{write: func(context.Context, string, []requestevent.Event) ([]string, error) {
		return nil, errors.New("synthetic unavailable")
	}}
	handler := gated(t, node, store, clustertransport.EventsWrite)
	raw := encoded([]requestevent.Event{event(node)})
	for range 8 {
		rec := invoke(handler, raw)
		require.Equal(t, 503, rec.Code)
		require.NotContains(t, rec.Body.String(), "synthetic")
	}
	require.Equal(t, 429, invoke(handler, raw).Code)
}

type box struct {
	mu            sync.Mutex
	live, backlog []requestevent.Event
	acks          int
}

func (b *box) Pending(_ context.Context, live bool) ([]requestevent.Event, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if live {
		return append([]requestevent.Event(nil), b.live...), nil
	}
	return append([]requestevent.Event(nil), b.backlog...), nil
}
func (b *box) Acknowledge(_ context.Context, ids []string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	keep := func(events []requestevent.Event) []requestevent.Event {
		out := events[:0]
		for _, e := range events {
			found := false
			for _, id := range ids {
				found = found || id == e.EventID
			}
			if !found {
				out = append(out, e)
			}
		}
		return out
	}
	b.live = keep(b.live)
	b.backlog = keep(b.backlog)
	b.acks++
	return nil
}
func (*box) Maintain(context.Context) error { return nil }

type clientFunc func(*http.Request) (*http.Response, error)

func (f clientFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }
func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}
}
func ackFor(events []requestevent.Event) string {
	ids := make([]string, len(events))
	for i, e := range events {
		ids[i] = e.EventID
	}
	raw, _ := json.Marshal(Ack{Schema: 1, IDs: ids})
	return string(raw)
}
func TestLostAcknowledgmentRetriesSameIDsAndOnlyDeletesAfterExactAck(t *testing.T) {
	node := uuid.NewString()
	e := event(node)
	out := &box{live: []requestevent.Event{e}}
	var calls int
	committed := map[string]bool{}
	client := clientFunc(func(r *http.Request) (*http.Response, error) {
		require.Equal(t, "https://100.72.1.1:9443/v1/events", r.URL.String())
		require.Empty(t, r.Header.Get("Cookie"))
		var body Envelope
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, e.EventID, body.Events[0].EventID)
		committed[e.EventID] = true
		calls++
		if calls == 1 {
			return response(200, `{"schema":1,"ids":`), nil
		}
		return response(200, ackFor(body.Events)), nil
	})
	sender, err := NewSender(out, client, "https://100.72.1.1:9443")
	require.NoError(t, err)
	require.Error(t, sender.deliver(context.Background(), true))
	require.Zero(t, out.acks)
	require.Len(t, out.live, 1)
	require.NoError(t, sender.deliver(context.Background(), true))
	require.Empty(t, out.live)
	require.Len(t, committed, 1)
	require.True(t, sender.Status().Available)
}
func TestForeignAckAndCollectorFailureKeepOutbox(t *testing.T) {
	for _, reply := range []*http.Response{response(200, ackFor([]requestevent.Event{event(uuid.NewString())})), response(503, "unavailable"), response(200, `{"schema":1,"ids":[],"unknown":true}`)} {
		out := &box{live: []requestevent.Event{event(uuid.NewString())}}
		sender, err := NewSender(out, clientFunc(func(*http.Request) (*http.Response, error) { return reply, nil }), "https://100.72.1.1:9443")
		require.NoError(t, err)
		require.Error(t, sender.deliver(context.Background(), true))
		require.Zero(t, out.acks)
		require.Len(t, out.live, 1)
	}
}
func TestCatchupCannotBlockLiveLaneAndCancellationStopsUploads(t *testing.T) {
	old, fresh := event(uuid.NewString()), event(uuid.NewString())
	out := &box{live: []requestevent.Event{fresh}, backlog: []requestevent.Event{old}}
	blocked, live := make(chan struct{}), make(chan struct{})
	var bo, lo sync.Once
	client := clientFunc(func(r *http.Request) (*http.Response, error) {
		var body Envelope
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			return nil, ErrDelivery
		}
		if body.Events[0].EventID == old.EventID {
			bo.Do(func() { close(blocked) })
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		lo.Do(func() { close(live) })
		return response(200, ackFor(body.Events)), nil
	})
	sender, err := NewSender(out, client, "https://100.72.1.1:9443")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- sender.Run(ctx) }()
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("backlog was not sent")
	}
	select {
	case <-live:
	case <-time.After(time.Second):
		t.Fatal("blocked catchup starved live lane")
	}
	require.Error(t, sender.Run(ctx))
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("upload did not cancel")
	}
}
func TestEnvelopeArrayStopsAtBoundBeforeAllocatingAllObjects(t *testing.T) {
	raw := []byte(`{"schema":1,"events":[` + strings.Repeat(`{},`, 10000) + `{}]}`)
	reader := bytes.NewReader(raw)
	_, err := decodeEnvelope(reader)
	require.Error(t, err)
	require.Greater(t, reader.Len(), len(raw)/2)
}

type rejectingBox struct {
	box
	rejected []string
}

func (b *rejectingBox) Reject(_ context.Context, ids []string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rejected = append(b.rejected, ids...)
	keep := []requestevent.Event{}
	for _, e := range b.live {
		found := false
		for _, id := range ids {
			found = found || id == e.EventID
		}
		if !found {
			keep = append(keep, e)
		}
	}
	b.live = keep
	return nil
}
func TestPermanentRejectionIsolatesPoisonWithoutAcknowledgingIt(t *testing.T) {
	node := uuid.NewString()
	a, b, c := event(node), event(node), event(node)
	box := &rejectingBox{box: box{live: []requestevent.Event{a, b, c}}}
	committed := map[string]bool{}
	client := clientFunc(func(r *http.Request) (*http.Response, error) {
		var body Envelope
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		for _, e := range body.Events {
			if e.EventID == b.EventID {
				return response(400, "invalid"), nil
			}
		}
		for _, e := range body.Events {
			committed[e.EventID] = true
		}
		return response(200, ackFor(body.Events)), nil
	})
	sender, err := NewSender(box, client, "https://100.72.1.1:9443")
	require.NoError(t, err)
	require.NoError(t, sender.deliver(context.Background(), true))
	require.Empty(t, box.live)
	require.Equal(t, []string{b.EventID}, box.rejected)
	require.Len(t, committed, 2)
	require.NotContains(t, committed, b.EventID)
	require.EqualValues(t, 1, sender.Status().Rejected)
	for _, status := range []int{429, 503} {
		box.live = []requestevent.Event{b}
		box.rejected = nil
		sender.client = clientFunc(func(*http.Request) (*http.Response, error) { return response(status, "later"), nil })
		require.Error(t, sender.deliver(context.Background(), true))
		require.Empty(t, box.rejected)
		require.Len(t, box.live, 1)
	}
}

func TestMaximumMixedBatchCapacityRejectionNeverDiscardsDecisions(t *testing.T) {
	node := uuid.NewString()
	out := &rejectingBox{}
	kinds := map[string]string{}
	decisions := map[string]bool{}
	for i := range requestevent.MaxBatch {
		e := event(node)
		if i%10 == 0 {
			e = requestevent.Event{Kind: "telemetry", EventID: e.EventID, NodeID: e.NodeID, NodeName: e.NodeName, Time: e.Time, Metrics: &requestevent.MetricSnapshot{Schema: 1, InstanceID: uuid.NewString(), StartedAt: e.Time, Points: []requestevent.MetricPoint{}}}
		}
		require.NoError(t, requestevent.Validate(e, time.Now()))
		out.live = append(out.live, e)
		kinds[e.EventID] = e.Kind
		if e.Kind == "decision" {
			decisions[e.EventID] = true
		}
	}
	committed := map[string]bool{}
	client := clientFunc(func(r *http.Request) (*http.Response, error) {
		var body Envelope
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		for _, e := range body.Events {
			if e.Kind == "telemetry" {
				return response(400, "capacity"), nil
			}
		}
		for _, e := range body.Events {
			committed[e.EventID] = true
		}
		return response(200, ackFor(body.Events)), nil
	})
	sender, err := NewSender(out, client, "https://100.72.1.1:9443")
	require.NoError(t, err)
	for attempt := 0; attempt < 40 && len(out.live) > 0; attempt++ {
		_ = sender.deliver(context.Background(), true)
	}
	require.Empty(t, out.live, "bounded retries must eventually drain a maximum-sized mixed batch")
	require.Equal(t, decisions, committed)
	require.Len(t, out.rejected, 10)
	for _, id := range out.rejected {
		require.Equal(t, "telemetry", kinds[id], "budget exhaustion must retain decisions rather than reject them")
	}
}
