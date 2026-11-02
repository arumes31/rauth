// Package eventrelay delivers local durable outboxes over the existing private
// node transport. Failures never participate in authentication admission.
package eventrelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"rauth/internal/clustertransport"
	"rauth/internal/eventstore"
	"rauth/internal/requestevent"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

const MaxBody = 1 << 20

var ErrDelivery = errors.New("event delivery unavailable")

type Envelope struct {
	Schema int                  `json:"schema"`
	Events []requestevent.Event `json:"events"`
}
type Ack struct {
	Schema int      `json:"schema"`
	IDs    []string `json:"ids"`
}
type Committer interface {
	Ingest(context.Context, string, []requestevent.Event) ([]string, error)
}

// Receiver is reached only through Gate.Protect(EventsWrite). Node identity is
// taken from its authorization context, never a submitted header/body claim.
func Receiver(current func() Committer, assigned map[string]bool) http.Handler {
	known := map[string]bool{}
	for id, enabled := range assigned {
		if enabled && requestevent.ValidID(id) {
			known[id] = true
		}
	}
	slots := make(chan struct{}, 4)
	var mu sync.Mutex
	type budget struct {
		at   time.Time
		used int
	}
	budgets := map[string]budget{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, ok := clustertransport.PeerForScope(r.Context(), clustertransport.EventsWrite)
		if !ok || !known[peer.NodeID] {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "Invalid events", http.StatusBadRequest)
			return
		}
		mu.Lock()
		now := time.Now()
		b := budgets[peer.NodeID]
		if now.Sub(b.at) >= time.Second || b.at.IsZero() {
			b = budget{at: now}
		}
		allowed := b.used < 8
		if allowed {
			b.used++
			budgets[peer.NodeID] = b
		}
		mu.Unlock()
		if !allowed {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Event upload budget exceeded", http.StatusTooManyRequests)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Event collector busy", http.StatusTooManyRequests)
			return
		}
		collector := current()
		if collector == nil {
			w.Header().Set("Retry-After", "2")
			http.Error(w, "Event collector unavailable", http.StatusServiceUnavailable)
			return
		}
		body, decodeErr := decodeEnvelope(http.MaxBytesReader(w, r.Body, MaxBody))
		if decodeErr != nil {
			http.Error(w, "Invalid events", http.StatusBadRequest)
			return
		}
		for _, event := range body.Events {
			if event.NodeID != peer.NodeID || requestevent.Validate(event, time.Now()) != nil {
				http.Error(w, "Invalid events", http.StatusBadRequest)
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		ids, err := collector.Ingest(ctx, peer.NodeID, body.Events)
		switch {
		case errors.Is(err, eventstore.ErrInvalid):
			http.Error(w, "Invalid events", http.StatusBadRequest)
			return
		case errors.Is(err, eventstore.ErrConflict):
			http.Error(w, "Event identity conflict", http.StatusConflict)
			return
		case err != nil:
			w.Header().Set("Retry-After", "2")
			http.Error(w, "Event collector unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(Ack{Schema: 1, IDs: ids})
	})
}

type Outbox interface {
	Pending(context.Context, bool) ([]requestevent.Event, error)
	Acknowledge(context.Context, []string) error
	Maintain(context.Context) error
}
type Client interface {
	Do(*http.Request) (*http.Response, error)
}
type Sender struct {
	box                           Outbox
	client                        Client
	endpoint                      string
	running                       atomic.Bool
	failed                        atomic.Bool
	acknowledged                  atomic.Uint64
	lastSuccess                   atomic.Int64
	rejected                      atomic.Uint64
	liveInterval, catchupInterval time.Duration
}
type DeliveryStatus struct {
	Available            bool      `json:"available"`
	Rejected             uint64    `json:"rejected"`
	AcknowledgedAttempts uint64    `json:"acknowledged_attempts"`
	LastSuccess          time.Time `json:"last_success,omitempty"`
}

func NewSender(box Outbox, client Client, endpoint string) (*Sender, error) {
	if box == nil || client == nil {
		return nil, ErrDelivery
	}
	if _, err := clustertransport.PrivateEndpoint(endpoint); err != nil {
		return nil, ErrDelivery
	}
	return &Sender{box: box, client: client, endpoint: endpoint, liveInterval: 250 * time.Millisecond, catchupInterval: time.Second}, nil
}
func (s *Sender) Status() DeliveryStatus {
	at := s.lastSuccess.Load()
	out := DeliveryStatus{Available: at > 0 && !s.failed.Load(), AcknowledgedAttempts: s.acknowledged.Load(), Rejected: s.rejected.Load()}
	if at > 0 {
		out.LastSuccess = time.Unix(0, at).UTC()
	}
	return out
}
func (s *Sender) Run(ctx context.Context) error {
	if !s.running.CompareAndSwap(false, true) {
		return ErrDelivery
	}
	var wg sync.WaitGroup
	lane := func(live bool, interval time.Duration) {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if ctx.Err() != nil {
				return
			}
			_ = s.deliver(ctx, live)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}
	wg.Go(func() { lane(true, s.liveInterval) })
	wg.Go(func() { lane(false, s.catchupInterval) })
	maintenance := time.NewTicker(time.Minute)
	defer maintenance.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil
		case <-maintenance.C:
			check, cancel := context.WithTimeout(ctx, 2*time.Second)
			_ = s.box.Maintain(check)
			cancel()
		}
	}
}
func (s *Sender) deliver(parent context.Context, live bool) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	events, err := s.box.Pending(ctx, live)
	if err != nil {
		s.failed.Store(true)
		return ErrDelivery
	}
	if len(events) == 0 {
		return nil
	}
	if len(events) > requestevent.MaxBatch {
		s.failed.Store(true)
		return ErrDelivery
	}
	budget := 8
	err = s.send(ctx, events, &budget)
	s.failed.Store(err != nil)
	return err
}
func (s *Sender) send(ctx context.Context, events []requestevent.Event, budget *int) error {
	if ctx.Err() != nil || *budget <= 0 {
		return ErrDelivery
	}
	*budget--
	payload, err := json.Marshal(Envelope{Schema: 1, Events: events})
	if err != nil || len(payload) > MaxBody {
		s.failed.Store(true)
		return ErrDelivery
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint+"/v1/events", bytes.NewReader(payload))
	if err != nil {
		return ErrDelivery
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		s.failed.Store(true)
		return ErrDelivery
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 2048))
		if response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusConflict {
			// Close this response before recursive uploads; keep retryable failures intact.
			_ = response.Body.Close()
			if len(events) > 1 {
				mid := len(events) / 2
				left := s.send(ctx, events[:mid], budget)
				right := s.send(ctx, events[mid:], budget)
				if left != nil || right != nil {
					return ErrDelivery
				}
				return nil
			}
			rejector, ok := s.box.(interface {
				Reject(context.Context, []string) error
			})
			if !ok || events[0].Kind == "gap" {
				return ErrDelivery
			}
			if rejector.Reject(ctx, []string{events[0].EventID}) != nil {
				return ErrDelivery
			}
			s.rejected.Add(1)
			return nil
		}
		s.failed.Store(true)
		return ErrDelivery
	}
	var ack Ack
	decoder := json.NewDecoder(io.LimitReader(response.Body, 16<<10))
	decoder.DisallowUnknownFields()
	expected := make([]string, len(events))
	for i, e := range events {
		expected[i] = e.EventID
	}
	if decoder.Decode(&ack) != nil || decoder.Decode(new(any)) != io.EOF || ack.Schema != 1 || !slices.Equal(ack.IDs, expected) {
		s.failed.Store(true)
		return ErrDelivery
	}
	if s.box.Acknowledge(ctx, ack.IDs) != nil {
		s.failed.Store(true)
		return ErrDelivery
	}
	s.failed.Store(false)
	s.lastSuccess.Store(time.Now().UnixNano())
	s.acknowledged.Add(uint64(len(events)))
	return nil
}

// Decode the array incrementally. A byte limit alone would still permit hundreds
// of thousands of tiny objects to allocate a large []Event before len checking.
func decodeEnvelope(reader io.Reader) (Envelope, error) {
	var out Envelope
	d := json.NewDecoder(reader)
	d.DisallowUnknownFields()
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return out, ErrDelivery
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return out, ErrDelivery
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return out, ErrDelivery
		}
		seen[name] = true
		switch name {
		case "schema":
			if d.Decode(&out.Schema) != nil {
				return out, ErrDelivery
			}
		case "events":
			token, err = d.Token()
			if err != nil || token != json.Delim('[') {
				return out, ErrDelivery
			}
			for d.More() {
				if len(out.Events) >= requestevent.MaxBatch {
					return out, ErrDelivery
				}
				var raw json.RawMessage
				if d.Decode(&raw) != nil || len(raw) > requestevent.MaxEventBytes {
					return out, ErrDelivery
				}
				var event requestevent.Event
				ed := json.NewDecoder(bytes.NewReader(raw))
				ed.DisallowUnknownFields()
				if ed.Decode(&event) != nil || ed.Decode(new(any)) != io.EOF {
					return out, ErrDelivery
				}
				out.Events = append(out.Events, event)
			}
			token, err = d.Token()
			if err != nil || token != json.Delim(']') {
				return out, ErrDelivery
			}
		default:
			return out, ErrDelivery
		}
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') || d.Decode(new(any)) != io.EOF || !seen["schema"] || !seen["events"] || out.Schema != 1 || len(out.Events) == 0 {
		return out, ErrDelivery
	}
	return out, nil
}
