package eventspool

import (
	"context"
	"errors"
	"rauth/internal/requestevent"
	"sync"
	"sync/atomic"
	"time"
)

const QueueCapacity = 1024

// Async owns the bounded not-yet-durable queue. Offer never performs disk,
// network, channel waits or unbounded allocations. Stable IDs are assigned by
// the writer before the first persistence attempt and retained on every retry.
type Async struct {
	store      *Store
	queue      chan requestevent.Event
	stop, done chan struct{}
	cancel     context.CancelFunc
	mu         sync.RWMutex
	closed     bool
	overflow   atomic.Uint64
	rejected   atomic.Uint64
	available  atomic.Bool
	write      func(context.Context, []requestevent.Event) ([]string, error)
	err        error
}

func NewAsync(store *Store) (*Async, error) { return newAsync(store, QueueCapacity, nil) }
func newAsync(store *Store, capacity int, write func(context.Context, []requestevent.Event) ([]string, error)) (*Async, error) {
	if store == nil || capacity < 1 || capacity > QueueCapacity {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &Async{store: store, queue: make(chan requestevent.Event, capacity), stop: make(chan struct{}), done: make(chan struct{}), cancel: cancel, write: write}
	if a.write == nil {
		a.write = store.Append
	}
	a.available.Store(true)
	go a.run(ctx)
	return a, nil
}
func (a *Async) Offer(event requestevent.Event) bool {
	event = requestevent.Decision(event)
	event.Time = time.Now().UTC()
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return false
	}
	select {
	case a.queue <- event:
		return true
	default:
		a.overflow.Add(1)
		return false
	}
}

// OfferMetrics runs only from the background telemetry collector. Snapshot
// slices are copied before crossing the queue boundary; full queues do not wait.
func (a *Async) OfferMetrics(snapshot requestevent.MetricSnapshot) bool {
	now := time.Now().UTC()
	if requestevent.ValidateMetrics(&snapshot, now) != nil {
		return false
	}
	snapshot = snapshot.Clone()
	event := requestevent.Event{Kind: "telemetry", Time: now, Metrics: &snapshot}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return false
	}
	select {
	case a.queue <- event:
		return true
	default:
		return false
	}
}

// NoteDropped accounts for records observed before the local buffer was ready.
func (a *Async) NoteDropped(count uint64) { a.overflow.Add(count) }

func (a *Async) Available() bool          { return a.available.Load() }
func (a *Async) Queued() int              { return len(a.queue) }
func (a *Async) UncommittedDrops() uint64 { return a.overflow.Load() }
func (a *Async) run(ctx context.Context) {
	defer close(a.done)
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	var pending []requestevent.Event
	var gapCount, rejectedCount uint64
	lastMaintenance := time.Now()
	stopping := false
	for {
		if len(pending) == 0 {
			for len(pending) < requestevent.MaxBatch-2 {
				select {
				case event := <-a.queue:
					pending = append(pending, a.store.Identity(event))
				default:
					goto drained
				}
			}
		drained:
			gapCount = a.overflow.Load()
			if gapCount > 1<<40 {
				gapCount = 1 << 40
			}
			if gapCount > 0 {
				pending = append(pending, a.store.Gap("queue_overflow", gapCount))
			}
			rejectedCount = a.rejected.Load()
			if rejectedCount > 0 {
				pending = append(pending, a.store.Gap("queue_invalid", rejectedCount))
			}
		}
		if len(pending) > 0 {
			attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
			_, err := a.write(attempt, pending)
			cancel()
			a.available.Store(err == nil)
			if errors.Is(err, ErrTelemetryCapacity) {
				// Storage rejected only the optional telemetry share. Keep decision IDs and
				// loss markers unchanged; retry them without manufacturing request loss.
				previousCount := len(pending)
				keep := pending[:0]
				for _, event := range pending {
					if event.Kind != "telemetry" {
						keep = append(keep, event)
					}
				}
				pending = keep
				if len(keep) < previousCount {
					a.available.Store(true)
					continue
				}
				// A corrupt/inconsistent store must back off, not busy-loop on a
				// capacity error that did not identify any optional records.
				err = ErrUnavailable
			}

			if err == nil {
				if gapCount > 0 {
					// Subtract the committed gap count using unsigned wraparound.
					a.overflow.Add(^uint64(gapCount - 1))
				}
				if rejectedCount > 0 {
					a.rejected.Add(^uint64(rejectedCount - 1))
				}
				rejectedCount = 0
				gapCount = 0
				pending = nil
			} else if errors.Is(err, ErrInvalid) || errors.Is(err, ErrConflict) {
				// A permanently rejected batch must not poison future logging.
				// Its uncommitted overflow marker remains in the atomic total.
				var discarded uint64
				for _, e := range pending {
					if e.Kind == "decision" {
						discarded++
					}
				}
				a.rejected.Add(discarded)
				gapCount = 0
				rejectedCount = 0
				pending = nil
			}
		}
		if stopping && len(pending) == 0 && len(a.queue) == 0 && a.overflow.Load() == 0 && a.rejected.Load() == 0 {
			clean, cancel := context.WithTimeout(ctx, 2*time.Second)
			a.err = a.store.MarkClean(clean)
			cancel()
			return
		}
		if time.Since(lastMaintenance) >= time.Minute {
			maintenance, cancel := context.WithTimeout(ctx, 2*time.Second)
			err := a.store.Maintain(maintenance)
			cancel()
			if err != nil {
				a.available.Store(false)
			}
			lastMaintenance = time.Now()
		}
		if !a.available.Load() {
			retry := time.NewTimer(200 * time.Millisecond)
			select {
			case <-ctx.Done():
				retry.Stop()
				a.err = ctx.Err()
				return
			case <-retry.C:
			}
		}
		select {
		case <-ctx.Done():
			a.err = ctx.Err()
			return
		case <-a.stop:
			stopping = true
		case <-ticker.C:
		}
	}
}

// Close stops admission and drains within the caller's deadline. If persistence
// fails, cancellation leaves dirty=1 so the next start reports potential loss.
func (a *Async) Close(ctx context.Context) error {
	a.mu.Lock()
	if !a.closed {
		a.closed = true
		close(a.stop)
	}
	a.mu.Unlock()
	select {
	case <-a.done:
		a.cancel()
		return a.err
	case <-ctx.Done():
		a.cancel()
		return ctx.Err()
	}
}
