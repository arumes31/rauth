// Package clusterworker coordinates durable policy storage, compilation and
// request admission. It does not enroll nodes or wire application HTTP routes.
package clusterworker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"rauth/internal/clusterpolicy"
	"rauth/internal/clusterstate"
	"sync"
	"time"
)

var ErrClosed = errors.New("policy worker is closed")
var ErrStarted = errors.New("policy worker reconciliation already started")

// Authority must read the HA write leader independently of the controller.
// Current must honor its context and return exact signed bytes. Blob/manifest
// reads do not renew freshness and must use separate connection budgets.
type Authority interface {
	Current(context.Context) (clusterstate.Head, error)
	OpenBlob(context.Context, clusterpolicy.Identity, clusterpolicy.Blob) (io.ReadCloser, error)
}

// Compiler stages privately. Finish transfers resource ownership only on success;
// Close always releases any untransferred resources, including after validation
// failure. Neither method may mutate application globals. Value is immutable.
type Compiler[T io.Closer] interface {
	Validate(clusterpolicy.Blob, io.Reader) error
	Finish(clusterpolicy.VerifiedBundle) (T, error)
	Close() error
}
type snapshot[T io.Closer] struct {
	bundle clusterpolicy.VerifiedBundle
	value  T
	refs   int // includes one active-owner reference; guarded by Worker.mu
}
type Worker[T io.Closer] struct {
	mu          sync.Mutex
	checkMu     sync.Mutex
	stageMu     sync.Mutex
	closeOnce   sync.Once
	store       *clusterpolicy.Store
	verifier    *clusterpolicy.Verifier
	freshness   *clusterpolicy.Freshness
	source      Authority
	factory     func() Compiler[T]
	active      *snapshot[T]
	desired     clusterstate.Head
	stageCancel context.CancelFunc
	stageID     clusterpolicy.Identity
	wake        chan struct{}
	hints       chan struct{}
	interval    time.Duration
	started     bool
	closed      bool
	cancel      context.CancelFunc
	done        chan struct{}
	closeErr    error
	headErr     error
	stageErr    error
}
type Status struct {
	Policy       clusterpolicy.Status
	HeadError    error
	StageError   error
	CleanupError error
}

// New opens an existing mount-guarded private Linux host root and verifies its
// active cache. A restart never restores a persisted lease; it starts unready.
// The caller still must verify the physical mount before invoking this method.
func New[T io.Closer](root string, v *clusterpolicy.Verifier, source Authority, factory func() Compiler[T], lease time.Duration) (*Worker[T], error) {
	if source == nil || factory == nil {
		return nil, clusterpolicy.ErrInvalid
	}
	store, err := clusterpolicy.OpenStore(root, v)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (*Worker[T], error) { _ = store.Close(); return nil, e }
	state, err := store.State()
	if err != nil {
		return fail(err)
	}
	freshness, err := clusterpolicy.NewFreshness(v, state.HighWater, lease)
	if err != nil {
		return fail(err)
	}
	w := &Worker[T]{store: store, verifier: v, freshness: freshness, source: source, factory: factory, wake: make(chan struct{}, 1), hints: make(chan struct{}, 1), interval: clusterpolicy.HeadCheckInterval, done: make(chan struct{})}
	// A cache below its durable watermark cannot authorize and will be replaced.
	if state.Active != (clusterpolicy.Identity{}) && state.Active == state.HighWater {
		compiler := factory()
		if compiler == nil {
			return fail(clusterpolicy.ErrInvalid)
		}
		bundle, e := store.LoadActive(compiler.Validate)
		if e != nil {
			w.stageErr = errors.Join(e, compiler.Close())
			return w, nil // retained watermark + unready runtime can reconcile
		}
		value, e := compiler.Finish(bundle)
		closeErr := compiler.Close()
		if e != nil {
			w.stageErr = errors.Join(e, closeErr)
			return w, nil
		}
		if closeErr != nil {
			_ = value.Close()
			w.stageErr = closeErr
			return w, nil
		}
		if e = freshness.Restore(bundle); e != nil {
			_ = value.Close()
			w.stageErr = e
			return w, nil
		}
		w.active = &snapshot[T]{bundle: bundle, value: value, refs: 1}
	}
	return w, nil
}
func (w *Worker[T]) reportHead(err error)  { w.mu.Lock(); w.headErr = err; w.mu.Unlock() }
func (w *Worker[T]) reportStage(err error) { w.mu.Lock(); w.stageErr = err; w.mu.Unlock() }

// check serializes head observations, but never waits for payload staging.
func (w *Worker[T]) check(ctx context.Context) error {
	w.checkMu.Lock()
	defer w.checkMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	current, err := w.source.Current(ctx)
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		if errors.Is(err, clusterstate.ErrNoHead) || errors.Is(err, clusterstate.ErrCorrupt) || errors.Is(err, clusterpolicy.ErrInvalid) {
			w.freshness.Invalidate()
		} else {
			w.freshness.HeadUnavailable()
		}
		w.reportHead(err)
		return err
	}
	head, err := w.verifier.Verify(current.Envelope)
	if err != nil || head.Identity() != current.Verified.Identity() {
		w.freshness.Invalidate()
		w.reportHead(clusterpolicy.ErrInvalid)
		return clusterpolicy.ErrInvalid
	}
	// Observe before disk I/O: a new policy withdraws old admission immediately.
	if err = w.freshness.ObserveHead(head); err != nil {
		// ObserveHead clears its lease on every rollback/equivocation rejection.
		w.reportHead(err)
		return err
	}
	if err = w.store.RecordHead(head); err != nil {
		w.freshness.Invalidate()
		w.reportHead(err)
		return err
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return ErrClosed
	}
	w.headErr = nil
	if w.desired.Verified.Identity() != head.Identity() && w.stageCancel != nil {
		w.stageCancel()
	}
	w.desired = clusterstate.Head{Verified: head, Envelope: bytes.Clone(current.Envelope)}
	if w.active != nil && w.active.bundle.Identity() == head.Identity() {
		err = w.freshness.Activate(w.active.bundle)
		w.mu.Unlock()
		return err
	}
	w.mu.Unlock()
	select {
	case w.wake <- struct{}{}:
	default:
	}
	return nil
}
func (w *Worker[T]) apply(ctx context.Context) error {
	w.stageMu.Lock()
	defer w.stageMu.Unlock()
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return ErrClosed
	}
	wanted := w.desired
	if wanted.Verified.Identity() == (clusterpolicy.Identity{}) {
		w.mu.Unlock()
		return clusterstate.ErrNoHead
	}
	if w.active != nil && w.active.bundle.Identity() == wanted.Verified.Identity() {
		w.mu.Unlock()
		return nil
	}
	stageCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	w.stageID = wanted.Verified.Identity()
	w.stageCancel = cancel
	w.mu.Unlock()
	defer func() {
		cancel()
		w.mu.Lock()
		w.stageCancel = nil
		w.stageID = clusterpolicy.Identity{}
		w.mu.Unlock()
	}()
	compiler := w.factory()
	if compiler == nil {
		return clusterpolicy.ErrInvalid
	}
	closeCompiler := sync.OnceValue(compiler.Close)
	defer func() { _ = closeCompiler() }()
	bundle, err := w.store.Stage(stageCtx, wanted.Envelope, func(fetchCtx context.Context, b clusterpolicy.Blob) (io.ReadCloser, error) {
		return w.source.OpenBlob(fetchCtx, wanted.Verified.Identity(), b)
	}, compiler.Validate)
	if err != nil {
		return err
	}
	value, err := compiler.Finish(bundle)
	if err != nil {
		return err
	}
	// Finish transfers ownership; every failure below retires this unused value.
	if err = closeCompiler(); err != nil {
		_ = value.Close()
		return err
	}
	if err = w.store.Activate(bundle); err != nil {
		_ = value.Close()
		return err
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		_ = value.Close()
		return ErrClosed
	}
	if err = w.freshness.Activate(bundle); err != nil {
		w.mu.Unlock()
		_ = value.Close()
		return err
	}
	old := w.active
	w.active = &snapshot[T]{bundle: bundle, value: value, refs: 1}
	w.stageErr = nil
	closeOld := false
	if old != nil {
		old.refs--
		closeOld = old.refs == 0
	}
	w.mu.Unlock()
	if closeOld {
		_ = old.value.Close()
	}
	return nil
}

// WithPolicy pins the exact fresh immutable generation for the whole callback.
// Do not retain Value/resources after returning or mutate its contents. Old
// readers (e.g. GeoIP) close only when every in-flight callback releases them.
func (w *Worker[T]) WithPolicy(use func(T) error) error {
	if use == nil {
		return clusterpolicy.ErrInvalid
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return ErrClosed
	}
	current := w.active
	if current == nil || !w.freshness.Status(current.bundle).Ready {
		w.mu.Unlock()
		return clusterpolicy.ErrNotCurrent
	}
	current.refs++
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		current.refs--
		closeValue := current.refs == 0
		w.mu.Unlock()
		if closeValue {
			_ = current.value.Close()
		}
	}()
	return use(current.value)
}
func (w *Worker[T]) Status() Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	bundle := clusterpolicy.VerifiedBundle{}
	if w.active != nil {
		bundle = w.active.bundle
	}
	return Status{Policy: w.freshness.Status(bundle), HeadError: w.headErr, StageError: w.stageErr, CleanupError: w.store.CleanupError()}
}

// Run has independent head-check and staging loops. Source/callbacks must honor
// cancellation. Normal shutdown invalidates readiness immediately. Run once;
// Close subsequently releases the cache and owner reference without closing a
// value still pinned by a request.
func (w *Worker[T]) Run(parent context.Context) error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return ErrClosed
	}
	if w.started {
		w.mu.Unlock()
		return ErrStarted
	}
	ctx, cancel := context.WithCancel(parent)
	w.cancel = cancel
	w.started = true
	w.mu.Unlock()
	defer func() { cancel(); w.freshness.Invalidate(); close(w.done) }()
	var loops sync.WaitGroup
	loops.Add(2)
	go func() {
		defer loops.Done()
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()
		for {
			_ = w.check(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-w.hints:
				// Coalesce notifications and cap their extra SQL-read budget.
				timer := time.NewTimer(time.Second)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-ticker.C:
				case <-timer.C:
				}
				timer.Stop()
			}
		}
	}()
	go func() {
		defer loops.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-w.wake:
				if err := w.apply(ctx); err != nil && !errors.Is(err, context.Canceled) {
					w.reportStage(err)
				}
			}
		}
	}()
	<-ctx.Done()
	w.freshness.Invalidate()
	loops.Wait()
	return ctx.Err()
}
func (w *Worker[T]) Close() error {
	w.closeOnce.Do(func() {
		w.mu.Lock()
		w.closed = true
		cancel := w.cancel
		started := w.started
		w.mu.Unlock()
		w.freshness.Invalidate()
		if cancel != nil {
			cancel()
		}
		if started {
			<-w.done
		}
		// A synchronous apply/check used before Run must finish before cache closure.
		w.checkMu.Lock()
		defer w.checkMu.Unlock()
		w.stageMu.Lock()
		defer w.stageMu.Unlock()
		w.closeErr = w.store.Close()
		w.mu.Lock()
		old := w.active
		w.active = nil
		closeOld := false
		if old != nil {
			old.refs--
			closeOld = old.refs == 0
		}
		w.mu.Unlock()
		if closeOld {
			w.closeErr = errors.Join(w.closeErr, old.value.Close())
		}
	})
	return w.closeErr
}

// Notify is only a coalesced hint, never a lease renewal or trusted policy head.
// The head loop re-reads the HA authority, with a one-second notification budget.
func (w *Worker[T]) Notify() {
	select {
	case w.hints <- struct{}{}:
	default:
	}
}
