package authstate

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeCounter mimics the SQL statement: one row per key, each call adds n.
type fakeCounter struct {
	mu    sync.Mutex
	rows  map[string]int64
	calls atomic.Int64
	delay time.Duration
	err   error
	// gate, when set, holds the first statement until it is closed.
	gate chan struct{}
	cap  int64
	// first is the batch size of the first statement (set before it blocks).
	first atomic.Int64
}

func (f *fakeCounter) add(_ context.Context, h []byte, _ time.Duration, n int64) (int64, error) {
	if f.calls.Add(1) == 1 {
		f.first.Store(n)
		if f.gate != nil {
			<-f.gate
		}
	}
	time.Sleep(f.delay)
	if f.err != nil {
		return 0, f.err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rows == nil {
		f.rows = map[string]int64{}
	}
	f.rows[string(h)] += n
	if f.cap > 0 && f.rows[string(h)] > f.cap {
		f.rows[string(h)] = f.cap
	}
	return f.rows[string(h)], nil
}

func burst(t *testing.T, co *counterCoalescer, f *fakeCounter, key string, n int) []int64 {
	t.Helper()
	got := make([]int64, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { got[i], errs[i] = co.increment(context.Background(), []byte(key), time.Minute, f.add) })
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("increment failed: %v", err)
		}
	}
	return got
}

func TestCounterCoalescerBurstKeepsExactDistinctCounts(t *testing.T) {
	var co counterCoalescer
	f := &fakeCounter{gate: make(chan struct{})}
	go func() {
		// Release the first statement only after every caller is accounted
		// for: in the blocked first statement or in the one open batch behind
		// it (the first statement may already hold several callers).
		for {
			co.mu.Lock()
			joined := int64(0)
			if b := co.open["ip\x00"+time.Minute.String()]; b != nil {
				joined = b.n
			}
			co.mu.Unlock()
			if first := f.first.Load(); first > 0 && first+joined == 200 {
				close(f.gate)
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	got := burst(t, &co, f, "ip", 200)
	slices.Sort(got)
	for i, v := range got {
		if v != int64(i+1) {
			t.Fatalf("counts are not exactly 1..200: position %d has %d", i, v)
		}
	}
	if f.rows["ip"] != 200 {
		t.Fatalf("stored total %d, want 200", f.rows["ip"])
	}
	if c := f.calls.Load(); c != 2 {
		t.Fatalf("burst used %d statements; want 2 (the first statement, then one batch)", c)
	}
	// Callers return as soon as their batch is done; the flush loop drops its
	// bookkeeping a moment later, so wait for that under the lock.
	deadline := time.Now().Add(2 * time.Second)
	for {
		co.mu.Lock()
		open, busy := len(co.open), len(co.busy)
		co.mu.Unlock()
		if open == 0 && busy == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("coalescer leaked state: open=%d busy=%d", open, busy)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCounterCoalescerKeepsCountersIndependent(t *testing.T) {
	var co counterCoalescer
	f := &fakeCounter{delay: 5 * time.Millisecond}
	var wg sync.WaitGroup
	var a, b []int64
	wg.Go(func() { a = burst(t, &co, f, "a", 50) })
	wg.Go(func() { b = burst(t, &co, f, "b", 30) })
	wg.Wait()
	if slices.Max(a) != 50 || slices.Max(b) != 30 || f.rows["a"] != 50 || f.rows["b"] != 30 {
		t.Fatalf("counters mixed: max a=%d b=%d rows=%v", slices.Max(a), slices.Max(b), f.rows)
	}
	// Same key with a different duration is a different statement and must not merge.
	if _, err := co.increment(context.Background(), []byte("a"), time.Hour, f.add); err != nil {
		t.Fatal(err)
	}
}

func TestCounterCoalescerFailsClosedForEveryJoinedCaller(t *testing.T) {
	var co counterCoalescer
	boom := errors.New("database unavailable")
	f := &fakeCounter{delay: 10 * time.Millisecond, err: boom}
	var wg sync.WaitGroup
	var failures atomic.Int64
	for range 40 {
		wg.Go(func() {
			if _, err := co.increment(context.Background(), []byte("k"), time.Minute, f.add); errors.Is(err, boom) {
				failures.Add(1)
			}
		})
	}
	wg.Wait()
	if failures.Load() != 40 {
		t.Fatalf("%d of 40 callers saw the error; all must fail closed", failures.Load())
	}
}

func TestCounterCoalescerCanceledCallerDoesNotFailOthers(t *testing.T) {
	var co counterCoalescer
	f := &fakeCounter{delay: 30 * time.Millisecond}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := co.increment(canceled, []byte("k"), time.Minute, f.add); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled caller: got %v", err)
	}
	got := burst(t, &co, f, "k", 10)
	// A request canceled before joining is never enqueued.
	if slices.Max(got) != 10 || f.rows["k"] != 10 {
		t.Fatalf("pre-canceled request was counted: max=%d stored=%d", slices.Max(got), f.rows["k"])
	}
}

func TestCounterCoalescerSaturatedBatchNeverReportsBelowStoredCount(t *testing.T) {
	var co counterCoalescer
	f := &fakeCounter{delay: 10 * time.Millisecond, cap: counterCap, rows: map[string]int64{"k": counterCap - 1}}
	got := burst(t, &co, f, "k", 20)
	for _, v := range got {
		if v < counterCap-1 || v > counterCap {
			t.Fatalf("saturated counter reported %d; must stay within [cap-1, cap]: %v", v, got)
		}
	}
	if slices.Max(got) != counterCap {
		t.Fatalf("expected the cap to be reached: %v", got)
	}
}

func TestCounterCoalescerBoundsWaitBehindStalledStatement(t *testing.T) {
	co := counterCoalescer{wait: 50 * time.Millisecond}
	f := &fakeCounter{gate: make(chan struct{})}
	defer close(f.gate)
	start := time.Now()
	var wg sync.WaitGroup
	errs := make([]error, 5)
	for i := range errs {
		wg.Go(func() { _, errs[i] = co.increment(context.Background(), []byte("k"), time.Minute, f.add) })
	}
	wg.Wait()
	for _, err := range errs {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("stalled statement: got %v, want fail-closed deadline", err)
		}
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("callers waited %v behind a stalled statement; want one wait budget", d)
	}
}
