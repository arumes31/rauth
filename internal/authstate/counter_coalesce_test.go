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
}

func (f *fakeCounter) add(_ context.Context, h []byte, _ time.Duration, n int64) (int64, error) {
	f.calls.Add(1)
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
	f := &fakeCounter{delay: 20 * time.Millisecond}
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
	if c := f.calls.Load(); c >= 200 || c > 10 {
		t.Fatalf("burst used %d statements; expected coalescing into a handful", c)
	}
	if len(co.open) != 0 || len(co.busy) != 0 {
		t.Fatalf("coalescer leaked state: open=%d busy=%d", len(co.open), len(co.busy))
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
	// The abandoned increment may still have been applied (stricter, never looser).
	if slices.Max(got) < 10 || slices.Max(got) > 11 {
		t.Fatalf("unexpected counts after a canceled caller: %v", got)
	}
}
