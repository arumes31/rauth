package eventspool

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"rauth/internal/requestevent"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

var background = context.Background()

func options() Options {
	return Options{ClusterID: uuid.NewString(), NodeID: uuid.NewString(), NodeName: "test-node", MaxBytes: 16 << 20, MaxAge: 24 * time.Hour}
}
func directory(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("host persistence guards require Linux")
	}
	root := t.TempDir()
	require.NoError(t, os.Chmod(root, 0o700))
	return root
}
func open(t *testing.T, root string, o Options) *Store {
	t.Helper()
	s, err := Open(background, root, o)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	return s
}
func decision() requestevent.Event {
	return requestevent.Decision(requestevent.Event{Time: time.Now().UTC(), URL: "https://example.com/document", Source: "192.0.2.1", Country: "US", Action: "authenticated", Status: 200})
}
func pending(t *testing.T, s *Store) []requestevent.Event {
	t.Helper()
	a, err := s.Pending(background, true)
	require.NoError(t, err)
	b, err := s.Pending(background, false)
	require.NoError(t, err)
	return append(a, b...)
}
func TestRestartStableRetryExactAckAndUnknownLoss(t *testing.T) {
	root := directory(t)
	o := options()
	s := open(t, root, o)
	e := s.Identity(decision())
	_, err := s.Append(background, []requestevent.Event{e})
	require.NoError(t, err)
	require.NoError(t, s.Close())
	s = open(t, root, o)
	events := pending(t, s)
	require.Len(t, events, 2)
	require.Equal(t, e.EventID, events[0].EventID)
	require.True(t, events[1].UnknownLoss)
	_, err = s.Append(background, []requestevent.Event{e})
	require.NoError(t, err)
	require.Len(t, pending(t, s), 2)
	altered := e
	altered.Status = 403
	_, err = s.Append(background, []requestevent.Event{altered})
	require.ErrorIs(t, err, ErrConflict)
	require.NoError(t, s.Acknowledge(background, []string{e.EventID}))
	require.NoError(t, s.Acknowledge(background, []string{e.EventID}))
	require.Len(t, pending(t, s), 1)
	require.NoError(t, s.MarkClean(background))
	require.NoError(t, s.Close())
	s = open(t, root, o)
	require.Len(t, pending(t, s), 1)
}
func TestRetentionGapAndPersistentDropCounter(t *testing.T) {
	s := open(t, directory(t), options())
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	e := s.Identity(decision())
	_, err := s.Append(background, []requestevent.Event{e})
	require.NoError(t, err)
	now = now.Add(25 * time.Hour)
	require.NoError(t, s.Maintain(background))
	events := pending(t, s)
	require.Len(t, events, 1)
	require.Equal(t, "storage_retention", events[0].Reason)
	require.EqualValues(t, 1, events[0].Dropped)
	st, err := s.Status(background)
	require.NoError(t, err)
	require.EqualValues(t, 1, st.Dropped)
	require.EqualValues(t, 1, st.Pending)
}
func TestPrivateHostGuardsNoFallbackOrSharedWriter(t *testing.T) {
	root := directory(t)
	o := options()
	_, err := Open(background, filepath.Join(root, "missing"), o)
	require.ErrorIs(t, err, ErrUnsafe)
	_, err = os.Stat(filepath.Join(root, "missing"))
	require.True(t, os.IsNotExist(err))
	target := directory(t)
	link := filepath.Join(root, "link")
	require.NoError(t, os.Symlink(target, link))
	_, err = Open(background, link, o)
	require.ErrorIs(t, err, ErrUnsafe)
	s := open(t, target, o)
	_, err = Open(background, target, o)
	require.ErrorIs(t, err, ErrUnavailable)
	require.NoError(t, s.Close())
	require.NoError(t, os.Chmod(filepath.Join(target, "spool.db"), 0o644))
	_, err = Open(background, target, o)
	require.Error(t, err)
	unsafe := directory(t)
	require.NoError(t, os.WriteFile(filepath.Join(unsafe, "outside"), nil, 0o600))
	require.NoError(t, os.Symlink(filepath.Join(unsafe, "outside"), filepath.Join(unsafe, "spool.db")))
	_, err = Open(background, unsafe, o)
	require.Error(t, err)
}
func TestQueueNeverBlocksRequestsAndPersistsOverflow(t *testing.T) {
	s := open(t, directory(t), options())
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	writer := func(ctx context.Context, events []requestevent.Event) ([]string, error) {
		once.Do(func() { close(entered) })
		select {
		case <-release:
			return s.Append(ctx, events)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	a, err := newAsync(s, 2, writer)
	require.NoError(t, err)
	require.True(t, a.Offer(decision()))
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("writer did not start")
	}
	started := time.Now()
	for range 10000 {
		a.Offer(decision())
	}
	require.Less(t, time.Since(started), time.Second)
	require.LessOrEqual(t, a.Queued(), 2)
	require.Positive(t, a.UncommittedDrops())
	close(release)
	ctx, cancel := context.WithTimeout(background, 5*time.Second)
	defer cancel()
	require.NoError(t, a.Close(ctx))
	require.Zero(t, a.UncommittedDrops())
	st, err := s.Status(background)
	require.NoError(t, err)
	require.Positive(t, st.Dropped)
}
func TestPermanentBatchFailureRecoversAndNormalizesTime(t *testing.T) {
	s := open(t, directory(t), options())
	var calls atomic.Int32
	var offered requestevent.Event
	writer := func(ctx context.Context, events []requestevent.Event) ([]string, error) {
		if calls.Add(1) == 1 {
			offered = events[0]
			return nil, ErrInvalid
		}
		return s.Append(ctx, events)
	}
	a, err := newAsync(s, 2, writer)
	require.NoError(t, err)
	event := decision()
	event.Time = time.Now().Add(24 * time.Hour)
	require.True(t, a.Offer(event))
	ctx, cancel := context.WithTimeout(background, 5*time.Second)
	defer cancel()
	require.NoError(t, a.Close(ctx))
	require.WithinDuration(t, time.Now(), offered.Time, 5*time.Second)
	events := pending(t, s)
	require.Len(t, events, 1)
	require.Equal(t, "queue_invalid", events[0].Reason)
	require.EqualValues(t, 1, events[0].Dropped)
}
func TestBoundedPhysicalFileAndMinimalRetention(t *testing.T) {
	s := open(t, directory(t), options())
	for range 22 {
		events := make([]requestevent.Event, 100)
		for i := range events {
			events[i] = s.Identity(decision())
			events[i].URL = "https://example.com/" + strings.Repeat("x", 1750)
		}
		_, err := s.Append(background, events)
		require.NoError(t, err)
		st, err := s.Status(background)
		require.NoError(t, err)
		require.LessOrEqual(t, st.DiskBytes, s.options.MaxBytes)
	}
	before, err := s.Status(background)
	require.NoError(t, err)
	require.Positive(t, before.Dropped)
	one := s.Identity(decision())
	one.URL = "https://example.com/" + strings.Repeat("x", 1750)
	_, err = s.Append(background, []requestevent.Event{one})
	require.NoError(t, err)
	after, err := s.Status(background)
	require.NoError(t, err)
	require.LessOrEqual(t, after.Dropped-before.Dropped, uint64(5), "one new event must not evict a full 128-row batch")
}
func TestSpoolCrashHelper(t *testing.T) {
	root := os.Getenv("RAUTH_BBOLT_CRASH_FIXTURE")
	if root == "" {
		return
	}
	var o Options
	require.NoError(t, json.Unmarshal([]byte(os.Getenv("RAUTH_BBOLT_CRASH_OPTIONS")), &o))
	s, err := Open(background, root, o)
	require.NoError(t, err)
	entered := make(chan struct{})
	var once sync.Once
	a, err := newAsync(s, 2, func(ctx context.Context, _ []requestevent.Event) ([]string, error) {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		return nil, ctx.Err()
	})
	require.NoError(t, err)
	require.True(t, a.Offer(decision()))
	<-entered
	require.NoError(t, os.WriteFile(filepath.Join(root, "ready"), []byte("ready"), 0o600))
	select {}
}
func TestKilledWriterReportsUnknownQueueLoss(t *testing.T) {
	root := directory(t)
	o := options()
	raw, _ := json.Marshal(o)
	exe, err := os.Executable()
	require.NoError(t, err)
	command := exec.Command(exe, "-test.run=^TestSpoolCrashHelper$", "-test.timeout=20s")
	command.Env = append(os.Environ(), "RAUTH_BBOLT_CRASH_FIXTURE="+root, "RAUTH_BBOLT_CRASH_OPTIONS="+string(raw))
	require.NoError(t, command.Start())
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	require.Eventually(t, func() bool { _, err := os.Stat(filepath.Join(root, "ready")); return err == nil }, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, command.Process.Kill())
	_ = command.Wait()
	s := open(t, root, o)
	events := pending(t, s)
	require.Len(t, events, 1)
	require.True(t, events[0].UnknownLoss)
	st, err := s.Status(background)
	require.NoError(t, err)
	require.EqualValues(t, 1, st.UncleanRestarts)
}
func TestStorageScopeCannotBeReusedByAnotherNode(t *testing.T) {
	root := directory(t)
	o := options()
	s := open(t, root, o)
	require.NoError(t, s.MarkClean(background))
	require.NoError(t, s.Close())
	other := o
	other.NodeID = uuid.NewString()
	_, err := Open(background, root, other)
	require.Error(t, err)
	s = open(t, root, o)
	require.Empty(t, pending(t, s))
}

func TestFullFileRollsBackAndCanRecover(t *testing.T) {
	s := open(t, directory(t), options())
	info, err := os.Stat(filepath.Join(s.root, "spool.db"))
	require.NoError(t, err)
	s.db.MaxSize = int(info.Size())
	events := make([]requestevent.Event, 100)
	for i := range events {
		events[i] = s.Identity(decision())
		events[i].URL = "https://example.com/" + strings.Repeat("x", 1750)
	}
	ack, err := s.Append(background, events)
	require.Error(t, err)
	require.Nil(t, ack)
	st, err := s.Status(background)
	require.NoError(t, err)
	require.Zero(t, st.Pending)
	s.db.MaxSize = int(s.options.MaxBytes)
	ack, err = s.Append(background, events)
	require.NoError(t, err)
	require.Len(t, ack, 100)
	st, err = s.Status(background)
	require.NoError(t, err)
	require.EqualValues(t, 100, st.Pending)
}

func TestEvictingGapMarkersPreservesTotalsAndUnknownSignal(t *testing.T) {
	s := open(t, directory(t), options())
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	known := s.Gap("queue_overflow", 7)
	unknown := s.gap("unclean_restart", 0, true)
	_, err := s.Append(background, []requestevent.Event{known, unknown})
	require.NoError(t, err)
	// The locally assigned wire totals must not make an ambiguous retry conflict
	// or increment the lifetime counters a second time.
	_, err = s.Append(background, []requestevent.Event{known, unknown})
	require.NoError(t, err)
	for range 2 {
		now = now.Add(25 * time.Hour)
		require.NoError(t, s.Maintain(background))
		st, err := s.Status(background)
		require.NoError(t, err)
		require.EqualValues(t, 7, st.Dropped)
		require.EqualValues(t, 1, st.UncleanRestarts)
		events := pending(t, s)
		require.Len(t, events, 2)
		var represented uint64
		var hasUnknown bool
		for _, event := range events {
			represented += event.Dropped
			hasUnknown = hasUnknown || event.UnknownLoss
			require.EqualValues(t, 7, event.LossTotal)
			require.EqualValues(t, 1, event.UncleanTotal)
		}
		require.EqualValues(t, 7, represented)
		require.True(t, hasUnknown)
	}
}

func TestPermanentRejectionAtomicallyPreservesDecisionLossAndTelemetryCoverage(t *testing.T) {
	store := open(t, directory(t), options())
	event := store.Identity(decision())
	_, err := store.Append(background, []requestevent.Event{event})
	require.NoError(t, err)
	require.NoError(t, store.Reject(background, []string{event.EventID}))
	records := pending(t, store)
	require.Len(t, records, 1)
	require.Equal(t, "gap", records[0].Kind)
	require.Equal(t, "queue_invalid", records[0].Reason)
	require.EqualValues(t, 1, records[0].LossTotal)
	st, err := store.Status(background)
	require.NoError(t, err)
	require.EqualValues(t, 1, st.Dropped)
	require.Error(t, store.Reject(background, []string{records[0].EventID}))
	require.Len(t, pending(t, store), 1)
	sample := store.Identity(requestevent.Event{Kind: "telemetry", Time: time.Now(), Metrics: &requestevent.MetricSnapshot{Schema: 1, InstanceID: uuid.NewString(), StartedAt: time.Now(), Points: []requestevent.MetricPoint{{Name: "go_goroutines", Value: 1}}}})
	_, err = store.Append(background, []requestevent.Event{sample})
	require.NoError(t, err)
	require.NoError(t, store.Reject(background, []string{sample.EventID}))
	st, err = store.Status(background)
	require.NoError(t, err)
	require.EqualValues(t, 1, st.Dropped)
	require.EqualValues(t, 1, st.Pending)
}

func localMetric() requestevent.Event {
	return requestevent.Event{Kind: "telemetry", Time: time.Now(), Metrics: &requestevent.MetricSnapshot{Schema: 1, InstanceID: uuid.NewString(), StartedAt: time.Now(), Points: []requestevent.MetricPoint{{Name: "process_cpu_seconds_total", Value: 1}}}}
}
func TestLocalTelemetryBudgetProtectsDecisionsWithoutCountingRequestLoss(t *testing.T) {
	store := open(t, directory(t), options())
	store.payloadLimit = 64 << 10
	anchor := store.Identity(decision())
	_, err := store.Append(background, []requestevent.Event{anchor})
	require.NoError(t, err)
	for range 100 {
		_, err = store.Append(background, []requestevent.Event{store.Identity(localMetric())})
		require.NoError(t, err)
	}
	records := pending(t, store)
	found := false
	for _, e := range records {
		found = found || e.EventID == anchor.EventID
	}
	require.True(t, found)
	status, err := store.Status(background)
	require.NoError(t, err)
	require.Zero(t, status.Dropped)
	require.NoError(t, store.db.View(func(tx *bolt.Tx) error {
		require.LessOrEqual(t, number(tx.Bucket(metaBucket).Get([]byte("telemetry_bytes"))), store.telemetryLimit())
		return nil
	}))
}
func TestOldSpoolTelemetryIndexRebuildResumesWithoutChangingRecords(t *testing.T) {
	root := directory(t)
	o := options()
	store := open(t, root, o)
	events := []requestevent.Event{}
	for range 300 {
		events = append(events, store.Identity(localMetric()))
	}
	for i := 0; i < len(events); i += 100 {
		_, err := store.Append(background, events[i:i+100])
		require.NoError(t, err)
	}
	require.NoError(t, store.MarkClean(background))
	require.NoError(t, store.Close())
	db, err := bolt.Open(filepath.Join(root, "spool.db"), 0o600, nil)
	require.NoError(t, err)
	require.NoError(t, db.Update(func(tx *bolt.Tx) error {
		require.NoError(t, tx.DeleteBucket(telemetryBucket))
		_, err := tx.CreateBucket(telemetryBucket)
		require.NoError(t, err)
		meta := tx.Bucket(metaBucket)
		require.NoError(t, meta.Put([]byte("schema"), []byte("2")))
		require.NoError(t, meta.Delete([]byte("telemetry_index_ready")))
		var total uint64
		cursor := tx.Bucket(eventBucket).Cursor()
		k, v := cursor.First()
		for range 128 {
			require.NotNil(t, k)
			size := uint64(len(v)) + 128
			require.NoError(t, tx.Bucket(telemetryBucket).Put(k, key(size)))
			total += size
			require.NoError(t, meta.Put([]byte("telemetry_index_cursor"), bytes.Clone(k)))
			k, v = cursor.Next()
		}
		return meta.Put([]byte("telemetry_bytes"), key(total))
	}))
	require.NoError(t, db.Close())
	store = open(t, root, o)
	require.NoError(t, store.db.View(func(tx *bolt.Tx) error {
		require.Equal(t, 300, tx.Bucket(telemetryBucket).Stats().KeyN)
		require.EqualValues(t, 1, number(tx.Bucket(metaBucket).Get([]byte("telemetry_index_ready"))))
		return nil
	}))
	status, err := store.Status(background)
	require.NoError(t, err)
	require.EqualValues(t, 300, status.Pending)
	require.Zero(t, status.Dropped)
}
func TestAsyncTelemetryCapacityDoesNotDiscardDecisions(t *testing.T) {
	store := open(t, directory(t), options())
	var sawTelemetry atomic.Bool
	var wroteDecisions atomic.Int32
	write := func(ctx context.Context, events []requestevent.Event) ([]string, error) {
		for _, e := range events {
			if e.Kind == "telemetry" {
				sawTelemetry.Store(true)
				return nil, ErrTelemetryCapacity
			}
		}
		for _, e := range events {
			if e.Kind == "decision" {
				wroteDecisions.Add(1)
			}
		}
		return store.Append(ctx, events)
	}
	a, err := newAsync(store, 8, write)
	require.NoError(t, err)
	require.True(t, a.OfferMetrics(*localMetric().Metrics))
	require.True(t, a.Offer(decision()))
	ctx, cancel := context.WithTimeout(background, 3*time.Second)
	defer cancel()
	require.NoError(t, a.Close(ctx))
	require.True(t, sawTelemetry.Load())
	require.EqualValues(t, 1, wroteDecisions.Load())
	status, err := store.Status(background)
	require.NoError(t, err)
	require.Zero(t, status.Dropped)
}
