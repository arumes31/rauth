package eventstore

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"rauth/internal/requestevent"
)

type retentionWANConn struct {
	net.Conn
	enabled *atomic.Bool
	delay   time.Duration
}

func (c *retentionWANConn) Write(p []byte) (int, error) {
	if c.enabled.Load() {
		time.Sleep(c.delay)
	}
	return c.Conn.Write(p)
}

func TestRetentionMakesProgressAcrossWAN(t *testing.T) {
	for _, delay := range []time.Duration{150 * time.Millisecond, 250 * time.Millisecond} {
		t.Run(delay.String(), func(t *testing.T) {
			pool := setup(t)
			s := open(t, pool, options())
			node := uuid.NewString()
			now := time.Now().UTC()
			s.now = func() time.Time { return now }
			oldDecision := decision(node)
			oldDecision.Time = now
			oldDecision.ProcessingMicros = 1234
			_, err := s.Ingest(background, node, []requestevent.Event{oldDecision})
			require.NoError(t, err)
			for offset := 0; offset < 260; offset += requestevent.MaxBatch {
				events := make([]requestevent.Event, 0, min(requestevent.MaxBatch, 260-offset))
				for range cap(events) {
					events = append(events, requestevent.Event{Kind: "telemetry", EventID: uuid.NewString(), NodeID: node, NodeName: "fixture", Time: now, Metrics: &requestevent.MetricSnapshot{Schema: 1, InstanceID: uuid.NewString(), StartedAt: now.Add(-time.Hour), Points: []requestevent.MetricPoint{}}})
				}
				_, err = s.Ingest(background, node, events)
				require.NoError(t, err)
			}
			now = now.Add(25 * time.Hour)
			incoming := decision(node)
			incoming.Time = now
			incoming.ProcessingMicros = 4321
			cfg := pool.Config()
			originalDial := cfg.ConnConfig.DialFunc
			var enabled atomic.Bool
			cfg.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
				conn, err := originalDial(ctx, network, address)
				if err != nil {
					return nil, err
				}
				return &retentionWANConn{Conn: conn, enabled: &enabled, delay: delay}, nil
			}
			delayed, err := pgxpool.NewWithConfig(background, cfg)
			require.NoError(t, err)
			t.Cleanup(delayed.Close)
			s.pool = delayed
			_, err = delayed.Exec(background, "SELECT 1")
			require.NoError(t, err)
			enabled.Store(true)
			previous := 260
			delivered := false
			// A timed-out upload may retain committed cleanup chunks. Every retry must
			// make durable progress; growing the backlog must not cause starvation.
			for attempt := 1; attempt <= 4; attempt++ {
				ctx, cancel := context.WithTimeout(background, 10*time.Second)
				started := time.Now()
				ids, ingestErr := s.Ingest(ctx, node, []requestevent.Event{incoming})
				cancel()
				const attemptGrace = time.Second
				require.LessOrEqual(t, time.Since(started), 10*time.Second+attemptGrace, "Ingest exceeded its attempt budget")
				var remaining int
				require.NoError(t, pool.QueryRow(background, "SELECT count(*) FROM request_events WHERE kind='telemetry'").Scan(&remaining))
				t.Logf("write_delay=%s attempt=%d elapsed=%s expired_telemetry_remaining=%d", delay, attempt, time.Since(started), remaining)
				if ingestErr == nil {
					require.Equal(t, []string{incoming.EventID}, ids)
					delivered = true
					break
				}
				require.Less(t, remaining, previous, "a bounded attempt must commit retention progress before retry: %v", ingestErr)
				previous = remaining
			}
			enabled.Store(false)
			require.True(t, delivered, "new decisions must eventually commit across the WAN")
			var events, samples, traffic, processing, count, bytes, telemetry, expectedBytes int64
			require.NoError(t, pool.QueryRow(background, "SELECT count(*),coalesce(sum(size),0) FROM request_events").Scan(&events, &expectedBytes))
			require.NoError(t, pool.QueryRow(background, "SELECT count(*) FROM event_node_samples").Scan(&samples))
			require.NoError(t, pool.QueryRow(background, "SELECT coalesce(sum(decisions),0),coalesce(sum(processing_us),0)::bigint FROM event_traffic_minute").Scan(&traffic, &processing))
			require.NoError(t, pool.QueryRow(background, "SELECT event_count,payload_bytes,telemetry_bytes FROM event_ledgers WHERE cluster_id=$1", s.options.ClusterID).Scan(&count, &bytes, &telemetry))
			require.EqualValues(t, 2, events)
			require.Zero(t, samples, "expired samples must cascade with telemetry")
			require.EqualValues(t, 2, traffic)
			require.EqualValues(t, 5555, processing)
			require.Equal(t, events, count)
			require.Equal(t, expectedBytes, bytes)
			require.Zero(t, telemetry)
			ids, err := s.Ingest(background, node, []requestevent.Event{incoming})
			require.NoError(t, err)
			require.Equal(t, []string{incoming.EventID}, ids, "replayed upload remains idempotent")
		})
	}
}

func TestRetentionChunkRollbackPreservesStatistics(t *testing.T) {
	pool := setup(t)
	s := open(t, pool, Options{ClusterID: uuid.NewString(), MaxBytes: 16 << 20, MaxAge: time.Hour})
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	node := uuid.NewString()
	events := make([]requestevent.Event, 20)
	for i := range events {
		events[i] = decision(node)
		events[i].Time = now
		events[i].ProcessingMicros = int64(i + 1)
	}
	_, err := s.Ingest(background, node, events)
	require.NoError(t, err)
	_, err = pool.Exec(background, `CREATE FUNCTION retention_test_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.seq=10 THEN RAISE EXCEPTION 'synthetic retention failure' USING ERRCODE='53100'; END IF; RETURN OLD; END $$; CREATE TRIGGER retention_test_failure BEFORE DELETE ON request_events FOR EACH ROW EXECUTE FUNCTION retention_test_failure()`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(background, "DROP TRIGGER IF EXISTS retention_test_failure ON request_events; DROP FUNCTION IF EXISTS retention_test_failure()")
	})
	now = now.Add(2 * time.Hour)
	err = s.Maintain(background)
	require.Error(t, err)
	var rows, traffic, processing, count int64
	require.NoError(t, pool.QueryRow(background, "SELECT count(*) FROM request_events").Scan(&rows))
	require.NoError(t, pool.QueryRow(background, "SELECT sum(decisions),sum(processing_us)::bigint FROM event_traffic_minute").Scan(&traffic, &processing))
	require.NoError(t, pool.QueryRow(background, "SELECT event_count FROM event_ledgers WHERE cluster_id=$1", s.options.ClusterID).Scan(&count))
	require.EqualValues(t, 20, rows)
	require.Equal(t, rows, traffic)
	require.Equal(t, rows, count)
	require.EqualValues(t, 210, processing)
	_, err = pool.Exec(background, "DROP TRIGGER retention_test_failure ON request_events; DROP FUNCTION retention_test_failure()")
	require.NoError(t, err)
	require.NoError(t, s.Maintain(background))
	for _, table := range []string{"request_events", "event_traffic_minute"} {
		require.NoError(t, pool.QueryRow(background, fmt.Sprintf("SELECT count(*) FROM %s", table)).Scan(&count))
		require.Zero(t, count)
	}
}

func TestCanceledIngestDoesNotWaitForAnotherWriter(t *testing.T) {
	pool := setup(t)
	s := open(t, pool, options())
	node := uuid.NewString()
	ctx, cancel := context.WithTimeout(background, 50*time.Millisecond)
	defer cancel()
	require.True(t, s.lockWriter(background))
	result := make(chan error, 1)
	go func() { _, err := s.Ingest(ctx, node, []requestevent.Event{decision(node)}); result <- err }()
	select {
	case err := <-result:
		s.unlockWriter()
		require.ErrorIs(t, err, ErrUnavailable)
	case <-time.After(time.Second):
		s.unlockWriter()
		select {
		case <-result:
		case <-time.After(2 * time.Second):
			t.Fatal("canceled writer failed to finish after lock release")
		}
		t.Fatal("canceled ingest held its receiver slot while waiting for another writer")
	}
}

func TestMaintenanceYieldsToQueuedWriterBetweenChunks(t *testing.T) {
	pool := setup(t)
	s := open(t, pool, options())
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	node := uuid.NewString()
	for offset := 0; offset < 260; offset += requestevent.MaxBatch {
		events := make([]requestevent.Event, 0, min(requestevent.MaxBatch, 260-offset))
		for range cap(events) {
			events = append(events, requestevent.Event{Kind: "telemetry", EventID: uuid.NewString(), NodeID: node, NodeName: "fixture", Time: now, Metrics: &requestevent.MetricSnapshot{Schema: 1, InstanceID: uuid.NewString(), StartedAt: now, Points: []requestevent.MetricPoint{}}})
		}
		_, err := s.Ingest(background, node, events)
		require.NoError(t, err)
	}
	_, err := pool.Exec(background, `CREATE FUNCTION retention_yield_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.seq IN (1,129) THEN PERFORM pg_advisory_xact_lock(110000+OLD.seq); END IF; RETURN OLD; END $$; CREATE TRIGGER retention_yield_barrier BEFORE DELETE ON request_events FOR EACH ROW EXECUTE FUNCTION retention_yield_barrier()`)
	require.NoError(t, err)
	blocker, err := pool.Acquire(background)
	require.NoError(t, err)
	_, err = blocker.Exec(background, "SELECT pg_advisory_lock(110001),pg_advisory_lock(110129)")
	require.NoError(t, err)
	now = now.Add(25 * time.Hour)
	ctx, cancel := context.WithTimeout(background, 10*time.Second)
	defer cancel()
	maintain := make(chan struct{})
	var maintenanceErr error
	release := make(chan struct{})
	writerDone := make(chan struct{})
	writerStarted := false
	releaseWriter := func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}
	defer func() {
		releaseWriter()
		_, _ = blocker.Exec(background, "SELECT pg_advisory_unlock_all()")
		blocker.Release()
		select {
		case <-maintain:
		case <-time.After(2 * time.Second):
		}
		if writerStarted {
			select {
			case <-writerDone:
			case <-time.After(2 * time.Second):
			}
		}
		_, _ = pool.Exec(background, "DROP TRIGGER IF EXISTS retention_yield_barrier ON request_events; DROP FUNCTION IF EXISTS retention_yield_barrier()")
	}()
	go func() { maintenanceErr = s.Maintain(ctx); close(maintain) }()
	require.Eventually(t, func() bool {
		var waiting bool
		err := pool.QueryRow(background, "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=110001 AND NOT granted)").Scan(&waiting)
		return err == nil && waiting
	}, 2*time.Second, 10*time.Millisecond)
	acquired := make(chan bool, 1)
	started := make(chan struct{})
	writerStarted = true
	go func() {
		defer close(writerDone)
		close(started)
		ok := s.lockWriter(ctx)
		acquired <- ok
		if ok {
			<-release
			s.unlockWriter()
		}
	}()
	<-started
	time.Sleep(20 * time.Millisecond)
	_, err = blocker.Exec(background, "SELECT pg_advisory_unlock(110001)")
	require.NoError(t, err)
	select {
	case ok := <-acquired:
		require.True(t, ok)
	case <-time.After(2 * time.Second):
		t.Fatal("maintenance retained the writer gate into the next chunk")
	}
	releaseWriter()
	_, err = blocker.Exec(background, "SELECT pg_advisory_unlock(110129)")
	require.NoError(t, err)
	select {
	case <-maintain:
		require.NoError(t, maintenanceErr)
	case <-time.After(2 * time.Second):
		t.Fatal("maintenance did not finish after the queued writer released")
	}
	var retained int
	require.NoError(t, pool.QueryRow(background, "SELECT count(*) FROM request_events").Scan(&retained))
	require.Zero(t, retained)
}

// Removal must decrement a shared bucket without dropping its retained decision.
func TestRetentionPartialRemovalPreservesSharedMinuteBucket(t *testing.T) {
	pool := setup(t)
	s := open(t, pool, Options{ClusterID: uuid.NewString(), MaxBytes: 16 << 20, MaxAge: time.Minute})
	node := uuid.NewString()
	minute := time.Now().UTC().Truncate(time.Minute)
	now := minute.Add(10 * time.Second)
	s.now = func() time.Time { return now }
	expired := decision(node)
	expired.Time = now
	expired.ProcessingMicros = 1234
	_, err := s.Ingest(background, node, []requestevent.Event{expired})
	require.NoError(t, err)
	now = minute.Add(40 * time.Second)
	retained := expired
	retained.EventID = uuid.NewString()
	retained.Time = now
	retained.ProcessingMicros = 2345
	require.Equal(t, latencyBucket(expired.ProcessingMicros), latencyBucket(retained.ProcessingMicros))
	_, err = s.Ingest(background, node, []requestevent.Event{retained})
	require.NoError(t, err)
	var buckets, traffic, processing int64
	require.NoError(t, pool.QueryRow(background, "SELECT count(*),sum(decisions),sum(processing_us)::bigint FROM event_traffic_minute").Scan(&buckets, &traffic, &processing))
	require.EqualValues(t, 1, buckets)
	require.EqualValues(t, 2, traffic)
	require.EqualValues(t, 3579, processing)
	now = minute.Add(90 * time.Second)
	require.NoError(t, s.Maintain(background))
	var ids []string
	rows, err := pool.Query(background, "SELECT event_id::text FROM request_events ORDER BY seq")
	require.NoError(t, err)
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		ids = append(ids, id)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	require.Equal(t, []string{retained.EventID}, ids)
	require.NoError(t, pool.QueryRow(background, "SELECT count(*),sum(decisions),sum(processing_us)::bigint FROM event_traffic_minute").Scan(&buckets, &traffic, &processing))
	require.EqualValues(t, 1, buckets)
	require.EqualValues(t, 1, traffic)
	require.EqualValues(t, retained.ProcessingMicros, processing)
	var ledgerCount int64
	require.NoError(t, pool.QueryRow(background, "SELECT event_count FROM event_ledgers WHERE cluster_id=$1", s.options.ClusterID).Scan(&ledgerCount))
	require.EqualValues(t, 1, ledgerCount)
}
