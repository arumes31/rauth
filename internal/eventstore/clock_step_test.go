package eventstore

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"rauth/internal/requestevent"
)

func telemetryEvent(node string, at time.Time) requestevent.Event {
	return requestevent.Event{Kind: "telemetry", EventID: uuid.NewString(), NodeID: node, NodeName: "fixture", Time: at, Metrics: &requestevent.MetricSnapshot{Schema: 1, InstanceID: uuid.NewString(), StartedAt: at.Add(-time.Hour), Points: []requestevent.MetricPoint{}}}
}

// A backward wall-clock step must not make received_at decrease in seq, or the
// telemetry expiry probe could miss rows that have expired.
func TestReceivedAtStaysMonotonicAcrossBackwardClockStep(t *testing.T) {
	pool := setup(t)
	s := open(t, pool, options())
	node := uuid.NewString()
	start := time.Now().UTC().Truncate(time.Second)
	clock := start
	s.now = func() time.Time { return clock }
	_, err := s.Ingest(background, node, []requestevent.Event{telemetryEvent(node, start)})
	require.NoError(t, err)
	clock = start.Add(-2 * time.Hour)
	_, err = s.Ingest(background, node, []requestevent.Event{telemetryEvent(node, clock)})
	require.NoError(t, err)
	var first, second time.Time
	require.NoError(t, pool.QueryRow(background, `SELECT min(received_at),max(received_at) FROM request_events WHERE cluster_id=$1`, s.options.ClusterID).Scan(&first, &second))
	require.True(t, first.Equal(start) && second.Equal(start), "received_at moved backwards: %s then %s", first, second)

	// A new owner seeds the clock from retained history.
	require.NoError(t, s.Close())
	reopened := open(t, pool, s.options)
	reopened.now = func() time.Time { return start.Add(-time.Hour) }
	_, err = reopened.Ingest(background, node, []requestevent.Event{telemetryEvent(node, start.Add(-time.Hour))})
	require.NoError(t, err)
	var stale int
	require.NoError(t, pool.QueryRow(background, `SELECT count(*) FROM request_events WHERE cluster_id=$1 AND received_at<$2`, s.options.ClusterID, start).Scan(&stale))
	require.Zero(t, stale)

	// Once the clock passes the telemetry age, every sample is reclaimed.
	reopened.now = func() time.Time { return start.Add(25 * time.Hour) }
	require.NoError(t, reopened.Maintain(background))
	var remaining int
	require.NoError(t, pool.QueryRow(background, `SELECT count(*) FROM request_events WHERE cluster_id=$1 AND kind='telemetry'`, s.options.ClusterID).Scan(&remaining))
	require.Zero(t, remaining)
}
