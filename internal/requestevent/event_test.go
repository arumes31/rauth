package requestevent

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"math"
	"strings"
	"testing"
	"time"
)

func TestDecisionDropsSecretsBeforePersistence(t *testing.T) {
	e := Decision(Event{URL: "https://name:password@example.com/document?token=secret#fragment", Source: "::ffff:192.0.2.1", Country: "US", Action: "authenticated", Status: 200, Time: time.Now()})
	require.Equal(t, "https://example.com/document", e.URL)
	require.Equal(t, "192.0.2.1", e.Source)
	e.EventID = uuid.NewString()
	e.NodeID = uuid.NewString()
	e.NodeName = "node"
	require.NoError(t, Validate(e, time.Now()))
	e.URL += "?password=secret"
	require.Error(t, Validate(e, time.Now()))
}
func TestEventRejectsIdentityTimeAndUnboundedLoss(t *testing.T) {
	base := Event{EventID: uuid.NewString(), NodeID: uuid.NewString(), NodeName: "node", Kind: "gap", Reason: "queue_overflow", Dropped: 1, Time: time.Now()}
	require.NoError(t, Validate(base, time.Now()))
	for _, change := range []func(*Event){func(e *Event) { e.EventID = "not-an-id" }, func(e *Event) { e.Time = time.Now().Add(-49 * time.Hour) }, func(e *Event) { e.Time = time.Now().Add(3 * time.Minute) }, func(e *Event) { e.Dropped = 1 << 63 }, func(e *Event) { e.Source = "credential" }, func(e *Event) { e.NodeName = strings.Repeat("x", 65) }} {
		event := base
		change(&event)
		require.Error(t, Validate(event, time.Now()))
	}
}

func TestMetricContractRejectsUnboundedAndAmbiguousSnapshots(t *testing.T) {
	now := time.Now()
	base := MetricSnapshot{Schema: 1, InstanceID: uuid.NewString(), StartedAt: now, GoVersion: "go-test", Points: []MetricPoint{{Name: "go_goroutines", Value: 2}}}
	require.NoError(t, ValidateMetrics(&base, now))
	for _, change := range []func(*MetricSnapshot){func(s *MetricSnapshot) { s.InstanceID = "unknown" }, func(s *MetricSnapshot) { s.Schema = 2 }, func(s *MetricSnapshot) { s.StartedAt = now.Add(3 * time.Minute) }, func(s *MetricSnapshot) { s.Points[0].Value = math.NaN() }, func(s *MetricSnapshot) { s.Points[0].Value = math.Inf(1) }, func(s *MetricSnapshot) { s.Points[0].Value = -1 }, func(s *MetricSnapshot) { s.Points[0].Name = "private\nvalue" }, func(s *MetricSnapshot) { s.Points = append(s.Points, s.Points[0]) }, func(s *MetricSnapshot) { s.Points = make([]MetricPoint, 65) }} {
		copy := base.Clone()
		change(&copy)
		require.Error(t, ValidateMetrics(&copy, now))
	}
	event := Event{Kind: "telemetry", Metrics: &base, EventID: uuid.NewString(), NodeID: uuid.NewString(), NodeName: "node", Time: now}
	require.NoError(t, Validate(event, now))
	event.Source = "192.0.2.1"
	require.Error(t, Validate(event, now))
	require.Nil(t, Decision(event).Metrics)
}
