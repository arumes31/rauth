package nodetelemetry

import (
	"errors"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
	"math"
	"rauth/internal/requestevent"
	"testing"
	"time"
)

func TestBoundedSnapshotsSeparateProcessAndAggregateOnlyEssentialLabels(t *testing.T) {
	r := prometheus.NewRegistry()
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "rauth_rate_limit_hits_total", Help: "fixture"}, []string{"type"})
	r.MustRegister(counter)
	counter.WithLabelValues("login").Add(2)
	counter.WithLabelValues("verify").Inc()
	private := prometheus.NewGauge(prometheus.GaugeOpts{Name: "unrelated_private_metric", Help: "must not cross the durable boundary"})
	r.MustRegister(private)
	a := New(r)
	first := a.Capture()
	second := a.Capture()
	require.Equal(t, first.InstanceID, second.InstanceID)
	require.NotEqual(t, first.InstanceID, New(r).Capture().InstanceID)
	require.NoError(t, requestevent.ValidateMetrics(&first, time.Now()))
	values := map[string]float64{}
	for _, point := range first.Points {
		values[point.Name] = point.Value
	}
	require.Equal(t, float64(3), values["rauth_rate_limit_hits_total"])
	require.NotContains(t, values, "unrelated_private_metric")
	require.Positive(t, values["go_goroutines"])
}

type brokenGatherer struct{}

func (brokenGatherer) Gather() ([]*dto.MetricFamily, error) { return nil, errors.New("unavailable") }
func TestPartialGatherAndInvalidNumbers(t *testing.T) {
	require.True(t, New(brokenGatherer{}).Capture().Partial)
	r := prometheus.NewRegistry()
	g := prometheus.NewGauge(prometheus.GaugeOpts{Name: "process_resident_memory_bytes", Help: "fixture"})
	r.MustRegister(g)
	g.Set(math.NaN())
	snapshot := New(r).Capture()
	require.True(t, snapshot.Partial)
	require.NoError(t, requestevent.ValidateMetrics(&snapshot, time.Now()))
}

func TestDiagnosticsPreserveFixedLabelsAndBoundChunks(t *testing.T) {
	r := prometheus.NewRegistry()
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "rauth_audit_logs_total", Help: "fixture"}, []string{"action"})
	r.MustRegister(counter)
	for i := 0; i < 180; i++ {
		counter.WithLabelValues(fmt.Sprintf("fixture_%d", i)).Add(float64(i))
	}
	parts := New(r).Diagnostics()
	require.Greater(t, len(parts), 1)
	require.LessOrEqual(t, len(parts), 8)
	seen := 0
	for i, p := range parts {
		require.NoError(t, requestevent.ValidateMetrics(&p, time.Now()))
		require.True(t, p.Diagnostics)
		require.Equal(t, parts[0].CaptureID, p.CaptureID)
		require.Equal(t, i, p.Part)
		require.Equal(t, len(parts), p.Parts)
		for _, point := range p.Points {
			require.Contains(t, point.Labels, "action")
			seen++
		}
	}
	require.Equal(t, 180, seen)
}

func TestDiagnosticsIncludeGoVersionAndMetricsHandlerFamilies(t *testing.T) {
	r := prometheus.NewRegistry()
	info := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "go_info", Help: "fixture"}, []string{"version"})
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "promhttp_metric_handler_requests_total", Help: "fixture"}, []string{"code"})
	r.MustRegister(info, requests)
	info.WithLabelValues("go1.27.3").Set(1)
	requests.WithLabelValues("200").Inc()
	seen := map[string]bool{}
	for _, part := range New(r).Diagnostics() {
		require.False(t, part.Partial)
		for _, point := range part.Points {
			seen[point.Name] = true
		}
	}
	require.True(t, seen["go_info"])
	require.True(t, seen["promhttp_metric_handler_requests_total"])
}
