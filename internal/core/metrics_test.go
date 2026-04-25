package core

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestMetrics(t *testing.T) {
	metrics := []struct {
		name   string
		metric interface{}
	}{
		{"rauth_login_success_total", LoginSuccessTotal},
		{"rauth_login_failed_total", LoginFailedTotal},
		{"rauth_rate_limit_hits_total", RateLimitHitsTotal},
		{"rauth_active_sessions", ActiveSessionsGauge},
		{"rauth_audit_logs_total", AuditLogsTotal},
		{"rauth_geoip_lookups_total", GeoIPLookupsTotal},
		{"rauth_geoip_db_build_timestamp", GeoIPDBBuildTimestamp},
	}

	for _, m := range metrics {
		if m.metric == nil {
			t.Errorf("Metric %s is not initialized", m.name)
		}
	}

	// Verify registration by gathering from the default registry
	gatherer := prometheus.DefaultGatherer
	metricFamilies, err := gatherer.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundMetrics := make(map[string]bool)
	for _, mf := range metricFamilies {
		foundMetrics[mf.GetName()] = true
	}

	for _, m := range metrics {
		if !foundMetrics[m.name] {
			t.Errorf("Metric %s was not found in the default registry", m.name)
		}
	}
}
