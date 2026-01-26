package core

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	LoginSuccessTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "rauth_login_success_total",
		Help: "The total number of successful logins",
	})

	LoginFailedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "rauth_login_failed_total",
		Help: "The total number of failed logins",
	})

	RateLimitHitsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rauth_rate_limit_hits_total",
		Help: "The total number of rate limit hits",
	}, []string{"type"})

	ActiveSessionsGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "rauth_active_sessions",
		Help: "The current number of active sessions",
	})

	AuditLogsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rauth_audit_logs_total",
		Help: "The total number of audit logs by action",
	}, []string{"action"})

	GeoIPLookupsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rauth_geoip_lookups_total",
		Help: "The total number of GeoIP lookups by status (hit, miss, internal)",
	}, []string{"status"})

	GeoIPDBBuildTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "rauth_geoip_db_build_timestamp",
		Help: "The build timestamp of the loaded GeoIP database",
	})
)
