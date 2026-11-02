package core

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	SecondFactorTotal            = promauto.NewCounterVec(prometheus.CounterOpts{Name: "rauth_second_factor_total", Help: "Verified second-factor outcomes"}, []string{"action"})
	ForwardAuthDecisionsTotal    = promauto.NewCounterVec(prometheus.CounterOpts{Name: "rauth_forward_auth_decisions_total", Help: "Forward-auth decisions processed by this RAuth instance"}, []string{"action"})
	ForwardAuthProcessingSeconds = promauto.NewHistogram(prometheus.HistogramOpts{Name: "rauth_forward_auth_processing_seconds", Help: "Time spent processing a forward-auth decision in RAuth", Buckets: []float64{.001, .003, .01, .03, .1, .3, 1, 3, 10, 30, 60, 120, 600}})

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

	RecoveryCodeUsedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "rauth_recovery_code_used_total",
		Help: "The total number of 2FA recovery codes consumed during login",
	})

	AuthBypassTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "rauth_auth_bypass_total",
		Help: "Forward-auth requests allowed anonymously by an auth bypass rule",
	})
)
