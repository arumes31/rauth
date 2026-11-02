package hahealth

import (
	"encoding/json"
	"errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"
)

const testCluster = "11111111-1111-4111-8111-111111111111"

func goodReport(now time.Time) Report {
	r := Report{Schema: 1, ClusterID: testCluster, Mode: "isolated-test", CheckedAt: now, ExpectedSystemID: "12345", ExpectedDCSClusterID: "67890"}
	for i, name := range []string{"state-a", "state-b", "state-c"} {
		id := []string{"11", "22", "33"}[i]
		lag := uint64(0)
		r.Members = append(r.Members, Member{Name: name, DatabaseReady: true, Role: "replica", SystemID: r.ExpectedSystemID, DCSClusterID: r.ExpectedDCSClusterID, Timeline: 3, ServerVersion: 180006, LagBytes: &lag, DCSReady: true, DCSMemberID: id, DCSLeaderID: "11", DCSBytes: 1024, DCSQuotaBytes: 64 << 20, CertificateExpiresAt: now.Add(time.Hour)})
	}
	r.Members[0].Role = "primary"
	r.Members[0].LeaderVerified = true
	r.Members[0].SyncReplicas = 1
	return r
}
func loaded(t *testing.T, r Report, clock *time.Time) *Observer {
	t.Helper()
	raw, err := json.Marshal(r)
	require.NoError(t, err)
	o := New(func() ([]byte, error) { return raw, nil }, testCluster)
	o.now = func() time.Time { return *clock }
	o.refresh()
	return o
}
func TestFreshObservationDegradesWithoutInventingZerosWhenProducerStops(t *testing.T) {
	now := time.Now().UTC()
	o := loaded(t, goodReport(now), &now)
	view := o.View()
	require.Equal(t, "healthy", view.State)
	require.True(t, view.QuorumAvailable)
	require.Equal(t, 3, view.HealthyVoters)
	require.Equal(t, "not_observed", view.Fencing)
	registry := prometheus.NewRegistry()
	require.NoError(t, registry.Register(o))
	families, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, families, 8)
	now = now.Add(FreshFor + time.Second)
	view = o.View()
	require.Equal(t, "stale", view.State)
	require.False(t, view.Available)
	require.NotNil(t, view.Report, "retain last known observations, not fictional current zeros")
	families, err = registry.Gather()
	require.NoError(t, err)
	names := []string{}
	for _, f := range families {
		names = append(names, f.GetName())
		if f.GetName() == "rauth_ha_observation_fresh" {
			require.Zero(t, f.Metric[0].Gauge.GetValue())
		}
	}
	require.NotContains(t, names, "rauth_ha_observation_healthy_voters", "unobserved counts must not be exported as zero")
}
func TestMissingQuorumForeignIdentityAndMultiplePrimariesCannotLookHealthy(t *testing.T) {
	now := time.Now().UTC()
	for name, edit := range map[string]func(*Report){
		"one_member_missing": func(r *Report) {
			r.Members[2].DatabaseReady = false
			r.Members[2].DCSReady = false
			r.Members[2].Issue = "unavailable"
		},
		"foreign_database":     func(r *Report) { r.Members[1].SystemID = "99999" },
		"foreign_dcs":          func(r *Report) { r.Members[1].DCSClusterID = "99999" },
		"missing_sync_partner": func(r *Report) { r.Members[0].SyncReplicas = 0 },
		"two_primaries":        func(r *Report) { r.Members[1].Role = "primary"; r.Members[1].LeaderVerified = true },
		"split_dcs_leader":     func(r *Report) { r.Members[1].DCSLeaderID = "22" },
		"unknown_dcs_leader": func(r *Report) {
			for i := range r.Members {
				r.Members[i].DCSLeaderID = "44"
			}
		},
		"expired_tls_observation": func(r *Report) { r.Members[0].CertificateExpiresAt = now.Add(-time.Second) },
		"old_timeline":            func(r *Report) { r.Members[2].Timeline = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			r := goodReport(now)
			edit(&r)
			o := loaded(t, r, &now)
			require.NotEqual(t, "healthy", o.View().State)
		})
	}
	r := goodReport(now)
	r.Members[2].DCSReady = false
	r.Members[2].DatabaseReady = false
	r.Members[2].Issue = "unavailable"
	view := loaded(t, r, &now).View()
	require.True(t, view.QuorumAvailable, "two live expected voters retain quorum while redundancy is degraded")
	require.Equal(t, "degraded", view.State)
}
func TestBoundedReportValidationAndForeignScope(t *testing.T) {
	now := time.Now().UTC()
	raw, err := json.Marshal(goodReport(now))
	require.NoError(t, err)
	bad := [][]byte{[]byte(strings.Repeat("x", MaxReportBytes+1)), append(append([]byte(nil), raw...), []byte("{}")...), []byte(strings.Replace(string(raw), `"schema":1`, `"schema":1,"unexpected":"secret"`, 1)), []byte(strings.Replace(string(raw), testCluster, "22222222-2222-4222-8222-222222222222", 1))}
	for _, value := range bad {
		_, err = Decode(value, testCluster, now)
		require.ErrorIs(t, err, ErrInvalid)
		require.NotContains(t, err.Error(), "secret")
	}
	for _, edit := range []func(*Report){func(r *Report) { r.CheckedAt = now.Add(5 * time.Second) }, func(r *Report) { r.Members[2].Name = r.Members[0].Name }, func(r *Report) { r.Members[2].DCSMemberID = r.Members[0].DCSMemberID }, func(r *Report) { r.Members[1].LeaderVerified = true }, func(r *Report) { r.Members[0].Issue = "<script>" }} {
		r := goodReport(now)
		edit(&r)
		value, err := json.Marshal(r)
		require.NoError(t, err)
		_, err = Decode(value, testCluster, now)
		require.Error(t, err)
	}
}
func TestReadFailureRetainsLastObservationButImmediatelyMarksItStale(t *testing.T) {
	now := time.Now().UTC()
	o := loaded(t, goodReport(now), &now)
	view := o.View()
	*view.Report.Members[0].LagBytes = 123
	require.Zero(t, *o.View().Report.Members[0].LagBytes, "callers cannot mutate the cached observation")
	o.load = func() ([]byte, error) { return nil, errors.New("private host path") }
	o.refresh()
	view = o.View()
	require.True(t, view.Stale)
	require.False(t, view.Available)
	require.NotNil(t, view.Report)
	empty := New(nil, testCluster).View()
	require.False(t, empty.Configured)
	require.Equal(t, "not_configured", empty.State)
}
