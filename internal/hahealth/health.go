// Package hahealth exposes bounded operational observations. No authorization
// or readiness decision may depend on this optional telemetry.
package hahealth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const MaxReportBytes = 64 << 10
const FreshFor = 15 * time.Second

var ErrInvalid = errors.New("HA observation unavailable")
var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
var decimalPattern = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Member struct {
	Name                 string    `json:"name"`
	DatabaseReady        bool      `json:"database_ready"`
	Role                 string    `json:"role"`
	LeaderVerified       bool      `json:"leader_verified"`
	SystemID             string    `json:"system_id,omitempty"`
	DCSClusterID         string    `json:"dcs_cluster_id,omitempty"`
	Timeline             uint64    `json:"timeline"`
	ServerVersion        uint64    `json:"server_version"`
	SyncReplicas         uint64    `json:"sync_replicas"`
	LagBytes             *uint64   `json:"lag_bytes,omitempty"`
	DCSReady             bool      `json:"dcs_ready"`
	DCSMemberID          string    `json:"dcs_member_id,omitempty"`
	DCSLeaderID          string    `json:"dcs_leader_id,omitempty"`
	DCSBytes             uint64    `json:"dcs_bytes"`
	DCSQuotaBytes        uint64    `json:"dcs_quota_bytes"`
	CertificateExpiresAt time.Time `json:"certificate_expires_at,omitzero"`
	DurationMS           uint64    `json:"duration_ms"`
	Issue                string    `json:"issue,omitempty"`
}
type Report struct {
	Schema               int       `json:"schema"`
	ClusterID            string    `json:"cluster_id"`
	Mode                 string    `json:"mode"`
	CheckedAt            time.Time `json:"checked_at"`
	ExpectedSystemID     string    `json:"expected_system_id"`
	ExpectedDCSClusterID string    `json:"expected_dcs_cluster_id"`
	Members              []Member  `json:"members"`
}
type View struct {
	Configured          bool    `json:"configured"`
	Available           bool    `json:"available"`
	Stale               bool    `json:"stale"`
	State               string  `json:"state"`
	QuorumAvailable     bool    `json:"quorum_available"`
	HealthyVoters       int     `json:"healthy_voters"`
	RunningDataMembers  int     `json:"running_data_members"`
	VerifiedLeaders     int     `json:"verified_leaders"`
	SynchronousReplicas uint64  `json:"synchronous_replicas"`
	Fencing             string  `json:"fencing"`
	Report              *Report `json:"report,omitempty"`
}

func Decode(raw []byte, cluster string, now time.Time) (*Report, error) {
	if len(raw) == 0 || len(raw) > MaxReportBytes {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var r Report
	if d.Decode(&r) != nil || d.Decode(&struct{}{}) != io.EOF || r.Schema != 1 || r.ClusterID != cluster || !uuidPattern.MatchString(r.ClusterID) || (r.Mode != "isolated-test" && r.Mode != "production") || !decimalPattern.MatchString(r.ExpectedSystemID) || !decimalPattern.MatchString(r.ExpectedDCSClusterID) || len(r.Members) != 3 || r.CheckedAt.IsZero() || r.CheckedAt.After(now.Add(2*time.Second)) {
		return nil, ErrInvalid
	}
	names := map[string]bool{}
	ids := map[string]bool{}
	for _, m := range r.Members {
		if !namePattern.MatchString(m.Name) || names[m.Name] || m.DurationMS > 10000 || m.Timeline > 1<<32-1 || m.ServerVersion > 999999 || m.SyncReplicas > 2 || m.DCSBytes > 1<<40 || m.DCSQuotaBytes > 1<<40 || m.LagBytes != nil && *m.LagBytes > 1<<60 {
			return nil, ErrInvalid
		}
		names[m.Name] = true
		switch m.Role {
		case "primary", "replica", "unknown":
		default:
			return nil, ErrInvalid
		}
		switch m.Issue {
		case "", "unavailable", "database_unavailable", "dcs_unavailable", "identity_mismatch", "invalid_response":
		default:
			return nil, ErrInvalid
		}
		if m.LeaderVerified && (!m.DatabaseReady || m.Role != "primary") {
			return nil, ErrInvalid
		}
		if m.DCSReady && (!decimalPattern.MatchString(m.DCSMemberID) || !decimalPattern.MatchString(m.DCSLeaderID) || m.DCSQuotaBytes == 0 || m.DCSBytes > m.DCSQuotaBytes || ids[m.DCSMemberID]) {
			return nil, ErrInvalid
		}
		if m.SystemID != "" && !decimalPattern.MatchString(m.SystemID) || m.DCSClusterID != "" && !decimalPattern.MatchString(m.DCSClusterID) {
			return nil, ErrInvalid
		}
		if m.DCSMemberID != "" && !decimalPattern.MatchString(m.DCSMemberID) || m.DCSLeaderID != "" && !decimalPattern.MatchString(m.DCSLeaderID) {
			return nil, ErrInvalid
		}
		if m.DCSReady {
			ids[m.DCSMemberID] = true
		}
	}
	return &r, nil
}

type Observer struct {
	mu      sync.RWMutex
	load    func() ([]byte, error)
	cluster string
	report  *Report
	lastErr bool
	now     func() time.Time
	descs   map[string]*prometheus.Desc
}

func New(load func() ([]byte, error), cluster string) *Observer {
	o := &Observer{load: load, cluster: cluster, now: time.Now, descs: map[string]*prometheus.Desc{}}
	for name, help := range map[string]string{
		"configured":                "Whether a guarded HA observation source is configured.",
		"fresh":                     "Whether the HA observation is available and fresh.",
		"checked_timestamp_seconds": "Unix time of the latest successfully decoded HA observation.",
		"healthy_voters":            "Number of observed healthy etcd voters in the expected cluster.",
		"running_data_members":      "Number of observed running PostgreSQL members with the expected identity.",
		"verified_leaders":          "Number of PostgreSQL leaders passing the current lease-aware primary endpoint.",
		"synchronous_replicas":      "Observed synchronous replicas of the verified primary.",
		"quorum_available":          "Whether the expected etcd quorum and leader identities are observed.",
	} {
		o.descs[name] = prometheus.NewDesc("rauth_ha_observation_"+name, help, nil, nil)
	}
	return o
}
func (o *Observer) refresh() {
	if o == nil || o.load == nil {
		return
	}
	raw, err := o.load()
	var r *Report
	if err == nil {
		r, err = Decode(raw, o.cluster, o.now())
	}
	o.mu.Lock()
	if err == nil {
		o.report = r
	}
	o.lastErr = err != nil
	o.mu.Unlock()
}
func (o *Observer) Run(ctx context.Context) {
	o.refresh()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			o.refresh()
		}
	}
}
func (o *Observer) View() View {
	v := View{Configured: o != nil && o.load != nil, State: "not_configured", Fencing: "not_observed"}
	if !v.Configured {
		return v
	}
	o.mu.RLock()
	r := o.report
	failed := o.lastErr
	if r != nil {
		clone := *r
		clone.Members = append([]Member(nil), r.Members...)
		for i := range clone.Members {
			if clone.Members[i].LagBytes != nil {
				value := *clone.Members[i].LagBytes
				clone.Members[i].LagBytes = &value
			}
		}
		r = &clone
	}
	o.mu.RUnlock()
	v.Report = r
	v.State = "unavailable"
	if r == nil {
		return v
	}
	age := o.now().Sub(r.CheckedAt)
	v.Stale = failed || age < -2*time.Second || age > FreshFor
	if v.Stale {
		v.State = "stale"
		return v
	}
	v.Available = true
	v.State = "degraded"
	leaders := map[string]bool{}
	voterIDs := map[string]bool{}
	consistent := true
	primaryTimeline := uint64(0)
	for _, m := range r.Members {
		if m.DatabaseReady && m.SystemID == r.ExpectedSystemID && m.Role != "unknown" {
			v.RunningDataMembers++
		}
		if m.DCSReady && m.DCSClusterID == r.ExpectedDCSClusterID {
			v.HealthyVoters++
			leaders[m.DCSLeaderID] = true
			voterIDs[m.DCSMemberID] = true
		}
		if m.LeaderVerified && m.SystemID == r.ExpectedSystemID {
			v.VerifiedLeaders++
			v.SynchronousReplicas += m.SyncReplicas
			primaryTimeline = m.Timeline
		}
	}
	for leader := range leaders {
		if !voterIDs[leader] {
			consistent = false
		}
	}
	v.QuorumAvailable = v.HealthyVoters >= 2 && len(leaders) == 1 && consistent
	for _, m := range r.Members {
		if m.SystemID != r.ExpectedSystemID || m.DCSClusterID != r.ExpectedDCSClusterID || m.Issue != "" || m.Timeline != primaryTimeline || (!m.CertificateExpiresAt.IsZero() && !m.CertificateExpiresAt.After(o.now())) {
			consistent = false
		}
	}
	if v.QuorumAvailable && consistent && v.HealthyVoters == 3 && v.RunningDataMembers == 3 && v.VerifiedLeaders == 1 && v.SynchronousReplicas >= 1 {
		v.State = "healthy"
	}
	return v
}
func (o *Observer) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range o.descs {
		ch <- d
	}
}
func (o *Observer) Collect(ch chan<- prometheus.Metric) {
	v := o.View()
	values := map[string]float64{"configured": 0, "fresh": 0}
	if v.Configured {
		values["configured"] = 1
	}
	if v.Available {
		values["fresh"] = 1
		values["quorum_available"] = 0
		if v.QuorumAvailable {
			values["quorum_available"] = 1
		}
		values["healthy_voters"] = float64(v.HealthyVoters)
		values["running_data_members"] = float64(v.RunningDataMembers)
		values["verified_leaders"] = float64(v.VerifiedLeaders)
		values["synchronous_replicas"] = float64(v.SynchronousReplicas)
	}
	if v.Report != nil {
		values["checked_timestamp_seconds"] = float64(v.Report.CheckedAt.Unix())
	}
	for name, value := range values {
		ch <- prometheus.MustNewConstMetric(o.descs[name], prometheus.GaugeValue, value)
	}
}
