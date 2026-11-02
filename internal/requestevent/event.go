// Package requestevent defines bounded operational decision metadata. It never
// accepts request headers, credentials, bodies, URL queries or fragments.
package requestevent

import (
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const MaxBatch = 100
const MaxEventBytes = 8192

var ErrInvalid = errors.New("invalid request event")

type MetricPoint struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
	Value  float64           `json:"value"`
}
type NodeHealth struct {
	Ready           bool      `json:"ready"`
	AuthReady       bool      `json:"auth_ready"`
	EnrollmentReady bool      `json:"enrollment_ready"`
	PolicyReady     bool      `json:"policy_ready"`
	Applied         int64     `json:"applied"`
	Desired         int64     `json:"desired"`
	LeaseExpiresAt  time.Time `json:"lease_expires_at"`
	LocalReady      bool      `json:"local_ready"`
	Pending         uint64    `json:"pending"`
	DiskBytes       int64     `json:"disk_bytes"`
	Oldest          time.Time `json:"oldest,omitempty"`
	Dropped         uint64    `json:"dropped"`
	UncleanRestarts uint64    `json:"unclean_restarts"`
	DeliveryReady   bool      `json:"delivery_ready"`
	LastDelivered   time.Time `json:"last_delivered,omitempty"`
}
type MetricSnapshot struct {
	Health        *NodeHealth   `json:"health,omitempty"`
	Schema        int           `json:"schema"`
	Diagnostics   bool          `json:"diagnostics,omitempty"`
	CaptureID     string        `json:"capture_id,omitempty"`
	Part          int           `json:"part,omitempty"`
	Parts         int           `json:"parts,omitempty"`
	InstanceID    string        `json:"instance_id"`
	StartedAt     time.Time     `json:"started_at"`
	GoVersion     string        `json:"go_version"`
	BuildRevision string        `json:"build_revision,omitempty"`
	Partial       bool          `json:"partial,omitempty"`
	Points        []MetricPoint `json:"points"`
}

func (s MetricSnapshot) Clone() MetricSnapshot {
	if s.Health != nil {
		h := *s.Health
		s.Health = &h
	}
	s.Points = append([]MetricPoint(nil), s.Points...)
	for i, point := range s.Points {
		if point.Labels != nil {
			labels := map[string]string{}
			for k, v := range point.Labels {
				labels[k] = v
			}
			s.Points[i].Labels = labels
		}
	}
	return s
}
func ValidateMetrics(s *MetricSnapshot, now time.Time) error {
	if s == nil || s.Schema != 1 || !ValidID(s.InstanceID) || s.StartedAt.IsZero() || s.StartedAt.After(now.Add(2*time.Minute)) || !text(s.GoVersion, 64) || !text(s.BuildRevision, 64) || len(s.Points) > 64 {
		return ErrInvalid
	}
	if h := s.Health; h != nil && (h.Applied < 0 || h.Desired < 0 || h.DiskBytes < 0 || h.Pending > 1<<40 || h.Dropped > 1<<53-1 || h.UncleanRestarts > 1<<40) {
		return ErrInvalid
	}
	if s.Diagnostics {
		if !ValidID(s.CaptureID) || s.Parts < 1 || s.Parts > 8 || s.Part < 0 || s.Part >= s.Parts {
			return ErrInvalid
		}
	} else if s.CaptureID != "" || s.Part != 0 || s.Parts != 0 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, point := range s.Points {
		keyRaw, _ := json.Marshal(point.Labels)
		key := point.Name + string(keyRaw)
		if len(point.Labels) > 4 || !s.Diagnostics && len(point.Labels) > 0 {
			return ErrInvalid
		}
		for name, value := range point.Labels {
			if name != "action" && name != "type" && name != "status" && name != "quantile" && name != "le" && name != "version" && name != "code" && name != "method" {
				return ErrInvalid
			}
			if len(value) > 64 || value == "" {
				return ErrInvalid
			}
			for _, r := range value {
				if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && !strings.ContainsRune("_.+-", r) {
					return ErrInvalid
				}
			}
		}

		if len(point.Name) == 0 || len(point.Name) > 96 || seen[key] || math.IsNaN(point.Value) || math.IsInf(point.Value, 0) || point.Value < 0 {
			return ErrInvalid
		}
		seen[key] = true
		for _, r := range point.Name {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
				return ErrInvalid
			}
		}
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > 6000 {
		return ErrInvalid
	}
	return nil
}

type Event struct {
	Metrics *MetricSnapshot `json:"metrics,omitempty"`

	ProcessingMicros int64     `json:"processing_us,omitempty"`
	LossTotal        uint64    `json:"loss_total,omitempty"`
	UncleanTotal     uint64    `json:"unclean_total,omitempty"`
	ID               uint64    `json:"id"`
	EventID          string    `json:"event_id,omitempty"`
	NodeID           string    `json:"node_id,omitempty"`
	NodeName         string    `json:"node_name,omitempty"`
	Time             time.Time `json:"time"`
	ReceivedAt       time.Time `json:"received_at,omitempty"`
	PolicyVersion    int64     `json:"policy_version,omitempty"`
	URL              string    `json:"url"`
	Source           string    `json:"source"`
	Country          string    `json:"country"`
	Action           string    `json:"action"`
	Status           int       `json:"status"`
	Reason           string    `json:"reason,omitempty"`
	Rule             string    `json:"rule,omitempty"`
	FeedID           string    `json:"feed_id,omitempty"`
	Kind             string    `json:"kind,omitempty"`
	Dropped          uint64    `json:"dropped,omitempty"`
	UnknownLoss      bool      `json:"unknown_loss,omitempty"`
}

func ValidName(raw string) bool { return raw != "" && text(raw, 64) }

func ValidID(raw string) bool {
	id, err := uuid.Parse(raw)
	return err == nil && id != uuid.Nil && id.String() == raw
}
func text(raw string, max int) bool {
	return utf8.ValidString(raw) && len(raw) <= max && !strings.ContainsFunc(raw, unicode.IsControl)
}

// Decision cleans local metadata before it crosses the asynchronous boundary.
// Ingestion additionally requires the submitted event to already be canonical.
func Decision(e Event) Event {
	e.ID = 0
	e.EventID = ""
	e.NodeID = ""
	e.NodeName = ""
	e.ReceivedAt = time.Time{}
	e.Metrics = nil
	e.Kind = "decision"
	e.Dropped = 0
	e.UnknownLoss = false
	e.LossTotal = 0
	e.UncleanTotal = 0
	if len(e.URL) > 16384 {
		e.URL = ""
	}
	if u, err := url.Parse(e.URL); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" {
		u.User = nil
		u.RawQuery = ""
		u.ForceQuery = false
		u.Fragment = ""
		u.RawFragment = ""
		e.URL = u.String()
	} else {
		e.URL = ""
	}
	if !text(e.URL, 2048) {
		e.URL = ""
	}
	if ip, err := netip.ParseAddr(e.Source); err == nil && ip.Zone() == "" {
		e.Source = ip.Unmap().String()
	} else {
		e.Source = "unknown"
	}
	if len(e.Country) != 2 || e.Country[0] < 'A' || e.Country[0] > 'Z' || e.Country[1] < 'A' || e.Country[1] > 'Z' {
		e.Country = "unknown"
	}
	switch e.Action {
	case "authenticated", "bypass", "login_required", "rate_limited", "blocked", "error":
	default:
		e.Action = "error"
	}
	if e.Status < 100 || e.Status > 599 {
		e.Status = 500
	}
	if !text(e.Reason, 64) {
		e.Reason = ""
	}
	if !text(e.Rule, 300) || strings.ContainsAny(e.Rule, "?#") {
		e.Rule = ""
	}
	if !text(e.FeedID, 64) {
		e.FeedID = ""
	}
	if e.ProcessingMicros < 0 {
		e.ProcessingMicros = 0
	}
	if e.ProcessingMicros > 600_000_000 {
		e.ProcessingMicros = 600_000_000
	}
	if e.PolicyVersion < 0 {
		e.PolicyVersion = 0
	}
	e.Time = e.Time.UTC()
	return e
}
func Validate(e Event, now time.Time) error {
	if e.ID != 0 || !e.ReceivedAt.IsZero() || !ValidID(e.EventID) || !ValidID(e.NodeID) || !ValidName(e.NodeName) || e.Time.IsZero() || e.Time.Before(now.Add(-48*time.Hour)) || e.Time.After(now.Add(2*time.Minute)) {
		return ErrInvalid
	}
	if e.LossTotal > 1<<53-1 || e.UncleanTotal > 1<<40 {
		return ErrInvalid
	}
	switch e.Kind {
	case "decision":
		if e.Metrics != nil {
			return ErrInvalid
		}
		clean := Decision(e)
		if clean.URL != e.URL || clean.Source != e.Source || clean.Country != e.Country || clean.Action != e.Action || clean.Status != e.Status || clean.Reason != e.Reason || clean.Rule != e.Rule || clean.FeedID != e.FeedID || clean.ProcessingMicros != e.ProcessingMicros || clean.PolicyVersion != e.PolicyVersion || e.Dropped != 0 || e.UnknownLoss || e.LossTotal != 0 || e.UncleanTotal != 0 {
			return ErrInvalid
		}
	case "gap":
		if e.Metrics != nil || e.URL != "" || e.Source != "" || e.Country != "" || e.Action != "" || e.Status != 0 || e.Rule != "" || e.FeedID != "" || e.ProcessingMicros != 0 || e.PolicyVersion != 0 {
			return ErrInvalid
		}
		switch e.Reason {
		case "queue_overflow", "queue_invalid", "storage_retention":
			if e.Dropped == 0 || e.Dropped > 1<<40 || e.UnknownLoss {
				return ErrInvalid
			}
		case "unclean_restart":
			if !e.UnknownLoss || e.Dropped != 0 {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	case "telemetry":
		if e.URL != "" || e.Source != "" || e.Country != "" || e.Action != "" || e.Status != 0 || e.Reason != "" || e.Rule != "" || e.FeedID != "" || e.ProcessingMicros != 0 || e.PolicyVersion != 0 || e.Dropped != 0 || e.UnknownLoss || e.LossTotal != 0 || e.UncleanTotal != 0 || ValidateMetrics(e.Metrics, now) != nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	b, err := json.Marshal(e)
	if err != nil || len(b) > MaxEventBytes {
		return ErrInvalid
	}
	return nil
}
