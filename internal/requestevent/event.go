// Package requestevent defines bounded operational decision metadata. It never
// accepts request headers, credentials, bodies, URL queries or fragments.
package requestevent

import (
	"encoding/json"
	"errors"
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

type Event struct {
	LossTotal     uint64    `json:"loss_total,omitempty"`
	UncleanTotal  uint64    `json:"unclean_total,omitempty"`
	ID            uint64    `json:"id"`
	EventID       string    `json:"event_id,omitempty"`
	NodeID        string    `json:"node_id,omitempty"`
	NodeName      string    `json:"node_name,omitempty"`
	Time          time.Time `json:"time"`
	ReceivedAt    time.Time `json:"received_at,omitempty"`
	PolicyVersion int64     `json:"policy_version,omitempty"`
	URL           string    `json:"url"`
	Source        string    `json:"source"`
	Country       string    `json:"country"`
	Action        string    `json:"action"`
	Status        int       `json:"status"`
	Reason        string    `json:"reason,omitempty"`
	Rule          string    `json:"rule,omitempty"`
	FeedID        string    `json:"feed_id,omitempty"`
	Kind          string    `json:"kind,omitempty"`
	Dropped       uint64    `json:"dropped,omitempty"`
	UnknownLoss   bool      `json:"unknown_loss,omitempty"`
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
		clean := Decision(e)
		if clean.URL != e.URL || clean.Source != e.Source || clean.Country != e.Country || clean.Action != e.Action || clean.Status != e.Status || clean.Reason != e.Reason || clean.Rule != e.Rule || clean.FeedID != e.FeedID || clean.PolicyVersion != e.PolicyVersion || e.Dropped != 0 || e.UnknownLoss || e.LossTotal != 0 || e.UncleanTotal != 0 {
			return ErrInvalid
		}
	case "gap":
		if e.URL != "" || e.Source != "" || e.Country != "" || e.Action != "" || e.Status != 0 || e.Rule != "" || e.FeedID != "" || e.PolicyVersion != 0 {
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
	default:
		return ErrInvalid
	}
	b, err := json.Marshal(e)
	if err != nil || len(b) > MaxEventBytes {
		return ErrInvalid
	}
	return nil
}
