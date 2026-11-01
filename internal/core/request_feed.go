package core

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const RequestFeedCapacity = 1000
const RequestFeedBatch = 100

var feedEpoch atomic.Uint64
var LiveRequests = NewRequestFeed(RequestFeedCapacity)

// RequestEvent contains operational request metadata, never session credentials.
type RequestEvent struct {
	ID      uint64    `json:"id"`
	Time    time.Time `json:"time"`
	URL     string    `json:"url"`
	Source  string    `json:"source"`
	Country string    `json:"country"`
	Action  string    `json:"action"`
	Status  int       `json:"status"`
}

// RequestFeed retains a bounded history. Notifications wake readers without
// queuing per-viewer messages or blocking the authentication request on I/O.
type RequestFeed struct {
	mu           sync.RWMutex
	epoch        string
	events       []RequestEvent
	start, count int
	latest       uint64
	changed      chan struct{}
}

type RequestBatch struct {
	Events         []RequestEvent
	Oldest, Latest uint64
	Changed        <-chan struct{}
}

func NewRequestFeed(capacity int) *RequestFeed {
	if capacity < 1 || capacity > RequestFeedCapacity {
		capacity = RequestFeedCapacity
	}
	return &RequestFeed{
		epoch:  fmt.Sprintf("%x-%x", time.Now().UnixNano(), feedEpoch.Add(1)),
		events: make([]RequestEvent, capacity), changed: make(chan struct{}),
	}
}

func (f *RequestFeed) Epoch() string { return f.epoch }

func (f *RequestFeed) Append(event RequestEvent) {
	event.URL = boundedFeedText(event.URL, 2048)
	if ip := net.ParseIP(event.Source); ip != nil {
		event.Source = ip.String()
	} else {
		event.Source = "unknown"
	}
	event.Country = boundedFeedText(event.Country, 32)
	switch event.Action {
	case "authenticated", "bypass", "login_required", "rate_limited", "blocked", "error":
	default:
		event.Action = "error"
	}
	event.Time = time.Now().UTC()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.latest++
	event.ID = f.latest
	if f.count < len(f.events) {
		f.events[(f.start+f.count)%len(f.events)] = event
		f.count++
	} else {
		f.events[f.start] = event
		f.start = (f.start + 1) % len(f.events)
	}
	close(f.changed)
	f.changed = make(chan struct{})
}

func (f *RequestFeed) After(cursor uint64) RequestBatch {
	f.mu.RLock()
	defer f.mu.RUnlock()
	b := RequestBatch{Latest: f.latest, Changed: f.changed, Events: []RequestEvent{}}
	if f.count == 0 {
		return b
	}
	b.Oldest = f.events[f.start].ID
	for i := 0; i < f.count && len(b.Events) < RequestFeedBatch; i++ {
		event := f.events[(f.start+i)%len(f.events)]
		if event.ID > cursor {
			b.Events = append(b.Events, event)
		}
	}
	return b
}

func boundedFeedText(s string, max int) string {
	r := []rune(strings.ToValidUTF8(s, ""))
	if len(r) > max {
		r = r[:max]
	}
	return string(r)
}

// ProtectedRequestURL drops userinfo, query strings and fragments before any
// request metadata enters the feed. Only call it with trusted proxy headers.
func ProtectedRequestURL(scheme, host, target string) string {
	if scheme != "http" && scheme != "https" {
		scheme = "https"
	}
	if host == "" || target == "" || len(host) > 512 || len(target) > 16384 || strings.ContainsAny(host, "\\\r\n\t /?#") {
		return ""
	}
	origin, err := url.Parse(scheme + "://" + host)
	if err != nil || origin.Hostname() == "" {
		return ""
	}
	target, _, _ = strings.Cut(target, "#")
	u, err := url.ParseRequestURI(target)
	if err != nil || (!u.IsAbs() && !strings.HasPrefix(target, "/")) {
		return ""
	}
	u.Scheme = scheme
	u.Host = origin.Host
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	return boundedFeedText(u.String(), 2048)
}
