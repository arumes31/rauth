package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"rauth/internal/clusterpolicy"
	"rauth/internal/clustertransport"
	"strings"
	"sync"
	"time"
)

// Notices only wake the bounded HA-head poller. They are never lease evidence.
type policyNoticeHub struct {
	mu      sync.Mutex
	latest  clusterpolicy.Identity
	changed chan struct{}
	streams map[string]bool
}

func newPolicyNoticeHub() *policyNoticeHub {
	return &policyNoticeHub{changed: make(chan struct{}), streams: map[string]bool{}}
}
func validPolicyIdentity(id clusterpolicy.Identity) bool {
	decoded, err := hex.DecodeString(id.SHA256)
	return id.Revision > 0 && err == nil && len(decoded) == 32 && strings.ToLower(id.SHA256) == id.SHA256
}
func (h *policyNoticeHub) publish(id clusterpolicy.Identity) {
	if !validPolicyIdentity(id) {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if id.Revision <= h.latest.Revision {
		return
	}
	h.latest = id
	close(h.changed)
	h.changed = make(chan struct{})
}
func (h *policyNoticeHub) after() (clusterpolicy.Identity, <-chan struct{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.latest, h.changed
}
func (h *policyNoticeHub) acquire(node string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.streams[node] || len(h.streams) >= 64 {
		return false
	}
	h.streams[node] = true
	return true
}
func (h *policyNoticeHub) release(node string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.streams, node)
}

func policyNoticeHandler(h *policyNoticeHub, authorize clustertransport.Authorizer, assigned map[string]bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		peer, ok := clustertransport.PeerForScope(request.Context(), clustertransport.PolicyRead)
		if !ok || !assigned[peer.NodeID] {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if !h.acquire(peer.NodeID) {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "Policy stream already connected", http.StatusTooManyRequests)
			return
		}
		defer h.release(peer.NodeID)
		ctx, cancel := context.WithTimeout(request.Context(), 45*time.Second)
		defer cancel()
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Accel-Buffering", "no")
		controller := http.NewResponseController(w)
		send := func(identity *clusterpolicy.Identity) bool {
			if controller.SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
				return false
			}
			if identity == nil {
				if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
					return false
				}
			} else {
				if _, err := io.WriteString(w, "event: policy\ndata: "); err != nil {
					return false
				}
				if err := json.NewEncoder(w).Encode(identity); err != nil {
					return false
				}
				if _, err := io.WriteString(w, "\n"); err != nil {
					return false
				}
			}
			return controller.Flush() == nil
		}
		if !send(nil) {
			return
		}
		heartbeat := time.NewTicker(5 * time.Second)
		defer heartbeat.Stop()
		var previous clusterpolicy.Identity
		for {
			identity, changed := h.after()
			checkCtx, stop := context.WithTimeout(ctx, 3*time.Second)
			err := authorize(checkCtx, peer, clustertransport.PolicyRead)
			stop()
			if err != nil || ctx.Err() != nil {
				return
			}
			if identity != previous && validPolicyIdentity(identity) {
				if !send(&identity) {
					return
				}
				previous = identity
			}
			select {
			case <-ctx.Done():
				return
			case <-changed:
			case <-heartbeat.C:
				if !send(nil) {
					return
				}
			}
		}
	})
}

func readPolicyNotices(response *http.Response, notify func()) error {
	if response == nil || response.Body == nil {
		return errors.New("policy notification response is missing")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" {
		return errors.New("policy notification stream is unavailable")
	}
	scanner := bufio.NewScanner(io.LimitReader(response.Body, 64<<10))
	scanner.Buffer(make([]byte, 1024), 1024)
	lines, notices := 0, 0
	for scanner.Scan() {
		lines++
		if lines > 256 {
			return errors.New("policy notification stream exceeds line budget")
		}
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var identity clusterpolicy.Identity
		decoder := json.NewDecoder(strings.NewReader(strings.TrimPrefix(line, "data: ")))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&identity) != nil || decoder.Decode(new(any)) != io.EOF || !validPolicyIdentity(identity) {
			return errors.New("invalid policy notification")
		}
		notices++
		if notices > 64 {
			return errors.New("policy notification stream exceeds notice budget")
		}
		notify()
	}
	return scanner.Err()
}
func (r *clusterRuntime) followPolicyNotices() {
	for r.ctx.Err() == nil {
		request, err := http.NewRequestWithContext(r.ctx, http.MethodGet, r.spec.Controller.Endpoint+"/v1/policy-notices", nil)
		if err == nil {
			request.Header.Set("Accept", "text/event-stream")
			response, callErr := r.relayClient.Do(request)
			if callErr == nil {
				_ = readPolicyNotices(response, r.worker.Notify)
			}
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-r.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
