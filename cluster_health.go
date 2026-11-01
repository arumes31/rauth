package main

import (
	"context"
	"sync"
	"time"
)

// Only health observations are cached. Private RPC authorization remains live.
type clusterHealth struct {
	mu                 sync.RWMutex
	refreshMu          sync.Mutex
	authority          func(context.Context) error
	enrollment         func(context.Context) error
	now                func() time.Time
	checkedAt          time.Time
	authOK, enrolledOK bool
}

func newClusterHealth(authority, enrollment func(context.Context) error) *clusterHealth {
	return &clusterHealth{authority: authority, enrollment: enrollment, now: time.Now}
}
func (h *clusterHealth) refresh(parent context.Context) {
	if !h.refreshMu.TryLock() {
		return
	}
	defer h.refreshMu.Unlock()
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	authOK := h.authority(ctx) == nil
	enrolledOK := h.enrollment(ctx) == nil
	h.mu.Lock()
	h.checkedAt = h.now()
	h.authOK, h.enrolledOK = authOK, enrolledOK
	h.mu.Unlock()
}
func (h *clusterHealth) status() (bool, bool) {
	if h == nil {
		return false, false
	}
	h.mu.RLock()
	checked, authOK, enrolledOK := h.checkedAt, h.authOK, h.enrolledOK
	h.mu.RUnlock()
	age := h.now().Sub(checked)
	if checked.IsZero() || age < 0 || age > 6*time.Second {
		return false, false
	}
	return authOK, enrolledOK
}
func (h *clusterHealth) run(ctx context.Context) {
	for ctx.Err() == nil {
		h.refresh(ctx)
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
