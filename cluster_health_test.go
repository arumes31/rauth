package main

import (
	"context"
	"errors"
	"github.com/stretchr/testify/assert"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClusterHealthRequestsNeverTriggerDatabaseChecks(t *testing.T) {
	var authority, enrollment atomic.Int32
	h := newClusterHealth(func(context.Context) error { authority.Add(1); return nil }, func(context.Context) error { enrollment.Add(1); return nil })
	a, e := h.status()
	assert.False(t, a)
	assert.False(t, e)
	h.refresh(context.Background())
	var requests sync.WaitGroup
	for range 1000 {
		requests.Go(func() { a, e := h.status(); assert.True(t, a); assert.True(t, e) })
	}
	requests.Wait()
	assert.EqualValues(t, 1, authority.Load())
	assert.EqualValues(t, 1, enrollment.Load())
}
func TestClusterHealthExpiresAndPreservesFailedEnrollment(t *testing.T) {
	now := time.Now()
	denied := false
	h := newClusterHealth(func(context.Context) error { return nil }, func(context.Context) error {
		if denied {
			return errors.New("not enrolled")
		}
		return nil
	})
	h.now = func() time.Time { return now }
	h.refresh(context.Background())
	a, e := h.status()
	assert.True(t, a)
	assert.True(t, e)
	now = now.Add(7 * time.Second)
	a, e = h.status()
	assert.False(t, a)
	assert.False(t, e)
	denied = true
	h.refresh(context.Background())
	a, e = h.status()
	assert.True(t, a)
	assert.False(t, e)
}
func TestClusterHealthChecksHonorCancellation(t *testing.T) {
	check := func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
	h := newClusterHealth(check, check)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	h.refresh(ctx)
	assert.Less(t, time.Since(start), time.Second)
	a, e := h.status()
	assert.False(t, a)
	assert.False(t, e)
}

func TestClusterHealthIndependentProbesShareDeadlineAndJoin(t *testing.T) {
	entered := make(chan time.Time, 2)
	release := make(chan struct{})
	check := func(ctx context.Context) error {
		deadline, ok := ctx.Deadline()
		if !ok {
			return errors.New("missing health deadline")
		}
		entered <- deadline
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	h := newClusterHealth(check, check)
	finished := make(chan struct{})
	go func() { h.refresh(context.Background()); close(finished) }()
	var deadlines []time.Time
	for range 2 {
		select {
		case d := <-entered:
			deadlines = append(deadlines, d)
		case <-time.After(time.Second):
			t.Fatal("independent health probes must overlap")
		}
	}
	assert.True(t, deadlines[0].Equal(deadlines[1]))
	a, e := h.status()
	assert.False(t, a)
	assert.False(t, e)
	h.refresh(context.Background()) // Existing refresh exclusion prevents a second pair.
	close(release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("health join did not finish")
	}
	a, e = h.status()
	assert.True(t, a)
	assert.True(t, e)
	assert.Empty(t, entered)
}
