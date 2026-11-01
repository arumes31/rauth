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
