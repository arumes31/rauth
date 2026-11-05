package authstate_test

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A burst on one counter from one node is coalesced but stays exact: every
// caller gets a distinct count and the stored row holds the full total, also
// across a window reset and alongside another node's increments.
func TestSQLCounterBurstIsCoalescedAndExact(t *testing.T) {
	p, a, b := fixture(t)
	ctx := context.Background()
	burst := func(n int) []int64 {
		got := make([]int64, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() {
				c, err := a.Counters().Increment(ctx, "validate:198.51.100.7", time.Minute)
				assert.NoError(t, err)
				got[i] = c
			})
		}
		wg.Wait()
		slices.Sort(got)
		return got
	}
	got := burst(100)
	for i, v := range got {
		require.Equal(t, int64(i+1), v, "distinct counts 1..100")
	}
	n, err := b.Counters().Count(ctx, "validate:198.51.100.7")
	require.NoError(t, err)
	assert.Equal(t, int64(100), n)

	// Another node keeps counting the same global row.
	n, err = b.Counters().Increment(ctx, "validate:198.51.100.7", time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(101), n)

	// After the window expires, a coalesced batch starts a fresh window at 1..n.
	_, err = p.Exec(ctx, "UPDATE auth_security_counters SET expires_at=clock_timestamp()-interval '1 second'")
	require.NoError(t, err)
	got = burst(25)
	for i, v := range got {
		require.Equal(t, int64(i+1), v, "fresh window counts 1..25")
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = a.Counters().Increment(canceled, "validate:198.51.100.7", time.Minute)
	require.Error(t, err)
	n, err = b.Counters().Count(ctx, "validate:198.51.100.7")
	require.NoError(t, err)
	assert.Equal(t, int64(25), n, "a request canceled before joining does not count")
}
