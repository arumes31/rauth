package main

import (
	"github.com/stretchr/testify/require"
	"rauth/internal/core"
	"testing"
	"time"
)

func TestEventAdmissionWithoutReadySpoolNeverWaitsOrTouchesAuthentication(t *testing.T) {
	var absent *clusterEvents
	require.NotPanics(t, func() { absent.record(core.RequestEvent{}) })
	events := &clusterEvents{}
	start := time.Now()
	for range 10000 {
		events.record(core.RequestEvent{})
	}
	require.Less(t, time.Since(start), time.Second)
	require.EqualValues(t, 10000, events.earlyDrops.Load())
}
func TestEventHealthExpiresIndependentlyOfAuthHealth(t *testing.T) {
	events := &clusterEvents{cached: clusterEventHealth{Configured: true, LocalReady: true, CollectorReady: true, CheckedAt: time.Now()}}
	require.True(t, events.snapshot().LocalReady)
	for _, at := range []time.Time{time.Time{}, time.Now().Add(-7 * time.Second), time.Now().Add(time.Second)} {
		events.cached.CheckedAt = at
		got := events.snapshot()
		require.False(t, got.LocalReady)
		require.False(t, got.CollectorReady)
		require.True(t, got.Configured)
	}
}
