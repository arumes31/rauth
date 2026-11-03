package eventstore

import (
	"context"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
	"time"
)

// Lifecycle and observation both heartbeat the same reserved session.
func TestConcurrentCollectorHeartbeatsAcrossWAN(t *testing.T) {
	for _, delay := range []time.Duration{225 * time.Millisecond, 400 * time.Millisecond} {
		t.Run(delay.String(), func(t *testing.T) {
			s, _, _, _ := coldReaderStore(t, delay)
			pid := s.lock.Conn().PgConn().PID()
			for round := 0; round < 3; round++ {
				var wg sync.WaitGroup
				errors := make([]error, 2)
				elapsed := make([]time.Duration, 2)
				start := make(chan struct{})
				for i := range errors {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						<-start
						ctx, cancel := context.WithTimeout(context.Background(), HealthTimeout)
						defer cancel()
						at := time.Now()
						_, errors[i] = s.Status(ctx)
						elapsed[i] = time.Since(at)
					}(i)
				}
				close(start)
				wg.Wait()
				for i, err := range errors {
					require.NoError(t, err, "round %d probe %d elapsed %s", round, i, elapsed[i])
					require.Less(t, elapsed[i], HealthTimeout)
				}
			}
			require.Equal(t, pid, s.lock.Conn().PgConn().PID(), "healthy probes must retain the original ownership session")
		})
	}
}

func TestCollectorWANHeartbeatStillRejectsStaleOwner(t *testing.T) {
	s, enabled, _, _ := coldReaderStore(t, 400*time.Millisecond)
	enabled.Store(false)
	_, err := s.pool.Exec(background, "UPDATE event_ledgers SET owner_token=$2 WHERE cluster_id=$1", s.options.ClusterID, uuid.NewString())
	require.NoError(t, err)
	enabled.Store(true)
	ctx, cancel := context.WithTimeout(background, HealthTimeout)
	defer cancel()
	_, err = s.Status(ctx)
	require.ErrorIs(t, err, ErrUnavailable, "WAN budget must not bypass live owner-token fencing")
}

func TestCollectorWANHeartbeatHonorsShortParent(t *testing.T) {
	s, enabled, _, _ := coldReaderStore(t, 400*time.Millisecond)
	ctx, cancel := context.WithTimeout(background, 50*time.Millisecond)
	defer cancel()
	at := time.Now()
	_, err := s.Status(ctx)
	enabled.Store(false)
	require.ErrorIs(t, err, ErrUnavailable)
	require.Less(t, time.Since(at), time.Second, "the health budget must not replace the caller cancellation")
}
