package core

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"rauth/internal/pgtest"
	"strings"
	"testing"
	"time"
)

type primaryCallbackStall struct{ seen chan time.Duration }

func (s *primaryCallbackStall) TraceQueryStart(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	if strings.Contains(q.SQL, "NOT pg_is_in_recovery()") {
		remaining := time.Duration(-1)
		if d, ok := ctx.Deadline(); ok {
			remaining = time.Until(d)
		}
		s.seen <- remaining
		timer := time.NewTimer(4 * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
		case <-timer.C:
		}
	}
	return ctx
}
func (*primaryCallbackStall) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func TestAuthenticationAfterConnectBoundsDetachedConstructor(t *testing.T) {
	fixture := pgtest.Open(t, Migrate)
	for _, shortParent := range []bool{false, true} {
		t.Run(map[bool]string{false: "own3s", true: "parentWins"}[shortParent], func(t *testing.T) {
			cfg := fixture.Config()
			require.NoError(t, configureAuthStateDatabase(&Config{AuthStateMode: "postgres"}, cfg))
			tracer := &primaryCallbackStall{make(chan time.Duration, 1)}
			cc := cfg.ConnConfig.Copy()
			cc.Tracer = tracer
			conn, err := pgx.ConnectConfig(t.Context(), cc)
			require.NoError(t, err)
			defer func() { _ = conn.Close(context.Background()) }()
			parent := context.Background()
			cancel := func() {}
			if shortParent {
				parent, cancel = context.WithTimeout(parent, 30*time.Millisecond)
			}
			defer cancel()
			started := time.Now()
			err = cfg.AfterConnect(parent, conn)
			elapsed := time.Since(started)
			require.ErrorIs(t, err, context.DeadlineExceeded)
			remaining := <-tracer.seen
			require.Positive(t, remaining)
			require.LessOrEqual(t, remaining, 3*time.Second)
			if shortParent {
				require.Less(t, elapsed, time.Second)
			} else {
				require.Greater(t, elapsed, 2800*time.Millisecond)
				require.Less(t, elapsed, 4*time.Second)
			}
		})
	}
}
func TestAuthenticationAfterConnectStillRejectsReadOnlyAuthority(t *testing.T) {
	fixture := pgtest.Open(t, Migrate)
	cfg := fixture.Config()
	require.NoError(t, configureAuthStateDatabase(&Config{AuthStateMode: "postgres"}, cfg))
	conn, err := pgx.ConnectConfig(t.Context(), cfg.ConnConfig.Copy())
	require.NoError(t, err)
	defer func() { _ = conn.Close(context.Background()) }()
	_, err = conn.Exec(t.Context(), "SET default_transaction_read_only=on")
	require.NoError(t, err)
	require.Error(t, cfg.AfterConnect(t.Context(), conn))
}

var _ pgx.QueryTracer = (*primaryCallbackStall)(nil)
