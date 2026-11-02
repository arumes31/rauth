package eventstore

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"rauth/internal/requestevent"
)

func TestStatisticsOptionalTimeoutKeepsSnapshotUsable(t *testing.T) {
	pool := setup(t)
	s := open(t, pool, options())
	node := uuid.NewString()
	_, err := s.Ingest(background, node, []requestevent.Event{decision(node)})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(background, 2*time.Second)
	defer cancel()
	tx, err := s.stats.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(background) }()
	top, unavailable, err := queryOptionalTop(ctx, tx, []any{s.options.ClusterID}, "cluster_id=$1 AND EXISTS(SELECT 1 FROM pg_sleep(1))")
	require.NoError(t, err)
	require.True(t, unavailable)
	require.Empty(t, top)
	var count int
	require.NoError(t, tx.QueryRow(ctx, "SELECT count(*) FROM request_events").Scan(&count))
	require.Equal(t, 1, count)
	var timeout string
	require.NoError(t, tx.QueryRow(ctx, "SHOW statement_timeout").Scan(&timeout))
	require.Equal(t, "1500ms", timeout)
	require.NoError(t, tx.Commit(ctx))
}
