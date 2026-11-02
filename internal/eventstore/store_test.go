package eventstore

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"rauth/internal/pgtest"
	"rauth/internal/requestevent"
	"strings"
	"testing"
	"time"
)

var background = context.Background()

func options() Options {
	return Options{ClusterID: uuid.NewString(), MaxBytes: 16 << 20, MaxAge: 7 * 24 * time.Hour}
}
func setup(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := pgtest.Open(t, Migrate)
	_, err := pool.Exec(background, "TRUNCATE event_node_samples,event_traffic_minute,request_events,event_ledgers")
	require.NoError(t, err)
	return pool
}
func open(t *testing.T, pool *pgxpool.Pool, o Options) *Store {
	t.Helper()
	var role string
	require.NoError(t, pool.QueryRow(background, "SELECT current_user").Scan(&role))
	require.NoError(t, Provision(background, pool, o, role))
	s, err := Open(background, pool, o)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	return s
}
func decision(node string) requestevent.Event {
	e := requestevent.Decision(requestevent.Event{Time: time.Now().UTC(), URL: "https://example.com/documents", Source: "192.0.2.1", Country: "US", Action: "authenticated", Status: 200})
	e.EventID = uuid.NewString()
	e.NodeID = node
	e.NodeName = "test-node"
	return e
}
func TestCollectorCommitDedupConflictAndRestartCursor(t *testing.T) {
	pool := setup(t)
	o := options()
	s := open(t, pool, o)
	node := uuid.NewString()
	one := decision(node)
	ack, err := s.Ingest(background, node, []requestevent.Event{one})
	require.NoError(t, err)
	require.Equal(t, []string{one.EventID}, ack)
	_, err = s.Ingest(background, node, []requestevent.Event{one})
	require.NoError(t, err)
	batch, err := s.After(background, 0, "")
	require.NoError(t, err)
	require.Len(t, batch.Events, 1)
	require.EqualValues(t, 1, batch.Events[0].ID)
	require.False(t, batch.Events[0].ReceivedAt.IsZero())
	conflicting := one
	conflicting.Status = 403
	conflicting.Action = "blocked"
	_, err = s.Ingest(background, node, []requestevent.Event{conflicting})
	require.ErrorIs(t, err, ErrConflict)
	foreign := decision(uuid.NewString())
	_, err = s.Ingest(background, node, []requestevent.Event{foreign})
	require.ErrorIs(t, err, ErrInvalid)
	private := decision(node)
	private.URL += "?token=secret"
	_, err = s.Ingest(background, node, []requestevent.Event{private})
	require.ErrorIs(t, err, ErrInvalid)
	epoch := s.Epoch()
	require.NoError(t, s.Close())
	s = open(t, pool, o)
	require.Equal(t, epoch, s.Epoch())
	two := decision(node)
	_, err = s.Ingest(background, node, []requestevent.Event{two})
	require.NoError(t, err)
	batch, err = s.After(background, 1, node)
	require.NoError(t, err)
	require.Len(t, batch.Events, 1)
	require.Equal(t, two.EventID, batch.Events[0].EventID)
	require.EqualValues(t, 2, batch.Events[0].ID)
}
func TestCollectorFailedTransactionNeverReturnsAcknowledgment(t *testing.T) {
	pool := setup(t)
	s := open(t, pool, options())
	_, err := pool.Exec(background, `CREATE FUNCTION event_test_disk_full() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic full event filesystem' USING ERRCODE='53100'; END $$;CREATE TRIGGER event_test_disk_full BEFORE INSERT ON request_events FOR EACH ROW EXECUTE FUNCTION event_test_disk_full()`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(background, "DROP TRIGGER IF EXISTS event_test_disk_full ON request_events;DROP FUNCTION IF EXISTS event_test_disk_full()")
	})
	node := uuid.NewString()
	ack, err := s.Ingest(background, node, []requestevent.Event{decision(node)})
	require.Error(t, err)
	require.Nil(t, ack)
	st, err := s.Status(background)
	require.NoError(t, err)
	require.Zero(t, st.Retained)
	batch, err := s.After(background, 0, "")
	require.NoError(t, err)
	require.Zero(t, batch.Latest)
}
func TestNodeFilterTraversesGlobalDurableCursor(t *testing.T) {
	pool := setup(t)
	s := open(t, pool, options())
	a, b := uuid.NewString(), uuid.NewString()
	for _, node := range []string{a, b, b} {
		_, err := s.Ingest(background, node, []requestevent.Event{decision(node)})
		require.NoError(t, err)
	}
	batch, err := s.After(background, 0, a)
	require.NoError(t, err)
	require.Len(t, batch.Events, 1)
	require.EqualValues(t, 3, batch.Next)
}
func TestLedgerActorLockAndDurableFencing(t *testing.T) {
	pool := setup(t)
	o := options()
	s := open(t, pool, o)
	ctx, cancel := context.WithTimeout(background, time.Second)
	defer cancel()
	_, err := Open(ctx, pool, o)
	require.ErrorIs(t, err, ErrUnavailable)
	_, err = pool.Exec(background, "UPDATE event_ledgers SET owner_token=$1 WHERE cluster_id=$2", uuid.NewString(), o.ClusterID)
	require.NoError(t, err)
	node := uuid.NewString()
	_, err = s.Ingest(background, node, []requestevent.Event{decision(node)})
	require.ErrorIs(t, err, ErrUnavailable)
	require.ErrorIs(t, s.Maintain(background), ErrUnavailable)
}
func TestRuntimeRoleCannotReadOrWriteAnotherLedger(t *testing.T) {
	pool := setup(t)
	other := open(t, pool, options())
	node := uuid.NewString()
	_, err := other.Ingest(background, node, []requestevent.Event{decision(node)})
	require.NoError(t, err)
	role := "event_test_" + uuid.NewString()[:8]
	ident := pgx.Identifier{role}.Sanitize()
	schema := pgx.Identifier{pool.Config().ConnConfig.RuntimeParams["search_path"]}.Sanitize()
	_, err = pool.Exec(background, "CREATE ROLE "+ident+" LOGIN PASSWORD 'rauth-event-fixture-only'")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(background, "DROP OWNED BY "+ident+";DROP ROLE "+ident) })
	_, err = pool.Exec(background, "GRANT USAGE ON SCHEMA "+schema+" TO "+ident+";GRANT SELECT ON event_schema_version TO "+ident+";GRANT SELECT,UPDATE ON event_ledgers TO "+ident+";GRANT SELECT,INSERT,DELETE ON request_events TO "+ident+";GRANT SELECT,INSERT,UPDATE,DELETE ON event_traffic_minute,event_node_samples TO "+ident)
	require.NoError(t, err)
	o := options()
	require.NoError(t, Provision(background, pool, o, role))
	cfg := pool.Config()
	cfg.ConnConfig.User = role
	cfg.ConnConfig.Password = "rauth-event-fixture-only"
	cfg.MaxConns = 3
	restricted, err := pgxpool.NewWithConfig(background, cfg)
	require.NoError(t, err)
	defer restricted.Close()
	own, err := Open(background, restricted, o)
	require.NoError(t, err)
	defer func() { _ = own.Close() }()
	var count int
	require.NoError(t, restricted.QueryRow(background, "SELECT count(*) FROM request_events").Scan(&count))
	require.Zero(t, count)
	_, err = restricted.Exec(background, `INSERT INTO request_events(cluster_id,seq,node_id,event_id,occurred_at,received_at,payload,size) VALUES($1,999,$2,$3,clock_timestamp(),clock_timestamp(),'x',1)`, other.options.ClusterID, node, uuid.NewString())
	require.Error(t, err)
	_, err = own.Ingest(background, node, []requestevent.Event{decision(node)})
	require.NoError(t, err)
	_, err = restricted.Exec(background, "CREATE TABLE event_role_must_not_create(id int)")
	require.Error(t, err)
	require.Error(t, Migrate(background, restricted))
}
func TestNonSuperuserOperatorCanProvisionDifferentRuntimeOwner(t *testing.T) {
	pool := setup(t)
	operator := "event_op_" + uuid.NewString()[:8]
	runtimeRole := "event_run_" + uuid.NewString()[:8]
	schemaName := "event_schema_" + uuid.NewString()[:8]
	op, run, sch := pgx.Identifier{operator}.Sanitize(), pgx.Identifier{runtimeRole}.Sanitize(), pgx.Identifier{schemaName}.Sanitize()
	_, err := pool.Exec(background, "CREATE ROLE "+op+" LOGIN PASSWORD 'rauth-event-fixture-only';CREATE ROLE "+run+";CREATE SCHEMA "+sch+" AUTHORIZATION "+op)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(background, "DROP SCHEMA "+sch+" CASCADE;DROP OWNED BY "+op+";DROP ROLE "+op+";DROP ROLE "+run)
	})
	cfg := pool.Config()
	cfg.ConnConfig.User = operator
	cfg.ConnConfig.Password = "rauth-event-fixture-only"
	cfg.ConnConfig.RuntimeParams["search_path"] = schemaName
	restricted, err := pgxpool.NewWithConfig(background, cfg)
	require.NoError(t, err)
	defer restricted.Close()
	require.NoError(t, Migrate(background, restricted))
	o := options()
	require.NoError(t, Provision(background, restricted, o, runtimeRole))
	var owner string
	require.NoError(t, restricted.QueryRow(background, "SELECT owner_role::text FROM event_ledgers WHERE cluster_id=$1", o.ClusterID).Scan(&owner))
	require.Equal(t, runtimeRole, owner)
}
func TestRetentionPrunesOnlyNecessaryEventsAndReportsWatermark(t *testing.T) {
	pool := setup(t)
	o := options()
	o.MaxBytes = 1 << 20
	s := open(t, pool, o)
	node := uuid.NewString()
	var last requestevent.Event
	for range 6 {
		events := make([]requestevent.Event, 100)
		for i := range events {
			events[i] = decision(node)
			events[i].URL = "https://example.com/" + strings.Repeat("x", 1750)
		}
		last = events[99]
		_, err := s.Ingest(background, node, events)
		require.NoError(t, err)
	}
	before, err := s.Status(background)
	require.NoError(t, err)
	require.Positive(t, before.Expired)
	one := decision(node)
	one.URL = last.URL
	_, err = s.Ingest(background, node, []requestevent.Event{one})
	require.NoError(t, err)
	after, err := s.Status(background)
	require.NoError(t, err)
	require.LessOrEqual(t, after.Expired-before.Expired, uint64(2))
	_, err = s.Ingest(background, node, []requestevent.Event{one})
	require.NoError(t, err)
	again, err := s.Status(background)
	require.NoError(t, err)
	require.Equal(t, after.Expired, again.Expired)
	s.now = func() time.Time { return time.Now().Add(8 * 24 * time.Hour) }
	require.NoError(t, s.Maintain(background))
	st, err := s.Status(background)
	require.NoError(t, err)
	require.Zero(t, st.Retained)
	batch, err := s.After(background, 0, "")
	require.NoError(t, err)
	require.Equal(t, batch.Latest, batch.PrunedThrough)
	require.Positive(t, batch.Latest)
}
func TestReadOnlyAuthorityCannotClaimCollector(t *testing.T) {
	pool := setup(t)
	o := options()
	var role string
	require.NoError(t, pool.QueryRow(background, "SELECT current_user").Scan(&role))
	require.NoError(t, Provision(background, pool, o, role))
	cfg := pool.Config()
	cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	readonly, err := pgxpool.NewWithConfig(background, cfg)
	require.NoError(t, err)
	defer readonly.Close()
	_, err = Open(background, readonly, o)
	require.ErrorIs(t, err, ErrUnavailable)
	var token *string
	require.NoError(t, pool.QueryRow(background, "SELECT owner_token::text FROM event_ledgers WHERE cluster_id=$1", o.ClusterID).Scan(&token))
	require.Nil(t, token)
}
