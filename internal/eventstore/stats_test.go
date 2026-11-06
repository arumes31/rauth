package eventstore

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"net/url"
	"rauth/internal/requestevent"
	"strings"
	"testing"
	"time"
)

func TestStatisticsDeduplicateReplayQuantilesFiltersAndPruning(t *testing.T) {
	pool := setup(t)
	s := open(t, pool, options())
	node, other := uuid.NewString(), uuid.NewString()
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	a, b, c := decision(node), decision(node), decision(other)
	a.Time = now.Add(-2 * time.Minute)
	a.ProcessingMicros = 900
	b.Time = now.Add(-time.Minute)
	b.Action = "blocked"
	b.Status = 403
	b.Country = "AT"
	b.ProcessingMicros = 9000
	c.ProcessingMicros = 50000
	c.Time = now.Add(-time.Second)
	for _, e := range []requestevent.Event{a, b, c, a} {
		_, err := s.Ingest(background, e.NodeID, []requestevent.Event{e})
		require.NoError(t, err)
	}
	view, err := s.Statistics(background, StatsQuery{Range: "5m"})
	require.NoError(t, err)
	require.EqualValues(t, 3, view.Total)
	require.EqualValues(t, 3, view.Latency.Samples)
	require.Equal(t, 10.0, *view.Latency.P50)
	require.Equal(t, 100.0, *view.Latency.P95)
	require.EqualValues(t, 3, view.Top["urls"][0].Count)
	filtered, err := s.Statistics(background, StatsQuery{Range: "5m", Node: node, Country: "AT"})
	require.NoError(t, err)
	require.EqualValues(t, 1, filtered.Total)
	filtered, err = s.Statistics(background, StatsQuery{Range: "5m", Node: node, URL: a.URL})
	require.NoError(t, err)
	require.EqualValues(t, 2, filtered.Total)
	history, err := s.Decisions(background, StatsQuery{Range: "5m", Node: node})
	require.NoError(t, err)
	require.Len(t, history, 2)
	older, err := s.Decisions(background, StatsQuery{Range: "5m", Before: history[0].ID, Node: node})
	require.NoError(t, err)
	require.Len(t, older, 1)
	s.now = func() time.Time { return now.Add(8 * 24 * time.Hour) }
	require.NoError(t, s.Maintain(background))
	var count int
	require.NoError(t, pool.QueryRow(background, "SELECT count(*) FROM event_traffic_minute").Scan(&count))
	require.Zero(t, count)
}
func TestNodeSamplesCounterResetAndMissingCoverage(t *testing.T) {
	pool := setup(t)
	s := open(t, pool, options())
	node := uuid.NewString()
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	instance := uuid.NewString()
	sample := func(at time.Time, id string, value float64) requestevent.Event {
		return requestevent.Event{Kind: "telemetry", EventID: uuid.NewString(), NodeID: node, NodeName: "fixture", Time: at, Metrics: &requestevent.MetricSnapshot{Schema: 1, InstanceID: id, StartedAt: now.Add(-time.Hour), Points: []requestevent.MetricPoint{{Name: "rauth_login_success_total", Value: value}}}}
	}
	for _, e := range []requestevent.Event{sample(now.Add(-10*time.Second), instance, 10), sample(now.Add(-5*time.Second), instance, 20)} {
		_, err := s.Ingest(background, node, []requestevent.Event{e})
		require.NoError(t, err)
	}
	view, err := s.Statistics(background, StatsQuery{Range: "5m"})
	require.NoError(t, err)
	require.Zero(t, view.Total)
	require.Len(t, view.Nodes, 1)
	require.True(t, view.Nodes[0].IntervalCovered)
	require.Equal(t, 2.0, view.Nodes[0].Rates["rauth_login_success_total"])
	_, err = s.Ingest(background, node, []requestevent.Event{sample(now, uuid.NewString(), 1)})
	require.NoError(t, err)
	view, err = s.Statistics(background, StatsQuery{Range: "5m"})
	require.NoError(t, err)
	require.False(t, view.Nodes[0].IntervalCovered)
	require.Empty(t, view.Nodes[0].Rates)
	s.now = func() time.Time { return now.Add(time.Minute) }
	view, err = s.Statistics(background, StatsQuery{Range: "5m"})
	require.NoError(t, err)
	require.True(t, view.Nodes[0].Stale)
}
func TestNodeSamplesFifteenSecondCadence(t *testing.T) {
	pool := setup(t)
	s := open(t, pool, options())
	node := uuid.NewString()
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	instance := uuid.NewString()
	sample := func(at time.Time, value float64) requestevent.Event {
		return requestevent.Event{Kind: "telemetry", EventID: uuid.NewString(), NodeID: node, NodeName: "fixture", Time: at, Metrics: &requestevent.MetricSnapshot{Schema: 1, InstanceID: instance, StartedAt: now.Add(-time.Hour), Points: []requestevent.MetricPoint{{Name: "rauth_login_success_total", Value: value}}}}
	}
	for _, e := range []requestevent.Event{sample(now.Add(-45*time.Second), 10), sample(now.Add(-30*time.Second), 40)} {
		_, err := s.Ingest(background, node, []requestevent.Event{e})
		require.NoError(t, err)
	}
	view, err := s.Statistics(background, StatsQuery{Range: "5m"})
	require.NoError(t, err)
	require.Len(t, view.Nodes, 1)
	require.True(t, view.Nodes[0].IntervalCovered, "15 s between samples is one regular interval")
	require.Equal(t, 2.0, view.Nodes[0].Rates["rauth_login_success_total"])
	require.False(t, view.Nodes[0].Stale, "a 30 s old sample is within three intervals")
}
func TestVersionOnePopulatedLedgerUpgradeKeepsEpochAndCursor(t *testing.T) {
	pool := setup(t)
	cfg := pool.Config()
	schemaName := "event_upgrade_" + uuid.NewString()[:8]
	_, err := pool.Exec(background, "CREATE SCHEMA "+schemaName)
	require.NoError(t, err)
	defer func() { _, _ = pool.Exec(background, "DROP SCHEMA "+schemaName+" CASCADE") }()
	cfg.ConnConfig.RuntimeParams["search_path"] = schemaName
	old, err := pgxpool.NewWithConfig(background, cfg)
	require.NoError(t, err)
	defer old.Close()
	_, err = old.Exec(background, schema)
	require.NoError(t, err)
	o := options()
	var role string
	require.NoError(t, old.QueryRow(background, "SELECT current_user").Scan(&role))
	_, err = old.Exec(background, `INSERT INTO event_ledgers(cluster_id,owner_role) VALUES($1,$2::name)`, o.ClusterID, role)
	require.NoError(t, err)
	e := decision(uuid.NewString())
	raw, err := json.Marshal(e)
	require.NoError(t, err)
	_, err = old.Exec(background, `INSERT INTO request_events(cluster_id,seq,node_id,event_id,occurred_at,received_at,payload,size) VALUES($1,1,$2,$3,$4,$4,$5,$6)`, o.ClusterID, e.NodeID, e.EventID, e.Time, raw, len(raw)+256)
	require.NoError(t, err)
	_, err = old.Exec(background, "UPDATE event_ledgers SET high_water=1,event_count=1,payload_bytes=$2 WHERE cluster_id=$1", o.ClusterID, len(raw)+256)
	require.NoError(t, err)
	var epoch string
	require.NoError(t, old.QueryRow(background, "SELECT epoch::text FROM event_ledgers").Scan(&epoch))
	require.NoError(t, Migrate(background, old))
	require.NoError(t, Migrate(background, old))
	s, err := Open(background, old, o)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	require.Equal(t, epoch, s.Epoch())
	batch, err := s.After(background, 0, "")
	require.NoError(t, err)
	require.EqualValues(t, 1, batch.Latest)
	view, err := s.Statistics(background, StatsQuery{Range: "5m"})
	require.NoError(t, err)
	require.EqualValues(t, 1, view.Total)
	require.EqualValues(t, 1, view.Latency.Unknown)
}
func TestStatsValidationAndCancelledQueries(t *testing.T) {
	for _, q := range []StatsQuery{{Range: "forever"}, {Range: "5m", Node: "spoof"}, {Range: "5m", Country: "AAx"}, {Range: "5m", Action: "anything"}, {Range: "5m", Source: "password"}, {Range: "5m", Domain: "user:secret@example.com"}, {Range: "5m", URL: "https://example.com/?password=x"}} {
		_, _, err := q.Window(time.Now())
		require.ErrorIs(t, err, ErrInvalid)
	}
	pool := setup(t)
	s := open(t, pool, options())
	ctx, cancel := context.WithCancel(background)
	cancel()
	_, err := s.Statistics(ctx, StatsQuery{Range: "5m"})
	require.ErrorIs(t, err, ErrUnavailable)
}

func TestDurableFeedWindowsCountDecisionsIndependentlyOfTelemetry(t *testing.T) {
	pool := setup(t)
	s := open(t, pool, options())
	node := uuid.NewString()
	a := decision(node)
	_, err := s.Ingest(background, node, []requestevent.Event{a})
	require.NoError(t, err)
	for range 3 {
		events := []requestevent.Event{}
		for range 100 {
			events = append(events, requestevent.Event{Kind: "telemetry", Time: time.Now(), EventID: uuid.NewString(), NodeID: node, NodeName: "fixture", Metrics: &requestevent.MetricSnapshot{Schema: 1, InstanceID: uuid.NewString(), StartedAt: time.Now(), Points: []requestevent.MetricPoint{}}})
		}
		_, err = s.Ingest(background, node, events)
		require.NoError(t, err)
	}
	cursor, err := s.FeedStart(background, node, 100)
	require.NoError(t, err)
	require.Zero(t, cursor)
	batch, err := s.After(background, cursor, node)
	require.NoError(t, err)
	require.Len(t, batch.Events, 1)
	require.Equal(t, a.EventID, batch.Events[0].EventID)
	require.EqualValues(t, 301, batch.Next)
	batch.Events[0].URL = "mutated by caller"
	cached, err := s.After(background, cursor, node)
	require.NoError(t, err)
	require.Equal(t, a.URL, cached.Events[0].URL)
	b := decision(node)
	_, err = s.Ingest(background, node, []requestevent.Event{b})
	require.NoError(t, err)
	cursor, err = s.FeedStart(background, node, 1)
	require.NoError(t, err)
	require.EqualValues(t, 301, cursor)
	fresh, err := s.After(background, 0, node)
	require.NoError(t, err)
	require.Len(t, fresh.Events, 2)
}

func TestReadOnlyReadersRetainWritableLeaderSelection(t *testing.T) {
	pool := setup(t)
	cfg := pool.Config()
	u, err := url.Parse(cfg.ConnConfig.ConnString())
	require.NoError(t, err)
	require.Contains(t, []string{"postgres", "postgresql"}, u.Scheme)
	query := u.Query()
	query.Set("target_session_attrs", "read-write")
	u.RawQuery = query.Encode()
	leader, err := pgxpool.ParseConfig(u.String())
	require.NoError(t, err)
	cfg.ConnConfig.ValidateConnect = leader.ConnConfig.ValidateConnect
	selected, err := pgxpool.NewWithConfig(background, cfg)
	require.NoError(t, err)
	t.Cleanup(selected.Close)
	o := options()
	s := open(t, selected, o)
	node := uuid.NewString()
	_, err = s.Ingest(background, node, []requestevent.Event{decision(node)})
	require.NoError(t, err)
	_, err = s.After(background, 0, "")
	require.NoError(t, err)
	_, err = s.Statistics(background, StatsQuery{Range: "5m"})
	require.NoError(t, err)
	_, err = s.Decisions(background, StatsQuery{Range: "5m"})
	require.NoError(t, err)
	for _, reader := range []*pgxpool.Pool{s.history, s.stats} {
		var mode string
		require.NoError(t, reader.QueryRow(background, "SHOW transaction_read_only").Scan(&mode))
		require.Equal(t, "on", mode)
	}
}

func metricEvent(node string, points int) requestevent.Event {
	list := []requestevent.MetricPoint{}
	for i := 0; i < points; i++ {
		list = append(list, requestevent.MetricPoint{Name: fmt.Sprintf("telemetry_%045d", i), Value: 1})
	}
	return requestevent.Event{Kind: "telemetry", Time: time.Now(), EventID: uuid.NewString(), NodeID: node, NodeName: "fixture", Metrics: &requestevent.MetricSnapshot{Schema: 1, InstanceID: uuid.NewString(), StartedAt: time.Now(), Points: list}}
}
func TestTelemetryBudgetCannotEvictDecisionHistoryOrAdvanceItsPruningCursor(t *testing.T) {
	pool := setup(t)
	o := options()
	o.MaxBytes = 1 << 20
	s := open(t, pool, o)
	node := uuid.NewString()
	anchor := decision(node)
	_, err := s.Ingest(background, node, []requestevent.Event{anchor})
	require.NoError(t, err)
	for range 40 {
		_, err = s.Ingest(background, node, []requestevent.Event{metricEvent(node, 32)})
		require.NoError(t, err)
	}
	var count, bytes int64
	require.NoError(t, pool.QueryRow(background, "SELECT count(*) FROM request_events WHERE event_id=$1", anchor.EventID).Scan(&count))
	require.EqualValues(t, 1, count)
	require.NoError(t, pool.QueryRow(background, "SELECT telemetry_bytes FROM event_ledgers WHERE cluster_id=$1", o.ClusterID).Scan(&bytes))
	require.LessOrEqual(t, bytes, s.telemetryLimit())
	batch, err := s.After(background, 0, "")
	require.NoError(t, err)
	require.Len(t, batch.Events, 1)
	require.Zero(t, batch.PrunedThrough)
	status, err := s.Status(background)
	require.NoError(t, err)
	require.Zero(t, status.Expired, "telemetry expiry is not request-history loss")
}
func TestFullDecisionStoreRejectsOptionalTelemetryWithoutDeletingDecisions(t *testing.T) {
	pool := setup(t)
	o := options()
	o.MaxBytes = 1 << 20
	s := open(t, pool, o)
	node := uuid.NewString()
	for range 4 {
		events := []requestevent.Event{}
		for range 50 {
			e := decision(node)
			e.URL = "https://example.com/" + strings.Repeat("a", 1700)
			events = append(events, e)
		}
		_, err := s.Ingest(background, node, events)
		require.NoError(t, err)
	}
	// Finish with individual inserts so batch reservation does not leave a
	// large, legitimate free region for the optional sample.
	for range 64 {
		e := decision(node)
		e.URL = "https://example.com/" + strings.Repeat("a", 1700)
		_, err := s.Ingest(background, node, []requestevent.Event{e})
		require.NoError(t, err)
	}
	before, err := s.Status(background)
	require.NoError(t, err)
	_, err = s.Ingest(background, node, []requestevent.Event{metricEvent(node, 64)})
	require.ErrorIs(t, err, ErrInvalid)
	after, err := s.Status(background)
	require.NoError(t, err)
	// Physical pg_database_size includes every concurrently tested schema and
	// maintenance activity. Rejected telemetry must preserve this ledger's
	// logical history, not freeze allocation for the entire database.
	require.Equal(t, before.Retained, after.Retained)
	require.Equal(t, before.PayloadBytes, after.PayloadBytes)
	require.Equal(t, before.Expired, after.Expired)
	require.Equal(t, before.Oldest, after.Oldest)
	require.Positive(t, after.DatabaseBytes)
}
func TestVersionTwoAccountingUpgradeAndIPv6Drilldown(t *testing.T) {
	pool := setup(t)
	cfg := pool.Config()
	name := "event_v2_" + uuid.NewString()[:8]
	_, err := pool.Exec(background, "CREATE SCHEMA "+name)
	require.NoError(t, err)
	defer func() { _, _ = pool.Exec(background, "DROP SCHEMA "+name+" CASCADE") }()
	cfg.ConnConfig.RuntimeParams["search_path"] = name
	old, err := pgxpool.NewWithConfig(background, cfg)
	require.NoError(t, err)
	defer old.Close()
	_, err = old.Exec(background, schema)
	require.NoError(t, err)
	o := options()
	var role string
	require.NoError(t, old.QueryRow(background, "SELECT current_user").Scan(&role))
	_, err = old.Exec(background, "INSERT INTO event_ledgers(cluster_id,owner_role) VALUES($1,$2::name)", o.ClusterID, role)
	require.NoError(t, err)
	e := decision(uuid.NewString())
	e.URL = "https://[2001:db8::1]/document"
	raw, err := json.Marshal(e)
	require.NoError(t, err)
	_, err = old.Exec(background, `INSERT INTO request_events(cluster_id,seq,node_id,event_id,occurred_at,received_at,payload,size) VALUES($1,1,$2,$3,$4,$4,$5,$6)`, o.ClusterID, e.NodeID, e.EventID, e.Time, raw, len(raw)+256)
	require.NoError(t, err)
	_, err = old.Exec(background, `UPDATE event_ledgers SET high_water=1,event_count=1,payload_bytes=$2 WHERE cluster_id=$1`, o.ClusterID, len(raw)+256)
	require.NoError(t, err)
	_, err = old.Exec(background, schema2)
	require.NoError(t, err)
	require.NoError(t, Migrate(background, old))
	require.NoError(t, Migrate(background, old))
	var used int64
	require.NoError(t, old.QueryRow(background, "SELECT payload_bytes FROM event_ledgers").Scan(&used))
	require.Equal(t, eventSize(raw), used)
	s, err := Open(background, old, o)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	view, err := s.Statistics(background, StatsQuery{Range: "5m", Domain: "2001:db8::1"})
	require.NoError(t, err)
	require.EqualValues(t, 1, view.Total)
	require.Equal(t, "2001:db8::1", view.Top["domains"][0].Key)
}
