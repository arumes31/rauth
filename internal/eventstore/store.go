// Package eventstore owns centrally persisted RAuth decision history in the HA
// PostgreSQL event database. Workers buffer locally with eventspool (bbolt).
package eventstore

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"math"
	"net/url"
	"rauth/internal/requestevent"
	"strings"
	"sync"
	"time"
)

var ErrInvalid = errors.New("invalid event storage operation")
var ErrConflict = errors.New("event identity conflicts with committed content")
var ErrUnavailable = errors.New("event storage unavailable")

const CentralBytes int64 = 8 << 30
const SchemaVersion = 3

//go:embed schema.sql
var schema string

//go:embed schema2.sql
var schema2 string

//go:embed schema3.sql
var schema3 string

type Options struct {
	ClusterID string
	MaxBytes  int64
	MaxAge    time.Duration
}
type Store struct {
	pool         *pgxpool.Pool
	history      *pgxpool.Pool
	stats        *pgxpool.Pool
	lock         *pgxpool.Conn
	options      Options
	epoch, token string
	mu           sync.Mutex
	lockMu       sync.Mutex
	changedMu    sync.Mutex
	readMu       sync.Mutex
	readCache    map[historyKey]historyEntry
	changed      chan struct{}
	closed       bool
	now          func() time.Time
}
type Batch struct {
	Events                              []requestevent.Event
	Oldest, Latest, Next, PrunedThrough uint64
	Changed                             <-chan struct{} `json:"-"`
}
type Status struct {
	Retained      int64     `json:"retained"`
	PayloadBytes  int64     `json:"payload_bytes"`
	DatabaseBytes int64     `json:"database_bytes"`
	Expired       uint64    `json:"expired"`
	Oldest        time.Time `json:"oldest,omitempty"`
}

func (o Options) validate() error {
	if !requestevent.ValidID(o.ClusterID) || o.MaxBytes < 1<<20 || o.MaxBytes > 32<<30 || o.MaxAge < time.Minute || o.MaxAge > 7*24*time.Hour {
		return ErrInvalid
	}
	return nil
}

// Migrate is operator-only. Runtime credentials have no DDL/provision privilege.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return ErrInvalid
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if primary(ctx, tx) != nil {
		return ErrUnavailable
	}
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended('rauth-event-schema',0))"); err != nil {
		return ErrUnavailable
	}
	var exists bool
	if tx.QueryRow(ctx, "SELECT to_regclass('event_schema_version') IS NOT NULL").Scan(&exists) != nil {
		return ErrUnavailable
	}
	version := 0
	if exists {
		var operator bool
		if tx.QueryRow(ctx, "SELECT pg_has_role(current_user,relowner,'USAGE') FROM pg_class WHERE oid=to_regclass('event_schema_version')").Scan(&operator) != nil || !operator {
			return ErrUnavailable
		}
		if tx.QueryRow(ctx, "SELECT version FROM event_schema_version WHERE singleton").Scan(&version) != nil || version < 1 || version > SchemaVersion {
			return ErrUnavailable
		}
	}
	for i, migration := range []string{schema, schema2, schema3} {
		if version >= i+1 {
			continue
		}
		if _, err = tx.Exec(ctx, migration); err != nil {
			return ErrUnavailable
		}
	}
	return tx.Commit(ctx)
}
func Provision(ctx context.Context, pool *pgxpool.Pool, o Options, role string) error {
	if pool == nil || o.validate() != nil || role == "" || len(role) > 63 {
		return ErrInvalid
	}
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		var existing string
		if err := tx.QueryRow(ctx, `INSERT INTO event_ledgers(cluster_id,owner_role) VALUES($1,$2::name) ON CONFLICT(cluster_id) DO UPDATE SET cluster_id=excluded.cluster_id RETURNING owner_role::text`, o.ClusterID, role).Scan(&existing); err != nil || existing != role {
			return ErrUnavailable
		}
		ident := pgx.Identifier{role}.Sanitize()
		var schemaName string
		if tx.QueryRow(ctx, "SELECT current_schema()").Scan(&schemaName) != nil || schemaName == "" {
			return ErrUnavailable
		}
		for _, sql := range []string{"GRANT USAGE ON SCHEMA " + pgx.Identifier{schemaName}.Sanitize() + " TO " + ident, "GRANT SELECT ON event_schema_version TO " + ident, "GRANT SELECT,UPDATE ON event_ledgers TO " + ident, "GRANT SELECT,INSERT,DELETE ON request_events TO " + ident, "GRANT SELECT,INSERT,UPDATE,DELETE ON event_traffic_minute,event_node_samples TO " + ident} {
			if _, err := tx.Exec(ctx, sql); err != nil {
				return ErrUnavailable
			}
		}
		return nil
	})
}
func Open(ctx context.Context, pool *pgxpool.Pool, o Options) (*Store, error) {
	if pool == nil || o.validate() != nil || pool.Config().MaxConns < 3 {
		return nil, ErrInvalid
	}
	s := &Store{pool: pool, options: o, token: uuid.NewString(), changed: make(chan struct{}), now: time.Now}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, ErrUnavailable
	}
	s.lock = conn
	var acquired bool
	var idleTimeout string
	// A broken network hop can leave the server-side advisory lock alive
	// after the client has abandoned it. Bound that orphan lifetime on this
	// dedicated session only; Status heartbeats keep a healthy owner alive.
	if conn.QueryRow(ctx, "SELECT set_config('idle_session_timeout','30s',false),pg_try_advisory_lock(hashtextextended($1,0))", s.lockName()).Scan(&idleTimeout, &acquired) != nil || idleTimeout != "30s" || !acquired {
		s.releaseLock()
		return nil, ErrUnavailable
	}
	fail := func() (*Store, error) { s.releaseLock(); return nil, ErrUnavailable }
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fail()
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var version int
	if primary(ctx, tx) != nil || tx.QueryRow(ctx, "SELECT version FROM event_schema_version WHERE singleton").Scan(&version) != nil || version != SchemaVersion {
		_ = tx.Rollback(ctx)
		return fail()
	}
	err = tx.QueryRow(ctx, `UPDATE event_ledgers SET owner_token=$2 WHERE cluster_id=$1 AND owner_role=current_user RETURNING epoch::text`, o.ClusterID, s.token).Scan(&s.epoch)
	if err != nil {
		_ = tx.Rollback(ctx)
		return fail()
	}
	if tx.Commit(ctx) != nil {
		return fail()
	}
	for _, target := range []**pgxpool.Pool{&s.history, &s.stats} {
		cfg := pool.Config()
		cfg.MaxConns = 2
		cfg.MinConns = 0
		// target_session_attrs=read-write must inspect the leader before this
		// reader session switches to read-only. A startup read-only parameter
		// would make the correct primary fail its own leader-selection check.
		delete(cfg.ConnConfig.RuntimeParams, "default_transaction_read_only")
		previous := cfg.AfterConnect
		cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			if previous != nil {
				if err := previous(ctx, conn); err != nil {
					return err
				}
			}
			_, err := conn.Exec(ctx, "SET default_transaction_read_only=on")
			return err
		}
		cfg.ConnConfig.RuntimeParams["statement_timeout"] = "1500"
		*target, err = pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			if s.history != nil {
				s.history.Close()
			}
			return fail()
		}
	}
	return s, nil
}
func (s *Store) lockName() string { return "rauth-events:" + s.options.ClusterID }
func primary(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, "SET LOCAL synchronous_commit=on"); err != nil {
		return ErrUnavailable
	}
	var writable bool
	if tx.QueryRow(ctx, "SELECT NOT pg_is_in_recovery() AND current_setting('transaction_read_only')='off' AND current_setting('fsync')='on' AND current_setting('full_page_writes')='on'").Scan(&writable) != nil || !writable {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) begin(ctx context.Context) (pgx.Tx, int64, int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, 0, 0, ErrUnavailable
	}
	fail := func() (pgx.Tx, int64, int64, error) { _ = tx.Rollback(ctx); return nil, 0, 0, ErrUnavailable }
	if primary(ctx, tx) != nil {
		return fail()
	}
	var used, high int64
	if tx.QueryRow(ctx, `SELECT payload_bytes,high_water FROM event_ledgers WHERE cluster_id=$1 AND owner_token=$2 AND owner_role=current_user FOR UPDATE`, s.options.ClusterID, s.token).Scan(&used, &high) != nil {
		return fail()
	}
	return tx, used, high, nil
}
func (s *Store) Epoch() string { return s.epoch }
func (s *Store) Ingest(ctx context.Context, peer string, events []requestevent.Event) ([]string, error) {
	if !requestevent.ValidID(peer) || len(events) == 0 {
		return nil, ErrInvalid
	}
	return s.insert(ctx, peer, events)
}
func (s *Store) Maintain(ctx context.Context) error { _, err := s.insert(ctx, "", nil); return err }
func (s *Store) insert(ctx context.Context, peer string, events []requestevent.Event) ([]string, error) {
	if len(events) > requestevent.MaxBatch {
		return nil, ErrInvalid
	}
	now := s.now().UTC()
	raws := make([][]byte, len(events))
	acks := make([]string, len(events))
	seen := map[string]bool{}
	for i, e := range events {
		if e.NodeID != peer || requestevent.Validate(e, now) != nil || seen[e.EventID] {
			return nil, ErrInvalid
		}
		seen[e.EventID] = true
		raws[i], _ = json.Marshal(e)
		acks[i] = e.EventID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrUnavailable
	}
	// Resolve duplicates once per batch, rather than one network round trip
	// per event. Recheck inside the fenced transaction after retention runs.
	old, err := s.existing(ctx, s.pool, peer, events)
	if err != nil {
		return nil, err
	}
	var incoming, incomingTelemetry int64
	for i, e := range events {
		if payload, found := old[e.EventID]; found {
			if !bytes.Equal(payload, raws[i]) {
				return nil, ErrConflict
			}
			continue
		}
		incoming += eventSize(raws[i])
		if e.Kind == "telemetry" {
			incomingTelemetry += eventSize(raws[i])
		}
	}
	if incoming > s.options.MaxBytes || incomingTelemetry > s.telemetryLimit() {
		return nil, ErrInvalid
	}
	if err := s.trim(ctx, incoming, incomingTelemetry, now); err != nil {
		return nil, err
	}
	tx, used, high, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	old, err = s.existing(ctx, tx, peer, events)
	if err != nil {
		return nil, err
	}
	var added, addedTelemetry int64
	batch := &pgx.Batch{}
	for i, e := range events {
		if payload, found := old[e.EventID]; found {
			if !bytes.Equal(payload, raws[i]) {
				return nil, ErrConflict
			}
			continue
		}
		if high == math.MaxInt64 {
			return nil, ErrUnavailable
		}
		high++
		batch.Queue(`INSERT INTO request_events(cluster_id,seq,node_id,event_id,occurred_at,received_at,payload,size,kind,node_name,action,country,source,domain,url,reason,feed_id,processing_us,latency_bucket) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`, s.options.ClusterID, high, e.NodeID, e.EventID, e.Time, now, raws[i], eventSize(raws[i]), e.Kind, e.NodeName, e.Action, e.Country, e.Source, eventDomain(e.URL), e.URL, e.Reason, e.FeedID, e.ProcessingMicros, latencyBucket(e.ProcessingMicros))
		if err = s.queueStatistics(batch, high, e, now); err != nil {
			return nil, err
		}
		used += eventSize(raws[i])
		if e.Kind == "telemetry" {
			addedTelemetry += eventSize(raws[i])
		}
		added++
	}
	batch.Queue(`UPDATE event_ledgers SET payload_bytes=$3,high_water=$4,event_count=event_count+$5,telemetry_bytes=telemetry_bytes+$6 WHERE cluster_id=$1 AND owner_token=$2`, s.options.ClusterID, s.token, used, high, added, addedTelemetry)
	results := tx.SendBatch(ctx, batch)
	// Close drains every result and reports any statement failure. No ACK is
	// returned until the whole transaction has synchronously committed.
	if err = results.Close(); err != nil {
		return nil, storageFailure(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, storageFailure(err)
	}
	if added > 0 {
		s.notifyLocked()
	}
	return acks, nil
}

type eventQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func (s *Store) existing(ctx context.Context, q eventQuerier, peer string, events []requestevent.Event) (map[string][]byte, error) {
	found := make(map[string][]byte, len(events))
	if len(events) == 0 {
		return found, nil
	}
	ids := make([]string, len(events))
	for i, event := range events {
		ids[i] = event.EventID
	}
	rows, err := q.Query(ctx, `SELECT event_id::text,payload FROM request_events WHERE cluster_id=$1 AND node_id=$2 AND event_id=ANY($3::uuid[])`, s.options.ClusterID, peer, ids)
	if err != nil {
		return nil, storageFailure(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var payload []byte
		if err = rows.Scan(&id, &payload); err != nil {
			return nil, storageFailure(err)
		}
		found[id] = payload
	}
	if err = rows.Err(); err != nil {
		return nil, storageFailure(err)
	}
	return found, nil
}

func (s *Store) telemetryLimit() int64 { return min(s.options.MaxBytes/8, 256<<20) }
func (s *Store) trim(ctx context.Context, incoming, incomingTelemetry int64, now time.Time) error {
	for {
		tx, used, _, err := s.begin(ctx)
		if err != nil {
			return err
		}
		changed, err := s.trimChunk(ctx, tx, incoming, incomingTelemetry, now, used)
		if err != nil {
			_ = tx.Rollback(ctx)
			if errors.Is(err, ErrInvalid) {
				return err
			}
			return storageFailure(err)
		}
		if !changed {
			_ = tx.Rollback(ctx)
			return nil
		}
		if err = tx.Commit(ctx); err != nil {
			return storageFailure(err)
		}
		s.notifyLocked()
	}
}
func (s *Store) trimChunk(ctx context.Context, tx pgx.Tx, incoming, incomingTelemetry int64, now time.Time, used int64) (bool, error) {
	type item struct {
		seq, size int64
		kind      string
	}
	var telemetry int64
	if err := tx.QueryRow(ctx, `SELECT telemetry_bytes FROM event_ledgers WHERE cluster_id=$1 AND owner_token=$2`, s.options.ClusterID, s.token).Scan(&telemetry); err != nil {
		return false, err
	}
	removed, removedHistory, last := int64(0), int64(0), int64(0)
	remove := func(i item) error {
		if err := s.removeStatistics(ctx, tx, i.seq); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM request_events WHERE cluster_id=$1 AND seq=$2`, s.options.ClusterID, i.seq); err != nil {
			return err
		}
		used -= i.size
		if i.kind == "telemetry" {
			telemetry -= i.size
		} else {
			removedHistory++
			if i.seq > last {
				last = i.seq
			}
		}
		removed++
		return nil
	}
	collect := func(sql string, args ...any) ([]item, error) {
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		items := []item{}
		for rows.Next() {
			var i item
			if err = rows.Scan(&i.seq, &i.size, &i.kind); err != nil {
				return nil, err
			}
			items = append(items, i)
		}
		return items, rows.Err()
	}
	// Telemetry has shorter age and its own cap. It is always reclaimed before
	// a decision is evicted, and incoming telemetry may never evict a decision.
	expired, err := collect(`SELECT seq,size,kind FROM request_events WHERE cluster_id=$1 AND (received_at<$2 OR (kind='telemetry' AND received_at<$3)) ORDER BY seq LIMIT 128`, s.options.ClusterID, now.Add(-s.options.MaxAge), now.Add(-min(s.options.MaxAge, 24*time.Hour)))
	if err != nil {
		return false, err
	}
	for _, i := range expired {
		if err = remove(i); err != nil {
			return false, err
		}
	}
	telemetryPressure := func() bool {
		return telemetry+incomingTelemetry > s.telemetryLimit() || used+incoming > s.options.MaxBytes
	}
	if removed < 128 && telemetryPressure() {
		samples, err := collect(`SELECT seq,size,kind FROM request_events WHERE cluster_id=$1 AND kind='telemetry' ORDER BY seq LIMIT 128`, s.options.ClusterID)
		if err != nil {
			return false, err
		}
		for _, i := range samples {
			if removed == 128 || !telemetryPressure() {
				break
			}
			if err = remove(i); err != nil {
				return false, err
			}
		}
	}
	if removed < 128 && (telemetry+incomingTelemetry > s.telemetryLimit() || incomingTelemetry > 0 && used+incoming > s.options.MaxBytes) {
		return false, ErrInvalid
	}
	if removed < 128 && used+incoming > s.options.MaxBytes {
		decisions, err := collect(`SELECT seq,size,kind FROM request_events WHERE cluster_id=$1 AND kind<>'telemetry' ORDER BY seq LIMIT 128`, s.options.ClusterID)
		if err != nil {
			return false, err
		}
		for _, i := range decisions {
			if removed == 128 || used+incoming <= s.options.MaxBytes {
				break
			}
			if err = remove(i); err != nil {
				return false, err
			}
		}
	}
	if removed == 0 {
		return false, nil
	}
	_, err = tx.Exec(ctx, `UPDATE event_ledgers SET payload_bytes=$3,telemetry_bytes=$6,event_count=event_count-$4,expired_count=expired_count+$7,pruned_through=GREATEST(pruned_through,$5) WHERE cluster_id=$1 AND owner_token=$2`, s.options.ClusterID, s.token, used, removed, last, telemetry, removedHistory)
	return true, err
}

type historyKey struct {
	cursor uint64
	node   string
}
type historyEntry struct {
	at    time.Time
	batch Batch
}

func (s *Store) After(ctx context.Context, cursor uint64, node string) (Batch, error) {
	key := historyKey{cursor, node}
	now := time.Now()
	s.readMu.Lock()
	cached, ok := s.readCache[key]
	s.readMu.Unlock()
	if ok && now.Sub(cached.at) >= 0 && now.Sub(cached.at) < time.Second {
		select {
		case <-cached.batch.Changed:
		default:
			return cloneBatch(cached.batch), nil
		}
	}
	batch, err := s.after(ctx, cursor, node)
	if err != nil {
		return batch, err
	}
	s.readMu.Lock()
	if len(s.readCache) >= 8 || s.readCache == nil {
		s.readCache = map[historyKey]historyEntry{}
	}
	s.readCache[key] = historyEntry{now, cloneBatch(batch)}
	s.readMu.Unlock()
	return batch, nil
}
func cloneBatch(b Batch) Batch {
	b.Events = append([]requestevent.Event(nil), b.Events...)
	for i := range b.Events {
		if b.Events[i].Metrics != nil {
			snapshot := b.Events[i].Metrics.Clone()
			b.Events[i].Metrics = &snapshot
		}
	}
	return b
}
func (s *Store) after(ctx context.Context, cursor uint64, node string) (Batch, error) {
	if (node != "" && !requestevent.ValidID(node)) || cursor > math.MaxInt64 {
		return Batch{}, ErrInvalid
	}
	s.changedMu.Lock()
	changed := s.changed
	s.changedMu.Unlock()
	b := Batch{Events: []requestevent.Event{}, Changed: changed}
	tx, err := s.history.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return b, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if tx.QueryRow(ctx, `SELECT COALESCE((SELECT min(seq) FROM request_events WHERE cluster_id=$1),0),high_water,pruned_through FROM event_ledgers WHERE cluster_id=$1`, s.options.ClusterID).Scan(&b.Oldest, &b.Latest, &b.PrunedThrough) != nil {
		return b, ErrUnavailable
	}
	rows, err := tx.Query(ctx, `SELECT seq,received_at,payload FROM request_events WHERE cluster_id=$1 AND seq>$2 AND kind<>'telemetry' AND ($3='' OR node_id::text=$3) ORDER BY seq LIMIT 100`, s.options.ClusterID, int64(cursor), node)
	if err != nil {
		return b, ErrUnavailable
	}
	for rows.Next() {
		var e requestevent.Event
		var id uint64
		var received time.Time
		var raw []byte
		if rows.Scan(&id, &received, &raw) != nil || json.Unmarshal(raw, &e) != nil {
			rows.Close()
			return b, ErrUnavailable
		}
		e.ID = id
		e.ReceivedAt = received.UTC()
		b.Events = append(b.Events, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || tx.Commit(ctx) != nil {
		return b, ErrUnavailable
	}
	b.Next = b.Latest
	if len(b.Events) == requestevent.MaxBatch {
		b.Next = b.Events[len(b.Events)-1].ID
	}
	return b, nil
}
func (s *Store) Status(ctx context.Context) (Status, error) {
	// Read health through the reserved lock session itself. This renews its
	// idle lease and checks ownership in the same network round trip.
	s.lockMu.Lock()
	defer s.lockMu.Unlock()
	if s.lock == nil {
		return Status{}, ErrUnavailable
	}
	var st Status
	var oldest *time.Time
	err := s.lock.QueryRow(ctx, `SELECT event_count,payload_bytes,expired_count,(SELECT min(occurred_at) FROM request_events WHERE cluster_id=$1),pg_database_size(current_database()) FROM event_ledgers WHERE cluster_id=$1 AND owner_token=$2 AND NOT pg_is_in_recovery() AND current_setting('transaction_read_only')='off'`, s.options.ClusterID, s.token).Scan(&st.Retained, &st.PayloadBytes, &st.Expired, &oldest, &st.DatabaseBytes)
	if err != nil {
		return st, ErrUnavailable
	}
	if oldest != nil {
		st.Oldest = oldest.UTC()
	}
	return st, nil
}
func (s *Store) notifyLocked() {
	s.changedMu.Lock()
	defer s.changedMu.Unlock()
	close(s.changed)
	s.changed = make(chan struct{})
}
func (s *Store) releaseLock() {
	s.lockMu.Lock()
	defer s.lockMu.Unlock()
	if s.lock == nil {
		return
	}
	// Never return a session-scoped lock (or its idle timeout) to the pool,
	// including when SQL unlock cannot reach the server during a WAN outage.
	conn := s.lock.Hijack()
	s.lock = nil
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = conn.Close(ctx)
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.notifyLocked()
	s.releaseLock()
	if s.history != nil {
		s.history.Close()
	}
	if s.stats != nil {
		s.stats.Close()
	}
	return nil
}
func storageFailure(err error) error {
	var coded *pgconn.PgError
	if errors.As(err, &coded) {
		return fmt.Errorf("%w (SQLSTATE %s)", ErrUnavailable, coded.Code)
	}
	return ErrUnavailable
}

// Conservative logical accounting reserves normalized-row, index and sample
// overhead too. Physical database/WAL space is separately monitored.
func eventSize(raw []byte) int64 { return int64(len(raw))*2 + 1024 }
func eventDomain(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

var latencyEdges = []int64{1000, 3000, 10000, 30000, 100000, 300000, 1000000, 3000000, 10000000, 30000000, 60000000, 120000000, 600000000}

func latencyBucket(us int64) int {
	if us <= 0 {
		return -1
	}
	for i, edge := range latencyEdges {
		if us <= edge {
			return i
		}
	}
	return len(latencyEdges)
}
func (s *Store) queueStatistics(batch *pgx.Batch, seq int64, e requestevent.Event, received time.Time) error {
	switch e.Kind {
	case "decision":
		batch.Queue(`INSERT INTO event_traffic_minute(cluster_id,node_id,minute,action,country,latency_bucket,decisions,processing_us) VALUES($1,$2,date_trunc('minute',$3::timestamptz),$4,$5,$6,1,$7) ON CONFLICT(cluster_id,node_id,minute,action,country,latency_bucket) DO UPDATE SET decisions=event_traffic_minute.decisions+1,processing_us=event_traffic_minute.processing_us+excluded.processing_us`, s.options.ClusterID, e.NodeID, e.Time, e.Action, e.Country, latencyBucket(e.ProcessingMicros), e.ProcessingMicros)
		return nil
	case "telemetry":
		raw, err := json.Marshal(e.Metrics)
		if err != nil {
			return err
		}
		batch.Queue(`INSERT INTO event_node_samples(cluster_id,seq,node_id,node_name,instance_id,occurred_at,received_at,snapshot,is_diagnostic) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, s.options.ClusterID, seq, e.NodeID, e.NodeName, e.Metrics.InstanceID, e.Time, received, raw, e.Metrics.Diagnostics)
		return nil
	}
	return nil
}
func (s *Store) removeStatistics(ctx context.Context, tx pgx.Tx, seq int64) error {
	// Delete singleton aggregate rows before decrementing to preserve CHECK>0.
	args := []any{s.options.ClusterID, seq}
	_, err := tx.Exec(ctx, `DELETE FROM event_traffic_minute a USING request_events e WHERE e.cluster_id=$1 AND e.seq=$2 AND e.kind='decision' AND a.cluster_id=e.cluster_id AND a.node_id=e.node_id AND a.minute=date_trunc('minute',e.occurred_at) AND a.action=e.action AND a.country=e.country AND a.latency_bucket=e.latency_bucket AND a.decisions=1`, args...)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE event_traffic_minute a SET decisions=a.decisions-1,processing_us=a.processing_us-e.processing_us FROM request_events e WHERE e.cluster_id=$1 AND e.seq=$2 AND e.kind='decision' AND a.cluster_id=e.cluster_id AND a.node_id=e.node_id AND a.minute=date_trunc('minute',e.occurred_at) AND a.action=e.action AND a.country=e.country AND a.latency_bucket=e.latency_bucket`, args...)
	return err
}

// FeedStart measures display/replay windows in decisions and loss markers,
// independent of the number of background telemetry records.
func (s *Store) FeedStart(parent context.Context, node string, limit int) (uint64, error) {
	if node != "" && !requestevent.ValidID(node) || limit < 1 || limit > 1000 {
		return 0, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	var cursor uint64
	err := s.history.QueryRow(ctx, `SELECT COALESCE(min(seq)-1,0) FROM (SELECT seq FROM request_events WHERE cluster_id=$1 AND kind<>'telemetry' AND ($2='' OR node_id::text=$2) ORDER BY seq DESC LIMIT $3) recent`, s.options.ClusterID, node, limit).Scan(&cursor)
	if err != nil {
		return 0, ErrUnavailable
	}
	return cursor, nil
}
