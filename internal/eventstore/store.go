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
	"rauth/internal/requestevent"
	"sync"
	"time"
)

var ErrInvalid = errors.New("invalid event storage operation")
var ErrConflict = errors.New("event identity conflicts with committed content")
var ErrUnavailable = errors.New("event storage unavailable")

const CentralBytes int64 = 8 << 30

//go:embed schema.sql
var schema string

type Options struct {
	ClusterID string
	MaxBytes  int64
	MaxAge    time.Duration
}
type Store struct {
	pool         *pgxpool.Pool
	lock         *pgxpool.Conn
	options      Options
	epoch, token string
	mu           sync.Mutex
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
	if _, err = tx.Exec(ctx, schema); err != nil {
		return ErrUnavailable
	}
	return tx.Commit(ctx)
}
func Provision(ctx context.Context, pool *pgxpool.Pool, o Options, role string) error {
	if pool == nil || o.validate() != nil || role == "" || len(role) > 63 {
		return ErrInvalid
	}
	_, err := pool.Exec(ctx, `INSERT INTO event_ledgers(cluster_id,owner_role) VALUES($1,$2::name) ON CONFLICT(cluster_id) DO NOTHING`, o.ClusterID, role)
	if err != nil {
		return ErrUnavailable
	}
	return nil
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
	if conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", s.lockName()).Scan(&acquired) != nil || !acquired {
		conn.Release()
		return nil, ErrUnavailable
	}
	fail := func() (*Store, error) { s.releaseLock(); return nil, ErrUnavailable }
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fail()
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var version int
	if primary(ctx, tx) != nil || tx.QueryRow(ctx, "SELECT version FROM event_schema_version WHERE singleton").Scan(&version) != nil || version != 1 {
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
	var incoming int64
	for i, e := range events {
		var old []byte
		err := s.pool.QueryRow(ctx, `SELECT payload FROM request_events WHERE cluster_id=$1 AND node_id=$2 AND event_id=$3`, s.options.ClusterID, e.NodeID, e.EventID).Scan(&old)
		if err == nil {
			if !bytes.Equal(old, raws[i]) {
				return nil, ErrConflict
			}
		} else if errors.Is(err, pgx.ErrNoRows) {
			incoming += int64(len(raws[i])) + 256
		} else {
			return nil, ErrUnavailable
		}
	}
	if err := s.trim(ctx, incoming, now); err != nil {
		return nil, err
	}
	tx, used, high, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var added int64
	for i, e := range events {
		var old []byte
		err = tx.QueryRow(ctx, `SELECT payload FROM request_events WHERE cluster_id=$1 AND node_id=$2 AND event_id=$3`, s.options.ClusterID, e.NodeID, e.EventID).Scan(&old)
		if err == nil {
			if !bytes.Equal(old, raws[i]) {
				return nil, ErrConflict
			}
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, storageFailure(err)
		}
		if high == math.MaxInt64 {
			return nil, ErrUnavailable
		}
		high++
		_, err = tx.Exec(ctx, `INSERT INTO request_events(cluster_id,seq,node_id,event_id,occurred_at,received_at,payload,size) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, s.options.ClusterID, high, e.NodeID, e.EventID, e.Time, now, raws[i], len(raws[i])+256)
		if err != nil {
			return nil, storageFailure(err)
		}
		used += int64(len(raws[i])) + 256
		added++
	}
	if _, err = tx.Exec(ctx, `UPDATE event_ledgers SET payload_bytes=$3,high_water=$4,event_count=event_count+$5 WHERE cluster_id=$1 AND owner_token=$2`, s.options.ClusterID, s.token, used, high, added); err != nil {
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
func (s *Store) trim(ctx context.Context, incoming int64, now time.Time) error {
	for {
		tx, used, _, err := s.begin(ctx)
		if err != nil {
			return err
		}
		changed, err := s.trimChunk(ctx, tx, incoming, now, used)
		if err != nil {
			_ = tx.Rollback(ctx)
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
func (s *Store) trimChunk(ctx context.Context, tx pgx.Tx, incoming int64, now time.Time, used int64) (bool, error) {
	type item struct{ seq, size int64 }
	var expired []item
	rows, err := tx.Query(ctx, `SELECT seq,size FROM request_events WHERE cluster_id=$1 AND received_at<$2 ORDER BY seq LIMIT 128`, s.options.ClusterID, now.Add(-s.options.MaxAge))
	if err != nil {
		return false, err
	}
	for rows.Next() {
		var i item
		if err = rows.Scan(&i.seq, &i.size); err != nil {
			rows.Close()
			return false, err
		}
		expired = append(expired, i)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return false, err
	}
	removed := int64(0)
	last := int64(0)
	remove := func(i item) error {
		if _, err := tx.Exec(ctx, `DELETE FROM request_events WHERE cluster_id=$1 AND seq=$2`, s.options.ClusterID, i.seq); err != nil {
			return err
		}
		used -= i.size
		removed++
		if i.seq > last {
			last = i.seq
		}
		return nil
	}
	for _, i := range expired {
		if err = remove(i); err != nil {
			return false, err
		}
	}
	if removed < 128 && used+incoming > s.options.MaxBytes {
		var oldest []item
		rows, err = tx.Query(ctx, `SELECT seq,size FROM request_events WHERE cluster_id=$1 ORDER BY seq LIMIT 128`, s.options.ClusterID)
		if err != nil {
			return false, err
		}
		for rows.Next() {
			var i item
			if err = rows.Scan(&i.seq, &i.size); err != nil {
				rows.Close()
				return false, err
			}
			oldest = append(oldest, i)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return false, err
		}
		for _, i := range oldest {
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
	_, err = tx.Exec(ctx, `UPDATE event_ledgers SET payload_bytes=$3,event_count=event_count-$4,expired_count=expired_count+$4,pruned_through=GREATEST(pruned_through,$5) WHERE cluster_id=$1 AND owner_token=$2`, s.options.ClusterID, s.token, used, removed, last)
	return true, err
}
func (s *Store) After(ctx context.Context, cursor uint64, node string) (Batch, error) {
	if (node != "" && !requestevent.ValidID(node)) || cursor > math.MaxInt64 {
		return Batch{}, ErrInvalid
	}
	s.mu.Lock()
	changed := s.changed
	s.mu.Unlock()
	b := Batch{Events: []requestevent.Event{}, Changed: changed}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return b, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if tx.QueryRow(ctx, `SELECT COALESCE((SELECT min(seq) FROM request_events WHERE cluster_id=$1),0),high_water,pruned_through FROM event_ledgers WHERE cluster_id=$1`, s.options.ClusterID).Scan(&b.Oldest, &b.Latest, &b.PrunedThrough) != nil {
		return b, ErrUnavailable
	}
	rows, err := tx.Query(ctx, `SELECT seq,received_at,payload FROM request_events WHERE cluster_id=$1 AND seq>$2 AND ($3='' OR node_id::text=$3) ORDER BY seq LIMIT 100`, s.options.ClusterID, int64(cursor), node)
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
	var st Status
	var oldest *time.Time
	err := s.pool.QueryRow(ctx, `SELECT event_count,payload_bytes,expired_count,(SELECT min(occurred_at) FROM request_events WHERE cluster_id=$1),pg_database_size(current_database()) FROM event_ledgers WHERE cluster_id=$1`, s.options.ClusterID).Scan(&st.Retained, &st.PayloadBytes, &st.Expired, &oldest, &st.DatabaseBytes)
	if err != nil {
		return st, ErrUnavailable
	}
	if oldest != nil {
		st.Oldest = oldest.UTC()
	}
	return st, nil
}
func (s *Store) notifyLocked() { close(s.changed); s.changed = make(chan struct{}) }
func (s *Store) releaseLock() {
	if s.lock == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _ = s.lock.Exec(ctx, "SELECT pg_advisory_unlock(hashtextextended($1,0))", s.lockName())
	s.lock.Release()
	s.lock = nil
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
	return nil
}
func storageFailure(err error) error {
	var coded *pgconn.PgError
	if errors.As(err, &coded) {
		return fmt.Errorf("%w (SQLSTATE %s)", ErrUnavailable, coded.Code)
	}
	return ErrUnavailable
}
