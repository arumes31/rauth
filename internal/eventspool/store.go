// Package eventspool persists each node's bounded local outbox in bbolt. It
// requires an existing private host directory; it never creates a mount fallback.
package eventspool

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"rauth/internal/requestevent"
	"sync"
	"time"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

var ErrUnsafe = errors.New("event spool directory is missing or unsafe")
var ErrInvalid = errors.New("invalid event spool operation")
var ErrConflict = errors.New("event identity conflicts with persisted content")
var ErrUnavailable = errors.New("local event spool unavailable")

const LocalBytes int64 = 2 << 30

var metaBucket = []byte("metadata")
var eventBucket = []byte("events")
var idBucket = []byte("by_id")
var timeBucket = []byte("by_time")

type Options struct {
	ClusterID, NodeID, NodeName string
	MaxBytes                    int64
	MaxAge                      time.Duration
}
type Store struct {
	payloadLimit uint64
	db           *bolt.DB
	directory    *os.File
	root         string
	options      Options
	mu           sync.Mutex
	closed       bool
	now          func() time.Time
}
type Status struct {
	Pending         uint64    `json:"pending"`
	PayloadBytes    uint64    `json:"payload_bytes"`
	DiskBytes       int64     `json:"disk_bytes"`
	Dropped         uint64    `json:"dropped"`
	UncleanRestarts uint64    `json:"unclean_restarts"`
	Oldest          time.Time `json:"oldest,omitempty"`
}

func Open(ctx context.Context, root string, o Options) (*Store, error) {
	if ctx == nil || !requestevent.ValidID(o.ClusterID) || !requestevent.ValidID(o.NodeID) || !requestevent.ValidName(o.NodeName) || o.MaxBytes < 16<<20 || o.MaxBytes > 32<<30 || o.MaxBytes > int64(math.MaxInt) || o.MaxAge < time.Minute || o.MaxAge > 24*time.Hour {
		return nil, ErrInvalid
	}
	dir, err := openDirectory(root)
	if err != nil {
		return nil, err
	}
	db, err := bolt.Open(filepath.Join(root, "spool.db"), 0o600, &bolt.Options{Timeout: 250 * time.Millisecond, MaxSize: int(o.MaxBytes), FreelistType: bolt.FreelistMapType, NoSync: false, NoGrowSync: false, OpenFile: func(path string, flags int, mode os.FileMode) (*os.File, error) {
		return openFile(dir, root, path, flags, mode)
	}})
	if err != nil {
		_ = dir.Close()
		return nil, ErrUnavailable
	}
	db.AllocSize = 1 << 20
	s := &Store{db: db, directory: dir, root: root, options: o, payloadLimit: uint64(o.MaxBytes) / 4, now: time.Now}
	fail := func() (*Store, error) { _ = db.Close(); _ = dir.Close(); return nil, ErrUnavailable }
	var dirty bool
	err = db.Update(func(tx *bolt.Tx) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		for _, name := range [][]byte{metaBucket, eventBucket, idBucket, timeBucket} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		meta := tx.Bucket(metaBucket)
		if meta.Get([]byte("schema")) == nil {
			for key, value := range map[string]string{"schema": "1", "cluster": o.ClusterID, "node": o.NodeID, "epoch": uuid.NewString()} {
				if err := meta.Put([]byte(key), []byte(value)); err != nil {
					return err
				}
			}
		}
		if string(meta.Get([]byte("schema"))) != "1" || string(meta.Get([]byte("cluster"))) != o.ClusterID || string(meta.Get([]byte("node"))) != o.NodeID {
			return ErrInvalid
		}
		dirty = number(meta.Get([]byte("dirty"))) != 0
		return meta.Put([]byte("dirty"), key(1))
	})
	if err != nil {
		return fail()
	}
	if dir.Sync() != nil {
		return fail()
	}
	if dirty {
		if _, err = s.Append(ctx, []requestevent.Event{s.gap("unclean_restart", 0, true)}); err != nil {
			return fail()
		}
	}
	return s, nil
}
func key(value uint64) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, value)
	return out
}
func number(raw []byte) uint64 {
	if len(raw) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(raw)
}
func timeKey(event requestevent.Event, seq uint64) []byte {
	out := make([]byte, 16)
	stamp := event.Time.UnixMilli()
	if stamp < 0 {
		stamp = 0
	}
	binary.BigEndian.PutUint64(out, uint64(stamp))
	binary.BigEndian.PutUint64(out[8:], seq)
	return out
}
func (s *Store) Identity(e requestevent.Event) requestevent.Event {
	e = requestevent.Decision(e)
	e.NodeID = s.options.NodeID
	e.NodeName = s.options.NodeName
	e.EventID = uuid.NewString()
	return e
}
func (s *Store) gap(reason string, count uint64, unknown bool) requestevent.Event {
	return requestevent.Event{EventID: uuid.NewString(), NodeID: s.options.NodeID, NodeName: s.options.NodeName, Time: s.now().UTC(), Kind: "gap", Reason: reason, Dropped: count, UnknownLoss: unknown}
}
func (s *Store) Gap(reason string, count uint64) requestevent.Event {
	return s.gap(reason, count, false)
}
func (s *Store) Append(ctx context.Context, events []requestevent.Event) ([]string, error) {
	if len(events) == 0 || len(events) > requestevent.MaxBatch {
		return nil, ErrInvalid
	}
	now := s.now().UTC()
	raws := make([][]byte, len(events))
	acks := make([]string, len(events))
	seen := map[string]bool{}
	for i, e := range events {
		if e.NodeID != s.options.NodeID || requestevent.Validate(e, now) != nil || seen[e.EventID] {
			return nil, ErrInvalid
		}
		seen[e.EventID] = true
		raws[i], _ = json.Marshal(e)
		acks[i] = e.EventID
	}
	if !s.mu.TryLock() {
		return nil, ErrUnavailable
	}
	defer s.mu.Unlock()
	if s.closed || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	var incoming uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		for i, e := range events {
			seq := tx.Bucket(idBucket).Get([]byte(e.EventID))
			if seq == nil {
				incoming += uint64(len(raws[i])) + 128
				continue
			}
			if !sameContent(tx.Bucket(eventBucket).Get(seq), raws[i]) {
				return ErrConflict
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err = s.trim(ctx, incoming+requestevent.MaxEventBytes, now); err != nil {
		return nil, ErrUnavailable
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		meta := tx.Bucket(metaBucket)
		for i, e := range events {
			seq := tx.Bucket(idBucket).Get([]byte(e.EventID))
			if seq != nil {
				if !sameContent(tx.Bucket(eventBucket).Get(seq), raws[i]) {
					return ErrConflict
				}
				continue
			}

			raw := raws[i]
			if e.Kind == "gap" {
				field := "dropped"
				count := e.Dropped
				if e.UnknownLoss {
					field = "unclean"
					count = 1
				}
				previous := number(meta.Get([]byte(field)))
				limit := uint64(1<<53 - 1)
				if field == "unclean" {
					limit = 1 << 40
				}
				if count > limit || previous > limit-count {
					return ErrUnavailable
				}
				if err := meta.Put([]byte(field), key(previous+count)); err != nil {
					return err
				}
				e.LossTotal = number(meta.Get([]byte("dropped")))
				e.UncleanTotal = number(meta.Get([]byte("unclean")))
				raw, _ = json.Marshal(e)
			}
			if err := s.put(tx, e, raw); err != nil {
				return err
			}

		}
		return nil
	})
	if errors.Is(err, ErrConflict) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	return acks, nil
}
func (s *Store) put(tx *bolt.Tx, e requestevent.Event, raw []byte) error {
	events := tx.Bucket(eventBucket)
	seq, err := events.NextSequence()
	if err != nil {
		return err
	}
	if seq == 0 {
		return ErrUnavailable
	}
	if err = events.Put(key(seq), raw); err != nil {
		return err
	}
	if err = tx.Bucket(idBucket).Put([]byte(e.EventID), key(seq)); err != nil {
		return err
	}
	if err = tx.Bucket(timeBucket).Put(timeKey(e, seq), []byte{1}); err != nil {
		return err
	}
	meta := tx.Bucket(metaBucket)
	if err := meta.Put([]byte("pending"), key(number(meta.Get([]byte("pending")))+1)); err != nil {
		return err
	}
	return meta.Put([]byte("bytes"), key(number(meta.Get([]byte("bytes")))+uint64(len(raw))+128))
}
func (s *Store) remove(tx *bolt.Tx, seq []byte) (*requestevent.Event, error) {
	events := tx.Bucket(eventBucket)
	raw := events.Get(seq)
	if raw == nil {
		return nil, nil
	}
	var e requestevent.Event
	if json.Unmarshal(raw, &e) != nil {
		return nil, ErrUnavailable
	}
	size := uint64(len(raw)) + 128
	meta := tx.Bucket(metaBucket)
	used := number(meta.Get([]byte("bytes")))
	if used < size {
		return nil, ErrUnavailable
	}
	if err := tx.Bucket(idBucket).Delete([]byte(e.EventID)); err != nil {
		return nil, err
	}
	if err := tx.Bucket(timeBucket).Delete(timeKey(e, number(seq))); err != nil {
		return nil, err
	}
	if err := events.Delete(seq); err != nil {
		return nil, err
	}
	if err := meta.Put([]byte("bytes"), key(used-size)); err != nil {
		return nil, err
	}
	count := number(meta.Get([]byte("pending")))
	if count == 0 {
		return nil, ErrUnavailable
	}
	if err := meta.Put([]byte("pending"), key(count-1)); err != nil {
		return nil, err
	}
	return &e, nil
}
func (s *Store) trim(ctx context.Context, incoming uint64, now time.Time) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		changed := false
		err := s.db.Update(func(tx *bolt.Tx) error {
			meta := tx.Bucket(metaBucket)
			var candidates [][]byte
			cutoff := key(uint64(now.Add(-s.options.MaxAge).UnixMilli()))
			times := tx.Bucket(timeBucket).Cursor()
			for k, _ := times.First(); k != nil && len(candidates) < 128; k, _ = times.Next() {
				if len(k) != 16 {
					return ErrUnavailable
				}
				if bytes.Compare(k[:8], cutoff) >= 0 {
					break
				}
				candidates = append(candidates, bytes.Clone(k[8:]))
			}
			var lost, represented uint64
			unknown := false
			account := func(e *requestevent.Event) {
				if e == nil {
					return
				}
				switch e.Kind {
				case "decision":
					lost++
					represented++
				case "gap":
					if e.Dropped <= 1<<53-1 && represented <= 1<<53-1-e.Dropped {
						represented += e.Dropped
					} else {
						represented = 1<<53 - 1
					}
					unknown = unknown || e.UnknownLoss
				}
			}
			for _, seq := range candidates {
				removed, err := s.remove(tx, seq)
				if err != nil {
					return err
				}
				account(removed)
				changed = true
			}
			// Reserve space for copy-on-write pages, indexes and a loss marker. Stop
			// deleting immediately when enough bytes have been freed.
			for count := len(candidates); count < 128 && number(meta.Get([]byte("bytes")))+incoming > s.payloadLimit; count++ {
				seq, _ := tx.Bucket(eventBucket).Cursor().First()
				if seq == nil {
					break
				}
				removed, err := s.remove(tx, bytes.Clone(seq))
				if err != nil {
					return err
				}
				account(removed)
				changed = true
			}

			total := number(meta.Get([]byte("dropped")))
			if lost > 1<<53-1 || total > 1<<53-1-lost {
				return ErrUnavailable
			}
			total += lost
			if err := meta.Put([]byte("dropped"), key(total)); err != nil {
				return err
			}
			if represented > 0 {
				count := represented
				if count > 1<<40 {
					count = 1 << 40
				}
				gap := s.gap("storage_retention", count, false)
				gap.LossTotal = total
				gap.UncleanTotal = number(meta.Get([]byte("unclean")))
				raw, _ := json.Marshal(gap)
				if err := s.put(tx, gap, raw); err != nil {
					return err
				}
			}
			if unknown {
				gap := s.gap("unclean_restart", 0, true)
				gap.LossTotal = total
				gap.UncleanTotal = number(meta.Get([]byte("unclean")))
				raw, _ := json.Marshal(gap)
				if err := s.put(tx, gap, raw); err != nil {
					return err
				}
			}

			return nil
		})
		if err != nil {
			return err
		}
		if !changed {
			return nil
		}
	}
}
func (s *Store) Maintain(ctx context.Context) error {
	if !s.mu.TryLock() {
		return ErrUnavailable
	}
	defer s.mu.Unlock()
	if s.closed {
		return ErrUnavailable
	}
	return s.trim(ctx, requestevent.MaxEventBytes, s.now().UTC())
}
func (s *Store) Pending(ctx context.Context, live bool) ([]requestevent.Event, error) {
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	events := []requestevent.Event{}
	err := s.db.View(func(tx *bolt.Tx) error {
		cutoff := key(uint64(s.now().Add(-10 * time.Second).UnixMilli()))
		c := tx.Bucket(timeBucket).Cursor()
		var k []byte
		if live {
			k, _ = c.Seek(cutoff)
		} else {
			k, _ = c.First()
		}
		for ; k != nil && len(events) < requestevent.MaxBatch; k, _ = c.Next() {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if len(k) != 16 {
				return ErrUnavailable
			}
			if !live && bytes.Compare(k[:8], cutoff) >= 0 {
				break
			}
			raw := tx.Bucket(eventBucket).Get(k[8:])
			var e requestevent.Event
			if raw == nil || json.Unmarshal(raw, &e) != nil {
				return ErrUnavailable
			}
			events = append(events, e)
		}
		return nil
	})
	if err != nil {
		return nil, ErrUnavailable
	}
	return events, nil
}
func (s *Store) Acknowledge(ctx context.Context, ids []string) error {
	if len(ids) == 0 || len(ids) > requestevent.MaxBatch {
		return ErrInvalid
	}
	for _, id := range ids {
		if !requestevent.ValidID(id) {
			return ErrInvalid
		}
	}
	if !s.mu.TryLock() {
		return ErrUnavailable
	}
	defer s.mu.Unlock()
	if s.closed {
		return ErrUnavailable
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		for _, id := range ids {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			seq := bytes.Clone(tx.Bucket(idBucket).Get([]byte(id)))
			if seq != nil {
				if _, err := s.remove(tx, seq); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) MarkClean(ctx context.Context) error {
	if !s.mu.TryLock() {
		return ErrUnavailable
	}
	defer s.mu.Unlock()
	if s.closed || ctx.Err() != nil {
		return ErrUnavailable
	}
	err := s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(metaBucket).Put([]byte("dirty"), key(0)) })
	if err != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) Status(ctx context.Context) (Status, error) {
	var st Status
	err := s.db.View(func(tx *bolt.Tx) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		meta := tx.Bucket(metaBucket)
		st.PayloadBytes = number(meta.Get([]byte("bytes")))
		st.Dropped = number(meta.Get([]byte("dropped")))
		st.UncleanRestarts = number(meta.Get([]byte("unclean")))
		st.Pending = number(meta.Get([]byte("pending")))
		k, _ := tx.Bucket(timeBucket).Cursor().First()
		if k != nil {
			if len(k) != 16 {
				return ErrUnavailable
			}
			stamp := number(k[:8])
			if stamp > math.MaxInt64 {
				return ErrUnavailable
			}
			st.Oldest = time.UnixMilli(int64(stamp)).UTC()
		}
		return nil
	})
	if err != nil {
		return st, ErrUnavailable
	}
	info, err := os.Stat(filepath.Join(s.root, "spool.db"))
	if err != nil {
		return st, ErrUnavailable
	}
	st.DiskBytes = info.Size()
	return st, nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	err := s.db.Close()
	_ = s.directory.Close()
	return err
}

// Loss counters are assigned at commit, not by a caller. They remain immutable
// in the persisted wire record; local retries compare the original content.
func sameContent(a, b []byte) bool {
	var left, right requestevent.Event
	if json.Unmarshal(a, &left) != nil || json.Unmarshal(b, &right) != nil {
		return false
	}
	left.LossTotal = 0
	left.UncleanTotal = 0
	right.LossTotal = 0
	right.UncleanTotal = 0
	x, _ := json.Marshal(left)
	y, _ := json.Marshal(right)
	return bytes.Equal(x, y)
}
