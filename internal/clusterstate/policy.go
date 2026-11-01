// Package clusterstate stores complete signed policy generations in PostgreSQL.
// It does not establish HA, fencing, connection routing or a worker listener.
package clusterstate

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"rauth/internal/clusterpolicy"
)

const chunkBytes = 1 << 20
const transferTimeout = 120 * time.Second

var ErrNoHead = errors.New("no published policy")
var ErrConflict = errors.New("policy publication base changed")
var ErrBusy = errors.New("another policy publication is in progress")
var ErrNotFound = errors.New("policy generation or dependency is no longer retained")
var ErrCorrupt = errors.New("stored policy is inconsistent")
var ErrUnavailable = errors.New("policy authority is not a writable primary")

// Reader uses a dedicated, verified-TLS pool independent of auth hot-path budgets.
// Its database role must have SELECT only on the cluster policy tables.
type Reader struct {
	pool     *pgxpool.Pool
	blobs    *pgxpool.Pool
	verifier *clusterpolicy.Verifier
	cluster  string
}

// Publisher must only be constructed by the control role, with separate write
// credentials. A worker must never receive this capability or its signing key.
type Publisher struct{ reader *Reader }

// Head preserves the exact signed envelope; do not re-encode it in a transport.
type Head struct {
	Verified clusterpolicy.VerifiedManifest
	Envelope []byte
}

func verifiedPool(pool *pgxpool.Pool) error {
	if pool == nil {
		return clusterpolicy.ErrInvalid
	}
	cfg := pool.Config()
	verified := func(c *tls.Config) bool { return c != nil && !c.InsecureSkipVerify && c.ServerName != "" }
	if !verified(cfg.ConnConfig.TLSConfig) {
		return errors.New("policy authority requires verified PostgreSQL TLS")
	}
	for _, fallback := range cfg.ConnConfig.Fallbacks {
		if !verified(fallback.TLSConfig) {
			return errors.New("policy authority prohibits unverified PostgreSQL fallback")
		}
	}
	return nil
}

// NewReader requires independent head and payload pools. A slow/abandoned blob
// stream cannot consume the connections reserved for periodic freshness checks.
func NewReader(headPool, blobPool *pgxpool.Pool, verifier *clusterpolicy.Verifier) (*Reader, error) {
	if verifier.ClusterID() == "" || headPool == blobPool {
		return nil, clusterpolicy.ErrInvalid
	}
	if err := verifiedPool(headPool); err != nil {
		return nil, err
	}
	if err := verifiedPool(blobPool); err != nil {
		return nil, err
	}
	return &Reader{pool: headPool, blobs: blobPool, verifier: verifier, cluster: verifier.ClusterID()}, nil
}
func NewPublisher(pool *pgxpool.Pool, verifier *clusterpolicy.Verifier) (*Publisher, error) {
	if verifier.ClusterID() == "" {
		return nil, clusterpolicy.ErrInvalid
	}
	if err := verifiedPool(pool); err != nil {
		return nil, err
	}
	return &Publisher{reader: &Reader{pool: pool, blobs: pool, verifier: verifier, cluster: verifier.ClusterID()}}, nil
}

// begin checks every operation, including reused connections. A writable former
// leader cannot be distinguished locally: verified leader routing and effective
// external fencing remain mandatory. Never use an async/read-only replica.
func begin(ctx context.Context, pool *pgxpool.Pool, isolation pgx.TxIsoLevel) (pgx.Tx, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: isolation})
	if err != nil {
		return nil, err
	}
	var primary bool
	err = tx.QueryRow(ctx, `SELECT NOT pg_is_in_recovery() AND current_setting('transaction_read_only')='off'`).Scan(&primary)
	if err != nil || !primary {
		rollback(tx)
		if err != nil {
			return nil, err
		}
		return nil, ErrUnavailable
	}
	return tx, nil
}
func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
func validIdentity(id clusterpolicy.Identity) bool {
	if id.Revision <= 0 || len(id.SHA256) != 64 {
		return false
	}
	b, err := hex.DecodeString(id.SHA256)
	return err == nil && hex.EncodeToString(b) == id.SHA256
}
func (r *Reader) decode(revision int64, hash string, raw []byte) (Head, error) {
	verified, err := r.verifier.Verify(raw)
	if err != nil || verified.Identity() != (clusterpolicy.Identity{Revision: revision, SHA256: hash}) {
		return Head{}, ErrCorrupt
	}
	return Head{Verified: verified, Envelope: bytes.Clone(raw)}, nil
}
func (r *Reader) current(ctx context.Context, tx pgx.Tx) (Head, error) {
	var revision int64
	var hash string
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT h.revision,h.sha256,m.envelope FROM cluster_policy_heads h JOIN cluster_policy_manifests m USING(cluster_id,revision,sha256) WHERE h.cluster_id=$1`, r.cluster).Scan(&revision, &hash, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return Head{}, ErrNoHead
	}
	if err != nil {
		return Head{}, err
	}
	return r.decode(revision, hash, raw)
}

// Current is an independent authoritative read, never a controller HTTP cache.
// A failed call must not renew Freshness; callers verify/persist observed heads.
func (r *Reader) Current(ctx context.Context) (Head, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, err := begin(ctx, r.pool, pgx.RepeatableRead)
	if err != nil {
		return Head{}, err
	}
	defer rollback(tx)
	return r.current(ctx, tx)
}
func (r *Reader) manifest(ctx context.Context, tx pgx.Tx, id clusterpolicy.Identity) (Head, error) {
	if !validIdentity(id) {
		return Head{}, clusterpolicy.ErrInvalid
	}
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT envelope FROM cluster_policy_manifests WHERE cluster_id=$1 AND revision=$2 AND sha256=$3`, r.cluster, id.Revision, id.SHA256).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return Head{}, ErrNotFound
	}
	if err != nil {
		return Head{}, err
	}
	return r.decode(id.Revision, id.SHA256, raw)
}

// Manifest fetches only a retained signed generation. It is not a fresh head.
func (r *Reader) Manifest(ctx context.Context, id clusterpolicy.Identity) (Head, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, err := begin(ctx, r.pool, pgx.RepeatableRead)
	if err != nil {
		return Head{}, err
	}
	defer rollback(tx)
	return r.manifest(ctx, tx, id)
}

// OpenBlob authorizes the requested metadata against the signed generation. Read
// to EOF to verify order, size and hash, and always Close to release its snapshot.
// Retirement during a download cannot invalidate the already-open snapshot.
func (r *Reader) OpenBlob(ctx context.Context, id clusterpolicy.Identity, b clusterpolicy.Blob) (io.ReadCloser, error) {
	ctx, cancel := context.WithTimeout(ctx, transferTimeout)
	tx, err := begin(ctx, r.blobs, pgx.RepeatableRead)
	if err != nil {
		cancel()
		return nil, err
	}
	head, err := r.manifest(ctx, tx, id)
	found := false
	if err == nil {
		for _, candidate := range head.Verified.Manifest().Blobs {
			if candidate == b {
				found = true
				break
			}
		}
		if !found {
			err = ErrNotFound
		}
	}
	if err != nil {
		rollback(tx)
		cancel()
		return nil, err
	}
	reader, err := openChunks(ctx, tx, r.cluster, b)
	if err != nil {
		rollback(tx)
		cancel()
		return nil, err
	}
	reader.owner = tx
	reader.cancel = cancel
	return reader, nil
}

// Publish streams every dependency and runs semantic validation before committing
// the head in the same transaction. An optimistic exact base prevents lost edits;
// retry of an already-committed exact head succeeds without refetching data.
// Nothing becomes visible if any source, hash, parser, SQL or commit check fails.
func (p *Publisher) Publish(ctx context.Context, base clusterpolicy.Identity, raw []byte, open func(clusterpolicy.Blob) (io.ReadCloser, error), validate func(clusterpolicy.Blob, io.Reader) error) (Head, error) {
	if (base != (clusterpolicy.Identity{}) && !validIdentity(base)) || base.Revision == math.MaxInt64 || open == nil || validate == nil || len(raw) > clusterpolicy.MaxEnvelopeBytes {
		return Head{}, clusterpolicy.ErrInvalid
	}
	raw = bytes.Clone(raw)
	head, err := p.reader.verifier.Verify(raw)
	if err != nil {
		return Head{}, err
	}
	if head.Identity().Revision != base.Revision+1 {
		return Head{}, ErrConflict
	}
	ctx, cancel := context.WithTimeout(ctx, transferTimeout)
	defer cancel()
	tx, err := begin(ctx, p.reader.pool, pgx.ReadCommitted)
	if err != nil {
		return Head{}, err
	}
	defer rollback(tx)
	var locked bool
	if err = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))`, "rauth-policy-v1:"+p.reader.cluster).Scan(&locked); err != nil {
		return Head{}, err
	}
	if !locked {
		return Head{}, ErrBusy
	}
	current, err := p.reader.current(ctx, tx)
	if err != nil && !errors.Is(err, ErrNoHead) {
		return Head{}, err
	}
	if err == nil && current.Verified.Identity() == head.Identity() {
		return current, nil
	}
	if (errors.Is(err, ErrNoHead) && base != (clusterpolicy.Identity{})) || (err == nil && current.Verified.Identity() != base) {
		return Head{}, ErrConflict
	}
	_, err = clusterpolicy.VerifyBundle(head, func(b clusterpolicy.Blob) (io.ReadCloser, error) {
		var size int64
		e := tx.QueryRow(ctx, `SELECT bytes FROM cluster_policy_blobs WHERE cluster_id=$1 AND sha256=$2`, p.reader.cluster, b.SHA256).Scan(&size)
		if e == nil {
			if size != b.Bytes {
				return nil, ErrCorrupt
			}
			return openChunks(ctx, tx, p.reader.cluster, b)
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return nil, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO cluster_policy_blobs(cluster_id,sha256,bytes) VALUES($1,$2,$3)`, p.reader.cluster, b.SHA256, b.Bytes); e != nil {
			return nil, e
		}
		source, e := open(b)
		if e != nil {
			return nil, e
		}
		if source == nil {
			return nil, clusterpolicy.ErrInvalid
		}
		writer := &chunkWriter{ctx: ctx, tx: tx, cluster: p.reader.cluster, blob: b}
		return &stagingReader{Reader: io.TeeReader(source, writer), source: source, writer: writer}, nil
	}, validate)
	if err != nil {
		return Head{}, err
	}
	id := head.Identity()
	if _, err = tx.Exec(ctx, `INSERT INTO cluster_policy_manifests(cluster_id,revision,sha256,envelope) VALUES($1,$2,$3,$4)`, p.reader.cluster, id.Revision, id.SHA256, raw); err != nil {
		return Head{}, err
	}
	for _, b := range head.Manifest().Blobs {
		if _, err = tx.Exec(ctx, `INSERT INTO cluster_policy_dependencies(cluster_id,revision,kind,logical_id,sha256,bytes) VALUES($1,$2,$3,$4,$5,$6)`, p.reader.cluster, id.Revision, b.Kind, b.ID, b.SHA256, b.Bytes); err != nil {
			return Head{}, err
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO cluster_policy_heads(cluster_id,revision,sha256) VALUES($1,$2,$3) ON CONFLICT(cluster_id) DO UPDATE SET revision=excluded.revision,sha256=excluded.sha256`, p.reader.cluster, id.Revision, id.SHA256); err != nil {
		return Head{}, err
	}
	// Retain active+previous; workers observing retirement restart with Current.
	if _, err = tx.Exec(ctx, `DELETE FROM cluster_policy_manifests WHERE cluster_id=$1 AND revision<$2`, p.reader.cluster, id.Revision-1); err != nil {
		return Head{}, err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM cluster_policy_blobs b WHERE b.cluster_id=$1 AND NOT EXISTS(SELECT 1 FROM cluster_policy_dependencies d WHERE d.cluster_id=b.cluster_id AND d.sha256=b.sha256)`, p.reader.cluster); err != nil {
		return Head{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Head{}, fmt.Errorf("commit complete policy: %w", err)
	}
	return Head{Verified: head, Envelope: bytes.Clone(raw)}, nil
}
