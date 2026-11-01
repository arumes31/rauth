// Package clusterstatus stores authenticated, observational policy receipts.
// Receipt/collector availability never determines local authentication readiness.
package clusterstatus

import (
	"context"
	"encoding/hex"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"rauth/internal/clusterpolicy"
	"rauth/internal/clustertransport"
	"slices"
	"strings"
	"time"
)

var ErrInvalid = errors.New("invalid policy receipt")

const RecentReport = 35 * time.Second

type Report struct {
	Applied        clusterpolicy.Identity `json:"applied"`
	Desired        clusterpolicy.Identity `json:"desired"`
	Ready          bool                   `json:"ready"`
	LeaseExpiresAt time.Time              `json:"lease_expires_at"`
}
type Node struct {
	NodeID     string    `json:"node_id"`
	Role       string    `json:"role"`
	Report     Report    `json:"report"`
	ReceivedAt time.Time `json:"received_at"`
	Eligible   bool      `json:"eligible"`
	Recent     bool      `json:"recent"`
	Confirmed  bool      `json:"confirmed"`
}
type View struct {
	Desired        clusterpolicy.Identity `json:"desired"`
	SourceRevision int64                  `json:"source_revision"`
	Nodes          []Node                 `json:"nodes"`
}
type Store struct {
	pool    *pgxpool.Pool
	cluster string
	now     func() time.Time
}

func New(pool *pgxpool.Pool, cluster string) (*Store, error) {
	id, err := uuid.Parse(cluster)
	if pool == nil || err != nil || id == uuid.Nil || id.String() != cluster {
		return nil, ErrInvalid
	}
	return &Store{pool: pool, cluster: cluster, now: time.Now}, nil
}
func identityValid(id clusterpolicy.Identity) bool {
	if id == (clusterpolicy.Identity{}) {
		return true
	}
	decoded, err := hex.DecodeString(id.SHA256)
	return id.Revision > 0 && err == nil && len(decoded) == 32 && strings.ToLower(id.SHA256) == id.SHA256
}
func (s *Store) Record(parent context.Context, peer clustertransport.Peer, report Report) error {
	now := s.now()
	node, err := uuid.Parse(peer.NodeID)
	if err != nil || node == uuid.Nil || node.String() != peer.NodeID || peer.ClusterID != s.cluster || peer.SPKI == ([32]byte{}) || !now.Before(peer.ExpiresAt) || !identityValid(report.Applied) || !identityValid(report.Desired) {
		return ErrInvalid
	}
	if report.LeaseExpiresAt.After(now.Add(clusterpolicy.MaxLease + 5*time.Second)) {
		return ErrInvalid
	}
	if report.Ready && (report.Applied == (clusterpolicy.Identity{}) || report.Applied != report.Desired || !now.Before(report.LeaseExpiresAt)) {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		for _, id := range []clusterpolicy.Identity{report.Applied, report.Desired} {
			if id == (clusterpolicy.Identity{}) {
				continue
			}
			var exists bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM cluster_policy_manifests WHERE cluster_id=$1 AND revision=$2 AND sha256=$3)", s.cluster, id.Revision, id.SHA256).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return ErrInvalid
			}
		}
		tag, err := tx.Exec(ctx, `INSERT INTO cluster_policy_receipts(cluster_id,node_id,spki_sha256,applied_revision,applied_sha256,desired_revision,desired_sha256,ready,lease_expires_at,received_at)
   SELECT $1,n.node_id,$3,$4,$5,$6,$7,$8,$9,clock_timestamp() FROM cluster_nodes n
   WHERE n.cluster_id=$1 AND n.node_id=$2 AND n.enabled AND n.expires_at>clock_timestamp() AND 'policy:read'=ANY(n.scopes) AND $3=ANY(n.spki_pins)
   ON CONFLICT(cluster_id,node_id) DO UPDATE SET spki_sha256=excluded.spki_sha256,applied_revision=excluded.applied_revision,applied_sha256=excluded.applied_sha256,desired_revision=excluded.desired_revision,desired_sha256=excluded.desired_sha256,ready=excluded.ready,lease_expires_at=excluded.lease_expires_at,received_at=excluded.received_at`, s.cluster, peer.NodeID, peer.SPKI[:], report.Applied.Revision, report.Applied.SHA256, report.Desired.Revision, report.Desired.SHA256, report.Ready, report.LeaseExpiresAt)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return clustertransport.ErrDenied
		}
		return nil
	})
}
func (s *Store) View(parent context.Context, assigned []string) (View, error) {
	out := View{Nodes: []Node{}}
	if len(assigned) == 0 || len(assigned) > 64 {
		return out, ErrInvalid
	}
	nodes := slices.Clone(assigned)
	slices.Sort(nodes)
	for i, id := range nodes {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id || (i > 0 && nodes[i-1] == id) {
			return out, ErrInvalid
		}
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
	}()
	var primary bool
	if err = tx.QueryRow(ctx, "SELECT NOT pg_is_in_recovery() AND current_setting('default_transaction_read_only')='off'").Scan(&primary); err != nil {
		return out, err
	}
	if !primary {
		return out, errors.New("policy confirmation leader is unavailable")
	}
	if err = tx.QueryRow(ctx, "SELECT revision FROM cluster_policy_source_state WHERE singleton").Scan(&out.SourceRevision); err != nil {
		return out, err
	}
	err = tx.QueryRow(ctx, "SELECT revision,sha256 FROM cluster_policy_heads WHERE cluster_id=$1", s.cluster).Scan(&out.Desired.Revision, &out.Desired.SHA256)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	rows, err := tx.Query(ctx, `SELECT a.node_id::text,COALESCE(n.role,''),COALESCE(n.enabled AND n.expires_at>clock_timestamp() AND 'policy:read'=ANY(n.scopes) AND r.spki_sha256=ANY(n.spki_pins),false),
  COALESCE(r.applied_revision,0),COALESCE(r.applied_sha256,''),COALESCE(r.desired_revision,0),COALESCE(r.desired_sha256,''),COALESCE(r.ready,false),COALESCE(r.lease_expires_at,'epoch'::timestamptz),COALESCE(r.received_at,'epoch'::timestamptz)
  FROM unnest($2::uuid[]) a(node_id) LEFT JOIN cluster_nodes n ON n.cluster_id=$1 AND n.node_id=a.node_id LEFT JOIN cluster_policy_receipts r ON r.cluster_id=$1 AND r.node_id=a.node_id ORDER BY a.node_id`, s.cluster, nodes)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	now := s.now()
	for rows.Next() {
		var n Node
		if err = rows.Scan(&n.NodeID, &n.Role, &n.Eligible, &n.Report.Applied.Revision, &n.Report.Applied.SHA256, &n.Report.Desired.Revision, &n.Report.Desired.SHA256, &n.Report.Ready, &n.Report.LeaseExpiresAt, &n.ReceivedAt); err != nil {
			return out, err
		}
		n.Recent = n.ReceivedAt.After(now.Add(-RecentReport)) && !n.ReceivedAt.After(now.Add(5*time.Second))
		n.Confirmed = n.Eligible && n.Recent && n.Report.Ready && now.Before(n.Report.LeaseExpiresAt) && n.Report.Applied == out.Desired && n.Report.Desired == out.Desired && out.Desired.Revision > 0
		out.Nodes = append(out.Nodes, n)
	}
	return out, rows.Err()
}
