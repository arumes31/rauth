package clusterstatus

import (
	"context"
	"crypto/sha256"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"rauth/internal/clusterpolicy"
	"rauth/internal/clustertransport"
	"rauth/internal/core"
	"rauth/internal/pgtest"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	pool     *pgxpool.Pool
	store    *Store
	peer     clustertransport.Peer
	identity clusterpolicy.Identity
	now      time.Time
}

func setup(t *testing.T) *fixture {
	t.Helper()
	pool := pgtest.Open(t, core.Migrate)
	cluster, node := uuid.NewString(), uuid.NewString()
	now := time.Now().UTC()
	pin := sha256.Sum256([]byte(node))
	peer := clustertransport.Peer{ClusterID: cluster, NodeID: node, SPKI: pin, ExpiresAt: now.Add(time.Hour)}
	_, err := pool.Exec(context.Background(), `INSERT INTO cluster_nodes(cluster_id,node_id,revision,role,service_ip,spki_pins,scopes,enabled,expires_at) VALUES($1,$2,1,'worker','100.72.1.2',ARRAY[$3::bytea],ARRAY['policy:read'],true,$4)`, cluster, node, pin[:], now.Add(time.Hour))
	require.NoError(t, err)
	id := clusterpolicy.Identity{Revision: 1, SHA256: strings.Repeat("a", 64)}
	_, err = pool.Exec(context.Background(), `INSERT INTO cluster_policy_manifests(cluster_id,revision,sha256,envelope)VALUES($1,1,$2,$3);`, cluster, id.SHA256, []byte{1})
	require.NoError(t, err)
	_, err = pool.Exec(context.Background(), `INSERT INTO cluster_policy_heads VALUES($1,1,$2)`, cluster, id.SHA256)
	require.NoError(t, err)
	store, err := New(pool, cluster)
	require.NoError(t, err)
	return &fixture{pool: pool, store: store, peer: peer, identity: id, now: now}
}
func (f *fixture) report() Report {
	return Report{Applied: f.identity, Desired: f.identity, Ready: true, LeaseExpiresAt: f.now.Add(time.Minute)}
}
func (f *fixture) view(t *testing.T) View {
	t.Helper()
	v, err := f.store.View(context.Background(), []string{f.peer.NodeID})
	require.NoError(t, err)
	require.Len(t, v.Nodes, 1)
	return v
}
func TestPolicyReceiptDurableIdempotentAndExactIdentity(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	require.NoError(t, f.store.Record(ctx, f.peer, f.report()))
	require.NoError(t, f.store.Record(ctx, f.peer, f.report()))
	v := f.view(t)
	assert.Equal(t, f.identity, v.Desired)
	assert.True(t, v.Nodes[0].Confirmed)
	assert.True(t, v.Nodes[0].Eligible)
	assert.True(t, v.Nodes[0].Recent)
	var count int
	require.NoError(t, f.pool.QueryRow(ctx, "SELECT count(*) FROM cluster_policy_receipts WHERE cluster_id=$1 AND node_id=$2", f.peer.ClusterID, f.peer.NodeID).Scan(&count))
	assert.Equal(t, 1, count)
	unknown := f.report()
	unknown.Applied.SHA256 = strings.Repeat("b", 64)
	unknown.Desired = unknown.Applied
	assert.ErrorIs(t, f.store.Record(ctx, f.peer, unknown), ErrInvalid)
	spoof := f.peer
	spoof.NodeID = uuid.NewString()
	assert.ErrorIs(t, f.store.Record(ctx, spoof, f.report()), clustertransport.ErrDenied)
	var stored bool
	require.NoError(t, f.pool.QueryRow(ctx, "SELECT ready FROM cluster_policy_receipts WHERE cluster_id=$1 AND node_id=$2", f.peer.ClusterID, f.peer.NodeID).Scan(&stored))
	assert.True(t, stored)
}
func TestPolicyReceiptRevocationAndKeyRotationInvalidatePriorConfirmation(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	require.NoError(t, f.store.Record(ctx, f.peer, f.report()))
	_, err := f.pool.Exec(ctx, "UPDATE cluster_nodes SET scopes=ARRAY['events:write'] WHERE cluster_id=$1 AND node_id=$2", f.peer.ClusterID, f.peer.NodeID)
	require.NoError(t, err)
	assert.False(t, f.view(t).Nodes[0].Confirmed)
	assert.ErrorIs(t, f.store.Record(ctx, f.peer, f.report()), clustertransport.ErrDenied)
	newPin := sha256.Sum256([]byte("rotated-" + f.peer.NodeID))
	_, err = f.pool.Exec(ctx, "UPDATE cluster_nodes SET scopes=ARRAY['policy:read'],spki_pins=ARRAY[$3::bytea] WHERE cluster_id=$1 AND node_id=$2", f.peer.ClusterID, f.peer.NodeID, newPin[:])
	require.NoError(t, err)
	assert.False(t, f.view(t).Nodes[0].Confirmed)
	assert.ErrorIs(t, f.store.Record(ctx, f.peer, f.report()), clustertransport.ErrDenied)
	f.peer.SPKI = newPin
	require.NoError(t, f.store.Record(ctx, f.peer, f.report()))
	assert.True(t, f.view(t).Nodes[0].Confirmed)
	_, err = f.pool.Exec(ctx, "UPDATE cluster_nodes SET enabled=false WHERE cluster_id=$1 AND node_id=$2", f.peer.ClusterID, f.peer.NodeID)
	require.NoError(t, err)
	assert.False(t, f.view(t).Nodes[0].Confirmed)
}
func TestPolicyReceiptStalenessLeaseAndChangedHeadCannotConfirm(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	require.NoError(t, f.store.Record(ctx, f.peer, f.report()))
	f.store.now = func() time.Time { return f.now.Add(RecentReport + time.Second) }
	v := f.view(t)
	assert.False(t, v.Nodes[0].Recent)
	assert.False(t, v.Nodes[0].Confirmed)
	f.store.now = time.Now
	_, err := f.pool.Exec(ctx, "UPDATE cluster_policy_receipts SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE cluster_id=$1 AND node_id=$2", f.peer.ClusterID, f.peer.NodeID)
	require.NoError(t, err)
	v = f.view(t)
	assert.True(t, v.Nodes[0].Recent)
	assert.False(t, v.Nodes[0].Confirmed)
	require.NoError(t, f.store.Record(ctx, f.peer, f.report()))
	next := clusterpolicy.Identity{Revision: 2, SHA256: strings.Repeat("c", 64)}
	_, err = f.pool.Exec(ctx, "INSERT INTO cluster_policy_manifests VALUES($1,2,$2,$3)", f.peer.ClusterID, next.SHA256, []byte{2})
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, "UPDATE cluster_policy_heads SET revision=2,sha256=$2 WHERE cluster_id=$1", f.peer.ClusterID, next.SHA256)
	require.NoError(t, err)
	v = f.view(t)
	assert.Equal(t, next, v.Desired)
	assert.False(t, v.Nodes[0].Confirmed)
}
func TestPolicyReceiptUnreadyAndUnassignedAreNeverConfirmed(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	report := Report{Desired: f.identity}
	require.NoError(t, f.store.Record(ctx, f.peer, report))
	assert.False(t, f.view(t).Nodes[0].Confirmed)
	v, err := f.store.View(ctx, []string{uuid.NewString(), f.peer.NodeID})
	require.NoError(t, err)
	require.Len(t, v.Nodes, 2)
	for _, n := range v.Nodes {
		assert.False(t, n.Confirmed)
	}
	_, err = f.store.View(ctx, []string{f.peer.NodeID, f.peer.NodeID})
	assert.ErrorIs(t, err, ErrInvalid)
}
func TestPolicyReceiptBounds(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	for _, edit := range []func(*Report){func(r *Report) { r.LeaseExpiresAt = time.Now().Add(clusterpolicy.MaxLease + time.Minute) }, func(r *Report) { r.LeaseExpiresAt = time.Now().Add(-time.Second) }, func(r *Report) { r.Desired = clusterpolicy.Identity{} }, func(r *Report) { r.Applied.SHA256 = strings.Repeat("A", 64) }} {
		r := f.report()
		edit(&r)
		assert.ErrorIs(t, f.store.Record(ctx, f.peer, r), ErrInvalid)
	}
	expired := f.peer
	expired.ExpiresAt = time.Now().Add(-time.Second)
	assert.ErrorIs(t, f.store.Record(ctx, expired, f.report()), ErrInvalid)
	_, err := New(nil, uuid.NewString())
	assert.ErrorIs(t, err, ErrInvalid)
	_, err = New(f.pool, uuid.Nil.String())
	assert.True(t, errors.Is(err, ErrInvalid))
}
