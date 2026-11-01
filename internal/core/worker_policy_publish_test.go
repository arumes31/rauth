package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"rauth/internal/clusterpolicy"
	"testing"
	"time"
)

type publisherFixture struct {
	config    *Config
	options   WorkerPolicyCaptureOptions
	pools     []*pgxpool.Pool
	verifier  *clusterpolicy.Verifier
	publisher *ControllerPolicyPublisher
}

func putCaptureRule(t *testing.T, tx interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, action string, ids []string) {
	t.Helper()
	body, err := json.Marshal(BypassRule{Action: action, RulePolicy: RulePolicy{DefaultFeedConfigured: true, BlockedFeedIDs: ids}, Note: "private audit note", CreatedBy: "private-operator"})
	require.NoError(t, err)
	_, err = tx.Exec(context.Background(), `INSERT INTO bypass_rules(rule,meta) VALUES('cloud.example.test',$1) ON CONFLICT(rule) DO UPDATE SET meta=excluded.meta`, body)
	require.NoError(t, err)
}
func putCaptureFeed(t *testing.T, tx interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, version int64, body string) {
	t.Helper()
	b := policyContent("feed", DefaultIPFeedID, []byte(body))
	_, err := tx.Exec(context.Background(), `INSERT INTO ip_feeds(id,name,source_url,refresh_minutes,active_version,entry_count,created_by,created_at,updated_by,updated_at) VALUES($1,'managed','https://feed.example.test/raw?credential=do-not-distribute',60,$2,1,'private-operator',1,'private-operator',1) ON CONFLICT(id) DO UPDATE SET active_version=excluded.active_version`, DefaultIPFeedID, version)
	require.NoError(t, err)
	_, err = tx.Exec(context.Background(), `INSERT INTO ip_feed_versions(feed_id,version,checksum,payload,created_at) VALUES($1,$2,$3,$4,1)`, DefaultIPFeedID, version, b.SHA256, []byte(body))
	require.NoError(t, err)
}
func newPublisherFixture(t *testing.T) *publisherFixture {
	t.Helper()
	setupPG(t)
	putCaptureFeed(t, PG, 1, "203.0.113.42/32")
	putCaptureRule(t, PG, BypassAllow, []string{DefaultIPFeedID})
	cfg := workerProfileConfig()
	cfg.AuthBypassRules = []string{"env.example.test", "!tie.example.test", "tie.example.test"}
	fingerprint, err := NodeSecurityFingerprint(cfg)
	require.NoError(t, err)
	options := WorkerPolicyCaptureOptions{NodeID: snapshotNode, Config: cfg, Profiles: map[string]WorkerPolicyNodeProfile{snapshotNode: {SecurityFingerprint: fingerprint}}}
	v, err := clusterpolicy.NewVerifier(snapshotCluster, map[string]ed25519.PublicKey{"v1": snapshotKey().Public().(ed25519.PublicKey)})
	require.NoError(t, err)
	f := &publisherFixture{config: cfg, options: options, verifier: v}
	for range 4 {
		config := PG.Config()
		config.MaxConns = 1
		pool, e := pgxpool.NewWithConfig(context.Background(), config)
		require.NoError(t, e)
		t.Cleanup(pool.Close)
		f.pools = append(f.pools, pool)
	}
	f.publisher, err = NewControllerPolicyPublisher(f.pools[0], f.pools[1], f.pools[2], f.pools[3], v, "v1", snapshotKey(), options)
	require.NoError(t, err)
	return f
}
func captureBlob(t *testing.T, source *CapturedWorkerPolicy, id string) string {
	t.Helper()
	for _, b := range source.blobs {
		if b.ID == id {
			r, err := source.open(b)
			require.NoError(t, err)
			defer func() { _ = r.Close() }()
			body, err := io.ReadAll(r)
			require.NoError(t, err)
			return string(body)
		}
	}
	t.Fatalf("missing captured blob %s", id)
	return ""
}
func TestWorkerPolicyCaptureUsesCompleteSourceAndExcludesPrivateMetadata(t *testing.T) {
	f := newPublisherFixture(t)
	source, err := CaptureWorkerPolicy(context.Background(), f.pools[1], f.options)
	require.NoError(t, err)
	assert.True(t, policyHash(source.Digest()))
	body, err := json.Marshal(source.document)
	require.NoError(t, err)
	assert.NotContains(t, string(body), "private audit")
	assert.NotContains(t, string(body), "private-operator")
	assert.NotContains(t, string(body), "credential")
	assert.NotContains(t, string(body), "feed.example.test")
	assert.Equal(t, "203.0.113.42/32", captureBlob(t, source, DefaultIPFeedID))
	assert.Len(t, source.document.Rules, 3, "environment deny ties are canonicalized without opening the route")
	foundDeny := false
	for _, r := range source.document.Rules {
		if r.Rule == "tie.example.test" {
			foundDeny = r.Action == BypassDeny
		}
	}
	assert.True(t, foundDeny)
	next, err := CaptureWorkerPolicy(context.Background(), f.pools[1], f.options)
	require.NoError(t, err)
	assert.Equal(t, source.Digest(), next.Digest())
}
func TestWorkerPolicyPublisherCommitsOnceAndRejectsIncompleteNextGeneration(t *testing.T) {
	f := newPublisherFixture(t)
	first, err := f.publisher.Reconcile(context.Background())
	require.NoError(t, err)
	assert.True(t, first.Changed)
	assert.EqualValues(t, 1, first.Identity.Revision)
	second, err := f.publisher.Reconcile(context.Background())
	require.NoError(t, err)
	assert.False(t, second.Changed)
	assert.Equal(t, first.Identity, second.Identity)
	assert.Equal(t, first.SourceSHA256, second.SourceSHA256)
	putCaptureRule(t, PG, BypassAllow, []string{snapshotFeed}) // absent dependency: final compilation must reject before head commit
	_, err = f.publisher.Reconcile(context.Background())
	require.Error(t, err)
	current, err := f.publisher.current.Current(context.Background())
	require.NoError(t, err)
	assert.Equal(t, first.Identity, current.Verified.Identity())
	var manifests int
	require.NoError(t, PG.QueryRow(context.Background(), `SELECT count(*) FROM cluster_policy_manifests`).Scan(&manifests))
	assert.Equal(t, 1, manifests)
	putCaptureRule(t, PG, BypassDeny, []string{DefaultIPFeedID})
	third, err := f.publisher.Reconcile(context.Background())
	require.NoError(t, err)
	assert.True(t, third.Changed)
	assert.EqualValues(t, 2, third.Identity.Revision)
}
func TestWorkerPolicyPublisherFreezesCallerConfigProfilesAndSigner(t *testing.T) {
	f := newPublisherFixture(t)
	f.config.AuthBypassRules[0] = "caller-mutated.example.test"
	f.options.Profiles[snapshotNode] = WorkerPolicyNodeProfile{SecurityFingerprint: "invalid"}
	result, err := f.publisher.Reconcile(context.Background())
	require.NoError(t, err)
	assert.True(t, result.Changed)
	current, err := f.publisher.current.Current(context.Background())
	require.NoError(t, err)
	compiler, err := NewWorkerPolicyCompiler(f.publisher.compiler)
	require.NoError(t, err)
	defer func() { _ = compiler.Close() }()
	bundle, err := clusterpolicy.VerifyBundle(current.Verified, func(b clusterpolicy.Blob) (io.ReadCloser, error) {
		return f.publisher.current.OpenBlob(context.Background(), current.Verified.Identity(), b)
	}, func(b clusterpolicy.Blob, r io.Reader) error { return compiler.Validate(context.Background(), b, r) })
	require.NoError(t, err)
	snapshot, err := compiler.Finish(context.Background(), bundle)
	require.NoError(t, err)
	defer func() { _ = snapshot.Close() }()
	_, found, err := snapshot.SelectRule("env.example.test", "/")
	require.NoError(t, err)
	assert.True(t, found)
	_, found, err = snapshot.SelectRule("caller-mutated.example.test", "/")
	require.NoError(t, err)
	assert.False(t, found)
}
func TestWorkerPolicyPublisherKeyRotationPublishesNewHeadForSameSource(t *testing.T) {
	f := newPublisherFixture(t)
	first, err := f.publisher.Reconcile(context.Background())
	require.NoError(t, err)
	seed := bytes.Repeat([]byte{42}, ed25519.SeedSize)
	nextKey := ed25519.NewKeyFromSeed(seed)
	verifier, err := clusterpolicy.NewVerifier(snapshotCluster, map[string]ed25519.PublicKey{"v1": snapshotKey().Public().(ed25519.PublicKey), "v2": nextKey.Public().(ed25519.PublicKey)})
	require.NoError(t, err)
	rotated, err := NewControllerPolicyPublisher(f.pools[0], f.pools[1], f.pools[2], f.pools[3], verifier, "v2", nextKey, f.options)
	require.NoError(t, err)
	nextKey[0] ^= 0xff // constructor owns the signing key
	second, err := rotated.Reconcile(context.Background())
	require.NoError(t, err)
	assert.True(t, second.Changed)
	assert.EqualValues(t, 2, second.Identity.Revision)
	assert.Equal(t, first.SourceSHA256, second.SourceSHA256)
}
func TestWorkerPolicyCaptureRejectsReadOnlySourceEvenWithWritableHead(t *testing.T) {
	f := newPublisherFixture(t)
	first, err := f.publisher.Reconcile(context.Background())
	require.NoError(t, err)
	_, err = f.pools[1].Exec(context.Background(), `SET default_transaction_read_only=on`)
	require.NoError(t, err)
	_, err = f.publisher.Reconcile(context.Background())
	require.ErrorContains(t, err, "source is not the primary")
	current, err := f.publisher.current.Current(context.Background())
	require.NoError(t, err)
	assert.Equal(t, first.Identity, current.Verified.Identity())
}
func TestWorkerPolicyCaptureReadsRulesAndFeedVersionsFromOneSnapshot(t *testing.T) {
	f := newPublisherFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var pid int
	require.NoError(t, f.pools[1].QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	writer, err := PG.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = writer.Rollback(context.Background()) }()
	_, err = writer.Exec(ctx, `LOCK TABLE bypass_rules IN ACCESS EXCLUSIVE MODE`)
	require.NoError(t, err)
	putCaptureRule(t, writer, BypassDeny, []string{DefaultIPFeedID})
	putCaptureFeed(t, writer, 2, "203.0.113.99/32")
	type captured struct {
		source *CapturedWorkerPolicy
		err    error
	}
	done := make(chan captured, 1)
	go func() {
		source, e := CaptureWorkerPolicy(ctx, f.pools[1], f.options)
		done <- captured{source: source, err: e}
	}()
	require.Eventually(t, func() bool {
		var waiting bool
		return PG.QueryRow(ctx, `SELECT wait_event_type='Lock' FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&waiting) == nil && waiting
	}, 5*time.Second, 50*time.Millisecond)
	require.NoError(t, writer.Commit(ctx))
	result := <-done
	require.NoError(t, result.err)
	assert.Equal(t, "203.0.113.42/32", captureBlob(t, result.source, DefaultIPFeedID))
	for _, r := range result.source.document.Rules {
		if r.Source == "ui" {
			assert.Equal(t, BypassAllow, r.Action)
		}
	}
	next, err := CaptureWorkerPolicy(ctx, f.pools[1], f.options)
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.99/32", captureBlob(t, next, DefaultIPFeedID))
	assert.NotEqual(t, result.source.Digest(), next.Digest())
}
func TestWorkerPolicyCaptureRequiresDefaultAndCountryPrerequisites(t *testing.T) {
	f := newPublisherFixture(t)
	_, err := PG.Exec(context.Background(), `UPDATE ip_feeds SET active_version=0 WHERE id=$1`, DefaultIPFeedID)
	require.NoError(t, err)
	_, err = f.publisher.Reconcile(context.Background())
	require.ErrorContains(t, err, "default feed is not ready")
	_, err = PG.Exec(context.Background(), `UPDATE ip_feeds SET active_version=1 WHERE id=$1`, DefaultIPFeedID)
	require.NoError(t, err)
	f.options.Profiles[snapshotNode] = WorkerPolicyNodeProfile{SecurityFingerprint: f.options.Profiles[snapshotNode].SecurityFingerprint, RequireGeoIP: true}
	_, err = CaptureWorkerPolicy(context.Background(), f.pools[1], f.options)
	require.ErrorContains(t, err, "required GeoIP source")
	f.options.OpenGeoIP = func(context.Context) (io.ReadCloser, error) { return nil, errors.New("private file diagnosis") }
	_, err = CaptureWorkerPolicy(context.Background(), f.pools[1], f.options)
	require.Error(t, err)
}

func TestWorkerPolicyCapturePreservesAcceptedCommentOnlyEmptyRefresh(t *testing.T) {
	f := newPublisherFixture(t)
	require.NoError(t, refreshIPFeed(context.Background(), DefaultIPFeedID, FeedRefreshOptions{AcceptEmpty: true, AcceptLargeDrop: true}, testFeedClient("# accepted upstream comment\n\n")))
	var payload []byte
	require.NoError(t, PG.QueryRow(context.Background(), `SELECT v.payload FROM ip_feed_versions v JOIN ip_feeds f ON f.id=v.feed_id AND f.active_version=v.version WHERE f.id=$1`, DefaultIPFeedID).Scan(&payload))
	assert.Empty(t, payload, "refresh persists normalized empty content, not raw comments")
	source, err := CaptureWorkerPolicy(context.Background(), f.pools[1], f.options)
	require.NoError(t, err)
	require.Len(t, source.document.Feeds, 1)
	assert.True(t, source.document.Feeds[0].ApprovedEmpty)
	result, err := f.publisher.Reconcile(context.Background())
	require.NoError(t, err)
	assert.True(t, result.Changed)
}

func TestPolicySourceRevisionCapturesSavedChangesWithoutUnneededHead(t *testing.T) {
	f := newPublisherFixture(t)
	first, err := f.publisher.Reconcile(context.Background())
	require.NoError(t, err)
	require.NoError(t, policyMutation(context.Background(), func(pgx.Tx) error { return nil }))
	next, err := f.publisher.Reconcile(context.Background())
	require.NoError(t, err)
	assert.Greater(t, next.SourceRevision, first.SourceRevision)
	assert.Equal(t, first.Identity, next.Identity)
	assert.False(t, next.Changed)
	before := next.SourceRevision
	expected := errors.New("rollback source edit")
	err = policyMutation(context.Background(), func(pgx.Tx) error { return expected })
	require.ErrorIs(t, err, expected)
	after, err := f.publisher.Reconcile(context.Background())
	require.NoError(t, err)
	assert.Equal(t, before, after.SourceRevision)
}
