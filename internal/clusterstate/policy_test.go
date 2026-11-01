package clusterstate_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"rauth/internal/clusterpolicy"
	"rauth/internal/clusterstate"
	"rauth/internal/core"
	"rauth/internal/pgtest"
)

// Separate test binaries use separate schemas and cluster identities; advisory
// locks are database-wide even when their tables live in different schemas.
var cluster = uuid.NewString()

const feedID = "2df76c22-740e-421c-a2a0-3aa80157d774"

var ctx = context.Background()

func key() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("synthetic-policy-authority-test-key"))
	return ed25519.NewKeyFromSeed(seed[:])
}
func verifier(t *testing.T, clusterID string) *clusterpolicy.Verifier {
	t.Helper()
	v, err := clusterpolicy.NewVerifier(clusterID, map[string]ed25519.PublicKey{"v1": key().Public().(ed25519.PublicKey)})
	require.NoError(t, err)
	return v
}
func fixture(t *testing.T) (*pgxpool.Pool, *clusterstate.Publisher, *clusterstate.Reader) {
	t.Helper()
	pool := pgtest.Open(t, core.Migrate)
	pgtest.Reset(t, pool)
	publisher, err := clusterstate.NewPublisher(pool, verifier(t, cluster))
	require.NoError(t, err)
	other, err := pgxpool.NewWithConfig(ctx, pool.Config())
	require.NoError(t, err)
	t.Cleanup(other.Close)
	payloads, err := pgxpool.NewWithConfig(ctx, pool.Config())
	require.NoError(t, err)
	t.Cleanup(payloads.Close)
	reader, err := clusterstate.NewReader(other, payloads, verifier(t, cluster))
	require.NoError(t, err)
	return pool, publisher, reader
}
func blob(kind, id string, body []byte) clusterpolicy.Blob {
	sum := sha256.Sum256(body)
	return clusterpolicy.Blob{Kind: kind, ID: id, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(body))}
}
func signed(t *testing.T, revision int64, policy string, feed []byte) ([]byte, map[string][]byte, []clusterpolicy.Blob) {
	t.Helper()
	bs := []clusterpolicy.Blob{blob("policy", "policy", []byte(policy)), blob("feed", feedID, feed)}
	raw, err := clusterpolicy.Sign(clusterpolicy.Manifest{Schema: 1, ClusterID: cluster, Revision: revision, PublishedAt: time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC), Blobs: bs}, "v1", key())
	require.NoError(t, err)
	return raw, map[string][]byte{bs[0].SHA256: []byte(policy), bs[1].SHA256: feed}, bs
}
func opener(bodies map[string][]byte) func(clusterpolicy.Blob) (io.ReadCloser, error) {
	return func(b clusterpolicy.Blob) (io.ReadCloser, error) {
		body, ok := bodies[b.SHA256]
		if !ok {
			return nil, io.ErrUnexpectedEOF
		}
		return io.NopCloser(bytes.NewReader(body)), nil
	}
}
func semantics(b clusterpolicy.Blob, r io.Reader) error {
	if b.Kind == "policy" {
		var data map[string]any
		decoder := json.NewDecoder(r)
		if err := decoder.Decode(&data); err != nil {
			return err
		}
		if decoder.Decode(new(any)) != io.EOF {
			return errors.New("trailing policy document")
		}
		return nil
	}
	_, err := io.Copy(io.Discard, r)
	return err
}
func publish(t *testing.T, p *clusterstate.Publisher, base clusterpolicy.Identity, revision int64, policy string, feed []byte) clusterstate.Head {
	t.Helper()
	raw, bodies, _ := signed(t, revision, policy, feed)
	head, err := p.Publish(ctx, base, raw, opener(bodies), semantics)
	require.NoError(t, err)
	return head
}
func read(t *testing.T, r *clusterstate.Reader, id clusterpolicy.Identity, b clusterpolicy.Blob) []byte {
	t.Helper()
	source, err := r.OpenBlob(ctx, id, b)
	require.NoError(t, err)
	defer func() { _ = source.Close() }()
	body, err := io.ReadAll(source)
	require.NoError(t, err)
	require.NoError(t, source.Close())
	return body
}
func counts(t *testing.T, p *pgxpool.Pool) (int, int, int) {
	t.Helper()
	var manifests, blobs, chunks int
	require.NoError(t, p.QueryRow(ctx, `SELECT (SELECT count(*) FROM cluster_policy_manifests),(SELECT count(*) FROM cluster_policy_blobs),(SELECT count(*) FROM cluster_policy_chunks)`).Scan(&manifests, &blobs, &chunks))
	return manifests, blobs, chunks
}
func TestPolicyAuthorityRequiresVerifiedTLS(t *testing.T) {
	v := verifier(t, cluster)
	_, err := clusterstate.NewReader(nil, nil, v)
	require.Error(t, err)
	config, err := pgxpool.ParseConfig("postgres://localhost/unused?sslmode=disable")
	require.NoError(t, err)
	pool, err := pgxpool.NewWithConfig(ctx, config)
	require.NoError(t, err)
	defer pool.Close()
	_, err = clusterstate.NewPublisher(pool, v)
	require.ErrorContains(t, err, "verified PostgreSQL TLS")
	_, err = clusterstate.NewPublisher(pool, nil)
	require.ErrorIs(t, err, clusterpolicy.ErrInvalid)
}
func TestPolicyAuthorityCrossConnectionStreamingAndDeduplication(t *testing.T) {
	pool, p, r := fixture(t)
	_, err := r.Current(ctx)
	require.ErrorIs(t, err, clusterstate.ErrNoHead)
	feed := bytes.Repeat([]byte("203.0.113.0/24\n"), 170000) // exceeds two chunks, below signed feed limit
	raw, bodies, bs := signed(t, 1, `{"rules":[]}`, feed)
	h, err := p.Publish(ctx, clusterpolicy.Identity{}, raw, opener(bodies), semantics)
	require.NoError(t, err)
	raw[0] = '[' // stored envelope and returned head cannot alias caller buffers
	current, err := r.Current(ctx)
	require.NoError(t, err)
	require.Equal(t, h.Verified.Identity(), current.Verified.Identity())
	require.Equal(t, h.Envelope, current.Envelope)
	for _, b := range bs {
		require.Equal(t, bodies[b.SHA256], read(t, r, h.Verified.Identity(), b))
	}
	_, err = clusterpolicy.VerifyBundle(current.Verified, func(b clusterpolicy.Blob) (io.ReadCloser, error) {
		return r.OpenBlob(ctx, current.Verified.Identity(), b)
	}, semantics)
	require.NoError(t, err)
	second := publish(t, p, h.Verified.Identity(), 2, `{"rules":["two"]}`, feed)
	require.EqualValues(t, 2, second.Verified.Identity().Revision)
	manifests, blobs, chunks := counts(t, pool)
	assert.Equal(t, 2, manifests)
	assert.Equal(t, 3, blobs)
	assert.Equal(t, 5, chunks)
	wrong := bs[0]
	wrong.ID = "not-enrolled"
	_, err = r.OpenBlob(ctx, h.Verified.Identity(), wrong)
	require.ErrorIs(t, err, clusterstate.ErrNotFound)
}
func TestPolicyAuthorityHeadReadsDoNotWaitForStaging(t *testing.T) {
	_, p, r := fixture(t)
	first := publish(t, p, clusterpolicy.Identity{}, 1, `{"rules":[]}`, []byte("feed-one"))
	raw, bodies, _ := signed(t, 2, `{"rules":["two"]}`, []byte("feed-two"))
	entered, release := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		once := false
		_, err := p.Publish(ctx, first.Verified.Identity(), raw, func(b clusterpolicy.Blob) (io.ReadCloser, error) {
			if !once {
				once = true
				close(entered)
				<-release
			}
			return opener(bodies)(b)
		}, semantics)
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("publisher failed to stage")
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	current, err := r.Current(bounded)
	close(release)
	require.NoError(t, err)
	assert.Equal(t, first.Verified.Identity(), current.Verified.Identity())
	require.NoError(t, <-result)
	current, err = r.Current(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 2, current.Verified.Identity().Revision)
}

type closeFailure struct{ io.Reader }

func (closeFailure) Close() error { return io.ErrClosedPipe }
func TestPolicyAuthorityFailedPublicationLeavesNoPartialData(t *testing.T) {
	for _, mode := range []string{"hash", "truncated", "excess", "missing", "parse", "close", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			pool, p, r := fixture(t)
			initial := publish(t, p, clusterpolicy.Identity{}, 1, `{"rules":[]}`, []byte("initial"))
			beforeM, beforeB, beforeC := counts(t, pool)
			raw, bodies, bs := signed(t, 2, `{"rules":["new"]}`, []byte("replacement"))
			operation, cancel := context.WithCancel(ctx)
			defer cancel()
			open := func(b clusterpolicy.Blob) (io.ReadCloser, error) {
				if b.Kind != "feed" {
					return opener(bodies)(b)
				}
				switch mode {
				case "hash":
					return io.NopCloser(strings.NewReader(strings.Repeat("x", int(b.Bytes)))), nil
				case "truncated":
					return io.NopCloser(strings.NewReader("x")), nil
				case "excess":
					return io.NopCloser(strings.NewReader("replacement!")), nil
				case "missing":
					return nil, io.ErrUnexpectedEOF
				case "close":
					return closeFailure{bytes.NewReader(bodies[b.SHA256])}, nil
				case "cancel":
					cancel()
				}
				return opener(bodies)(b)
			}
			validate := func(b clusterpolicy.Blob, source io.Reader) error {
				if mode == "parse" && b == bs[1] {
					return errors.New("invalid policy reference")
				}
				return semantics(b, source)
			}
			_, err := p.Publish(operation, initial.Verified.Identity(), raw, open, validate)
			require.Error(t, err)
			current, err := r.Current(ctx)
			require.NoError(t, err)
			assert.Equal(t, initial.Verified.Identity(), current.Verified.Identity())
			afterM, afterB, afterC := counts(t, pool)
			assert.Equal(t, []int{beforeM, beforeB, beforeC}, []int{afterM, afterB, afterC})
		})
	}
}
func TestPolicyAuthorityConcurrentWritersConflictAndLostAckRetry(t *testing.T) {
	pool, p, r := fixture(t)
	initial := publish(t, p, clusterpolicy.Identity{}, 1, `{"rules":[]}`, []byte("initial"))
	other, err := clusterstate.NewPublisher(pool, verifier(t, cluster))
	require.NoError(t, err)
	raw, bodies, _ := signed(t, 2, `{"rules":["winner"]}`, []byte("same"))
	rival, rivalBodies, _ := signed(t, 2, `{"rules":["loser"]}`, []byte("other"))
	entered, release := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		once := false
		_, err := p.Publish(ctx, initial.Verified.Identity(), raw, func(b clusterpolicy.Blob) (io.ReadCloser, error) {
			if !once {
				once = true
				close(entered)
				<-release
			}
			return opener(bodies)(b)
		}, semantics)
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("publisher failed to stage")
	}
	_, err = other.Publish(ctx, initial.Verified.Identity(), rival, opener(rivalBodies), semantics)
	close(release)
	require.ErrorIs(t, err, clusterstate.ErrBusy)
	require.NoError(t, <-result)
	_, err = other.Publish(ctx, initial.Verified.Identity(), rival, opener(rivalBodies), semantics)
	require.ErrorIs(t, err, clusterstate.ErrConflict)
	retried, err := other.Publish(ctx, initial.Verified.Identity(), raw, func(clusterpolicy.Blob) (io.ReadCloser, error) {
		t.Error("lost ACK retry refetched data")
		return nil, io.ErrUnexpectedEOF
	}, semantics)
	require.NoError(t, err)
	current, err := r.Current(ctx)
	require.NoError(t, err)
	assert.Equal(t, current.Verified.Identity(), retried.Verified.Identity())
}
func TestPolicyAuthorityRetirementPreservesOpenSnapshot(t *testing.T) {
	pool, p, r := fixture(t)
	feed := bytes.Repeat([]byte("a"), 2<<20)
	initial := publish(t, p, clusterpolicy.Identity{}, 1, `{"rules":["one"]}`, feed)
	dependency := initial.Verified.Manifest().Blobs[1]
	opened, err := r.OpenBlob(ctx, initial.Verified.Identity(), dependency)
	require.NoError(t, err)
	defer func() { _ = opened.Close() }()
	second := publish(t, p, initial.Verified.Identity(), 2, `{"rules":["two"]}`, []byte("two"))
	third := publish(t, p, second.Verified.Identity(), 3, `{"rules":["three"]}`, []byte("three"))
	_, err = r.Manifest(ctx, initial.Verified.Identity())
	require.ErrorIs(t, err, clusterstate.ErrNotFound)
	got, err := io.ReadAll(opened)
	require.NoError(t, err)
	require.Equal(t, feed, got)
	require.NoError(t, opened.Close())
	_, err = r.Manifest(ctx, second.Verified.Identity())
	require.NoError(t, err)
	_, err = r.Manifest(ctx, third.Verified.Identity())
	require.NoError(t, err)
	manifests, blobs, chunks := counts(t, pool)
	assert.Equal(t, []int{2, 4, 4}, []int{manifests, blobs, chunks})
}
func TestPolicyAuthorityRejectsCorruptEnvelopeAndChunks(t *testing.T) {
	for _, mode := range []string{"envelope", "chunk", "missing", "order"} {
		t.Run(mode, func(t *testing.T) {
			pool, p, r := fixture(t)
			head := publish(t, p, clusterpolicy.Identity{}, 1, `{"rules":[]}`, []byte("first"))
			b := head.Verified.Manifest().Blobs[1]
			var err error
			switch mode {
			case "envelope":
				_, err = pool.Exec(ctx, `UPDATE cluster_policy_manifests SET envelope=$1`, []byte(`{}`))
			case "chunk":
				_, err = pool.Exec(ctx, `UPDATE cluster_policy_chunks SET payload=$1 WHERE sha256=$2`, []byte("other"), b.SHA256)
			case "missing":
				_, err = pool.Exec(ctx, `DELETE FROM cluster_policy_chunks WHERE sha256=$1`, b.SHA256)
			case "order":
				_, err = pool.Exec(ctx, `UPDATE cluster_policy_chunks SET part=1 WHERE sha256=$1`, b.SHA256)
			}
			require.NoError(t, err)
			if mode == "envelope" {
				_, err = r.Current(ctx)
				require.ErrorIs(t, err, clusterstate.ErrCorrupt)
				return
			}
			source, err := r.OpenBlob(ctx, head.Verified.Identity(), b)
			require.NoError(t, err)
			defer func() { _ = source.Close() }()
			_, err = io.ReadAll(source)
			require.ErrorIs(t, err, clusterstate.ErrCorrupt)
			raw, bodies, _ := signed(t, 2, `{"rules":["new"]}`, []byte("first"))
			_, err = p.Publish(ctx, head.Verified.Identity(), raw, opener(bodies), semantics)
			require.Error(t, err, "reusing a corrupt dependency cannot publish")
			current, err := r.Current(ctx)
			require.NoError(t, err)
			assert.Equal(t, head.Verified.Identity(), current.Verified.Identity())
		})
	}
}
func TestPolicyAuthorityReadOnlyReusedConnectionCannotRenewHead(t *testing.T) {
	pool, p, _ := fixture(t)
	initial := publish(t, p, clusterpolicy.Identity{}, 1, `{"rules":[]}`, []byte("first"))
	cfg := pool.Config()
	cfg.MaxConns = 1
	other, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer other.Close()
	payloads, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer payloads.Close()
	r, err := clusterstate.NewReader(other, payloads, verifier(t, cluster))
	require.NoError(t, err)
	h, err := r.Current(ctx)
	require.NoError(t, err)
	assert.Equal(t, initial.Verified.Identity(), h.Verified.Identity())
	_, err = other.Exec(ctx, `SET default_transaction_read_only=on`)
	require.NoError(t, err)
	_, err = r.Current(ctx)
	require.ErrorIs(t, err, clusterstate.ErrUnavailable)
	_, err = r.Manifest(ctx, initial.Verified.Identity())
	require.ErrorIs(t, err, clusterstate.ErrUnavailable)
	_, err = payloads.Exec(ctx, `SET default_transaction_read_only=on`)
	require.NoError(t, err)
	_, err = r.OpenBlob(ctx, initial.Verified.Identity(), initial.Verified.Manifest().Blobs[0])
	require.ErrorIs(t, err, clusterstate.ErrUnavailable)
}
func TestPolicyAuthorityClusterScopeAndRevisionValidation(t *testing.T) {
	pool, p, r := fixture(t)
	raw, bodies, _ := signed(t, 1, `{"rules":[]}`, nil)
	foreign, err := clusterstate.NewPublisher(pool, verifier(t, "857a4ac0-27ec-45d1-9849-21bb4e6c070e"))
	require.NoError(t, err)
	_, err = foreign.Publish(ctx, clusterpolicy.Identity{}, raw, opener(bodies), semantics)
	require.ErrorIs(t, err, clusterpolicy.ErrInvalid)
	// A foreign signer cannot publish into this cluster.
	_, err = r.Current(ctx)
	require.ErrorIs(t, err, clusterstate.ErrNoHead)
	_, err = p.Publish(ctx, clusterpolicy.Identity{Revision: -1}, raw, opener(bodies), semantics)
	require.ErrorIs(t, err, clusterpolicy.ErrInvalid)
	skipped, skippedBodies, _ := signed(t, 2, `{"rules":[]}`, nil)
	_, err = p.Publish(ctx, clusterpolicy.Identity{}, skipped, opener(skippedBodies), semantics)
	require.ErrorIs(t, err, clusterstate.ErrConflict)
	head, err := p.Publish(ctx, clusterpolicy.Identity{}, raw, opener(bodies), semantics)
	require.NoError(t, err)
	empty := head.Verified.Manifest().Blobs[1]
	require.Empty(t, read(t, r, head.Verified.Identity(), empty))
}

func TestPolicyAuthorityPayloadBudgetCannotStarveHeadPoll(t *testing.T) {
	pool, p, _ := fixture(t)
	head := publish(t, p, clusterpolicy.Identity{}, 1, `{"rules":[]}`, []byte("first"))
	cfg := pool.Config()
	cfg.MaxConns = 1
	heads, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer heads.Close()
	payloads, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer payloads.Close()
	r, err := clusterstate.NewReader(heads, payloads, verifier(t, cluster))
	require.NoError(t, err)
	_, err = clusterstate.NewReader(heads, heads, verifier(t, cluster))
	require.ErrorIs(t, err, clusterpolicy.ErrInvalid)
	_, err = r.Current(ctx) // warm TLS before testing independence from an occupied payload pool
	require.NoError(t, err)
	opened, err := r.OpenBlob(ctx, head.Verified.Identity(), head.Verified.Manifest().Blobs[1])
	require.NoError(t, err)
	defer func() { _ = opened.Close() }()
	require.EqualValues(t, 1, payloads.Stat().AcquiredConns())
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	current, err := r.Current(bounded)
	require.NoError(t, err)
	assert.Equal(t, head.Verified.Identity(), current.Verified.Identity())
}
