package clusterworker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"os"
	"path/filepath"
	"rauth/internal/clusterpolicy"
	"rauth/internal/clusterstate"
	"rauth/internal/core"
	"rauth/internal/pgtest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var testCluster = uuid.NewString()
var background = context.Background()

func signingKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("worker-coordination-synthetic-test-key"))
	return ed25519.NewKeyFromSeed(seed[:])
}
func trust(t *testing.T) *clusterpolicy.Verifier {
	t.Helper()
	v, err := clusterpolicy.NewVerifier(testCluster, map[string]ed25519.PublicKey{"v1": signingKey().Public().(ed25519.PublicKey)})
	require.NoError(t, err)
	return v
}
func signed(t *testing.T, revision int64, policy string) (clusterstate.Head, map[string][]byte) {
	t.Helper()
	body := []byte(policy)
	sum := sha256.Sum256(body)
	manifest := clusterpolicy.Manifest{Schema: 1, ClusterID: testCluster, Revision: revision, PublishedAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Blobs: []clusterpolicy.Blob{{Kind: "policy", ID: "policy", SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(body))}}}
	raw, err := clusterpolicy.Sign(manifest, "v1", signingKey())
	require.NoError(t, err)
	verified, err := trust(t).Verify(raw)
	require.NoError(t, err)
	return clusterstate.Head{Verified: verified, Envelope: raw}, map[string][]byte{manifest.Blobs[0].SHA256: body}
}

type fakeAuthority struct {
	mu              sync.Mutex
	head            clusterstate.Head
	bodies          map[string][]byte
	err             error
	checks          int
	fetches         int
	blockedRevision int64
	entered         chan struct{}
	release         chan struct{}
}

func (s *fakeAuthority) set(head clusterstate.Head, bodies map[string][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.head = head
	s.bodies = bodies
	s.err = nil
}
func (s *fakeAuthority) Current(context.Context) (clusterstate.Head, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checks++
	return clusterstate.Head{Verified: s.head.Verified, Envelope: bytes.Clone(s.head.Envelope)}, s.err
}
func (s *fakeAuthority) OpenBlob(ctx context.Context, id clusterpolicy.Identity, b clusterpolicy.Blob) (io.ReadCloser, error) {
	s.mu.Lock()
	s.fetches++
	body := bytes.Clone(s.bodies[b.SHA256])
	blocked := id.Revision == s.blockedRevision
	entered, release := s.entered, s.release
	s.mu.Unlock()
	if blocked {
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return io.NopCloser(bytes.NewReader(body)), nil
}

type testValue struct {
	rule   string
	closes atomic.Int32
}

func (v *testValue) Close() error { v.closes.Add(1); return nil }

type testCompiler struct {
	draft      *testValue
	closeCalls int
}

func (c *testCompiler) Validate(_ context.Context, b clusterpolicy.Blob, r io.Reader) error {
	if b.Kind != "policy" {
		return errors.New("unexpected blob")
	}
	c.draft = &testValue{}
	var document struct {
		Rule string `json:"rule"`
	}
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF || document.Rule == "" {
		return errors.New("invalid semantic rule")
	}
	c.draft.rule = document.Rule
	return nil
}
func (c *testCompiler) Finish(ctx context.Context, bundle clusterpolicy.VerifiedBundle) (*testValue, error) {
	if c.draft == nil || len(bundle.Manifest().Blobs) != 1 {
		return nil, errors.New("missing dependency")
	}
	value := c.draft
	c.draft = nil
	return value, nil
}
func (c *testCompiler) Close() error {
	c.closeCalls++
	if c.closeCalls > 1 {
		return errors.New("compiler closed twice")
	}
	if c.draft != nil {
		_ = c.draft.Close()
		c.draft = nil
	}
	return nil
}
func factory() Compiler[*testValue] { return &testCompiler{} }
func linux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("durable cache requires Linux host filesystem")
	}
}
func rootDir(t *testing.T) string {
	t.Helper()
	linux(t)
	root := t.TempDir()
	require.NoError(t, os.Chmod(root, 0o700))
	return root
}
func worker(t *testing.T, source Authority) (*Worker[*testValue], string) {
	t.Helper()
	root := rootDir(t)
	w, err := New(root, trust(t), source, factory, 10*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, w.Close()) })
	return w, root
}
func rule(t *testing.T, w *Worker[*testValue]) string {
	t.Helper()
	var text string
	require.NoError(t, w.WithPolicy(func(value *testValue) error { text = value.rule; assert.Zero(t, value.closes.Load()); return nil }))
	return text
}
func activate(t *testing.T, w *Worker[*testValue]) {
	t.Helper()
	require.NoError(t, w.check(background))
	require.NoError(t, w.apply(background))
}
func TestWorkerRejectsMissingCapabilities(t *testing.T) {
	_, err := New[*testValue]("", nil, nil, nil, 0)
	require.ErrorIs(t, err, clusterpolicy.ErrInvalid)
}
func TestWorkerStartupAndRestartRequireFreshAuthoritativeHead(t *testing.T) {
	h, b := signed(t, 1, `{"rule":"one"}`)
	source := &fakeAuthority{}
	source.set(h, b)
	w, root := worker(t, source)
	require.ErrorIs(t, w.WithPolicy(func(*testValue) error { return nil }), clusterpolicy.ErrNotCurrent)
	activate(t, w)
	require.Equal(t, "one", rule(t, w))
	require.NoError(t, w.Close())
	source.mu.Lock()
	source.err = io.ErrUnexpectedEOF
	previousFetches := source.fetches
	source.mu.Unlock()
	restarted, err := New(root, trust(t), source, factory, 10*time.Second)
	require.NoError(t, err)
	defer func() { _ = restarted.Close() }()
	require.False(t, restarted.Status().Policy.Ready)
	require.Error(t, restarted.check(background))
	require.ErrorIs(t, restarted.WithPolicy(func(*testValue) error { return nil }), clusterpolicy.ErrNotCurrent)
	source.set(h, b)
	require.NoError(t, restarted.check(background))
	require.Equal(t, "one", rule(t, restarted))
	source.mu.Lock()
	assert.Equal(t, previousFetches, source.fetches, "verified cached policy needs no controller payload fetch after restart")
	source.mu.Unlock()
}
func TestWorkerNewHeadWithdrawsBeforeBlockedDownloadAndCancelsObsoleteStage(t *testing.T) {
	one, b1 := signed(t, 1, `{"rule":"one"}`)
	source := &fakeAuthority{}
	source.set(one, b1)
	w, _ := worker(t, source)
	activate(t, w)
	two, b2 := signed(t, 2, `{"rule":"two"}`)
	source.set(two, b2)
	source.blockedRevision = 2
	source.entered = make(chan struct{}, 1)
	source.release = make(chan struct{})
	require.NoError(t, w.check(background))
	require.False(t, w.Status().Policy.Ready)
	done := make(chan error, 1)
	go func() { done <- w.apply(background) }()
	select {
	case <-source.entered:
	case <-time.After(time.Second):
		t.Fatal("did not stage")
	}
	require.ErrorIs(t, w.WithPolicy(func(*testValue) error { return nil }), clusterpolicy.ErrNotCurrent)
	three, b3 := signed(t, 3, `{"rule":"three"}`)
	source.set(three, b3)
	require.NoError(t, w.check(background))
	require.ErrorIs(t, <-done, context.Canceled)
	require.NoError(t, w.apply(background))
	require.Equal(t, "three", rule(t, w))
	state, err := w.store.State()
	require.NoError(t, err)
	assert.Equal(t, three.Verified.Identity(), state.HighWater)
}
func TestWorkerFailedCompilerKeepsDurableActiveButCannotAuthorizeIt(t *testing.T) {
	one, b1 := signed(t, 1, `{"rule":"one"}`)
	source := &fakeAuthority{}
	source.set(one, b1)
	w, cacheRoot := worker(t, source)
	activate(t, w)
	two, b2 := signed(t, 2, `{"unexpected":"bad"}`)
	source.set(two, b2)
	require.NoError(t, w.check(background))
	require.Error(t, w.apply(background))
	require.False(t, w.Status().Policy.Ready)
	state, err := w.store.State()
	require.NoError(t, err)
	assert.Equal(t, one.Verified.Identity(), state.Active)
	assert.Equal(t, two.Verified.Identity(), state.HighWater)
	require.NoError(t, w.Close())
	restarted, err := New(cacheRoot, trust(t), source, factory, 10*time.Second)
	require.NoError(t, err)
	defer func() { _ = restarted.Close() }()
	w = restarted
	require.False(t, w.Status().Policy.Ready, "restart cannot revive active data below the durable watermark")
	// A deliberate rollback is a newly signed higher revision, never a lower head.
	source.set(one, b1)
	require.ErrorIs(t, w.check(background), clusterpolicy.ErrRollback)
	three, b3 := signed(t, 3, `{"rule":"one"}`)
	source.set(three, b3)
	activate(t, w)
	require.Equal(t, "one", rule(t, w))
}
func TestWorkerPinsRetiredResourcesUntilCallbacksFinish(t *testing.T) {
	one, b1 := signed(t, 1, `{"rule":"one"}`)
	source := &fakeAuthority{}
	source.set(one, b1)
	w, _ := worker(t, source)
	activate(t, w)
	entered, release := make(chan *testValue, 1), make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- w.WithPolicy(func(value *testValue) error { entered <- value; <-release; return nil }) }()
	old := <-entered
	two, b2 := signed(t, 2, `{"rule":"two"}`)
	source.set(two, b2)
	activate(t, w)
	assert.Zero(t, old.closes.Load())
	assert.Equal(t, "two", rule(t, w))
	close(release)
	require.NoError(t, <-done)
	assert.EqualValues(t, 1, old.closes.Load())
	entered2, release2 := make(chan *testValue, 1), make(chan struct{})
	go func() {
		done <- w.WithPolicy(func(value *testValue) error { entered2 <- value; <-release2; return nil })
	}()
	current := <-entered2
	require.NoError(t, w.Close())
	assert.Zero(t, current.closes.Load())
	require.ErrorIs(t, w.WithPolicy(func(*testValue) error { return nil }), ErrClosed)
	close(release2)
	require.NoError(t, <-done)
	assert.EqualValues(t, 1, current.closes.Load())
}
func TestWorkerOperationalReadFailureUsesOnlyExistingLeaseAndCorruptionInvalidates(t *testing.T) {
	one, b1 := signed(t, 1, `{"rule":"one"}`)
	source := &fakeAuthority{}
	source.set(one, b1)
	w, _ := worker(t, source)
	activate(t, w)
	source.mu.Lock()
	source.err = io.ErrUnexpectedEOF
	source.mu.Unlock()
	require.Error(t, w.check(background))
	require.Equal(t, "one", rule(t, w))
	source.mu.Lock()
	source.err = clusterstate.ErrCorrupt
	source.mu.Unlock()
	require.ErrorIs(t, w.check(background), clusterstate.ErrCorrupt)
	require.False(t, w.Status().Policy.Ready)
	source.set(one, b1)
	require.NoError(t, w.check(background))
	require.Equal(t, "one", rule(t, w))
	corrupt := one
	corrupt.Envelope = bytes.Clone(one.Envelope)
	corrupt.Envelope[0] = '['
	source.set(corrupt, b1)
	require.ErrorIs(t, w.check(background), clusterpolicy.ErrInvalid)
	require.False(t, w.Status().Policy.Ready)
}
func TestWorkerPersistenceFailureWithdrawsReadinessImmediately(t *testing.T) {
	one, b1 := signed(t, 1, `{"rule":"one"}`)
	source := &fakeAuthority{}
	source.set(one, b1)
	w, _ := worker(t, source)
	activate(t, w)
	require.NoError(t, w.store.Close())
	require.ErrorIs(t, w.check(background), clusterpolicy.ErrStoreClosed)
	require.False(t, w.Status().Policy.Ready)
}
func TestWorkerRunPollsIndependentlyAndClosesCleanly(t *testing.T) {
	one, b1 := signed(t, 1, `{"rule":"one"}`)
	source := &fakeAuthority{}
	source.set(one, b1)
	w, _ := worker(t, source)
	w.interval = 10 * time.Millisecond
	cancelCtx, cancel := context.WithCancel(background)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Run(cancelCtx) }()
	require.Eventually(t, func() bool { return w.Status().Policy.Ready }, 2*time.Second, 10*time.Millisecond)
	require.ErrorIs(t, w.Run(background), ErrStarted)
	two, b2 := signed(t, 2, `{"rule":"two"}`)
	source.mu.Lock()
	source.blockedRevision = 2
	source.entered = make(chan struct{}, 1)
	source.release = make(chan struct{})
	source.mu.Unlock()
	source.set(two, b2)
	select {
	case <-source.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("did not stage")
	}
	source.mu.Lock()
	before := source.checks
	source.mu.Unlock()
	require.Eventually(t, func() bool { source.mu.Lock(); defer source.mu.Unlock(); return source.checks >= before+3 }, time.Second, 10*time.Millisecond)
	require.False(t, w.Status().Policy.Ready)
	three, b3 := signed(t, 3, `{"rule":"three"}`)
	source.set(three, b3)
	require.Eventually(t, func() bool { return w.Status().Policy.Ready && w.Status().Policy.Applied == three.Verified.Identity() }, 2*time.Second, 10*time.Millisecond)
	require.Equal(t, "three", rule(t, w))
	require.NoError(t, w.Close())
	require.ErrorIs(t, <-done, context.Canceled)
	require.NoError(t, w.Close())
}
func TestWorkerRealAuthoritySharedStateRestartAndLeaseExpiry(t *testing.T) {
	linux(t)
	pool := pgtest.Open(t, core.Migrate)
	pgtest.Reset(t, pool)
	publisher, err := clusterstate.NewPublisher(pool, trust(t))
	require.NoError(t, err)
	makeSource := func() (*clusterstate.Reader, *pgxpool.Pool) {
		cfg := pool.Config()
		cfg.MaxConns = 1
		heads, e := pgxpool.NewWithConfig(background, cfg)
		require.NoError(t, e)
		t.Cleanup(heads.Close)
		payloads, e := pgxpool.NewWithConfig(background, cfg)
		require.NoError(t, e)
		t.Cleanup(payloads.Close)
		reader, e := clusterstate.NewReader(heads, payloads, trust(t))
		require.NoError(t, e)
		return reader, heads
	}
	reader1, heads1 := makeSource()
	reader2, _ := makeSource()
	a, root := worker(t, reader1)
	b, _ := worker(t, reader2)
	one, b1 := signed(t, 1, `{"rule":"one"}`)
	open := func(bodies map[string][]byte) func(clusterpolicy.Blob) (io.ReadCloser, error) {
		return func(blob clusterpolicy.Blob) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodies[blob.SHA256])), nil
		}
	}
	validate := func(_ clusterpolicy.Blob, r io.Reader) error { _, e := io.Copy(io.Discard, r); return e }
	_, err = publisher.Publish(background, clusterpolicy.Identity{}, one.Envelope, open(b1), validate)
	require.NoError(t, err)
	activate(t, a)
	activate(t, b)
	require.Equal(t, "one", rule(t, a))
	require.Equal(t, "one", rule(t, b))
	require.NoError(t, a.Close())
	a, err = New(root, trust(t), reader1, factory, 10*time.Second)
	require.NoError(t, err)
	defer func() { _ = a.Close() }()
	require.False(t, a.Status().Policy.Ready)
	require.NoError(t, a.check(background))
	require.Equal(t, "one", rule(t, a))
	two, b2 := signed(t, 2, `{"rule":"two"}`)
	_, err = publisher.Publish(background, one.Verified.Identity(), two.Envelope, open(b2), validate)
	require.NoError(t, err)
	require.NoError(t, a.check(background))
	require.NoError(t, b.check(background))
	require.False(t, a.Status().Policy.Ready)
	require.False(t, b.Status().Policy.Ready)
	require.NoError(t, a.apply(background))
	require.NoError(t, b.apply(background))
	require.Equal(t, "two", rule(t, a))
	require.Equal(t, "two", rule(t, b))
	// Closing only this worker's head pool simulates loss of authoritative reads.
	heads1.Close()
	require.Error(t, a.check(background))
	require.Equal(t, "two", rule(t, a))
	deadline := a.Status().Policy.LeaseExpiresAt
	timer := time.NewTimer(time.Until(deadline) + 25*time.Millisecond)
	defer timer.Stop()
	<-timer.C
	require.ErrorIs(t, a.WithPolicy(func(*testValue) error { return nil }), clusterpolicy.ErrNotCurrent)
	require.NoError(t, b.check(background))
	require.Equal(t, "two", rule(t, b), "independent healthy worker can renew from shared authority")
}

func TestWorkerNotificationIsOnlyHintAndDoesNotNeedPeriodicTick(t *testing.T) {
	one, b1 := signed(t, 1, `{"rule":"one"}`)
	source := &fakeAuthority{}
	source.set(one, b1)
	w, _ := worker(t, source)
	w.interval = time.Hour
	done := make(chan error, 1)
	go func() { done <- w.Run(background) }()
	require.Eventually(t, func() bool { return w.Status().Policy.Ready }, 2*time.Second, 10*time.Millisecond)
	two, b2 := signed(t, 2, `{"rule":"two"}`)
	source.set(two, b2)
	for range 1000 {
		w.Notify()
	}
	require.Eventually(t, func() bool { return w.Status().Policy.Ready && w.Status().Policy.Applied == two.Verified.Identity() }, 3*time.Second, 10*time.Millisecond)
	require.Equal(t, "two", rule(t, w))
	require.NoError(t, w.Close())
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestWorkerRejectedHeadInvalidatesPreviouslyReadyPolicy(t *testing.T) {
	one, b1 := signed(t, 1, `{"rule":"one"}`)
	source := &fakeAuthority{}
	source.set(one, b1)
	w, _ := worker(t, source)
	activate(t, w)
	two, b2 := signed(t, 2, `{"rule":"two"}`)
	source.set(two, b2)
	activate(t, w)
	require.Equal(t, "two", rule(t, w))
	source.set(one, b1)
	require.ErrorIs(t, w.check(background), clusterpolicy.ErrRollback)
	require.False(t, w.Status().Policy.Ready)
	require.ErrorIs(t, w.WithPolicy(func(*testValue) error { return nil }), clusterpolicy.ErrNotCurrent)
	source.set(two, b2)
	require.NoError(t, w.check(background))
	require.Equal(t, "two", rule(t, w))
	equivocation, bad := signed(t, 2, `{"rule":"different-at-same-revision"}`)
	source.set(equivocation, bad)
	require.ErrorIs(t, w.check(background), clusterpolicy.ErrRollback)
	require.False(t, w.Status().Policy.Ready)
	require.ErrorIs(t, w.WithPolicy(func(*testValue) error { return nil }), clusterpolicy.ErrNotCurrent)
}

func TestWorkerCorruptActiveBlobStartsUnreadyForVerifiedRepair(t *testing.T) {
	one, b1 := signed(t, 1, `{"rule":"one"}`)
	source := &fakeAuthority{}
	source.set(one, b1)
	w, cacheRoot := worker(t, source)
	activate(t, w)
	require.NoError(t, w.Close())
	blob := one.Verified.Manifest().Blobs[0]
	require.NoError(t, os.WriteFile(filepath.Join(cacheRoot, "blobs", blob.SHA256), []byte("corrupt"), 0o600))
	restarted, err := New(cacheRoot, trust(t), source, factory, 10*time.Second)
	require.NoError(t, err)
	defer func() { _ = restarted.Close() }()
	require.False(t, restarted.Status().Policy.Ready)
	require.Error(t, restarted.Status().StageError)
	require.ErrorIs(t, restarted.WithPolicy(func(*testValue) error { return nil }), clusterpolicy.ErrNotCurrent)
	activate(t, restarted)
	require.Equal(t, "one", rule(t, restarted))
	require.NoError(t, restarted.Status().StageError)
}

type rejectOldCompiler struct{ testCompiler }

func (c *rejectOldCompiler) Finish(ctx context.Context, bundle clusterpolicy.VerifiedBundle) (*testValue, error) {
	if c.draft != nil && c.draft.rule == "one" {
		return nil, errors.New("old policy cannot compile under the new node profile")
	}
	return c.testCompiler.Finish(ctx, bundle)
}
func TestWorkerChangedCompilerCanStartAndAwaitNewCompatiblePolicy(t *testing.T) {
	one, b1 := signed(t, 1, `{"rule":"one"}`)
	source := &fakeAuthority{}
	source.set(one, b1)
	w, cacheRoot := worker(t, source)
	activate(t, w)
	require.NoError(t, w.Close())
	changedFactory := func() Compiler[*testValue] { return &rejectOldCompiler{} }
	restarted, err := New(cacheRoot, trust(t), source, changedFactory, 10*time.Second)
	require.NoError(t, err)
	defer func() { _ = restarted.Close() }()
	require.False(t, restarted.Status().Policy.Ready)
	require.Error(t, restarted.Status().StageError)
	two, b2 := signed(t, 2, `{"rule":"two"}`)
	source.set(two, b2)
	activate(t, restarted)
	require.Equal(t, "two", rule(t, restarted))
}

type blockingFinalCompiler struct {
	testCompiler
	entered chan<- struct{}
}

func (c *blockingFinalCompiler) Finish(ctx context.Context, bundle clusterpolicy.VerifiedBundle) (*testValue, error) {
	if c.draft != nil && c.draft.rule == "two" {
		select {
		case c.entered <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return c.testCompiler.Finish(ctx, bundle)
}
func TestWorkerFinalCompilationCancelsForNewHeadAndShutdown(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(fmt.Sprintf("shutdown=%t", shutdown), func(t *testing.T) {
			one, b1 := signed(t, 1, `{"rule":"one"}`)
			source := &fakeAuthority{}
			source.set(one, b1)
			entered := make(chan struct{}, 1)
			cacheRoot := rootDir(t)
			w, err := New(cacheRoot, trust(t), source, func() Compiler[*testValue] { return &blockingFinalCompiler{entered: entered} }, 10*time.Second)
			require.NoError(t, err)
			defer func() { _ = w.Close() }()
			w.interval = 10 * time.Millisecond
			done := make(chan error, 1)
			go func() { done <- w.Run(background) }()
			require.Eventually(t, func() bool { return w.Status().Policy.Ready }, 2*time.Second, 10*time.Millisecond)
			two, b2 := signed(t, 2, `{"rule":"two"}`)
			source.set(two, b2)
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("final compile did not begin")
			}
			if shutdown {
				closed := make(chan error, 1)
				go func() { closed <- w.Close() }()
				select {
				case err := <-closed:
					require.NoError(t, err)
				case <-time.After(time.Second):
					t.Fatal("shutdown did not cancel final compilation")
				}
			} else {
				three, b3 := signed(t, 3, `{"rule":"three"}`)
				source.set(three, b3)
				require.Eventually(t, func() bool { return w.Status().Policy.Ready && w.Status().Policy.Applied == three.Verified.Identity() }, 2*time.Second, 10*time.Millisecond)
				require.Equal(t, "three", rule(t, w))
				require.NoError(t, w.Close())
			}
			require.ErrorIs(t, <-done, context.Canceled)
		})
	}
}
