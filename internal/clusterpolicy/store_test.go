package clusterpolicy

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func cacheFixture(t *testing.T) (string, *Verifier) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("durable worker cache is Linux-only")
	}
	path := t.TempDir()
	require.NoError(t, os.Chmod(path, 0o700))
	v, err := NewVerifier(testCluster, map[string]ed25519.PublicKey{"one": testKey("one").Public().(ed25519.PublicKey)})
	require.NoError(t, err)
	return path, v
}
func cacheGeneration(t *testing.T, v *Verifier, revision int64) ([]byte, VerifiedManifest, map[string]string) {
	t.Helper()
	policy := fmt.Sprintf(`{"rules":["v%d.example.test"]}`, revision)
	feed := fmt.Sprintf("203.0.113.%d/32\n", revision)
	manifest := Manifest{Schema: 1, ClusterID: testCluster, Revision: revision, PublishedAt: time.Date(2026, 11, 1, 0, 0, int(revision), 0, time.UTC), Blobs: []Blob{testBlob("policy", "policy", policy), testBlob("feed", testFeed, feed)}}
	raw, err := Sign(manifest, "one", testKey("one"))
	require.NoError(t, err)
	head, err := v.Verify(raw)
	require.NoError(t, err)
	return raw, head, map[string]string{manifest.Blobs[0].SHA256: policy, manifest.Blobs[1].SHA256: feed}
}
func cacheFetcher(content map[string]string) func(context.Context, Blob) (io.ReadCloser, error) {
	return func(ctx context.Context, b Blob) (io.ReadCloser, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s, ok := content[b.SHA256]
		if !ok {
			return nil, os.ErrNotExist
		}
		return io.NopCloser(strings.NewReader(s)), nil
	}
}
func cacheValidator(b Blob, r io.Reader) error {
	raw, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	switch b.Kind {
	case "policy":
		var policy struct {
			Rules []string `json:"rules"`
		}
		if strictJSON(raw, &policy) != nil || len(policy.Rules) == 0 {
			return ErrInvalid
		}
	case "feed":
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if _, err := netip.ParsePrefix(line); err != nil {
				return err
			}
		}
	default:
		return ErrInvalid
	}
	return nil
}
func activateCache(t *testing.T, s *Store, v *Verifier, revision int64) (VerifiedManifest, VerifiedBundle) {
	t.Helper()
	raw, head, content := cacheGeneration(t, v, revision)
	require.NoError(t, s.RecordHead(head))
	bundle, err := s.Stage(context.Background(), raw, cacheFetcher(content), cacheValidator)
	require.NoError(t, err)
	require.NoError(t, s.Activate(bundle))
	return head, bundle
}
func TestCacheRequiresExistingPrivateRootAndExclusiveWriter(t *testing.T) {
	root, v := cacheFixture(t)
	missing := filepath.Join(root, "missing")
	_, err := OpenStore(missing, v)
	require.Error(t, err)
	_, err = os.Stat(missing)
	require.ErrorIs(t, err, os.ErrNotExist)
	s, err := OpenStore(root, v)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	_, err = OpenStore(root, v)
	require.Error(t, err, "a second writer must not overwrite the journal")
	other := t.TempDir()
	require.NoError(t, os.Chmod(other, 0o777))
	_, err = OpenStore(other, v)
	require.Error(t, err)
	link := filepath.Join(t.TempDir(), "cache-link")
	require.NoError(t, os.Symlink(root, link))
	_, err = OpenStore(link+string(os.PathSeparator), v)
	require.Error(t, err)
}
func TestCacheRestartVerifiesActiveAndNeverRestoresALease(t *testing.T) {
	root, v := cacheFixture(t)
	s, err := OpenStore(root, v)
	require.NoError(t, err)
	head, bundle := activateCache(t, s, v, 1)
	require.NoError(t, s.Close())
	s, err = OpenStore(root, v)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	loaded, err := s.LoadActive(cacheValidator)
	require.NoError(t, err)
	assert.Equal(t, bundle.Identity(), loaded.Identity())
	st, err := s.State()
	require.NoError(t, err)
	assert.Equal(t, head.Identity(), st.HighWater)
	f, err := NewFreshness(v, st.HighWater, DefaultLease)
	require.NoError(t, err)
	require.NoError(t, f.Restore(loaded))
	assert.False(t, f.Status(loaded).Ready)
	require.NoError(t, f.ObserveHead(head))
	assert.True(t, f.Status(loaded).Ready)
}
func TestCacheKeepsOnlyActivePreviousAndOneStagedGeneration(t *testing.T) {
	root, v := cacheFixture(t)
	s, err := OpenStore(root, v)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	activateCache(t, s, v, 1)
	head2, _ := activateCache(t, s, v, 2)
	head3, _ := activateCache(t, s, v, 3)
	st, err := s.State()
	require.NoError(t, err)
	assert.Equal(t, head3.Identity(), st.Active)
	assert.Equal(t, head2.Identity(), st.Previous)
	manifests, err := os.ReadDir(filepath.Join(root, "manifests"))
	require.NoError(t, err)
	assert.Len(t, manifests, 2)
	blobs, err := os.ReadDir(filepath.Join(root, "blobs"))
	require.NoError(t, err)
	assert.Len(t, blobs, 4)
	for rev := int64(4); rev <= 5; rev++ {
		raw, _, content := cacheGeneration(t, v, rev)
		_, err = s.Stage(context.Background(), raw, cacheFetcher(content), cacheValidator)
		require.NoError(t, err)
	}
	manifests, err = os.ReadDir(filepath.Join(root, "manifests"))
	require.NoError(t, err)
	assert.Len(t, manifests, 3)
	blobs, err = os.ReadDir(filepath.Join(root, "blobs"))
	require.NoError(t, err)
	assert.Len(t, blobs, 6)
}
func TestCachePartialOrCorruptStagingDoesNotReplaceActive(t *testing.T) {
	for _, mode := range []string{"missing", "corrupt", "parse", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			root, v := cacheFixture(t)
			s, err := OpenStore(root, v)
			require.NoError(t, err)
			defer func() { _ = s.Close() }()
			_, old := activateCache(t, s, v, 1)
			raw, head, content := cacheGeneration(t, v, 2)
			require.NoError(t, s.RecordHead(head))
			for hash := range content {
				if mode == "missing" {
					delete(content, hash)
					break
				}
				if mode == "corrupt" {
					content[hash] += "trailing"
					break
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			validate := cacheValidator
			if mode == "parse" {
				validate = func(Blob, io.Reader) error { return errors.New("semantic compilation failed") }
			}
			_, err = s.Stage(ctx, raw, cacheFetcher(content), validate)
			require.Error(t, err)
			st, err := s.State()
			require.NoError(t, err)
			assert.Equal(t, old.Identity(), st.Active)
			assert.Equal(t, head.Identity(), st.HighWater)
			assert.Empty(t, st.Staged)
			loaded, err := s.LoadActive(cacheValidator)
			require.NoError(t, err)
			assert.Equal(t, old.Identity(), loaded.Identity())
			blobs, err := os.ReadDir(filepath.Join(root, "blobs"))
			require.NoError(t, err)
			assert.Len(t, blobs, 2, "failed staging must not accumulate orphan data")
		})
	}
}
func TestHeadObservationDoesNotWaitForNetworkAndInvalidatesDelayedStage(t *testing.T) {
	root, v := cacheFixture(t)
	s, err := OpenStore(root, v)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	_, old := activateCache(t, s, v, 1)
	raw, head, content := cacheGeneration(t, v, 2)
	require.NoError(t, s.RecordHead(head))
	_, newer, _ := cacheGeneration(t, v, 3)
	paused, resume := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := s.Stage(context.Background(), raw, func(ctx context.Context, b Blob) (io.ReadCloser, error) {
			if b.Kind == "feed" {
				close(paused)
				<-resume
			}
			return cacheFetcher(content)(ctx, b)
		}, cacheValidator)
		done <- err
	}()
	select {
	case <-paused:
	case <-time.After(5 * time.Second):
		t.Fatal("stage did not reach network pause")
	}
	observed := make(chan error, 1)
	go func() { observed <- s.RecordHead(newer) }()
	select {
	case err = <-observed:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("head observation waited for network")
	}
	close(resume)
	select {
	case err = <-done:
		require.ErrorIs(t, err, ErrRollback)
	case <-time.After(5 * time.Second):
		t.Fatal("stage did not terminate")
	}
	st, err := s.State()
	require.NoError(t, err)
	assert.Equal(t, newer.Identity(), st.HighWater)
	assert.Equal(t, old.Identity(), st.Active)
}
func TestCacheFailsClosedForSymlinksCorruptionAndMissingJournal(t *testing.T) {
	for _, mode := range []string{"blob-symlink", "corrupt-state", "lost-journal", "directory-symlink"} {
		t.Run(mode, func(t *testing.T) {
			root, v := cacheFixture(t)
			s, err := OpenStore(root, v)
			require.NoError(t, err)
			_, bundle := activateCache(t, s, v, 1)
			require.NoError(t, s.Close())
			outside := filepath.Join(t.TempDir(), "unrelated")
			require.NoError(t, os.WriteFile(outside, []byte("operator-data"), 0o600))
			switch mode {
			case "blob-symlink":
				target := filepath.Join(root, "blobs", bundle.head.manifest.Blobs[0].SHA256)
				require.NoError(t, os.Remove(target))
				require.NoError(t, os.Symlink(outside, target))
			case "corrupt-state":
				require.NoError(t, os.WriteFile(filepath.Join(root, "state.json"), []byte(`{"schema":1,"active":"broken"}`), 0o600))
			case "lost-journal":
				require.NoError(t, os.Remove(filepath.Join(root, "state.json")))
			case "directory-symlink":
				require.NoError(t, os.Rename(filepath.Join(root, "blobs"), filepath.Join(root, "old-blobs")))
				require.NoError(t, os.Symlink(filepath.Dir(outside), filepath.Join(root, "blobs")))
			}
			reopened, err := OpenStore(root, v)
			if err == nil {
				defer func() { _ = reopened.Close() }()
				_, err = reopened.LoadActive(cacheValidator)
			}
			require.Error(t, err)
			got, err := os.ReadFile(outside)
			require.NoError(t, err)
			assert.Equal(t, "operator-data", string(got))
		})
	}
}
func TestCacheRecoversAtomicJournalCommitWithoutTrustingPriorReadiness(t *testing.T) {
	root, v := cacheFixture(t)
	s, err := OpenStore(root, v)
	require.NoError(t, err)
	activateCache(t, s, v, 1)
	raw, head, content := cacheGeneration(t, v, 2)
	require.NoError(t, s.RecordHead(head))
	bundle, err := s.Stage(context.Background(), raw, cacheFetcher(content), cacheValidator)
	require.NoError(t, err)
	realSync := s.syncDir
	s.syncDir = func(dir string) error {
		if dir == "." {
			return errors.New("simulated fsync failure")
		}
		return realSync(dir)
	}
	require.ErrorIs(t, s.Activate(bundle), ErrStoreIndeterminate)
	_, err = s.State()
	require.ErrorIs(t, err, ErrStoreClosed)
	require.NoError(t, s.Close())
	s, err = OpenStore(root, v)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	loaded, err := s.LoadActive(cacheValidator)
	require.NoError(t, err)
	assert.Equal(t, bundle.Identity(), loaded.Identity())
	st, err := s.State()
	require.NoError(t, err)
	f, err := NewFreshness(v, st.HighWater, DefaultLease)
	require.NoError(t, err)
	require.NoError(t, f.Restore(loaded))
	assert.False(t, f.Status(loaded).Ready)
}
func TestCacheCrashTemporariesAreBoundedWithoutDeletingOperatorFiles(t *testing.T) {
	root, v := cacheFixture(t)
	s, err := OpenStore(root, v)
	require.NoError(t, err)
	activateCache(t, s, v, 1)
	require.NoError(t, s.Close())
	for _, dir := range []string{".", "blobs", "manifests"} {
		require.NoError(t, os.WriteFile(filepath.Join(root, dir, ".tmp-0123456789abcdef0123456789abcdef"), []byte("interrupted"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(root, dir, ".tmp-operator-notes"), []byte("keep"), 0o600))
	}
	s, err = OpenStore(root, v)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	for _, dir := range []string{".", "blobs", "manifests"} {
		_, err = os.Stat(filepath.Join(root, dir, ".tmp-0123456789abcdef0123456789abcdef"))
		require.ErrorIs(t, err, os.ErrNotExist)
		raw, err := os.ReadFile(filepath.Join(root, dir, ".tmp-operator-notes"))
		require.NoError(t, err)
		assert.Equal(t, "keep", string(raw))
	}
}
func TestCacheRejectsJournalRollbackAndSameRevisionConflict(t *testing.T) {
	root, v := cacheFixture(t)
	s, err := OpenStore(root, v)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	_, old := activateCache(t, s, v, 1)
	head, _ := activateCache(t, s, v, 2)
	require.ErrorIs(t, s.RecordHead(old.head), ErrRollback)
	m := head.Manifest()
	m.PublishedAt = m.PublishedAt.Add(time.Second)
	raw, err := Sign(m, "one", testKey("one"))
	require.NoError(t, err)
	conflict, err := v.Verify(raw)
	require.NoError(t, err)
	require.ErrorIs(t, s.RecordHead(conflict), ErrRollback)
	st, err := s.State()
	require.NoError(t, err)
	data, err := json.Marshal(st)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "lease")
}

func TestCacheRejectsAHeadVerifiedWithForeignTrustKeys(t *testing.T) {
	root, v := cacheFixture(t)
	s, err := OpenStore(root, v)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	head, _ := activateCache(t, s, v, 1)
	key := testKey("untrusted")
	other, err := NewVerifier(testCluster, map[string]ed25519.PublicKey{"untrusted": key.Public().(ed25519.PublicKey)})
	require.NoError(t, err)
	m := head.Manifest()
	m.Revision = 2
	raw, err := Sign(m, "untrusted", key)
	require.NoError(t, err)
	foreign, err := other.Verify(raw)
	require.NoError(t, err)
	require.ErrorIs(t, s.RecordHead(foreign), ErrRollback)
	st, err := s.State()
	require.NoError(t, err)
	assert.Equal(t, head.Identity(), st.HighWater)
}

func TestCacheActivationCommitSurvivesCleanupFailureAndRetry(t *testing.T) {
	root, v := cacheFixture(t)
	s, err := OpenStore(root, v)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	activateCache(t, s, v, 1)
	raw, head, content := cacheGeneration(t, v, 2)
	require.NoError(t, s.RecordHead(head))
	bundle, err := s.Stage(context.Background(), raw, cacheFetcher(content), cacheValidator)
	require.NoError(t, err)
	realSync := s.syncDir
	s.syncDir = func(dir string) error {
		if dir == "blobs" {
			return errors.New("simulated post-commit cleanup failure")
		}
		return realSync(dir)
	}
	require.NoError(t, s.Activate(bundle), "post-commit cleanup cannot masquerade as a failed activation")
	require.Error(t, s.CleanupError())
	st, err := s.State()
	require.NoError(t, err)
	assert.Equal(t, bundle.Identity(), st.Active)
	assert.Empty(t, st.Staged)
	s.syncDir = realSync
	require.NoError(t, s.Activate(bundle), "retry is idempotent after the commit")
	require.NoError(t, s.CleanupError())
}
func TestArtifactCleanupDoesNotRemoveConcurrentHeadJournalTemporary(t *testing.T) {
	root, v := cacheFixture(t)
	s, err := OpenStore(root, v)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	activateCache(t, s, v, 1)
	_, head, _ := cacheGeneration(t, v, 2)
	st, err := s.State()
	require.NoError(t, err)
	paused := make(chan string, 1)
	resume := make(chan struct{})
	done := make(chan error, 1)
	s.beforeRename = func(target, tmp string) error {
		if target == "state.json" {
			paused <- tmp
			<-resume
		}
		return nil
	}
	go func() { done <- s.RecordHead(head) }()
	var tmp string
	select {
	case tmp = <-paused:
	case <-time.After(5 * time.Second):
		t.Fatal("journal did not reach atomic rename")
	}
	// Stage's artifact reclamation uses only stageMu. A RecordHead writer owns
	// stateMu and its journal temporary must remain untouched by that cleanup.
	s.stageMu.Lock()
	err = s.gc(st, false)
	s.stageMu.Unlock()
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(root, tmp))
	require.NoError(t, err, "concurrent journal temporary was deleted")
	close(resume)
	select {
	case err = <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("head commit did not resume")
	}
	current, err := s.State()
	require.NoError(t, err)
	assert.Equal(t, head.Identity(), current.HighWater)
}
func TestCacheFailedAtomicRenameKeepsPriorActiveAndAllowsRetry(t *testing.T) {
	root, v := cacheFixture(t)
	s, err := OpenStore(root, v)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	_, old := activateCache(t, s, v, 1)
	raw, head, content := cacheGeneration(t, v, 2)
	require.NoError(t, s.RecordHead(head))
	bundle, err := s.Stage(context.Background(), raw, cacheFetcher(content), cacheValidator)
	require.NoError(t, err)
	s.beforeRename = func(target, _ string) error {
		if target == "state.json" {
			return syscall.ENOSPC
		}
		return nil
	}
	require.ErrorIs(t, s.Activate(bundle), syscall.ENOSPC)
	st, err := s.State()
	require.NoError(t, err)
	assert.Equal(t, old.Identity(), st.Active)
	assert.Equal(t, bundle.Identity(), st.Staged)
	s.beforeRename = nil
	require.NoError(t, s.Activate(bundle))
}
