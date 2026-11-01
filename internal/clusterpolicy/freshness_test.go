package clusterpolicy

import (
	"crypto/ed25519"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFreshnessRestartNeedsFreshHeadAndControllerOutageDoesNotMatter(t *testing.T) {
	head, bundle, _, v := fixture(t, 10)
	now := time.Now()
	f, err := NewFreshness(v, head.Identity(), 0)
	require.NoError(t, err)
	f.now = func() time.Time { return now }
	require.NoError(t, f.Restore(bundle))
	assert.False(t, f.Status(bundle).Ready)
	require.NoError(t, f.ObserveHead(head))
	assert.True(t, f.Status(bundle).Ready)
	// No controller contact is necessary if a fresh HA head stays unchanged.
	now = now.Add(100 * time.Second)
	require.NoError(t, f.ObserveHead(head))
	assert.True(t, f.Status(bundle).Ready)
	now = now.Add(119 * time.Second)
	f.HeadUnavailable()
	assert.True(t, f.Status(bundle).Ready)
	now = now.Add(time.Second)
	assert.False(t, f.Status(bundle).Ready, "lease is closed at the deadline, not one tick later")
	restarted, err := NewFreshness(v, head.Identity(), DefaultLease)
	require.NoError(t, err)
	restarted.now = f.now
	require.NoError(t, restarted.Restore(bundle))
	assert.False(t, restarted.Status(bundle).Ready, "disk cache alone cannot renew an outage lease")
}
func TestNewHeadWithdrawsReadinessUntilCompleteCurrentActivation(t *testing.T) {
	old, oldBundle, _, v := fixture(t, 1)
	next, nextBundle, _, _ := fixture(t, 2)
	now := time.Now()
	f, err := NewFreshness(v, Identity{}, DefaultLease)
	require.NoError(t, err)
	f.now = func() time.Time { return now }
	require.NoError(t, f.Restore(oldBundle))
	require.NoError(t, f.ObserveHead(old))
	assert.True(t, f.Status(oldBundle).Ready)
	require.NoError(t, f.ObserveHead(next))
	assert.False(t, f.Status(oldBundle).Ready)
	require.ErrorIs(t, f.Activate(oldBundle), ErrNotCurrent)
	assert.False(t, f.Status(oldBundle).Ready)
	require.ErrorIs(t, f.Activate(VerifiedBundle{}), ErrNotCurrent)
	require.NoError(t, f.Activate(nextBundle))
	assert.True(t, f.Status(nextBundle).Ready)
	assert.False(t, f.Status(oldBundle).Ready, "admission is bound to the actual evaluated generation")
	require.ErrorIs(t, f.ObserveHead(old), ErrRollback)
	assert.False(t, f.Status(oldBundle).Ready, "rollback evidence withdraws the lease immediately")
	require.NoError(t, f.ObserveHead(next))
	assert.True(t, f.Status(nextBundle).Ready)
}
func TestFreshnessRejectsEquivocationDelayedActivationAndInvalidLimits(t *testing.T) {
	head, bundle, _, v := fixture(t, 8)
	other, _, _, _ := fixture(t, 8)
	// A different signed payload at the same revision is never a rollback alias.
	m := other.Manifest()
	m.PublishedAt = m.PublishedAt.Add(time.Second)
	raw, err := Sign(m, "one", testKey("one"))
	require.NoError(t, err)
	other, err = v.Verify(raw)
	require.NoError(t, err)
	now := time.Now()
	f, err := NewFreshness(v, head.Identity(), 10*time.Second)
	require.NoError(t, err)
	f.now = func() time.Time { return now }
	require.NoError(t, f.Restore(bundle))
	require.NoError(t, f.ObserveHead(head))
	assert.True(t, f.Status(bundle).Ready)
	require.ErrorIs(t, f.ObserveHead(other), ErrRollback)
	assert.False(t, f.Status(bundle).Ready)
	require.ErrorIs(t, f.ObserveHead(VerifiedManifest{}), ErrRollback)
	require.NoError(t, f.ObserveHead(head))
	now = now.Add(10 * time.Second)
	require.ErrorIs(t, f.Activate(bundle), ErrNotCurrent)
	assert.False(t, f.Status(bundle).Ready)
	_, err = NewFreshness(v, Identity{}, MaxLease+time.Second)
	require.ErrorIs(t, err, ErrInvalid)
	_, err = NewFreshness(v, Identity{}, time.Second)
	require.ErrorIs(t, err, ErrInvalid)
	_, err = NewFreshness(v, Identity{Revision: 2, SHA256: "bad"}, 0)
	require.ErrorIs(t, err, ErrInvalid)
}
func TestPersistedHighWaterRejectsOldRestoredGenerations(t *testing.T) {
	old, oldBundle, _, v := fixture(t, 5)
	current, _, _, _ := fixture(t, 6)
	f, err := NewFreshness(v, current.Identity(), DefaultLease)
	require.NoError(t, err)
	require.ErrorIs(t, f.Restore(oldBundle), ErrRollback)
	require.ErrorIs(t, f.ObserveHead(old), ErrRollback)
	assert.False(t, f.Status(oldBundle).Ready)
}

func TestNewHeadDuringStagingCannotPublishAnOlderBundleAsReady(t *testing.T) {
	initial, initialBundle, _, v := fixture(t, 1)
	next, _, _, _ := fixture(t, 2)
	newest, newestBundle, _, _ := fixture(t, 3)
	f, err := NewFreshness(v, Identity{}, DefaultLease)
	require.NoError(t, err)
	require.NoError(t, f.Restore(initialBundle))
	require.NoError(t, f.ObserveHead(initial))
	require.NoError(t, f.ObserveHead(next))
	paused := make(chan struct{})
	resume := make(chan struct{})
	completed := make(chan VerifiedBundle, 1)
	failed := make(chan error, 1)
	go func() {
		bundle, err := VerifyBundle(next, func(b Blob) (io.ReadCloser, error) {
			if b.Kind == "feed" {
				close(paused)
				<-resume
				return io.NopCloser(strings.NewReader("203.0.113.42/32\n")), nil
			}
			return io.NopCloser(strings.NewReader(`{"rules":["app.other.test"]}`)), nil
		}, func(_ Blob, r io.Reader) error { _, err := io.Copy(io.Discard, r); return err })
		if err != nil {
			failed <- err
			return
		}
		completed <- bundle
	}()
	select {
	case <-paused:
	case err := <-failed:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("staging did not reach pause")
	}
	assert.False(t, f.Status(initialBundle).Ready)
	require.NoError(t, f.ObserveHead(newest))
	close(resume)
	var staged VerifiedBundle
	select {
	case staged = <-completed:
	case err := <-failed:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("staging did not complete")
	}
	require.ErrorIs(t, f.Activate(staged), ErrNotCurrent)
	assert.False(t, f.Status(staged).Ready, "publishing the delayed generation cannot borrow another generation's lease")
	require.NoError(t, f.Activate(newestBundle))
	assert.True(t, f.Status(newestBundle).Ready)
	assert.False(t, f.Status(staged).Ready)
}

func TestFreshnessCannotAdmitEvidenceFromAnotherTrustKeySet(t *testing.T) {
	head, bundle, _, v := fixture(t, 1)
	foreignKey := testKey("foreign")
	foreign, err := NewVerifier(testCluster, map[string]ed25519.PublicKey{"foreign": foreignKey.Public().(ed25519.PublicKey)})
	require.NoError(t, err)
	m := head.Manifest()
	m.Revision = 2
	raw, err := Sign(m, "foreign", foreignKey)
	require.NoError(t, err)
	foreignHead, err := foreign.Verify(raw)
	require.NoError(t, err)
	foreignBundle := VerifiedBundle{head: foreignHead, valid: true}
	f, err := NewFreshness(v, head.Identity(), DefaultLease)
	require.NoError(t, err)
	require.NoError(t, f.Restore(bundle))
	require.NoError(t, f.ObserveHead(head))
	assert.True(t, f.Status(bundle).Ready)
	require.ErrorIs(t, f.ObserveHead(foreignHead), ErrRollback)
	assert.False(t, f.Status(bundle).Ready)
	require.ErrorIs(t, f.Restore(foreignBundle), ErrRollback)
	require.ErrorIs(t, f.Activate(foreignBundle), ErrNotCurrent)
	assert.False(t, f.Status(foreignBundle).Ready)
	// A valid signature under a different key set cannot even borrow an identical
	// raw envelope's identity (key rotation requires re-verification/reloading).
	overlap, err := NewVerifier(testCluster, map[string]ed25519.PublicKey{"one": testKey("one").Public().(ed25519.PublicKey), "foreign": foreignKey.Public().(ed25519.PublicKey)})
	require.NoError(t, err)
	originalRaw, err := Sign(head.Manifest(), "one", testKey("one"))
	require.NoError(t, err)
	alternate, err := overlap.Verify(originalRaw)
	require.NoError(t, err)
	assert.Equal(t, head.Identity(), alternate.Identity())
	require.ErrorIs(t, f.ObserveHead(alternate), ErrRollback)
}
