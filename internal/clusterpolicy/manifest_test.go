package clusterpolicy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testCluster = "6c6da2bf-d532-4bb7-895a-ae32b9b5bc50"
const testFeed = "e8aabaf1-9bbc-46cd-85fd-39281d9b8a89"

func testKey(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("synthetic-cluster-policy-" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}
func hashText(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
func testBlob(kind, id, body string) Blob {
	return Blob{Kind: kind, ID: id, SHA256: hashText(body), Bytes: int64(len(body))}
}
func fixture(t *testing.T, revision int64) (VerifiedManifest, VerifiedBundle, []byte, *Verifier) {
	t.Helper()
	policy := `{"rules":["app.other.test"]}`
	feed := "203.0.113.42/32\n"
	manifest := Manifest{Schema: 1, ClusterID: testCluster, Revision: revision, PublishedAt: time.Date(2026, 11, 1, 1, 2, 3, 0, time.UTC), Blobs: []Blob{testBlob("policy", "policy", policy), testBlob("feed", testFeed, feed)}}
	key := testKey("one")
	raw, err := Sign(manifest, "one", key)
	require.NoError(t, err)
	verifier, err := NewVerifier(testCluster, map[string]ed25519.PublicKey{"one": key.Public().(ed25519.PublicKey)})
	require.NoError(t, err)
	head, err := verifier.Verify(raw)
	require.NoError(t, err)
	bundle, err := VerifyBundle(head, func(b Blob) (io.ReadCloser, error) {
		s := policy
		if b.Kind == "feed" {
			s = feed
		}
		return io.NopCloser(strings.NewReader(s)), nil
	}, func(_ Blob, r io.Reader) error { _, err := io.Copy(io.Discard, r); return err })
	require.NoError(t, err)
	return head, bundle, raw, verifier
}
func TestSignedManifestPinsIdentityAndCopiesKeysAndMetadata(t *testing.T) {
	head, bundle, raw, v := fixture(t, 8)
	assert.EqualValues(t, 8, head.Identity().Revision)
	assert.Equal(t, hashText(string(raw)), head.Identity().SHA256)
	assert.Equal(t, head.Identity(), bundle.Identity())
	original := head.Manifest()
	original.Blobs[0].SHA256 = hashText("tampered")
	assert.NotEqual(t, original.Blobs[0].SHA256, head.Manifest().Blobs[0].SHA256)
	key := testKey("copy")
	pub := key.Public().(ed25519.PublicKey)
	copyVerifier, err := NewVerifier(testCluster, map[string]ed25519.PublicKey{"copy": pub})
	require.NoError(t, err)
	signed, err := Sign(head.Manifest(), "copy", key)
	require.NoError(t, err)
	pub[0] ^= 0xff
	_, err = copyVerifier.Verify(signed)
	require.NoError(t, err, "caller mutation cannot replace a trust key")
	raw[0] = '['
	_, err = v.Verify(raw)
	require.ErrorIs(t, err, ErrInvalid)
	assert.True(t, head.valid, "verified state does not alias transport buffers")
}
func TestManifestRejectsTamperUnknownKeyAndNoncanonicalEncoding(t *testing.T) {
	_, _, raw, v := fixture(t, 2)
	var e envelope
	require.NoError(t, json.Unmarshal(raw, &e))
	for _, change := range []func(*envelope){func(e *envelope) { e.KeyID = "unknown" }, func(e *envelope) { e.Signature = base64.RawStdEncoding.EncodeToString(make([]byte, 64)) }, func(e *envelope) {
		p, err := base64.RawStdEncoding.DecodeString(e.Payload)
		require.NoError(t, err)
		p[10] ^= 1
		e.Payload = base64.RawStdEncoding.EncodeToString(p)
	}, func(e *envelope) { e.Signature += "\n" }} {
		copy := e
		change(&copy)
		bad, err := json.Marshal(copy)
		require.NoError(t, err)
		_, err = v.Verify(bad)
		require.ErrorIs(t, err, ErrInvalid)
	}
	for _, bad := range [][]byte{nil, []byte("null"), append(append([]byte{}, raw...), []byte(" {}")...), append([]byte(" "), raw...), []byte(strings.Repeat("x", MaxEnvelopeBytes+1)), []byte(strings.Replace(string(raw), `{"key_id":`, `{"extra":true,"key_id":`, 1)), []byte(strings.Replace(string(raw), `{"key_id":`, `{"key_id":"one","key_id":`, 1))} {
		_, err := v.Verify(bad)
		require.ErrorIs(t, err, ErrInvalid)
	}
	other, err := NewVerifier("9b997316-f7f3-48f2-941a-b9e1e6e76c1a", map[string]ed25519.PublicKey{"one": testKey("one").Public().(ed25519.PublicKey)})
	require.NoError(t, err)
	_, err = other.Verify(raw)
	require.ErrorIs(t, err, ErrInvalid)
	// Even valid signatures may not hide duplicate or unknown fields in payloads.
	for _, mutate := range []func(string) string{func(s string) string { return " " + s }, func(s string) string { return strings.Replace(s, `{"schema":1,`, `{"schema":1,"schema":1,`, 1) }, func(s string) string { return strings.Replace(s, `{"schema":1,`, `{"future":true,"schema":1,`, 1) }} {
		p, err := base64.RawStdEncoding.DecodeString(e.Payload)
		require.NoError(t, err)
		p = []byte(mutate(string(p)))
		bad := e
		bad.Payload = base64.RawStdEncoding.EncodeToString(p)
		bad.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(testKey("one"), signingInput("one", p)))
		encoded, err := json.Marshal(bad)
		require.NoError(t, err)
		_, err = v.Verify(encoded)
		require.ErrorIs(t, err, ErrInvalid)
	}
}
func TestManifestLimitsAndDependencySemantics(t *testing.T) {
	head, _, _, _ := fixture(t, 1)
	base := head.Manifest()
	for _, mutate := range []func(*Manifest){func(m *Manifest) { m.Schema++ }, func(m *Manifest) { m.Revision = 0 }, func(m *Manifest) { m.ClusterID = "bad" }, func(m *Manifest) { m.PublishedAt = time.Time{} }, func(m *Manifest) { m.Blobs = nil }, func(m *Manifest) { m.Blobs = append(m.Blobs, m.Blobs[0]) }, func(m *Manifest) { m.Blobs[0].SHA256 = strings.ToUpper(m.Blobs[0].SHA256) }, func(m *Manifest) { m.Blobs[0].ID = "../policy" }, func(m *Manifest) { m.Blobs[1].Bytes = MaxFeedBytes + 1 }, func(m *Manifest) { m.Blobs[1].ID = "../../outside" }, func(m *Manifest) { m.Blobs[0].Bytes = -1 }, func(m *Manifest) { m.Blobs[0].Kind = "script" }} {
		copy := base
		copy.Blobs = append([]Blob{}, base.Blobs...)
		mutate(&copy)
		_, err := Sign(copy, "one", testKey("one"))
		require.ErrorIs(t, err, ErrInvalid)
	}
	_, err := Sign(base, "one", []byte("bad"))
	require.ErrorIs(t, err, ErrInvalid)
	_, err = NewVerifier(testCluster, map[string]ed25519.PublicKey{"../bad": testKey("one").Public().(ed25519.PublicKey)})
	require.ErrorIs(t, err, ErrInvalid)
	_, err = NewVerifier(testCluster, map[string]ed25519.PublicKey{"one": make([]byte, 32)})
	require.ErrorIs(t, err, ErrInvalid)
}
func TestBlobStreamingRejectsTruncatedExcessAndChangedContent(t *testing.T) {
	b := testBlob("feed", testFeed, "198.51.100.5/32\n")
	require.NoError(t, VerifyBlob(b, strings.NewReader("198.51.100.5/32\n")))
	for _, s := range []string{"198.51.100.5/32", "198.51.100.5/32\nextra", "198.51.100.6/32\n"} {
		require.ErrorIs(t, VerifyBlob(b, strings.NewReader(s)), ErrInvalid)
	}
	huge := b
	huge.Bytes = MaxFeedBytes + 1
	require.ErrorIs(t, VerifyBlob(huge, strings.NewReader("")), ErrInvalid)
	empty := testBlob("feed", testFeed, "")
	require.NoError(t, VerifyBlob(empty, strings.NewReader("")))
	readError := errors.New("simulated disk error")
	require.ErrorIs(t, VerifyBlob(b, errorReader{readError}), readError)
}

type errorReader struct{ err error }

func (e errorReader) Read([]byte) (int, error) { return 0, e.err }

type closeTracking struct {
	io.Reader
	closed *int
	err    error
}

func (r closeTracking) Close() error { (*r.closed)++; return r.err }
func TestBundleNeverActivatesWithMissingCorruptOrUnparsedDependencies(t *testing.T) {
	head, _, _, _ := fixture(t, 1)
	_, err := VerifyBundle(head, nil, nil)
	require.ErrorIs(t, err, ErrInvalid)
	for _, mode := range []string{"missing", "corrupt", "parse", "close-error"} {
		t.Run(mode, func(t *testing.T) {
			closed := 0
			bundle, err := VerifyBundle(head, func(b Blob) (io.ReadCloser, error) {
				if mode == "missing" && b.Kind == "feed" {
					return nil, errors.New("missing dependency")
				}
				body := `{"rules":["app.other.test"]}`
				if b.Kind == "feed" {
					body = "203.0.113.42/32\n"
				}
				if mode == "corrupt" && b.Kind == "feed" {
					body = "198.51.100.1/32\n"
				}
				var closeErr error
				if mode == "close-error" {
					closeErr = errors.New("close failed")
				}
				return closeTracking{Reader: strings.NewReader(body), closed: &closed, err: closeErr}, nil
			}, func(b Blob, r io.Reader) error {
				if mode == "parse" && b.Kind == "feed" {
					return errors.New("invalid feed content")
				}
				return nil
			})
			require.Error(t, err)
			assert.False(t, bundle.valid)
			assert.Greater(t, closed, 0)
		})
	}
	// The verifier hashes the complete body even if the semantic parser reads
	// only a small prefix; a matching prefix cannot hide a changed suffix.
	closed := 0
	_, err = VerifyBundle(head, func(b Blob) (io.ReadCloser, error) {
		return closeTracking{Reader: bytes.NewReader([]byte(`{"rules":["app.other.test"]}junk`)), closed: &closed}, nil
	}, func(_ Blob, r io.Reader) error { var one [1]byte; _, err := r.Read(one[:]); return err })
	require.ErrorIs(t, err, ErrInvalid)
	assert.Equal(t, 1, closed)
}

func TestSigningKeyAliasCannotReuseAnotherDomainSignature(t *testing.T) {
	_, _, raw, _ := fixture(t, 1)
	key := testKey("one")
	v, err := NewVerifier(testCluster, map[string]ed25519.PublicKey{"one": key.Public().(ed25519.PublicKey), "alias": key.Public().(ed25519.PublicKey)})
	require.NoError(t, err)
	var e envelope
	require.NoError(t, json.Unmarshal(raw, &e))
	e.KeyID = "alias"
	aliased, err := json.Marshal(e)
	require.NoError(t, err)
	_, err = v.Verify(aliased)
	require.ErrorIs(t, err, ErrInvalid)
	e.KeyID = "one"
	payload, err := base64.RawStdEncoding.DecodeString(e.Payload)
	require.NoError(t, err)
	e.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, payload))
	wrongDomain, err := json.Marshal(e)
	require.NoError(t, err)
	_, err = v.Verify(wrongDomain)
	require.ErrorIs(t, err, ErrInvalid)
}
