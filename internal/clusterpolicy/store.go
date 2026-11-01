package clusterpolicy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var ErrStoreCorrupt = errors.New("policy cache is corrupt")
var ErrStoreClosed = errors.New("policy cache is closed or requires reopening")
var ErrStoreIndeterminate = errors.New("policy cache commit needs recovery before further writes")
var ErrStoreLocked = errors.New("policy cache already has an exclusive writer")
var ErrStoreUnsupported = errors.New("durable policy cache requires a Linux host bind mount")

// CacheState is one atomically committed journal. HighWater may be newer than
// Active while downloads are pending; it must never be reset to the old cache.
type CacheState struct {
	Schema    int      `json:"schema"`
	ClusterID string   `json:"cluster_id"`
	HighWater Identity `json:"high_water"`
	Active    Identity `json:"active"`
	Previous  Identity `json:"previous"`
	Staged    Identity `json:"staged"`
}

type Store struct {
	stageMu      sync.Mutex // Network/compilation never holds stateMu.
	stateMu      sync.Mutex
	root         *os.Root
	lock         *os.File
	verifier     *Verifier
	state        CacheState
	closed       bool
	poisoned     bool
	syncDir      func(string) error
	beforeRename func(string, string) error
	cleanupErr   error
}

// OpenStore does not create its configured root: an absent host bind/mount must
// never silently become a directory on the OS disk, especially on the USB node.
// One Linux writer owns the root for its lifetime. Atomic journal and directory
// fsync durability are required; other platforms may still use the verifier.
func OpenStore(path string, v *Verifier) (*Store, error) {
	if runtime.GOOS != "linux" {
		return nil, ErrStoreUnsupported
	}
	if !filepath.IsAbs(path) || v == nil || !validCluster(v.cluster) {
		return nil, ErrInvalid
	}
	path = filepath.Clean(path)
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0o027 != 0 {
		return nil, ErrInvalid
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	if err = validateOpenedStoreRoot(root, st); err != nil {
		_ = root.Close()
		return nil, err
	}
	s := &Store{root: root, verifier: v}
	fail := func(err error) (*Store, error) {
		if s.lock != nil {
			_ = s.lock.Close()
		}
		_ = root.Close()
		return nil, err
	}
	s.syncDir = func(name string) error {
		f, err := root.Open(name)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		return f.Sync()
	}
	if st, err := root.Lstat(".lock"); err == nil && (!st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0) {
		return fail(ErrStoreCorrupt)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fail(err)
	}
	s.lock, err = root.OpenFile(".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fail(err)
	}
	if err = lockStoreFile(s.lock); err != nil {
		return fail(err)
	}
	for _, dir := range []string{"blobs", "manifests"} {
		st, err := root.Lstat(dir)
		if errors.Is(err, os.ErrNotExist) {
			if err = root.Mkdir(dir, 0o700); err != nil {
				return fail(err)
			}
			if err = s.syncDir("."); err != nil {
				return fail(err)
			}
		} else if err != nil {
			return fail(err)
		} else if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0o027 != 0 {
			return fail(ErrStoreCorrupt)
		}
	}
	data, err := s.readRegular("state.json", 4096)
	if errors.Is(err, os.ErrNotExist) {
		// A lost journal beside artifacts is not a fresh cache. Refuse to reset the
		// watermark; recovery must use the authoritative HA head explicitly.
		for _, dir := range []string{"blobs", "manifests"} {
			names, e := s.names(dir)
			if e != nil {
				return fail(e)
			}
			if len(names) != 0 {
				return fail(ErrStoreCorrupt)
			}
		}
		s.state = CacheState{Schema: 1, ClusterID: v.cluster}
		if err = s.writeState(s.state); err != nil {
			return fail(err)
		}
	} else {
		if err != nil {
			return fail(err)
		}
		if strictJSON(data, &s.state) != nil || !s.validState(s.state) {
			return fail(ErrStoreCorrupt)
		}
	}
	if err = s.gc(s.state, true); err != nil {
		return fail(err)
	}
	return s, nil
}
func validateOpenedStoreRoot(root *os.Root, checked os.FileInfo) error {
	opened, err := root.Stat(".")
	if err != nil {
		return err
	}
	if !opened.IsDir() || !os.SameFile(checked, opened) || opened.Mode().Perm()&0o027 != 0 {
		return ErrInvalid
	}
	return nil
}

func (s *Store) validState(st CacheState) bool {
	if st.Schema != 1 || st.ClusterID != s.verifier.cluster {
		return false
	}
	for _, id := range []Identity{st.HighWater, st.Active, st.Previous, st.Staged} {
		if id != (Identity{}) && !id.valid() {
			return false
		}
	}
	if st.Active.Revision > st.HighWater.Revision || st.Previous.Revision > st.Active.Revision {
		return false
	}
	if st.Active.Revision == st.HighWater.Revision && st.Active != st.HighWater {
		return false
	}
	if st.Previous.Revision == st.Active.Revision && st.Previous != (Identity{}) {
		return false
	}
	// Staging a signed upcoming head is permitted; it cannot be committed until
	// an authoritative head observation matches it exactly.
	return true
}
func (s *Store) usable() error {
	if s.closed || s.poisoned {
		return ErrStoreClosed
	}
	return nil
}
func (s *Store) State() (CacheState, error) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if err := s.usable(); err != nil {
		return CacheState{}, err
	}
	return s.state, nil
}
func (s *Store) Close() error {
	s.stageMu.Lock()
	defer s.stageMu.Unlock()
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	lockErr := s.lock.Close()
	rootErr := s.root.Close()
	return errors.Join(lockErr, rootErr)
}
func (s *Store) readRegular(name string, limit int64) ([]byte, error) {
	st, err := s.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || st.Size() > limit {
		return nil, ErrStoreCorrupt
	}
	f, err := s.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, ErrStoreCorrupt
	}
	return data, nil
}
func (s *Store) names(dir string) ([]os.DirEntry, error) {
	f, err := s.root.Open(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return f.ReadDir(-1)
}
func (s *Store) temp(dir string) (*os.File, string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, "", err
	}
	name := dir + "/.tmp-" + hex.EncodeToString(b[:])
	if dir == "." {
		name = ".tmp-" + hex.EncodeToString(b[:])
	}
	f, err := s.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	return f, name, err
}
func (s *Store) atomicBytes(name string, data []byte) error {
	dir := filepath.Dir(name)
	f, tmp, err := s.temp(dir)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close(); _ = s.root.Remove(tmp) }()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if s.beforeRename != nil {
		if err = s.beforeRename(name, tmp); err != nil {
			return err
		}
	}
	if err = s.root.Rename(tmp, name); err != nil {
		return err
	}
	if err = s.syncDir(dir); err != nil {
		return errors.Join(ErrStoreIndeterminate, err)
	}
	return nil
}

// Caller owns stateMu (or is constructing an unpublished Store).
func (s *Store) writeState(next CacheState) error {
	if !s.validState(next) {
		return ErrStoreCorrupt
	}
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err = s.atomicBytes("state.json", data); err != nil {
		if errors.Is(err, ErrStoreIndeterminate) {
			s.poisoned = true
		}
		return err
	}
	s.state = next
	return nil
}
func newerOrSame(id, minimum Identity) bool {
	return id.valid() && (minimum.Revision == 0 || id.Revision > minimum.Revision || id == minimum)
}

// RecordHead accepts only signature-verified current HA evidence. A poller must
// withdraw old readiness immediately on a new head, before waiting on disk I/O;
// durable recording is required before activating its replacement.
func (s *Store) RecordHead(head VerifiedManifest) error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if err := s.usable(); err != nil {
		return err
	}
	if !head.valid || head.scope != s.verifier.scope || head.manifest.ClusterID != s.verifier.cluster || !newerOrSame(head.Identity(), s.state.HighWater) {
		return ErrRollback
	}
	if head.Identity() == s.state.HighWater {
		return nil
	}
	next := s.state
	next.HighWater = head.Identity()
	return s.writeState(next)
}
func (s *Store) loadManifest(id Identity) (VerifiedManifest, error) {
	if !id.valid() {
		return VerifiedManifest{}, ErrStoreCorrupt
	}
	data, err := s.readRegular("manifests/"+id.SHA256+".json", MaxEnvelopeBytes)
	if err != nil {
		return VerifiedManifest{}, err
	}
	head, err := s.verifier.Verify(data)
	if err != nil || head.Identity() != id {
		return VerifiedManifest{}, ErrStoreCorrupt
	}
	return head, nil
}
func (s *Store) openBlob(blob Blob) (io.ReadCloser, error) {
	name := "blobs/" + blob.SHA256
	st, err := s.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || st.Size() != blob.Bytes {
		return nil, ErrStoreCorrupt
	}
	return s.root.Open(name)
}
func (s *Store) LoadActive(validate func(Blob, io.Reader) error) (VerifiedBundle, error) {
	s.stageMu.Lock()
	defer s.stageMu.Unlock()
	s.stateMu.Lock()
	if err := s.usable(); err != nil {
		s.stateMu.Unlock()
		return VerifiedBundle{}, err
	}
	id := s.state.Active
	s.stateMu.Unlock()
	if id == (Identity{}) {
		return VerifiedBundle{}, os.ErrNotExist
	}
	head, err := s.loadManifest(id)
	if err != nil {
		return VerifiedBundle{}, err
	}
	return VerifyBundle(head, s.openBlob, validate)
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
func (s *Store) stageBlob(ctx context.Context, b Blob, fetch func(context.Context, Blob) (io.ReadCloser, error)) (bool, error) {
	target := "blobs/" + b.SHA256
	existed := false
	if st, err := s.root.Lstat(target); err == nil {
		if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
			return false, ErrStoreCorrupt
		}
		f, err := s.root.Open(target)
		if err != nil {
			return false, err
		}
		existed = true
		verifyErr := VerifyBlob(b, contextReader{ctx: ctx, r: f})
		closeErr := f.Close()
		if verifyErr == nil {
			return false, closeErr
		}
		if !errors.Is(verifyErr, ErrInvalid) {
			return false, verifyErr
		}
		if closeErr != nil {
			return false, closeErr
		}
		// A verified identical replacement is safe for every referencing head.

	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	r, err := fetch(ctx, b)
	if err != nil {
		return false, err
	}
	if r == nil {
		return false, ErrInvalid
	}
	f, tmp, err := s.temp("blobs")
	if err != nil {
		_ = r.Close()
		return false, err
	}
	defer func() { _ = f.Close(); _ = s.root.Remove(tmp) }()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(contextReader{ctx: ctx, r: r}, b.Bytes+1))
	closeErr := r.Close()
	if err != nil {
		return false, err
	}
	if closeErr != nil {
		return false, closeErr
	}
	if n != b.Bytes || hex.EncodeToString(h.Sum(nil)) != b.SHA256 {
		return false, ErrInvalid
	}
	if err = ctx.Err(); err != nil {
		return false, err
	}
	if err = f.Sync(); err != nil {
		return false, err
	}
	if err = f.Close(); err != nil {
		return false, err
	}
	if err = s.root.Rename(tmp, target); err != nil {
		return false, err
	}
	if err = s.syncDir("blobs"); err != nil {
		return !existed, err
	}
	return !existed, nil
}

// Stage retains at most one staging generation beside active/previous. Fetch
// must honor ctx and its own network timeout. Head observations use stateMu and
// remain independent of this potentially slow network/semantic compilation.
func (s *Store) Stage(ctx context.Context, raw []byte, fetch func(context.Context, Blob) (io.ReadCloser, error), validate func(Blob, io.Reader) error) (VerifiedBundle, error) {
	s.stageMu.Lock()
	defer s.stageMu.Unlock()
	if len(raw) > MaxEnvelopeBytes {
		return VerifiedBundle{}, ErrInvalid
	}
	raw = bytes.Clone(raw)
	head, err := s.verifier.Verify(raw)
	if err != nil || fetch == nil || validate == nil {
		return VerifiedBundle{}, ErrInvalid
	}
	s.stateMu.Lock()
	if err = s.usable(); err != nil {
		s.stateMu.Unlock()
		return VerifiedBundle{}, err
	}
	if !newerOrSame(head.Identity(), s.state.HighWater) {
		s.stateMu.Unlock()
		return VerifiedBundle{}, ErrRollback
	}
	if head.Identity() == s.state.Staged {
		s.stateMu.Unlock()
		cached, err := s.loadManifest(head.Identity())
		if err != nil {
			return VerifiedBundle{}, err
		}
		// Keep the staged journal reference while repairing damaged content.
		// Valid staged bytes require no network access.
		for _, blob := range cached.manifest.Blobs {
			if _, e := s.stageBlob(ctx, blob, fetch); e != nil {
				return VerifiedBundle{}, e
			}
		}
		bundle, err := VerifyBundle(cached, s.openBlob, validate)
		if err != nil {
			return VerifiedBundle{}, err
		}
		s.stateMu.Lock()
		defer s.stateMu.Unlock()
		if err = s.usable(); err != nil {
			return VerifiedBundle{}, err
		}
		if !newerOrSame(head.Identity(), s.state.HighWater) {
			return VerifiedBundle{}, ErrRollback
		}
		return bundle, nil
	}
	next := s.state
	next.Staged = Identity{}
	err = s.writeState(next)
	if err == nil {
		// Include root temporaries while holding stateMu: no concurrent head
		// journal is in flight, and successful reclamation clears its health.
		s.cleanupErr = s.gc(next, true)
		err = s.cleanupErr
	}
	s.stateMu.Unlock()
	if err != nil {
		return VerifiedBundle{}, err
	}
	protected := map[string]bool{}
	for _, id := range []Identity{next.Active, next.Previous} {
		if id == (Identity{}) {
			continue
		}
		retained, e := s.loadManifest(id)
		if e != nil {
			return VerifiedBundle{}, e
		}
		for _, blob := range retained.manifest.Blobs {
			protected[blob.SHA256] = true
		}
	}
	created := []string{}
	keep := false
	defer func() {
		if !keep {
			for _, name := range created {
				_ = s.root.Remove(name)
			}
			_ = s.syncDir("blobs")
			_ = s.syncDir("manifests")
		}
	}()
	for _, blob := range head.manifest.Blobs {
		made, err := s.stageBlob(ctx, blob, fetch)
		if made && !protected[blob.SHA256] {
			created = append(created, "blobs/"+blob.SHA256)
		}
		if err != nil {
			return VerifiedBundle{}, err
		}
	}
	bundle, err := VerifyBundle(head, s.openBlob, validate)
	if err != nil {
		return VerifiedBundle{}, err
	}
	name := "manifests/" + head.Identity().SHA256 + ".json"
	if _, err = s.root.Lstat(name); errors.Is(err, os.ErrNotExist) {
		created = append(created, name)
	} else if err != nil {
		return VerifiedBundle{}, err
	}
	if err = s.atomicBytes(name, raw); err != nil {
		return VerifiedBundle{}, err
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if err = s.usable(); err != nil {
		return VerifiedBundle{}, err
	}
	if !newerOrSame(head.Identity(), s.state.HighWater) {
		return VerifiedBundle{}, ErrRollback
	}
	next = s.state
	next.Staged = head.Identity()
	if err = s.writeState(next); err != nil {
		keep = errors.Is(err, ErrStoreIndeterminate)
		return VerifiedBundle{}, err
	}
	keep = true
	return bundle, nil
}
func (s *Store) Activate(bundle VerifiedBundle) error {
	s.stageMu.Lock()
	defer s.stageMu.Unlock()
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if err := s.usable(); err != nil {
		return err
	}
	id := bundle.Identity()
	if !bundle.valid || bundle.head.scope != s.verifier.scope || id != s.state.HighWater {
		return ErrNotCurrent
	}
	if id == s.state.Active {
		s.cleanupErr = s.gc(s.state, true)
		return nil
	}
	if id != s.state.Staged {
		return ErrNotCurrent
	}
	next := s.state
	if next.Active != id {
		next.Previous = next.Active
	}
	next.Active = id
	next.Staged = Identity{}
	if err := s.writeState(next); err != nil {
		return err
	}
	// The durable commit succeeded. Report cleanup separately so callers can
	// publish this generation and retry reclamation without guessing the outcome.
	s.cleanupErr = s.gc(next, true)
	return nil
}

// gc removes only generated hash/temp filenames inside the opened root. Never
// recurse or remove unrelated operator files. Parse every retained manifest
// before deleting anything, so corrupt metadata cannot erase the good cache.
func (s *Store) gc(st CacheState, rootTemps bool) error {
	manifests := map[string]bool{}
	blobs := map[string]bool{}
	for _, id := range []Identity{st.Active, st.Previous, st.Staged} {
		if id == (Identity{}) {
			continue
		}
		head, err := s.loadManifest(id)
		if err != nil {
			return err
		}
		manifests[id.SHA256+".json"] = true
		for _, blob := range head.manifest.Blobs {
			blobs[blob.SHA256] = true
		}
	}
	dirs := []string{"blobs", "manifests"}
	if rootTemps {
		dirs = append(dirs, ".")
	}
	for _, dir := range dirs {
		names, err := s.names(dir)
		if err != nil {
			return err
		}
		for _, entry := range names {
			name := entry.Name()
			generated := validTempName(name)
			keep := false
			switch dir {
			case "blobs":
				generated = generated || validHash(name)
				keep = blobs[name]
			case "manifests":
				digest, ok := strings.CutSuffix(name, ".json")
				generated = generated || (ok && validHash(digest))
				keep = manifests[name]
			}
			if !generated || keep || entry.IsDir() {
				continue
			}
			if err = s.root.Remove(dir + "/" + name); err != nil {
				return err
			}
		}
		if err = s.syncDir(dir); err != nil {
			return err
		}
	}
	return nil
}

func validTempName(name string) bool {
	if !strings.HasPrefix(name, ".tmp-") || len(name) != len(".tmp-")+32 {
		return false
	}
	suffix := strings.TrimPrefix(name, ".tmp-")
	if suffix != strings.ToLower(suffix) {
		return false
	}
	_, err := hex.DecodeString(suffix)
	return err == nil
}

// CleanupError reports post-commit reclamation health, independently of whether
// the active generation committed. Further Stage calls reclaim before writing.
func (s *Store) CleanupError() error { s.stateMu.Lock(); defer s.stateMu.Unlock(); return s.cleanupErr }
