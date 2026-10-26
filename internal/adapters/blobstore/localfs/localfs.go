// Package localfs implements ports.BlobStore using the local filesystem.
//
// Artefacts are stored under an address derived from the artefact's identity —
// the h1 hash the fetch pipeline measured — at:
//
//	{root}/blobs/{addr[:2]}/{addr}
//
// where addr is the SHA-256 of the identity's canonical string. The indirection
// exists only because an h1 value is base64 and so not filesystem-safe; it is a
// pure function of the identity, computed on demand and never persisted, so the
// layout is the adapter's own business and nothing outside it can depend on the
// mapping. The two-character shard mirrors the OCI blob convention and keeps
// large stores navigable without hitting directory entry limits.
//
// The store does not choose addresses. It used to: Put hashed the bytes it was
// handed and returned "sha256:<hex>", which the caller then wrote into a fact
// record. That made the record describe where one run had put the bytes rather
// than what the bytes were, so the same artefact acquired by two routes produced
// two irreconcilable records. Addressing by identity removes the possibility.
package localfs

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"code.eitanity.com/kanonarion/internal/audit"
	"code.eitanity.com/kanonarion/internal/fetch/ports"
	"golang.org/x/mod/sumdb/dirhash"
)

var ErrBlobNotFound = errors.New("blob not found")

// Compile-time checks: the local FS store is a full BlobStore and also offers
// the optional path capability.
var (
	_ ports.BlobStore         = (*Store)(nil)
	_ ports.BlobPathOptimizer = (*Store)(nil)
)

// Store is the local filesystem blob store.
type Store struct {
	root string

	audit   ports.AuditSink
	command string
	observe func(ports.BlobIdentity, *ports.BlobTamperedError)

	// verdicts holds one hash verdict per identity for this process. A verdict
	// stands only while the file keeps the size and modification time it was
	// hashed at; any change to either re-hashes it on the next read.
	mu       sync.Mutex
	verdicts map[string]verdict
}

// verdict is the outcome of hashing one held file: nil err means it verified.
type verdict struct {
	size  int64
	mtime time.Time
	err   error
}

// New constructs a Store rooted at root. root need not exist yet; Put creates
// it on first write.
func New(root string) *Store {
	return &Store{root: root, verdicts: map[string]verdict{}}
}

// WithAudit appends a verification_failed event to sink for every held file
// that does not hash to its identity, naming command as the reader. Returns the
// receiver for chaining.
func (s *Store) WithAudit(sink ports.AuditSink, command string) *Store {
	s.audit, s.command = sink, command
	return s
}

// WithRefusalObserver tells observe of every held file refused for not hashing
// to its identity, so a caller can act on a refusal a reader did not return,
// and calls it with a nil refusal when Put replaces refused bytes. nil observes
// nothing. Returns the receiver for chaining.
func (s *Store) WithRefusalObserver(observe func(ports.BlobIdentity, *ports.BlobTamperedError)) *Store {
	s.observe = observe
	return s
}

// Put stores content under the given artefact identity. Idempotent: if the
// artefact is already held, the content is discarded and Put succeeds.
//
// Content is streamed to a temp file via io.TeeReader so memory use is bounded
// by the copy buffer (~32 KB) regardless of artefact size.
func (s *Store) Put(_ context.Context, identity ports.BlobIdentity, content io.Reader) error {
	if identity.IsZero() {
		return errors.New("storing blob: no artefact identity")
	}
	blobsDir := filepath.Join(s.root, "blobs")
	if err := os.MkdirAll(blobsDir, 0o750); err != nil {
		return fmt.Errorf("creating blobs dir: %w", err)
	}

	blobPath := s.blobPath(identity)
	held, replacing, herr := s.heldIntact(identity, blobPath)
	if herr != nil {
		return herr
	}
	if held {
		// Drain the reader so a caller streaming from a network connection is not
		// left with a half-consumed body.
		if _, derr := io.Copy(io.Discard, content); derr != nil {
			return fmt.Errorf("draining already-stored blob %s: %w", identity, derr)
		}
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(blobPath), 0o750); err != nil {
		return fmt.Errorf("creating blob dir: %w", err)
	}

	// When the caller hands us an open file — a module-cache entry, a staged
	// download — take a hard link instead of copying the bytes. It is what makes
	// populating from a module cache cost no disk, and the link outlives
	// `go clean -modcache`: the toolchain unlinks its own name and the inode
	// survives while this link holds it. A link across filesystems fails, and the
	// copy below is the fallback.
	if f, ok := content.(*os.File); ok && !replacing {
		if err := os.Link(f.Name(), blobPath); err == nil {
			return nil
		}
	}

	tmp, err := os.CreateTemp(blobsDir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := io.Copy(tmp, content); err != nil {
		cerr := tmp.Close()
		rerr := os.Remove(tmpName)
		return fmt.Errorf("streaming blob: %w", errors.Join(err, cerr, rerr))
	}
	if err := tmp.Close(); err != nil {
		rerr := os.Remove(tmpName)
		return fmt.Errorf("closing temp file: %w", errors.Join(err, rerr))
	}

	if err := os.Rename(tmpName, blobPath); err != nil {
		rerr := os.Remove(tmpName)
		return fmt.Errorf("renaming blob: %w", errors.Join(err, rerr))
	}
	if replacing {
		s.replaced(identity)
	}
	return nil
}

// replaced drops the refused verdict of bytes Put has just replaced, and tells
// the observer the refusal no longer stands.
func (s *Store) replaced(identity ports.BlobIdentity) {
	s.forget(identity)
	if s.observe != nil {
		s.observe(identity, nil)
	}
}

// heldIntact reports whether blobPath already holds bytes that verify, and
// whether it holds refused ones Put must replace: that replacement is what the
// re-fetch a refusal names has to achieve.
func (s *Store) heldIntact(identity ports.BlobIdentity, blobPath string) (held, replacing bool, err error) {
	if _, serr := os.Stat(blobPath); serr != nil {
		return false, false, nil //nolint:nilerr // not held: Put writes it
	}
	verr := s.verifyPath(identity, blobPath)
	switch {
	case verr == nil:
		return true, false, nil
	case errors.Is(verr, ports.ErrBlobTampered):
		return false, true, nil
	default:
		return false, false, verr
	}
}

// Get opens the artefact identified by identity for reading. The open file is
// hashed against identity before it is returned, so the bytes a caller reads are
// the bytes that were hashed; a mismatch closes it and returns ErrBlobTampered.
func (s *Store) Get(_ context.Context, identity ports.BlobIdentity) (io.ReadCloser, error) {
	if identity.IsZero() {
		return nil, ErrBlobNotFound
	}
	path := s.blobPath(identity)
	f, err := os.Open(path) // #nosec G304 -- path derived from the store's own blob layout
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrBlobNotFound
		}
		return nil, fmt.Errorf("opening blob %s: %w", identity, err)
	}
	if err := s.verify(identity, path, f); err != nil {
		return nil, errors.Join(err, closeQuietly(f))
	}
	return f, nil
}

// GetPath returns the local filesystem path to the artefact identified by
// identity, after hashing the file against it. It satisfies the optional
// ports.BlobPathOptimizer capability.
func (s *Store) GetPath(_ context.Context, identity ports.BlobIdentity) (string, error) {
	if identity.IsZero() {
		return "", ErrBlobNotFound
	}
	path := s.blobPath(identity)
	if err := s.verifyPath(identity, path); err != nil {
		return "", err
	}
	return path, nil
}

// verifyPath opens path and verifies it against identity.
func (s *Store) verifyPath(identity ports.BlobIdentity, path string) error {
	f, err := os.Open(path) // #nosec G304 -- path derived from the store's own blob layout
	if err != nil {
		if os.IsNotExist(err) {
			return ErrBlobNotFound
		}
		return fmt.Errorf("opening blob %s: %w", identity, err)
	}
	return errors.Join(s.verify(identity, path, f), f.Close())
}

// verify hashes f by identity's kind and compares the h1 with identity, once
// per identity while the file keeps its size and modification time. f is left
// positioned at its start.
func (s *Store) verify(identity ports.BlobIdentity, path string, f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("checking blob %s: %w", identity, err)
	}
	key := identity.String()
	s.mu.Lock()
	v, ok := s.verdicts[key]
	s.mu.Unlock()
	if ok && v.size == info.Size() && v.mtime.Equal(info.ModTime()) {
		return v.err
	}

	observed, herr := hashFile(identity.Kind(), f, info.Size())
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewinding blob %s: %w", identity, err)
	}
	var result error
	if herr != nil || observed != identity.Hash().String() {
		tampered := &ports.BlobTamperedError{Identity: identity, Observed: observed, Path: path}
		if herr != nil {
			tampered.Observed, tampered.Unhashable = "", herr.Error()
		}
		result = errors.Join(tampered, s.recordTamper(tampered))
		if s.observe != nil {
			s.observe(identity, tampered)
		}
	}
	s.mu.Lock()
	s.verdicts[key] = verdict{size: info.Size(), mtime: info.ModTime(), err: result}
	s.mu.Unlock()
	return result
}

// forget drops identity's verdict, for a file Put has just replaced.
func (s *Store) forget(identity ports.BlobIdentity) {
	s.mu.Lock()
	delete(s.verdicts, identity.String())
	s.mu.Unlock()
}

// recordTamper appends the refusal to the assurance log. A failed append is
// returned beside the refusal: the event that says the store's bytes changed
// must never be lost silently.
func (s *Store) recordTamper(t *ports.BlobTamperedError) error {
	if s.audit == nil {
		return nil
	}
	payload := map[string]any{
		"reason":            "stored artefact does not hash to its identity",
		"artefact_identity": t.Identity.String(),
		"expected_hash":     t.Identity.Hash().String(),
		"observed_hash":     t.Observed,
		"path":              t.Path,
	}
	if t.Unhashable != "" {
		payload["unhashable"] = t.Unhashable
	}
	if s.command != "" {
		payload["command"] = s.command
	}
	if err := s.audit.RecordEvent(audit.Event{Type: audit.EventVerificationFailed, Payload: payload}); err != nil {
		return fmt.Errorf("recording the refusal of %s: %w", t.Identity, err)
	}
	return nil
}

// hashFile computes the h1 of a held artefact: over the zip's entries for a
// module zip, as the go command does, and over the single file named go.mod for
// a standalone go.mod.
func hashFile(kind ports.BlobKind, f *os.File, size int64) (string, error) {
	if kind == ports.BlobKindGoMod {
		h, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
			return io.NopCloser(io.NewSectionReader(f, 0, size)), nil
		})
		if err != nil {
			return "", fmt.Errorf("hashing go.mod: %w", err)
		}
		return h, nil
	}
	zr, err := zip.NewReader(f, size)
	if err != nil {
		return "", fmt.Errorf("reading module zip: %w", err)
	}
	names := make([]string, len(zr.File))
	byName := make(map[string]*zip.File, len(zr.File))
	for i, zf := range zr.File {
		names[i] = zf.Name
		byName[zf.Name] = zf
	}
	h, err := dirhash.Hash1(names, func(name string) (io.ReadCloser, error) {
		zf := byName[name]
		if zf == nil {
			return nil, fmt.Errorf("file %q not in zip", name)
		}
		rc, oerr := zf.Open()
		if oerr != nil {
			return nil, fmt.Errorf("opening %q in module zip: %w", name, oerr)
		}
		return rc, nil
	})
	if err != nil {
		return "", fmt.Errorf("hashing module zip: %w", err)
	}
	return h, nil
}

// closeQuietly closes a file Get will not hand out; a close error is returned
// beside the refusal that caused it.
func closeQuietly(f *os.File) error {
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing refused blob: %w", err)
	}
	return nil
}

// Exists reports whether the artefact is held by the store.
func (s *Store) Exists(_ context.Context, identity ports.BlobIdentity) (bool, error) {
	if identity.IsZero() {
		return false, nil
	}
	_, err := os.Stat(s.blobPath(identity))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("checking blob existence: %w", err)
	}
	return true, nil
}

// CleanOrphanedTemps removes any.tmp-* files left in the blobs directory by
// interrupted Put operations. Safe to call at startup because a completed Put
// always renames the temp file to its final address.
//
// Returns the number of files removed and the bytes they occupied. The bytes
// are measured here rather than by the caller because they are only knowable
// before the unlink, and a caller that stats first is racing this sweep.
func (s *Store) CleanOrphanedTemps() (removed int, freed int64, err error) {
	blobsDir := filepath.Join(s.root, "blobs")
	entries, err := os.ReadDir(blobsDir)
	if os.IsNotExist(err) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, fmt.Errorf("reading blobs dir: %w", err)
	}
	var errs []error
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".tmp-") {
			continue
		}
		var size int64
		if info, ierr := e.Info(); ierr == nil {
			size = info.Size()
		}
		if rerr := os.Remove(filepath.Join(blobsDir, e.Name())); rerr != nil && !os.IsNotExist(rerr) {
			errs = append(errs, rerr)
		} else {
			removed++
			freed += size
		}
	}
	return removed, freed, errors.Join(errs...)
}

// LegacyPath returns the path a blob occupied under the store-chosen
// "sha256:<hex>" addressing this adapter used before artefact identity became
// the address. It exists solely for AdoptLegacyBlob; nothing else may depend on
// the old layout.
func (s *Store) LegacyPath(handle string) (string, bool) {
	digest, ok := strings.CutPrefix(handle, "sha256:")
	if !ok || len(digest) < 2 {
		return "", false
	}
	return filepath.Join(s.root, "blobs", digest[:2], digest), true
}

// AdoptLegacyBlob re-addresses a blob written under the old store-chosen handle
// so it is reachable by its artefact identity, reporting whether it did so.
//
// Without it, every artefact already in the store would read as absent the
// moment addressing changed, and a store built up over months would silently
// re-download from scratch. The fact records carry both the old handle and the
// artefact's h1, so the mapping is known exactly and needs no guessing.
//
// The blob is hard-linked, not moved: the old path keeps working for anything
// still holding it, the new path is live immediately, and both names share one
// inode so the adoption costs no disk. A cross-device or unsupported link falls
// back to a copy. Adoption is skipped, not failed, when the legacy blob is
// missing — an absent artefact is re-acquired, which is ordinary behaviour.
func (s *Store) AdoptLegacyBlob(identity ports.BlobIdentity, legacyHandle string) (bool, error) {
	if identity.IsZero() {
		return false, nil
	}
	src, ok := s.LegacyPath(legacyHandle)
	if !ok {
		return false, nil
	}
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("checking legacy blob %s: %w", legacyHandle, err)
	}

	dst := s.blobPath(identity)
	if _, err := os.Stat(dst); err == nil {
		return false, nil // already adopted
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return false, fmt.Errorf("creating blob dir for %s: %w", identity, err)
	}
	if err := os.Link(src, dst); err == nil {
		return true, nil
	}
	if err := copyFile(src, dst); err != nil {
		return false, fmt.Errorf("adopting legacy blob %s as %s: %w", legacyHandle, identity, err)
	}
	return true, nil
}

// copyFile is the fallback when a hard link cannot be made (a different
// filesystem, or a filesystem without link support).
func copyFile(src, dst string) error {
	in, err := os.Open(src) // #nosec G304 -- path derived from the store's own blob layout
	if err != nil {
		return fmt.Errorf("opening source blob: %w", err)
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- path derived from the store's own blob layout
	if err != nil {
		return fmt.Errorf("creating destination blob: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		cerr := out.Close()
		rerr := os.Remove(dst)
		return fmt.Errorf("copying blob: %w", errors.Join(err, cerr, rerr))
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("closing destination blob: %w", err)
	}
	return nil
}

// blobPath maps an artefact identity onto this store's layout. The mapping is a
// pure function computed on demand: it is never persisted, so no record and no
// other adapter can come to depend on it.
func (s *Store) blobPath(identity ports.BlobIdentity) string {
	sum := sha256.Sum256([]byte(identity.String()))
	addr := hex.EncodeToString(sum[:])
	return filepath.Join(s.root, "blobs", addr[:2], addr)
}
