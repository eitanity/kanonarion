package localfs_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// testIdentity is a well-formed artefact identity for tests that need one but do
// not care what it names.
func testIdentity(value string) ports.BlobIdentity {
	return ports.BlobIdentity{
		Kind: ports.BlobKindZip,
		Hash: fetchtest.H1(value),
	}
}

// The malformed-handle cases these tests used to cover no longer exist. An
// address is a typed value derived from a fetch measurement rather than a string
// the caller assembles, so it cannot arrive misspelled; the only degenerate
// value left is the zero identity, which names no artefact and so reports
// absence.
func TestStore_GetZeroIdentityIsAbsence(t *testing.T) {
	store := localfs.New(t.TempDir())
	_, err := store.Get(context.Background(), ports.BlobIdentity{})
	if !errors.Is(err, localfs.ErrBlobNotFound) {
		t.Errorf("Get(zero identity): got %v, want ErrBlobNotFound", err)
	}
}

func TestStore_ExistsZeroIdentityIsAbsence(t *testing.T) {
	store := localfs.New(t.TempDir())
	exists, err := store.Exists(context.Background(), ports.BlobIdentity{})
	if err != nil {
		t.Fatalf("Exists(zero identity): %v", err)
	}
	if exists {
		t.Error("Exists(zero identity) = true, want false")
	}
}

func TestStore_GetUnknownIdentity(t *testing.T) {
	store := localfs.New(t.TempDir())
	_, err := store.Get(context.Background(), testIdentity("never-stored"))
	if !errors.Is(err, localfs.ErrBlobNotFound) {
		t.Errorf("Get(unknown): got %v, want ErrBlobNotFound", err)
	}
}

// An artefact with no identity has no address, so storing it is refused rather
// than silently filed somewhere the store chose.
func TestStore_PutZeroIdentityRejected(t *testing.T) {
	store := localfs.New(t.TempDir())
	if err := store.Put(context.Background(), ports.BlobIdentity{}, strings.NewReader("content")); err == nil {
		t.Error("Put(zero identity) succeeded; an artefact with no identity has no address to be stored at")
	}
}

func TestStore_PutMkdirFail(t *testing.T) {
	root := t.TempDir()
	store := localfs.New(root)

	// Create a file where the blobs directory should be, to cause MkdirAll to fail.
	if err := os.WriteFile(filepath.Join(root, "blobs"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := store.Put(context.Background(), testIdentity("mkdir-fail"), strings.NewReader("content")); err == nil {
		t.Error("expected error when MkdirAll fails")
	}
}

type errorReader struct{}

func (errorReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

func TestStore_PutReadError(t *testing.T) {
	store := localfs.New(t.TempDir())
	if err := store.Put(context.Background(), testIdentity("read-error"), errorReader{}); err == nil {
		t.Error("expected error for read failure")
	}
}
