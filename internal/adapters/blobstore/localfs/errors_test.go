package localfs_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

func TestStore_GetBadHandle(t *testing.T) {
	store := localfs.New(t.TempDir())
	_, err := store.Get(context.Background(), ports.BlobHandle("notasha256handle"))
	if err == nil {
		t.Error("expected error for bad handle")
	}
}

func TestStore_ExistsBadHandle(t *testing.T) {
	store := localfs.New(t.TempDir())
	_, err := store.Exists(context.Background(), ports.BlobHandle("notasha256handle"))
	if err == nil {
		t.Error("expected error for bad handle")
	}
}

func TestStore_GetUnknownHandle(t *testing.T) {
	store := localfs.New(t.TempDir())
	_, err := store.Get(context.Background(), ports.BlobHandle("sha256:"+string(make([]byte, 64))))
	if err == nil {
		t.Error("expected error for unknown blob")
	}
}

func TestStore_PutMkdirFail(t *testing.T) {
	root := t.TempDir()
	store := localfs.New(root)

	// Create a file where the blobs directory should be, to cause MkdirAll to fail.
	err := os.WriteFile(filepath.Join(root, "blobs"), []byte("not a directory"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.Put(context.Background(), strings.NewReader("content"))
	if err == nil {
		t.Error("expected error when MkdirAll fails")
	}
}

type errorReader struct{}

func (errorReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

func TestStore_PutReadError(t *testing.T) {
	store := localfs.New(t.TempDir())
	_, err := store.Put(context.Background(), errorReader{})
	if err == nil {
		t.Error("expected error for read failure")
	}
}
