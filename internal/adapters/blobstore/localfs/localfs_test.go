package localfs_test

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

func TestStore_PutGetExists(t *testing.T) {
	dir := t.TempDir()
	store := localfs.New(dir)
	ctx := context.Background()

	content := "hello, blob store"
	handle, err := store.Put(ctx, strings.NewReader(content))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if handle == "" {
		t.Fatal("empty handle")
	}

	ok, err := store.Exists(ctx, handle)
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !ok {
		t.Error("blob should exist after Put")
	}

	rc, err := store.Get(ctx, handle)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() {
		if err := rc.Close(); err != nil {
			t.Errorf("rc.Close: %v", err)
		}
	}()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != content {
		t.Errorf("got %q, want %q", got, content)
	}
}

func TestStore_Idempotent(t *testing.T) {
	dir := t.TempDir()
	store := localfs.New(dir)
	ctx := context.Background()

	h1, err := store.Put(ctx, strings.NewReader("data"))
	if err != nil {
		t.Fatalf("first Put: %v", err)
	}
	h2, err := store.Put(ctx, strings.NewReader("data"))
	if err != nil {
		t.Fatalf("second Put: %v", err)
	}
	if h1 != h2 {
		t.Errorf("handles differ: %q vs %q", h1, h2)
	}
}

func TestStore_ExistsUnknown(t *testing.T) {
	dir := t.TempDir()
	store := localfs.New(dir)

	ok, err := store.Exists(context.Background(), ports.BlobHandle("sha256:"+strings.Repeat("a", 64)))
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if ok {
		t.Error("should not exist")
	}
}
