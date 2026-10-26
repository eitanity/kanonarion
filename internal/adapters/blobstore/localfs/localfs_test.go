package localfs_test

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/adapters/blobstore/localfs"
	"code.eitanity.com/kanonarion/internal/fetch/fetchtest"
	"code.eitanity.com/kanonarion/internal/fetch/ports"
)

func TestStore_PutGetExists(t *testing.T) {
	dir := t.TempDir()
	store := localfs.New(dir)
	ctx := context.Background()

	data, identity := fetchtest.ModuleZip(t, "example.com/m", "v1.0.0", map[string]string{"go.mod": "module example.com/m\n"})
	content := string(data)
	if err := store.Put(ctx, identity, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	ok, err := store.Exists(ctx, identity)
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !ok {
		t.Error("blob should exist after Put")
	}

	rc, err := store.Get(ctx, identity)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() {
		if cerr := rc.Close(); cerr != nil {
			t.Errorf("rc.Close: %v", cerr)
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

// Storing the same identity twice is a no-op the second time and leaves the
// first bytes in place. The store no longer derives an address from the bytes it
// is handed, so idempotence is a property of the identity, not of the content.
func TestStore_Idempotent(t *testing.T) {
	dir := t.TempDir()
	store := localfs.New(dir)
	ctx := context.Background()
	identity := fetchtest.GoModBlob(t, "data")

	if err := store.Put(ctx, identity, strings.NewReader("data")); err != nil {
		t.Fatalf("first Put: %v", err)
	}
	if err := store.Put(ctx, identity, strings.NewReader("other data")); err != nil {
		t.Fatalf("second Put: %v", err)
	}

	rc, err := store.Get(ctx, identity)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = rc.Close() }()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "data" {
		t.Errorf("got %q, want %q", got, "data")
	}
}

// The zip and the go.mod of one module can carry the same h1 value in principle,
// so the kind must keep them apart: a store holding both must not serve one for
// the other.
func TestStore_KindSeparatesArtefactsOfEqualHash(t *testing.T) {
	dir := t.TempDir()
	store := localfs.New(dir)
	ctx := context.Background()

	goMod := fetchtest.GoModBlob(t, "go.mod bytes")
	zip := fetchtest.Blob(ports.BlobKindZip, goMod.Hash())

	if err := store.Put(ctx, zip, strings.NewReader("zip bytes")); err != nil {
		t.Fatalf("Put zip: %v", err)
	}
	if err := store.Put(ctx, goMod, strings.NewReader("go.mod bytes")); err != nil {
		t.Fatalf("Put go.mod: %v", err)
	}

	rc, err := store.Get(ctx, goMod)
	if err != nil {
		t.Fatalf("Get go.mod: %v", err)
	}
	defer func() { _ = rc.Close() }()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "go.mod bytes" {
		t.Errorf("go.mod artefact resolved to %q; the zip of equal hash was served instead", got)
	}
}

func TestStore_ExistsUnknown(t *testing.T) {
	dir := t.TempDir()
	store := localfs.New(dir)

	ok, err := store.Exists(context.Background(), testIdentity("never-stored"))
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if ok {
		t.Error("should not exist")
	}
}
