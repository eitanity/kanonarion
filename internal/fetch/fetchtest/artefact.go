package fetchtest

import (
	"archive/zip"
	"bytes"
	"io"
	"sort"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
	"golang.org/x/mod/sumdb/dirhash"
)

// ModuleZip returns the bytes of a module zip holding files, named relative to
// the module root, and the blob identity those bytes hash to. A blob store
// verifies what it serves, so a fixture it is to serve has to be one.
func ModuleZip(t testing.TB, path, version string, files map[string]string) ([]byte, ports.BlobIdentity) {
	t.Helper()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range names {
		w, err := zw.Create(path + "@" + version + "/" + name)
		if err != nil {
			t.Fatalf("fetchtest: adding %s to module zip: %v", name, err)
		}
		if _, err := io.WriteString(w, files[name]); err != nil {
			t.Fatalf("fetchtest: writing %s to module zip: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("fetchtest: closing module zip: %v", err)
	}
	data := buf.Bytes()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("fetchtest: reading module zip back: %v", err)
	}
	entries := make([]string, len(zr.File))
	byName := make(map[string]*zip.File, len(zr.File))
	for i, f := range zr.File {
		entries[i], byName[f.Name] = f.Name, f
	}
	h1, err := dirhash.Hash1(entries, func(name string) (io.ReadCloser, error) { return byName[name].Open() })
	if err != nil {
		t.Fatalf("fetchtest: hashing module zip: %v", err)
	}
	return data, blobOf(t, ports.BlobKindZip, h1)
}

// GoModBlob returns the blob identity a standalone go.mod holding content
// hashes to.
func GoModBlob(t testing.TB, content string) ports.BlobIdentity {
	t.Helper()
	h1, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(content)), nil
	})
	if err != nil {
		t.Fatalf("fetchtest: hashing go.mod: %v", err)
	}
	return blobOf(t, ports.BlobKindGoMod, h1)
}

func blobOf(t testing.TB, kind ports.BlobKind, h1 string) ports.BlobIdentity {
	t.Helper()
	hash, err := domain.ParseModuleHash(h1)
	if err != nil {
		t.Fatalf("fetchtest: parsing %s: %v", h1, err)
	}
	return Blob(kind, hash)
}
