package ziparchive_test

import (
	"archive/zip"
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/ziparchive"
)

func buildZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("zip create %q: %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("zip write %q: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// TestFSWalkBoundedOnAdversarialNames is the regression: a
// proxy-fetched module zip carrying a pathologically deep entry name, an
// absolute path, or empty path segments must not drive fs.WalkDir over the
// stripped FS into unbounded (effectively infinite) recursion. The iface
// extractor walks exactly this FS, so an un-bounded walk here is a remote DoS.
// Before the isSafeEntryName filter this overflowed the goroutine stack.
func TestFSWalkBoundedOnAdversarialNames(t *testing.T) {
	// The original fuzz crash was *infinite* recursion: an absolute path or
	// an empty path segment makes strippedFS synthesise a zero-width child
	// directory that never consumes characters, so fs.WalkDir recurses
	// forever. "deep" additionally exceeds maxEntryDepth (defence in depth);
	// zip caps entry names at 64KiB so unbounded depth alone is impossible.
	deep := strings.Repeat("a/", 400) + "x.go"
	data := buildZip(t, map[string]string{
		deep:         "package a\n",
		"/abs.go":    "package abs\n",
		"a//b.go":    "package b\n",
		"./dot.go":   "package dot\n",
		"../esc.go":  "package esc\n",
		"ok/real.go": "package real\n",
	})
	a, err := ziparchive.New(data)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	visits := 0
	err = fs.WalkDir(a.FS(""), ".", func(p string, _ fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		visits++
		if visits > 10_000 {
			t.Fatalf("WalkDir not bounded: still visiting at %q (visit %d)", p, visits)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	// The one legitimately-named file must still be reachable.
	if _, rerr := fs.ReadFile(a.FS(""), "ok/real.go"); rerr != nil {
		t.Fatalf("safe entry ok/real.go should remain readable: %v", rerr)
	}
}

func TestNewInvalid(t *testing.T) {
	if _, err := ziparchive.New([]byte("not a zip")); err == nil {
		t.Fatal("expected error for invalid zip")
	}
}

func TestNamesAndReadFile(t *testing.T) {
	data := buildZip(t, map[string]string{
		"m@v1.0.0/go.mod":  "module m",
		"m@v1.0.0/a/a.go":  "package a",
		"m@v1.0.0/LICENSE": "MIT",
	})
	a, err := ziparchive.New(data)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	names := a.Names()
	want := []string{"m@v1.0.0/LICENSE", "m@v1.0.0/a/a.go", "m@v1.0.0/go.mod"}
	if len(names) != len(want) {
		t.Fatalf("Names() = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("Names() not sorted: got %v, want %v", names, want)
		}
	}

	content, found, err := a.ReadFile("m@v1.0.0/go.mod")
	if err != nil || !found {
		t.Fatalf("ReadFile go.mod: found=%v err=%v", found, err)
	}
	if string(content) != "module m" {
		t.Fatalf("ReadFile content = %q", content)
	}

	if _, found, err := a.ReadFile("m@v1.0.0/missing"); err != nil || found {
		t.Fatalf("ReadFile missing: found=%v err=%v (want false,nil)", found, err)
	}
}

func TestFSStripsPrefix(t *testing.T) {
	data := buildZip(t, map[string]string{
		"m@v1.0.0/go.mod":   "module m",
		"m@v1.0.0/sub/b.go": "package b",
	})
	a, err := ziparchive.New(data)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fsys := a.FS("m@v1.0.0/")

	got, err := fs.ReadFile(fsys, "go.mod")
	if err != nil {
		t.Fatalf("fs.ReadFile go.mod: %v", err)
	}
	if string(got) != "module m" {
		t.Fatalf("fs.ReadFile = %q", got)
	}

	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		t.Fatalf("fs.ReadDir .: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("root entries = %d, want 2", len(entries))
	}

	if _, err := fs.ReadFile(fsys, "nope.go"); err == nil {
		t.Fatal("expected error reading missing file")
	}
}

func TestHashModuleZipDeterministic(t *testing.T) {
	data := buildZip(t, map[string]string{"m@v1.0.0/go.mod": "module m"})
	h1, err := ziparchive.HashModuleZip(data)
	if err != nil {
		t.Fatalf("HashModuleZip: %v", err)
	}
	h2, err := (ziparchive.Hasher{}).HashModuleZip(data)
	if err != nil {
		t.Fatalf("Hasher.HashModuleZip: %v", err)
	}
	if h1 != h2 || h1 == "" {
		t.Fatalf("hash mismatch or empty: %q vs %q", h1, h2)
	}
}

func TestExtractStream(t *testing.T) {
	data := buildZip(t, map[string]string{
		"a.txt":   "alpha",
		"d/b.txt": "beta",
	})
	dest := t.TempDir()
	if err := ziparchive.ExtractStream(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("ExtractStream: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "d", "b.txt")) /* #nosec G304 -- test-controlled temp path */
	if err != nil {
		t.Fatalf("read extracted: %v", err)
	}
	if string(got) != "beta" {
		t.Fatalf("extracted content = %q", got)
	}
}

func TestExtractStreamContainsZipSlip(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create("../escape.txt")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := io.WriteString(f, "x"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	parent := t.TempDir()
	dest := filepath.Join(parent, "dest")
	if err := os.Mkdir(dest, 0o750); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}
	if err := ziparchive.ExtractStream(bytes.NewReader(buf.Bytes()), dest); err != nil {
		t.Fatalf("ExtractStream: %v", err)
	}
	// The traversing entry must be sanitised into dest, never written to the
	// parent directory.
	if _, err := os.Stat(filepath.Join(parent, "escape.txt")); !os.IsNotExist(err) {
		t.Fatalf("zip-slip entry escaped dest: stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "escape.txt")); err != nil {
		t.Fatalf("sanitised entry not found in dest: %v", err)
	}
}
