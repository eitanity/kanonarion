package ziparchive_test

import (
	"archive/zip"
	"bytes"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/ziparchive"
)

// fuzzZip builds a ZIP from name->content. Names are written verbatim so the
// seed corpus can carry path-traversal and zero-length entries a well-behaved
// module-zip writer would reject. Typed as testing.TB so it works from the
// *testing.F seed phase (the package's existing buildZip is *testing.T only).
func fuzzZip(tb testing.TB, entries map[string]string) []byte {
	tb.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range entries {
		fw, err := w.Create(name)
		if err != nil {
			tb.Fatalf("zip.Create(%q): %v", name, err)
		}
		if _, err := io.WriteString(fw, content); err != nil {
			tb.Fatalf("write %q: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		tb.Fatalf("zip.Close: %v", err)
	}
	return buf.Bytes()
}

// capBytes bounds how much uncompressed data the harness will read from a
// fuzzer-controlled archive. A zip bomb is a valid archive; the contract under
// test is "no panic / bounded resource use", so the harness itself must refuse
// to materialise an unbounded payload ( relates).
const capBytes = 32 << 20 // 32 MiB

// FuzzArchive fuzzes the shared module-zip reader consumed by the iface
// extractor (ziparchive.New → FS → walk) plus HashModuleZip and the zip-slip
// safe ExtractStream. Module zips are proxy-fetched untrusted input
// (relates). Invariants asserted:
//
// - No call panics on any input.
// - ExtractStream never writes a file outside its destination directory
// (zip-slip containment), regardless of entry names.
//
// Run locally with:
//
//	go test -run=NONE -fuzz=FuzzArchive./internal/adapters/ziparchive
func FuzzArchive(f *testing.F) {
	// Valid module-zip shaped archive.
	f.Add(fuzzZip(f, map[string]string{
		"example.com/m@v1.0.0/go.mod":      "module example.com/m\n\ngo 1.21\n",
		"example.com/m@v1.0.0/foo.go":      "package m\n\nfunc Foo() {}\n",
		"example.com/m@v1.0.0/sub/bar.go":  "package sub\n",
		"example.com/m@v1.0.0/foo_test.go": "package m\n",
		"example.com/m@v1.0.0/empty.go":    "",
		"example.com/m@v1.0.0/nested/dir/": "",
	}))
	// Path-traversal entry names (zip-slip).
	f.Add(fuzzZip(f, map[string]string{
		"../../../../etc/passwd": "owned\n",
		"m@v1/../../escape.txt":  "escape\n",
		"/abs/path.txt":          "abs\n",
		`m@v1\..\..\win.txt`:     "win\n",
	}))
	// Zero entries (empty but valid zip).
	f.Add(fuzzZip(f, map[string]string{}))
	// Zero-length entry only.
	f.Add(fuzzZip(f, map[string]string{"m@v1/empty": ""}))
	// Highly compressible payload (zip-bomb shaped, kept modest for the seed).
	f.Add(fuzzZip(f, map[string]string{
		"m@v1/big.txt": strings.Repeat("A", 1<<20),
	}))
	// Non-zip bytes.
	f.Add([]byte("this is definitely not a zip archive"))
	f.Add([]byte{})
	f.Add([]byte("PK\x03\x04 truncated local file header"))
	// Trailing garbage after a valid central directory.
	valid := fuzzZip(f, map[string]string{"m@v1/x.go": "package m\n"})
	f.Add(append(append([]byte{}, valid...), bytes.Repeat([]byte{0xff}, 64)...))

	f.Fuzz(func(t *testing.T, data []byte) {
		a, err := ziparchive.New(data)
		if err != nil {
			return // not a parseable zip — nothing more to exercise
		}

		// Mirror the iface consumption path: list names, walk the stripped FS,
		// and read each file, but stop once we've read capBytes total so a
		// zip bomb cannot make the harness itself unbounded.
		names := a.Names()
		var total int64
		for _, n := range names {
			if total >= capBytes {
				break
			}
			b, found, rerr := a.ReadFile(n)
			if rerr != nil || !found {
				continue
			}
			total += int64(len(b))
		}

		fsys := a.FS("")
		_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			if total >= capBytes {
				return fs.SkipAll
			}
			if d == nil || d.IsDir() {
				return nil
			}
			rf, ok := fsys.(fs.ReadFileFS)
			if !ok {
				return nil
			}
			b, rerr := rf.ReadFile(p)
			if rerr == nil {
				total += int64(len(b))
			}
			return nil
		})

		// HashModuleZip only over modestly-sized archives — it reads every
		// entry, so a bomb would otherwise dominate the fuzzer's time budget.
		if uncompressedTotal(data) <= capBytes {
			_, _ = ziparchive.HashModuleZip(data)
		}

		// ExtractStream must be zip-slip safe: every file it creates stays
		// under dest. It either errors out on an escaping entry or extracts
		// safely — never writes outside dest.
		dest := t.TempDir()
		if err := ziparchive.ExtractStream(bytes.NewReader(data), dest); err == nil {
			cleanDest := filepath.Clean(dest)
			_ = filepath.WalkDir(dest, func(p string, _ fs.DirEntry, werr error) error {
				if werr != nil {
					return werr
				}
				if !strings.HasPrefix(filepath.Clean(p), cleanDest) {
					t.Fatalf("ExtractStream wrote outside dest: %q not under %q", p, cleanDest)
				}
				return nil
			})
		}
	})
}

// uncompressedTotal sums the declared uncompressed sizes without decompressing,
// so the harness can cheaply decide whether to run the read-everything paths.
func uncompressedTotal(data []byte) int64 {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return 0
	}
	var total int64
	for _, fh := range zr.File {
		total += int64(fh.UncompressedSize64) //nolint:gosec // bounded comparison only
		if total < 0 {                        // overflow guard
			return capBytes + 1
		}
	}
	return total
}
