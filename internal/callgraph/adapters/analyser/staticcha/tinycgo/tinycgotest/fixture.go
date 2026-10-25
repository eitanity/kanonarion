// Package tinycgotest builds a TinyGo frame for tests without the tinygo
// command: a fake TINYGOROOT from tinycgo's testdata, and a merged GOROOT that
// links this toolchain's source beside the fake's packages, as tinygo merges
// its own. The fixtures' Go files are kept as .go.txt, so no tool that walks
// the module reads their C, and become .go when copied out.
package tinycgotest

import (
	"fmt"
	"go/build"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"github.com/eitanity/kanonarion/internal/callgraph/adapters/analyser/staticcha/tinycgo"
)

// Triple is the fake board's LLVM triple.
const Triple = "thumbv6m-unknown-unknown-eabi"

// Testdata is tinycgo's testdata directory.
func Testdata(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locating tinycgo's testdata")
	}
	return filepath.Join(filepath.Dir(file), "..", "testdata")
}

// Frame is a fakeboard frame: linux/arm over a merged GOROOT whose src links
// every entry of this toolchain's src, and tinycgofx from the fake TINYGOROOT.
func Frame(t testing.TB) goenv.TinyGo {
	t.Helper()
	root := t.TempDir()
	copyTree(t, filepath.Join(Testdata(t), "tinygoroot"), root)
	host := build.Default.GOROOT
	merged := t.TempDir()
	entries, err := os.ReadDir(host)
	if err != nil {
		t.Fatalf("reading GOROOT %s: %v", host, err)
	}
	for _, e := range entries {
		if e.Name() != "src" {
			link(t, filepath.Join(host, e.Name()), filepath.Join(merged, e.Name()))
		}
	}
	src := filepath.Join(merged, "src")
	if mkErr := os.Mkdir(src, 0o750); mkErr != nil {
		t.Fatal(mkErr)
	}
	srcEntries, err := os.ReadDir(filepath.Join(host, "src"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range srcEntries {
		link(t, filepath.Join(host, "src", e.Name()), filepath.Join(src, e.Name()))
	}
	link(t, filepath.Join(root, "src", "tinycgofx"), filepath.Join(src, "tinycgofx"))
	f, err := goenv.NewTinyGo("fakeboard", "0.42.0", "go1.27.2", "linux", "arm", "6", merged, root, Triple,
		[]string{"fakeboard", "tinygo"})
	if err != nil {
		t.Fatalf("NewTinyGo: %v", err)
	}
	return f
}

func link(t testing.TB, from, to string) {
	t.Helper()
	if err := os.Symlink(from, to); err != nil {
		t.Fatalf("linking %s: %v", to, err)
	}
}

// Program copies testdata/programs/<name> into a fresh directory.
func Program(t testing.TB, name string) string {
	t.Helper()
	dir := t.TempDir()
	copyTree(t, filepath.Join(Testdata(t), "programs", name), dir)
	return dir
}

// copyTree copies from into to, a .go.txt file as .go.
func copyTree(t testing.TB, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, path)
		if err != nil {
			return fmt.Errorf("relating %s: %w", path, err)
		}
		dst := filepath.Join(to, rel)
		if strings.HasSuffix(dst, ".go.txt") {
			dst = strings.TrimSuffix(dst, ".txt")
		}
		if d.IsDir() {
			return os.MkdirAll(dst, 0o750)
		}
		b, err := os.ReadFile(path) // #nosec G304 G122 -- a checked-in fixture tree
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		return os.WriteFile(dst, b, 0o600) // #nosec G703 -- under a fresh temp directory
	})
	if err != nil {
		t.Fatalf("copying %s: %v", from, err)
	}
}

// RequireClang is the C compiler found by the shipped rule. Off CI a host
// without one skips the test by name; on CI (CI set) it fails, because the
// runner image ships clang and a skip there would hide the test.
func RequireClang(t testing.TB) string {
	t.Helper()
	path, err := tinycgo.FindCompiler(os.Getenv("PATH"))
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI provides no C compiler by the shipped rule (clang on PATH, else the highest clang-<N>): %v", err)
		}
		t.Skipf("skipping: %v", err)
	}
	return path
}
