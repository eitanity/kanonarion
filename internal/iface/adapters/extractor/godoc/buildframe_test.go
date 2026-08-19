package godoc_test

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"testing/fstest"
	"time"

	"github.com/eitanity/kanonarion/internal/iface/adapters/extractor/godoc"
	domain2 "github.com/eitanity/kanonarion/internal/iface/domain"
)

// variantFS builds a package directory that declares ONE exported function
// several times over, once per mutually exclusive build constraint — the shape
// of every module the defect was measured on: golang.org/x/sys, modernc.org/libc,
// github.com/mattn/go-isatty. Only the linux/amd64 variant is in a linux/amd64
// build.
func variantFS() fstest.MapFS {
	fsys := fstest.MapFS{}
	variants := map[string]string{
		"isatty_linux.go":   "//go:build linux\n",
		"isatty_windows.go": "//go:build windows\n",
		"isatty_darwin.go":  "//go:build darwin || freebsd || openbsd\n",
		"isatty_plan9.go":   "//go:build plan9\n",
		"isatty_solaris.go": "//go:build solaris\n",
		"isatty_others.go":  "//go:build js || wasm || appengine\n",
	}
	for name, tag := range variants {
		fsys[name] = &fstest.MapFile{Data: []byte(fmt.Sprintf(
			"%s\npackage variant\n\n// IsTerminal reports a terminal on %s.\nfunc IsTerminal(fd uintptr) bool { return false }\n",
			tag, name))}
	}
	return fsys
}

func linuxAmd64() domain2.BuildFrame {
	return domain2.BuildFrame{GOOS: "linux", GOARCH: "amd64", CgoEnabled: true}
}

func framedExtractor(t *testing.T, frame domain2.BuildFrame) *godoc.Extractor {
	t.Helper()
	ext, err := godoc.New("0.1.0", fixedClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}).WithFrame(frame)
	if err != nil {
		t.Fatalf("WithFrame: %v", err)
	}
	return ext
}

// TestExtract_DuplicateDeclarationsResolveDeterministically is the regression.
//
// Before build constraints were evaluated, go/doc was handed all six
// declarations of IsTerminal and picked one in MAP ITERATION ORDER, so repeated
// extraction of one module zip produced several different public APIs. Go
// randomises map seeding per process but not per iteration, so the flip is
// sampled by repeating the extraction inside one process too — the loop below
// caught six distinct outcomes in 200 iterations against the unfixed extractor.
func TestExtract_DuplicateDeclarationsResolveDeterministically(t *testing.T) {
	ext := framedExtractor(t, linuxAmd64())
	fsys := variantFS()

	seen := map[string]int{}
	const iterations = 200
	for range iterations {
		r, err := ext.Extract(context.Background(), fsys, coord(t))
		if err != nil {
			t.Fatalf("Extract: %v", err)
		}
		seen[domain2.APIDigest(r)]++
	}
	if len(seen) != 1 {
		t.Fatalf("public API digests over %d extractions = %d distinct, want 1: %v", iterations, len(seen), seen)
	}
}

// TestExtract_KeepsOnlyTheInFrameDeclaration is the correctness half: one answer
// is not enough, it has to be the answer for the frame the record names.
func TestExtract_KeepsOnlyTheInFrameDeclaration(t *testing.T) {
	for _, tc := range []struct {
		frame domain2.BuildFrame
		want  string
	}{
		{domain2.BuildFrame{GOOS: "linux", GOARCH: "amd64", CgoEnabled: true}, "isatty_linux.go"},
		{domain2.BuildFrame{GOOS: "windows", GOARCH: "amd64", CgoEnabled: true}, "isatty_windows.go"},
		{domain2.BuildFrame{GOOS: "darwin", GOARCH: "arm64", CgoEnabled: true}, "isatty_darwin.go"},
		{domain2.BuildFrame{GOOS: "plan9", GOARCH: "386", CgoEnabled: false}, "isatty_plan9.go"},
		{domain2.BuildFrame{GOOS: "solaris", GOARCH: "amd64", CgoEnabled: true}, "isatty_solaris.go"},
	} {
		t.Run(tc.frame.GOOS, func(t *testing.T) {
			r, err := framedExtractor(t, tc.frame).Extract(context.Background(), variantFS(), coord(t))
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			if len(r.Packages) != 1 {
				t.Fatalf("packages = %d, want 1", len(r.Packages))
			}
			funcs := r.Packages[0].Funcs
			if len(funcs) != 1 {
				t.Fatalf("funcs = %d, want 1: %v", len(funcs), funcs)
			}
			if got := funcs[0].Position.File; got != tc.want {
				t.Errorf("IsTerminal declared in %q, want %q", got, tc.want)
			}
			if r.BuildFrame != tc.frame {
				t.Errorf("BuildFrame = %v, want %v", r.BuildFrame, tc.frame)
			}
		})
	}
}

// TestExtract_FrameSelectsByFilenameSuffix covers the OTHER spelling of a build
// constraint. A fix that only read //go:build lines would keep every _GOOS.go
// file and leave the defect standing on golang.org/x/sys, which is mostly named
// that way.
func TestExtract_FrameSelectsByFilenameSuffix(t *testing.T) {
	fsys := fstest.MapFS{}
	for _, goos := range []string{"linux", "windows", "darwin", "plan9"} {
		fsys["syscall_"+goos+"_amd64.go"] = &fstest.MapFile{Data: []byte(
			"package variant\n\nfunc Syscall() string { return \"" + goos + "\" }\n")}
	}
	r, err := framedExtractor(t, linuxAmd64()).Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	funcs := r.Packages[0].Funcs
	if len(funcs) != 1 || funcs[0].Position.File != "syscall_linux_amd64.go" {
		t.Fatalf("funcs = %v, want only syscall_linux_amd64.go", funcs)
	}
}

// TestExtract_PackageWithNoInFrameFilesIsKeptAndMarked holds the narrowing
// visible. A directory that exists in the module and not in this build must not
// vanish from the record: "removed from the module" and "not built here" are
// different facts and a reader has to be able to tell them apart.
func TestExtract_PackageWithNoInFrameFilesIsKeptAndMarked(t *testing.T) {
	fsys := fstest.MapFS{
		"lib.go":            &fstest.MapFile{Data: []byte("package m\n\nfunc Here() {}\n")},
		"plan9/only.go":     &fstest.MapFile{Data: []byte("//go:build plan9\n\npackage only\n\nfunc Elsewhere() {}\n")},
		"plan9/only_two.go": &fstest.MapFile{Data: []byte("//go:build plan9\n\npackage only\n\nfunc AlsoElsewhere() {}\n")},
	}
	r, err := framedExtractor(t, linuxAmd64()).Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(r.Packages) != 2 {
		t.Fatalf("packages = %d, want 2 (the directory is kept, not dropped): %v", len(r.Packages), r.Packages)
	}
	if r.OverallStatus != domain2.InterfaceStatusExtracted {
		t.Errorf("OverallStatus = %s, want Extracted: an out-of-frame package is a measured fact, not a failure", r.OverallStatus)
	}
	var out domain2.PackageInterface
	for _, p := range r.Packages {
		if p.ImportPath == "example.com/m/plan9" {
			out = p
		}
	}
	if !out.OutOfFrame {
		t.Errorf("plan9 package OutOfFrame = false, want true")
	}
	if len(out.Funcs) != 0 {
		t.Errorf("plan9 package carries %d funcs, want 0", len(out.Funcs))
	}
}

// TestExtract_DefaultFrameIsTheHost states the default the extractor takes when
// no frame is declared. It is a real, buildable configuration; "every platform
// at once" never was.
func TestExtract_DefaultFrameIsTheHost(t *testing.T) {
	r, err := makeExtractor().Extract(context.Background(), variantFS(), coord(t))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if r.BuildFrame.GOOS != runtime.GOOS || r.BuildFrame.GOARCH != runtime.GOARCH {
		t.Errorf("BuildFrame = %v, want %s/%s", r.BuildFrame, runtime.GOOS, runtime.GOARCH)
	}
	if r.BuildFrame.IsZero() {
		t.Error("BuildFrame is zero: a record that names no frame cannot be compared with one that does")
	}
}

// TestWithFrame_RefusesZero is the value-object refusal. An extractor with no
// frame would hand go/doc every platform's files again.
func TestWithFrame_RefusesZero(t *testing.T) {
	if _, err := godoc.New("0.1.0", fixedClock{}).WithFrame(domain2.BuildFrame{}); err == nil {
		t.Fatal("WithFrame(zero) returned no error")
	}
}

// TestExtract_CgoIsPartOfTheFrame proves the third axis matters: the cgo tag
// selects files, so two runs that disagree about it measure different packages.
func TestExtract_CgoIsPartOfTheFrame(t *testing.T) {
	fsys := fstest.MapFS{
		"with_cgo.go":    &fstest.MapFile{Data: []byte("//go:build cgo\n\npackage m\n\nfunc Impl() string { return \"cgo\" }\n")},
		"without_cgo.go": &fstest.MapFile{Data: []byte("//go:build !cgo\n\npackage m\n\nfunc Impl() string { return \"pure\" }\n")},
	}
	on, err := framedExtractor(t, domain2.BuildFrame{GOOS: "linux", GOARCH: "amd64", CgoEnabled: true}).
		Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	off, err := framedExtractor(t, domain2.BuildFrame{GOOS: "linux", GOARCH: "amd64", CgoEnabled: false}).
		Extract(context.Background(), fsys, coord(t))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if on.Packages[0].Funcs[0].Position.File != "with_cgo.go" {
		t.Errorf("cgo on selected %q, want with_cgo.go", on.Packages[0].Funcs[0].Position.File)
	}
	if off.Packages[0].Funcs[0].Position.File != "without_cgo.go" {
		t.Errorf("cgo off selected %q, want without_cgo.go", off.Packages[0].Funcs[0].Position.File)
	}
}

// TestExtract_PackageDirOrderIsFixed covers the neighbouring surface: the set of
// package directories was iterated in map order too. The record is sorted before
// it is hashed, so that order does not reach the stored bytes — this holds the
// order fixed anyway, so a future short circuit cannot make it matter again.
func TestExtract_PackageDirOrderIsFixed(t *testing.T) {
	fsys := fstest.MapFS{}
	for _, d := range []string{"z", "a", "m", "b", "q", "c", "y", "d", "x", "e"} {
		fsys[d+"/pkg.go"] = &fstest.MapFile{Data: []byte("package " + d + "\n\nfunc F() {}\n")}
	}
	ext := framedExtractor(t, linuxAmd64())
	var first []string
	for i := range 50 {
		r, err := ext.Extract(context.Background(), fsys, coord(t))
		if err != nil {
			t.Fatalf("Extract: %v", err)
		}
		got := make([]string, 0, len(r.Packages))
		for _, p := range r.Packages {
			got = append(got, p.ImportPath)
		}
		if i == 0 {
			first = got
			continue
		}
		if fmt.Sprint(got) != fmt.Sprint(first) {
			t.Fatalf("package order varied: %v then %v", first, got)
		}
	}
}
