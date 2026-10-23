package gotoolchain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
)

// mergedTree is a stub of TinyGo's merged GOROOT: TinyGo's and Go's source roots
// and a merged root linking whole directories into each, plus one directory that
// is real and holds per-file links into both, as a mixed package would.
type mergedTree struct{ tinygo, golang, merged string }

func newMergedTree(t *testing.T) mergedTree {
	t.Helper()
	base := t.TempDir()
	m := mergedTree{
		tinygo: filepath.Join(base, "tinygoroot"),
		golang: filepath.Join(base, "go"),
		merged: filepath.Join(base, "merged"),
	}
	write := func(path string) {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("package x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, name string) {
		if err := os.MkdirAll(filepath.Dir(name), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(m.tinygo, "src", "machine", "machine.go"))
	write(filepath.Join(m.tinygo, "src", "sync", "mutex.go"))
	write(filepath.Join(m.golang, "src", "io", "io.go"))
	write(filepath.Join(m.golang, "src", "sync", "once.go"))
	write(filepath.Join(m.golang, "src", "sync", "pool.go"))
	link(filepath.Join(m.tinygo, "src", "machine"), filepath.Join(m.merged, "src", "machine"))
	link(filepath.Join(m.golang, "src", "io"), filepath.Join(m.merged, "src", "io"))
	link(filepath.Join(m.tinygo, "src", "sync", "mutex.go"), filepath.Join(m.merged, "src", "sync", "mutex.go"))
	link(filepath.Join(m.golang, "src", "sync", "once.go"), filepath.Join(m.merged, "src", "sync", "once.go"))
	link(filepath.Join(m.golang, "src", "sync", "pool.go"), filepath.Join(m.merged, "src", "sync", "pool.go"))
	return m
}

func (m mergedTree) listing(t *testing.T, pkgs ...listedStdPackage) []byte {
	t.Helper()
	var b strings.Builder
	for _, p := range pkgs {
		out, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(out)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func (m mergedTree) pkg(path string, files ...string) listedStdPackage {
	return listedStdPackage{ImportPath: path, Dir: filepath.Join(m.merged, "src", path), GoFiles: files}
}

func TestAttributeStandard_PartitionsBySupplier(t *testing.T) {
	m := newMergedTree(t)
	module := listedStdPackage{ImportPath: "example.com/app", Dir: t.TempDir(), GoFiles: []string{"main.go"},
		Module: &struct{ Path string }{Path: "example.com/app"}}
	out := m.listing(t, m.pkg("machine", "machine.go"), m.pkg("io", "io.go"),
		m.pkg("sync", "mutex.go", "pool.go", "once.go"), module)

	split, err := attributeStandard(out, m.tinygo, m.golang)
	if err != nil {
		t.Fatalf("attributeStandard: %v", err)
	}
	facts, goPkgs := split.facts, split.goPkgs
	if want := []string{"machine", "sync"}; !reflect.DeepEqual(facts.Packages, want) {
		t.Errorf("TinyGo packages = %v, want %v (tinygo-only and mixed)", facts.Packages, want)
	}
	if want := []string{"io"}; !reflect.DeepEqual(goPkgs, want) {
		t.Errorf("Go packages = %v, want %v (go-only; the module package is in neither)", goPkgs, want)
	}
	if want := map[string][]string{"sync": {"once.go", "pool.go"}}; !reflect.DeepEqual(facts.Mixed, want) {
		t.Errorf("mixed = %v, want %v: the Go-served files of the mixed package, sorted", facts.Mixed, want)
	}
}

func TestAttributeStandard_NoMixedPackageLeavesMixedNil(t *testing.T) {
	m := newMergedTree(t)
	split, err := attributeStandard(m.listing(t, m.pkg("machine", "machine.go"), m.pkg("io", "io.go")), m.tinygo, m.golang)
	if err != nil {
		t.Fatalf("attributeStandard: %v", err)
	}
	if split.facts.Mixed != nil {
		t.Errorf("mixed = %v, want nil so the canonical form omits it", split.facts.Mixed)
	}
}

func TestAttributeStandard_APackageWithoutGoFilesIsAttributedByItsDirectory(t *testing.T) {
	m := newMergedTree(t)
	split, err := attributeStandard(m.listing(t, m.pkg("machine"), m.pkg("io")), m.tinygo, m.golang)
	if err != nil {
		t.Fatalf("attributeStandard: %v", err)
	}
	if !reflect.DeepEqual(split.facts.Packages, []string{"machine"}) || !reflect.DeepEqual(split.goPkgs, []string{"io"}) {
		t.Errorf("TinyGo %v, Go %v", split.facts.Packages, split.goPkgs)
	}
}

func TestAttributeStandard_RefusesWhatItCannotAttribute(t *testing.T) {
	m := newMergedTree(t)
	elsewhere := t.TempDir()
	if err := os.WriteFile(filepath.Join(elsewhere, "x.go"), []byte("package x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		out              []byte
		tinygoRoot, goRt string
		want             string
	}{
		"a file under neither root": {
			out:        m.listing(t, listedStdPackage{ImportPath: "stray", Dir: elsewhere, GoFiles: []string{"x.go"}}),
			tinygoRoot: m.tinygo, goRt: m.golang, want: "under neither",
		},
		"a file that does not exist": {
			out:        m.listing(t, m.pkg("io", "missing.go")),
			tinygoRoot: m.tinygo, goRt: m.golang, want: "resolving missing.go of package io",
		},
		"output that is not JSON": {
			out: []byte("{"), tinygoRoot: m.tinygo, goRt: m.golang, want: "decoding go list output",
		},
		"a TinyGo root without src": {
			out: m.listing(t), tinygoRoot: elsewhere, goRt: m.golang, want: "resolving the source root",
		},
		"a Go root without src": {
			out: m.listing(t), tinygoRoot: m.tinygo, goRt: elsewhere, want: "resolving the source root",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := attributeStandard(tc.out, tc.tinygoRoot, tc.goRt)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

// TestAttributeStandard_CustodyCoversEveryCompiledFileOfTinyGo: every compiled
// list counts, only TinyGo's own tree is hashed, and a Go-served file of a mixed
// package or a file of a Go-only package is the stdlib's, not TinyGo's.
func TestAttributeStandard_CustodyCoversEveryCompiledFileOfTinyGo(t *testing.T) {
	m := newMergedTree(t)
	asm := filepath.Join(m.tinygo, "src", "machine", "boot.S")
	if err := os.WriteFile(asm, []byte("nop\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	machine := m.pkg("machine", "machine.go")
	machine.SFiles = []string{"boot.S"}
	out := m.listing(t, machine, m.pkg("io", "io.go"), m.pkg("sync", "mutex.go", "pool.go", "once.go"))

	split, err := attributeStandard(out, m.tinygo, m.golang)
	if err != nil {
		t.Fatalf("attributeStandard: %v", err)
	}
	var paths []string
	for _, f := range split.files {
		paths = append(paths, f.Path)
	}
	if want := []string{"machine/boot.S", "machine/machine.go", "sync/mutex.go"}; !reflect.DeepEqual(paths, want) {
		t.Errorf("custody files = %v, want %v", paths, want)
	}
	sum := sha256.Sum256([]byte("nop\n"))
	if got, want := split.files[0].SHA256, hex.EncodeToString(sum[:]); got != want {
		t.Errorf("boot.S hash = %s, want %s: the installed bytes", got, want)
	}
}

// TestAttributeStandard_CustodyRefusesAFileItCannotRead: a compiled file that
// does not resolve fails the listing rather than leaving custody short.
func TestAttributeStandard_CustodyRefusesAFileItCannotRead(t *testing.T) {
	m := newMergedTree(t)
	machine := m.pkg("machine", "machine.go")
	machine.CFiles = []string{"gone.c"}
	if _, err := attributeStandard(m.listing(t, machine), m.tinygo, m.golang); err == nil || !strings.Contains(err.Error(), "resolving gone.c") {
		t.Errorf("err = %v, want the unresolvable file named", err)
	}
}

// TestResolve_AListingThatFailsFailsTheBuildList: a closure nobody could list
// yields no build list, never one with the split silently missing.
func TestResolve_AListingThatFailsFailsTheBuildList(t *testing.T) {
	m := newMergedTree(t)
	frame, err := goenv.NewTinyGo("pico", "0.42.0", "go1.27.2", "linux", "arm", "6", m.merged, m.tinygo,
		"thumbv6m-unknown-unknown-eabi", []string{"tinygo"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "go")
	script := "#!/bin/sh\n" +
		`case "$*" in *-deps*) echo 'package machine is not in std' >&2; exit 1 ;; list*) echo '{"Path":"example.com/frame","Main":true}' ;; env*) printf 'go1.27.2\nlinux\narm\n' ;; esac` + "\n"
	if werr := os.WriteFile(bin, []byte(script), 0o700); werr != nil { // #nosec G306 -- a test stand-in that must be executable
		t.Fatal(werr)
	}

	_, err = New(bin, nil).WithTinyGo(frame).Resolve(context.Background(), dir)

	if err == nil {
		t.Fatal("Resolve succeeded although the package listing failed")
	}
	for _, want := range []string{"package machine is not in std", "-deps -json ./...", "--tinygo pico"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to carry %q", err, want)
		}
	}
}

func TestResolve_GoRootThatCannotBeAskedFailsTheBuildList(t *testing.T) {
	m := newMergedTree(t)
	frame, err := goenv.NewTinyGo("pico", "0.42.0", "go1.27.2", "linux", "arm", "6", m.merged, m.tinygo,
		"thumbv6m-unknown-unknown-eabi", nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, envBranch := range map[string]string{
		"go env fails":          `"env GOROOT") exit 3 ;;`,
		"go env prints nothing": `"env GOROOT") ;;`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "go")
			script := "#!/bin/sh\n" +
				`case "$*" in *-deps*) ;; list*) echo '{"Path":"example.com/frame","Main":true}' ;; ` + envBranch +
				` env*) printf 'go1.27.2\nlinux\narm\n' ;; esac` + "\n"
			if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { // #nosec G306 -- a test stand-in that must be executable
				t.Fatal(err)
			}
			if _, err := New(bin, nil).WithTinyGo(frame).Resolve(context.Background(), dir); err == nil ||
				!strings.Contains(err.Error(), "GOROOT") {
				t.Errorf("err = %v, want the GOROOT probe named", err)
			}
		})
	}
}
