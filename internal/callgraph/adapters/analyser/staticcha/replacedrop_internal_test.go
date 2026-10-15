package staticcha

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/tools/go/packages"
)

// writeGoMod puts a go.mod in a fresh directory and returns the directory.
func writeGoMod(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	return dir
}

func readGoMod(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "go.mod")) //nolint:gosec // dir is the test's own temp dir
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	return string(b)
}

// TestDropLocalReplaces_DropsTargetsOutsideTheTreeAndKeepsTheRest is the whole
// rule in one table. A target outside the extracted tree cannot resolve here and
// applies to no consumer's build; a target inside it resolves exactly as
// published; a target that is a module version resolves with no filesystem at
// all.
func TestDropLocalReplaces_DropsTargetsOutsideTheTreeAndKeepsTheRest(t *testing.T) {
	t.Parallel()

	const monorepo = `module example.com/mod/config

go 1.21

require (
	example.com/mod v1.42.0
	example.com/mod/creds v1.19.24
	example.com/other v1.0.0
	example.com/nested v1.0.0
)

replace example.com/mod => ../

replace example.com/mod/creds => ../creds/

replace example.com/other v1.0.0 => example.com/fork v1.2.3

replace example.com/nested => ./nested/
`

	dir := writeGoMod(t, monorepo)
	dropped, err := dropLocalReplaces(dir, "example.com/mod/config")
	if err != nil {
		t.Fatalf("dropLocalReplaces: %v", err)
	}
	if len(dropped) != 2 {
		t.Fatalf("dropped %d directive(s), want the 2 filesystem ones: %v", len(dropped), dropped)
	}
	// Sorted by path, so the order is a fact about the record rather than about
	// the order they happened to appear in the file.
	if got, want := dropped[0].String(), "example.com/mod => ../"; got != want {
		t.Errorf("dropped[0] = %q, want %q", got, want)
	}
	if got, want := dropped[1].String(), "example.com/mod/creds => ../creds/"; got != want {
		t.Errorf("dropped[1] = %q, want %q", got, want)
	}

	rewritten := readGoMod(t, dir)
	if strings.Contains(rewritten, "../") {
		t.Errorf("a replace targeting a directory outside the tree survived the rewrite:\n%s", rewritten)
	}
	// A zip can carry a nested module and replace onto it. That directive resolves
	// exactly as published, and dropping it would send the load hunting for a
	// version of a module sitting in the extraction directory.
	if !strings.Contains(rewritten, "example.com/nested => ./nested/") {
		t.Errorf("a replace targeting a directory inside the tree was dropped:\n%s", rewritten)
	}
	// The version-to-version replace resolves without a filesystem, so nothing
	// about the extraction breaks it and it must be exactly as published.
	if !strings.Contains(rewritten, "example.com/other v1.0.0 => example.com/fork v1.2.3") {
		t.Errorf("the version-to-version replace was not left alone:\n%s", rewritten)
	}
	// The requirements are what the module declares; dropping a replace must not
	// touch them.
	for _, want := range []string{"example.com/mod v1.42.0", "example.com/mod/creds v1.19.24", "example.com/nested v1.0.0"} {
		if !strings.Contains(rewritten, want) {
			t.Errorf("require %q was lost:\n%s", want, rewritten)
		}
	}
}

// TestDropLocalReplaces_AbsoluteTargetGoesToo. An absolute path names a
// directory on the publisher's own machine. It is no more resolvable here than a
// relative one, and if it DOES resolve on this host it is worse: an unrelated
// tree would silently enter the analysis.
func TestDropLocalReplaces_AbsoluteTargetGoesToo(t *testing.T) {
	t.Parallel()

	dir := writeGoMod(t, "module example.com/mod\n\ngo 1.21\n\nrequire example.com/dep v1.0.0\n\nreplace example.com/dep => /home/publisher/dep\n")
	dropped, err := dropLocalReplaces(dir, "example.com/mod")
	if err != nil {
		t.Fatalf("dropLocalReplaces: %v", err)
	}
	if len(dropped) != 1 || dropped[0].Target != "/home/publisher/dep" {
		t.Fatalf("dropped = %v, want the absolute-path directive", dropped)
	}
}

// TestDropLocalReplaces_LeavesAFileWithNothingToDropByteIdentical is what makes
// this a no-op for the overwhelming majority of modules. A rewrite that
// reformatted every go.mod would change the analysed tree of modules this fix has
// no business touching.
func TestDropLocalReplaces_LeavesAFileWithNothingToDropByteIdentical(t *testing.T) {
	t.Parallel()

	// Deliberately not gofmt-shaped for a go.mod: extra blank lines and a comment
	// that modfile.Format would normalise away if the file were rewritten.
	const published = "module example.com/mod\n\n\ngo 1.21\n\n// a comment the module ships\nrequire example.com/dep v1.0.0\n\nreplace example.com/dep v1.0.0 => example.com/fork v2.0.0\n"

	dir := writeGoMod(t, published)
	dropped, err := dropLocalReplaces(dir, "example.com/mod")
	if err != nil {
		t.Fatalf("dropLocalReplaces: %v", err)
	}
	if len(dropped) != 0 {
		t.Fatalf("dropped %v from a file with no filesystem replace", dropped)
	}
	if got := readGoMod(t, dir); got != published {
		t.Errorf("go.mod was rewritten when nothing was dropped:\ngot:\n%s\nwant:\n%s", got, published)
	}
}

// TestDropLocalReplaces_AbsentAndUnparseableAreNoOps. A module published before
// Go modules ships no go.mod, and a malformed one is about to be reported by the
// load with a line number this cannot produce. Neither is this function's
// business, and neither may be turned into an error of its own.
func TestDropLocalReplaces_AbsentAndUnparseableAreNoOps(t *testing.T) {
	t.Parallel()

	t.Run("absent", func(t *testing.T) {
		t.Parallel()
		dropped, err := dropLocalReplaces(t.TempDir(), "example.com/mod")
		if err != nil {
			t.Fatalf("dropLocalReplaces on a directory with no go.mod: %v", err)
		}
		if len(dropped) != 0 {
			t.Errorf("dropped = %v, want none", dropped)
		}
	})

	t.Run("unparseable", func(t *testing.T) {
		t.Parallel()
		const broken = "module example.com/mod\n\nthis is not a directive\n"
		dir := writeGoMod(t, broken)
		dropped, err := dropLocalReplaces(dir, "example.com/mod")
		if err != nil {
			t.Fatalf("dropLocalReplaces on an unparseable go.mod: %v", err)
		}
		if len(dropped) != 0 {
			t.Errorf("dropped = %v, want none", dropped)
		}
		if got := readGoMod(t, dir); got != broken {
			t.Errorf("an unparseable go.mod was rewritten:\n%s", got)
		}
	})
}

// TestDropLocalReplaces_KeepsAnInsideTargetThatDoesNotExist. The go command then
// says "replacement directory ./dep does not exist", which is a true statement
// about the published bytes and is the module's own fault. Dropping it would
// replace a real diagnosis with a search for a module nobody published.
func TestDropLocalReplaces_KeepsAnInsideTargetThatDoesNotExist(t *testing.T) {
	t.Parallel()

	const published = "module example.com/mod\n\ngo 1.21\n\nrequire example.com/dep v1.0.0\n\nreplace example.com/dep => ./dep\n"
	dir := writeGoMod(t, published)
	dropped, err := dropLocalReplaces(dir, "example.com/mod")
	if err != nil {
		t.Fatalf("dropLocalReplaces: %v", err)
	}
	if len(dropped) != 0 {
		t.Fatalf("dropped %v: a target inside the tree must be left for the load to report on", dropped)
	}
	if got := readGoMod(t, dir); got != published {
		t.Errorf("go.mod was rewritten:\n%s", got)
	}
}

// TestDropLocalReplaces_IsIdempotent. Analyse runs once per extraction, but the
// function must not depend on that: a second pass over a rewritten file has
// nothing to drop and must leave it alone.
func TestDropLocalReplaces_IsIdempotent(t *testing.T) {
	t.Parallel()

	dir := writeGoMod(t, "module example.com/mod\n\ngo 1.21\n\nrequire example.com/dep v1.0.0\n\nreplace example.com/dep => ../dep/\n")
	if _, err := dropLocalReplaces(dir, "example.com/mod"); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	first := readGoMod(t, dir)
	dropped, err := dropLocalReplaces(dir, "example.com/mod")
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if len(dropped) != 0 {
		t.Errorf("second pass dropped %v", dropped)
	}
	if got := readGoMod(t, dir); got != first {
		t.Errorf("second pass rewrote the file:\ngot:\n%s\nwant:\n%s", got, first)
	}
}

// TestDropLocalReplaces_NestedModuleWithAbsentTarget is the otel shape: a
// module replaces its own nested modules with in-tree paths, and the zip format
// leaves those directories out. Each such directive is dropped and named, with a
// version on the left kept as written; a nested replace whose target is present
// stays, as does an absent target for a module that is not nested.
func TestDropLocalReplaces_NestedModuleWithAbsentTarget(t *testing.T) {
	t.Parallel()

	const published = `module example.com/mod

go 1.21

require (
	example.com/mod/file v1.0.0
	example.com/mod/metric v1.0.0
	example.com/mod/present v1.0.0
	example.com/mod/trace v1.0.0
	example.com/modx v1.0.0
	example.com/other v1.0.0
)

replace example.com/mod/metric => ./metric

replace example.com/mod/trace v1.0.0 => ./trace

replace example.com/mod/file => ./afile/sub

replace example.com/mod/present => ./present

replace example.com/modx => ./modx

replace example.com/other => ./other
`
	dir := writeGoMod(t, published)
	if err := os.MkdirAll(filepath.Join(dir, "present"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "present", "go.mod"), []byte("module example.com/mod/present\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A path element that is a file leaves the target absent all the same.
	if err := os.WriteFile(filepath.Join(dir, "afile"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	dropped, err := dropLocalReplaces(dir, "example.com/mod")
	if err != nil {
		t.Fatalf("dropLocalReplaces: %v", err)
	}
	got := make([]string, 0, len(dropped))
	for _, d := range dropped {
		got = append(got, d.String())
	}
	want := []string{
		"example.com/mod/file => ./afile/sub",
		"example.com/mod/metric => ./metric",
		"example.com/mod/trace v1.0.0 => ./trace",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("dropped = %q, want %q", got, want)
	}

	rewritten := readGoMod(t, dir)
	for _, kept := range []string{
		"example.com/mod/present => ./present",
		"example.com/modx => ./modx",
		"example.com/other => ./other",
	} {
		if !strings.Contains(rewritten, kept) {
			t.Errorf("%q was dropped:\n%s", kept, rewritten)
		}
	}
	for _, gone := range []string{"=> ./metric", "=> ./trace"} {
		if strings.Contains(rewritten, gone) {
			t.Errorf("%q survived the rewrite:\n%s", gone, rewritten)
		}
	}
}

// TestUnresolvableHere_AbsentTargetReadings covers the three readings of a
// nested-module target that does not Lstat: a path element is a file, the
// directory exists but lacks the target, and neither, which stays an error.
func TestUnresolvableHere_AbsentTargetReadings(t *testing.T) {
	t.Parallel()
	replace := func(target string) *modfile.Replace {
		return &modfile.Replace{
			Old: module.Version{Path: "example.com/mod/sub"},
			New: module.Version{Path: target},
		}
	}

	t.Run("path element is a file", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "afile"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, target := range []string{"./afile/sub", "./afile/a/b/c"} {
			got, err := unresolvableHere(root, "example.com/mod", replace(target))
			if err != nil || !got {
				t.Errorf("%s: got (%v, %v), want (true, nil)", target, got, err)
			}
		}
	})

	t.Run("directory exists but lacks the target", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "adir"), 0o750); err != nil {
			t.Fatal(err)
		}
		got, err := unresolvableHere(root, "example.com/mod", replace("./adir/sub"))
		if err != nil || !got {
			t.Errorf("got (%v, %v), want (true, nil)", got, err)
		}
	})

	t.Run("unreadable parent is an error", func(t *testing.T) {
		t.Parallel()
		if os.Geteuid() == 0 {
			t.Skip("root reads a mode-0 directory, so there is no permission error to observe")
		}
		root := t.TempDir()
		locked := filepath.Join(root, "locked")
		if err := os.MkdirAll(filepath.Join(locked, "sub"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(locked, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			// TempDir cannot remove a directory it cannot read.
			if err := os.Chmod(locked, 0o700); err != nil {
				t.Errorf("restoring %s: %v", locked, err)
			}
		})
		got, err := unresolvableHere(root, "example.com/mod", replace("./locked/sub"))
		if err == nil || got {
			t.Fatalf("got (%v, %v), want (false, error)", got, err)
		}
		if !errors.Is(err, fs.ErrPermission) {
			t.Errorf("err = %v, want it to wrap fs.ErrPermission", err)
		}
	})
}

// TestIsNestedModulePath pins the "/" boundary: a shared string prefix is not
// nesting, and a module is not nested in itself.
func TestIsNestedModulePath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		mod, path string
		want      bool
	}{
		{"example.com/mod", "example.com/mod/sub", true},
		{"example.com/mod", "example.com/mod/a/b", true},
		{"example.com/mod/v2", "example.com/mod/v2/sub", true},
		{"example.com/mod", "example.com/modx", false},
		{"example.com/mod", "example.com/mod", false},
		{"example.com/mod", "example.com/other", false},
		{"example.com/mod/sub", "example.com/mod", false},
		{"", "example.com/mod", false},
	} {
		if got := isNestedModulePath(tc.mod, tc.path); got != tc.want {
			t.Errorf("isNestedModulePath(%q, %q) = %v, want %v", tc.mod, tc.path, got, tc.want)
		}
	}
}

// TestDependencyListErrors reads the go command's errors off dependencies only:
// a root's errors are LoadErrs already, a type error is a consequence, and a
// cache miss or a missing go.sum entry has its own reading.
func TestDependencyListErrors(t *testing.T) {
	t.Parallel()
	listErr := func(msg string) packages.Error { return packages.Error{Msg: msg, Kind: packages.ListError} }
	replaced := &packages.Package{PkgPath: "example.com/other", Errors: []packages.Error{
		listErr("example.com/other@v1.0.0: replacement directory ./other\n\tdoes not exist"),
	}}
	missing := &packages.Package{PkgPath: "example.com/cold", Errors: []packages.Error{
		listErr("example.com/cold@v1.0.0: module lookup disabled by GOPROXY=off"),
	}}
	typed := &packages.Package{PkgPath: "example.com/typed", Errors: []packages.Error{
		{Msg: "undefined: x", Kind: packages.TypeError},
	}}
	root := &packages.Package{
		PkgPath: "example.com/mod",
		Errors:  []packages.Error{listErr("a root error")},
		Imports: map[string]*packages.Package{"a": replaced, "b": missing, "c": typed},
	}
	got := dependencyListErrors([]*packages.Package{root})
	want := []string{"example.com/other@v1.0.0: replacement directory ./other does not exist"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("dependencyListErrors = %q, want %q", got, want)
	}
	if got := leadWithDependencyError("x; "+want[0], want); got != "x; "+want[0] {
		t.Errorf("a sentence already in the detail was repeated: %q", got)
	}
}

// TestSourceRootsRelText writes a path quoted in an error the way a position is
// written: module-cache paths cache-relative, the extraction's module-relative,
// GOROOT's GOROOT-relative. A path under no root is left as it is.
func TestSourceRootsRelText(t *testing.T) {
	t.Parallel()
	roots := newSourceRoots("/tmp/x-extract-1", "/tmp/kanonarion-cg-modcache-1",
		SourceDirs{GOROOT: "/usr/local/go", ModuleCache: "/home/u/go/pkg/mod"})
	for in, want := range map[string]string{
		"build constraints exclude all Go files in /tmp/kanonarion-cg-modcache-1/golang.org/x/sys@v0.1.0/windows": "build constraints exclude all Go files in golang.org/x/sys@v0.1.0/windows",
		"/tmp/x-extract-1/premod.go:3:8: could not import x":                                                      "premod.go:3:8: could not import x",
		"/home/u/go/pkg/mod/example.com/a@v1.0.0/a.go:1:1: x":                                                     "example.com/a@v1.0.0/a.go:1:1: x",
		"/usr/local/go/src/os/file.go:1:1: x":                                                                     "src/os/file.go:1:1: x",
		"/elsewhere/a.go: x":                                                                                      "/elsewhere/a.go: x",
	} {
		if got := roots.relText(in); got != want {
			t.Errorf("relText(%q) = %q, want %q", in, got, want)
		}
	}
}
