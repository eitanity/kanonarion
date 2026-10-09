package staticcha

import (
	"slices"
	"testing"
)

// TestIsStdlibPackagePath is the go command's own rule, applied to decide what
// counts as the standard library: a module path's first element carries a dot,
// and a standard-library path's does not.
func TestIsStdlibPackagePath(t *testing.T) {
	t.Parallel()

	for path, want := range map[string]bool{
		"net/http":                     true,
		"fmt":                          true,
		"internal/godebug":             true,
		"vendor/golang.org/x/net/idna": true,
		"":                             false,
		"example.com/mod":              false,
		"example.com/mod/internal/x":   false,
		"gopkg.in/yaml.v2":             false,
	} {
		if got := isStdlibPackagePath(path); got != want {
			t.Errorf("isStdlibPackagePath(%q) = %v, want %v", path, got, want)
		}
	}
}

// TestStdlibMembership_AdmitsWhatTheLoaderResolved: neither the loader's module
// answer nor a path prefix can decide the standard library's membership — the
// toolchain places every std package in no module, and no std import path
// begins with "stdlib" — so the `std` pattern's own closure is the rule.
func TestStdlibMembership_AdmitsWhatTheLoaderResolved(t *testing.T) {
	t.Parallel()

	coord := mustCoord(t, "stdlib", "v1.26.5")
	m := moduleMembership{
		coord:      coord,
		stdlib:     true,
		pkgModule:  map[string]string{"net/http": "", "vendor/golang.org/x/net/idna": ""},
		pkgVersion: map[string]string{},
	}
	for _, pkg := range []string{"net/http", "vendor/golang.org/x/net/idna"} {
		if !m.contains(pkg) {
			t.Errorf("%s is not admitted to the standard library, so its nodes record as external", pkg)
		}
	}
	if m.contains("example.com/mod") {
		t.Error("a package the loader never resolved is admitted to the standard library")
	}
	if m.contains("") {
		t.Error("a package with no path is admitted")
	}
	if got := m.prefixAttributed(); got != nil {
		t.Errorf("prefixAttributed = %v, want none: nothing here was decided by a prefix", got)
	}
}

// TestModuleMembership_StdlibPackagesIsTheBuildsClosure: the field a joined
// read acts on is the standard-library closure the go command resolved, and it
// holds the vendored trees the toolchain links in as well.
func TestModuleMembership_StdlibPackagesIsTheBuildsClosure(t *testing.T) {
	t.Parallel()

	m := moduleMembership{
		coord: mustCoord(t, "example.com/mod", "v1.0.0"),
		pkgModule: map[string]string{
			"example.com/mod":              "example.com/mod",
			"net/http":                     "",
			"vendor/golang.org/x/net/idna": "",
			"gopkg.in/yaml.v2":             "gopkg.in/yaml.v2",
			"example.com/old":              "",
		},
		pkgVersion: map[string]string{},
	}
	got := m.stdlibPackages()
	want := []string{"net/http", "vendor/golang.org/x/net/idna"}
	if len(got) != len(want) {
		t.Fatalf("stdlibPackages() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("stdlibPackages() = %v, want %v", got, want)
		}
	}
}

// TestModuleMembership_DependencyPackagesIsEveryOtherModule: the dependency
// closure is every package the loader placed in a module other than the
// analysed one; the module's own, the standard library and the unplaced are not
// in it.
func TestModuleMembership_DependencyPackagesIsEveryOtherModule(t *testing.T) {
	t.Parallel()

	m := moduleMembership{
		coord: mustCoord(t, "example.com/mod", "v1.0.0"),
		pkgModule: map[string]string{
			"example.com/mod":            "example.com/mod",
			"example.com/mod/sub":        "example.com/mod",
			"example.com/mod/nested/pkg": "example.com/mod/nested",
			"net/http":                   "",
			"gopkg.in/yaml.v2":           "gopkg.in/yaml.v2",
			"example.com/old":            "",
		},
		pkgVersion: map[string]string{},
	}
	got := m.dependencyPackages()
	want := []string{"example.com/mod/nested/pkg", "gopkg.in/yaml.v2"}
	if !slices.Equal(got, want) {
		t.Fatalf("dependencyPackages() = %v, want %v", got, want)
	}
}
