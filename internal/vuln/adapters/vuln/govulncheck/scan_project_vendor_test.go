package govulncheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestScanEnv_VendoredSurfaceReadsTheVendoredTree guards the one flag the whole
// vendored surface turns on. -mod=mod is what tells the toolchain to ignore
// vendor/, so a vendored analysis must not carry it, and must carry -mod=vendor
// instead. GOPROXY=off is the guarantee that a vendored analysis fetches
// nothing: a vendored build that reached the network would no longer be the
// build being analysed.
func TestScanEnv_VendoredSurfaceReadsTheVendoredTree(t *testing.T) {
	got := envMap(scanEnv([]string{"PATH=/usr/bin"}, "/tmp/kanonarion-modcache", domain.AnalysisSurfaceVendored))

	if got["GOFLAGS"] != "-mod=vendor" {
		t.Errorf("GOFLAGS = %q, want -mod=vendor", got["GOFLAGS"])
	}
	if got["GOPROXY"] != "off" {
		t.Errorf("GOPROXY = %q, want off: a vendored analysis must fetch nothing", got["GOPROXY"])
	}
	// A module cache is meaningless under vendor mode — nothing resolves through
	// it — and naming one would suggest the analysis might read from it.
	if v, ok := got["GOMODCACHE"]; ok {
		t.Errorf("vendored scanEnv set GOMODCACHE=%q; vendor mode resolves nothing through a module cache", v)
	}
}

// TestScanEnv_VendoredOverridesInheritedModMod guards the failure this whole
// change exists to fix, at the level of the environment: an ambient
// GOFLAGS=-mod=mod must not survive into a vendored analysis, because it would
// silently redirect the scan away from the tree the project compiles.
func TestScanEnv_VendoredOverridesInheritedModMod(t *testing.T) {
	got := envMap(scanEnv([]string{"GOFLAGS=-mod=mod"}, "", domain.AnalysisSurfaceVendored))

	if got["GOFLAGS"] != "-mod=vendor" {
		t.Errorf("GOFLAGS = %q, want -mod=vendor to override the inherited -mod=mod", got["GOFLAGS"])
	}
}

// TestProjectScanSurface_DetectsAndOverrides pins the three ways a project scan
// can be routed: an unvendored project has only the fetched surface; a vendored
// one is analysed from vendor/ by default; and a caller declining the vendored
// surface for a vendored project gets -mod=mod FORCED rather than merely left
// alone — the toolchain defaults to -mod=vendor whenever vendor/modules.txt is
// present, so an unforced run would be the vendored analysis wearing a fetched
// label.
func TestProjectScanSurface_DetectsAndOverrides(t *testing.T) {
	unvendored := t.TempDir()
	vendored := writeVendoredFixture(t)

	surface, env := projectScanSurface(unvendored, true)
	if surface != domain.AnalysisSurfaceFetched {
		t.Errorf("unvendored project: surface = %q, want fetched — a tree that does not exist cannot be the surface", surface)
	}
	if got := envMap(env)["GOFLAGS"]; strings.Contains(got, "-mod=") {
		t.Errorf("unvendored project: GOFLAGS = %q, want no -mod override", got)
	}

	surface, env = projectScanSurface(vendored, true)
	if surface != domain.AnalysisSurfaceVendored {
		t.Errorf("vendored project: surface = %q, want vendored", surface)
	}
	if got := envMap(env)["GOFLAGS"]; got != "-mod=vendor" {
		t.Errorf("vendored project: GOFLAGS = %q, want -mod=vendor", got)
	}

	surface, env = projectScanSurface(vendored, false)
	if surface != domain.AnalysisSurfaceFetched {
		t.Errorf("vendored project with the vendored surface declined: surface = %q, want fetched", surface)
	}
	if got := envMap(env)["GOFLAGS"]; got != "-mod=mod" {
		t.Errorf("declined vendored surface: GOFLAGS = %q, want -mod=mod forced; "+
			"left alone the toolchain would default to -mod=vendor and the comparison run would not be a comparison", got)
	}
}

// TestProjectScanSurface_VendoredTreeAnalysesAModuleWithNoGoMod is the mechanism
// this change exists for, measured against the real Go toolchain rather than
// asserted about flags.
//
// The fixture's one dependency ships no go.mod, which is true of every
// dependency published before Go modules — and is exactly the population that
// filled the no-go-mod coverage bucket, because resolving such a module on its
// own requires synthesising a go.mod for it and that synthesis can fail. Under
// the vendored surface the question never arises: the whole build loads from
// vendor/ in one pass, and a vendored package needs no module file of its own.
//
// The fetched leg is the control. Under -mod=mod the toolchain ignores vendor/
// entirely and goes looking for the module, which offline it cannot find. Both
// legs run with the network pinned off, so the difference measured is the
// resolution mode and nothing else.
func TestProjectScanSurface_VendoredTreeAnalysesAModuleWithNoGoMod(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("the go toolchain is not on PATH; this test measures real resolution")
	}
	// Pin the ambient environment so the only difference between the two legs is
	// the mode flag projectScanSurface chooses.
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOWORK", "off")
	t.Setenv("GOPROXY", "off")

	dir := writeVendoredFixture(t)

	_, vendoredEnv := projectScanSurface(dir, true)
	if out, err := runGoList(t, dir, vendoredEnv); err != nil {
		t.Fatalf("the vendored surface failed to load a build whose dependency ships no go.mod: %v\n%s", err, out)
	} else if !strings.Contains(out, "example.com/nogomod") {
		t.Fatalf("the vendored surface loaded the build but not the vendored dependency; go list said:\n%s", out)
	}

	_, fetchedEnv := projectScanSurface(dir, false)
	out, err := runGoList(t, dir, fetchedEnv)
	if err == nil {
		t.Fatalf("the fetched surface resolved example.com/nogomod offline; the control leg proves nothing:\n%s", out)
	}
	if !strings.Contains(out, "example.com/nogomod") {
		t.Errorf("the fetched surface failed for some reason other than the unresolvable dependency:\n%s", out)
	}
}

// runGoList loads the fixture's package graph the way a source-mode analysis
// does — govulncheck's loader is the same toolchain resolution — and returns the
// combined output so a failure names its own cause.
func runGoList(t *testing.T, dir string, env []string) (string, error) {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", "./...")
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// writeVendoredFixture builds a minimal vendored project whose single
// dependency ships no go.mod of its own, and returns the project directory.
func writeVendoredFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	write := func(rel, content string) {
		t.Helper()
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("creating %q: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("writing %q: %v", path, err)
		}
	}

	write("go.mod", "module example.com/proj\n\ngo 1.21\n\nrequire example.com/nogomod v1.0.0\n")
	write("main.go", "package main\n\nimport \"example.com/nogomod\"\n\nfunc main() { _ = nogomod.Answer }\n")
	// No go.mod under the vendored module: `go mod vendor` strips it, and a
	// pre-modules dependency never published one in the first place.
	write("vendor/example.com/nogomod/nogomod.go", "package nogomod\n\n// Answer is the vendored dependency's only symbol.\nconst Answer = 42\n")
	write("vendor/modules.txt", "# example.com/nogomod v1.0.0\n## explicit; go 1.21\nexample.com/nogomod\n")

	return dir
}
