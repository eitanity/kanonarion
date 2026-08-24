package govulncheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/goenv"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// checkPosture asserts one producer's output against the posture of that name.
func checkPosture(t *testing.T, name string, base, got []string) {
	t.Helper()
	p, ok := goenv.For(name)
	if !ok {
		t.Fatalf("no posture named %q is stated", name)
	}
	for _, v := range goenv.Verify(p, base, got) {
		t.Error(v)
	}
}

// TestScanProducersMatchTheStatedPostures holds every environment this package
// hands a Go child against the one table that states them, builders and branches
// alike. Three closed defects were a variable missing from a branch beside a
// builder that had it, which a per-builder assertion cannot see.
func TestScanProducersMatchTheStatedPostures(t *testing.T) {
	base := []string{"PATH=/usr/bin"}
	checkPosture(t, "scan-vendored", base, scanEnv(base, goenv.ModCache, domain.AnalysisSurfaceVendored))
	checkPosture(t, "scan-fetched", base, scanEnv(base, "", domain.AnalysisSurfaceFetched))
	checkPosture(t, "scan-fetched-modcache", base, scanEnv(base, goenv.ModCache, domain.AnalysisSurfaceFetched))

	ambient := os.Environ()
	vendored := writeWorkspaceVendoredFixture(t, false)
	plain := t.TempDir()

	_, env := projectScanSurface(vendored, true)
	checkPosture(t, "scan-vendored", ambient, env)
	_, env = projectScanSurface(vendored, false)
	checkPosture(t, "project-fetched-over-vendor", ambient, env)
	_, env = projectScanSurface(plain, false)
	checkPosture(t, "scan-fetched", ambient, env)
}

// TestProjectScanSurface_VendorTreeUnderAWorkspaceScans measures the combination
// that reached a user: a vendor tree, a caller declining it, and a go.work in
// scope. The toolchain rejects -mod=mod in workspace mode outright, so the scan
// exited 1 before it read a line of source.
func TestProjectScanSurface_VendorTreeUnderAWorkspaceScans(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("the go toolchain is not on PATH; this test measures real resolution")
	}
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOWORK", "")
	dir := writeWorkspaceVendoredFixture(t, true)

	surface, env := projectScanSurface(dir, false)
	if surface != domain.AnalysisSurfaceFetched {
		t.Fatalf("surface = %q, want fetched", surface)
	}

	cmd := exec.Command("go", "list", "./...")
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the fetched surface of a vendored project under a workspace failed to load: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "example.com/wsproj") {
		t.Errorf("go list did not report the project's own package:\n%s", out)
	}
}

// writeWorkspaceVendoredFixture builds a self-contained project carrying a
// vendor/modules.txt, and a go.work at its root when workspace is true.
func writeWorkspaceVendoredFixture(t *testing.T, workspace bool) string {
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
	write("go.mod", "module example.com/wsproj\n\ngo 1.21\n")
	write("main.go", "package main\n\nfunc main() {}\n")
	write("vendor/modules.txt", "")
	if workspace {
		write("go.work", "go 1.21\n\nuse .\n")
	}
	return dir
}
