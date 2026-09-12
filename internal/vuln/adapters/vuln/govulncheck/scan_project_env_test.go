package govulncheck

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// TestScanProject_ChildResolvesWithTheDevelopersOwnEnvironment asserts the
// project surface's posture on the environment the scan actually handed its
// child, not on what a builder returns in isolation.
//
// The four variables below decide which code the build contains, and this
// surface leaves every one of them as the developer has it, because the build it
// exists to measure is the one the go command produces in that developer's tree.
// A later change that pins any of them fails here rather than silently changing
// what an existing project scan resolves.
func TestScanProject_ChildResolvesWithTheDevelopersOwnEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the govulncheck stub is a POSIX shell script")
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/proj\n\ngo 1.21\n")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n\nfunc main() {}\n")
	work := filepath.Join(dir, "go.work")
	writeFile(t, work, "go 1.21\n\nuse .\n")

	// Values a developer might genuinely have. Each is one this surface must
	// carry through untouched.
	ambient := map[string]string{
		"GOTOOLCHAIN": "auto",
		"GOPROXY":     "https://proxy.example.invalid",
		"GOSUMDB":     "sum.example.invalid",
		"GOWORK":      work,
	}
	for k, v := range ambient {
		t.Setenv(k, v)
	}
	t.Setenv("GOFLAGS", "")

	child := runProjectScanForChildEnv(t, dir)

	for k, want := range ambient {
		if got := child[k]; got != want {
			t.Errorf("the scan child was given %s=%q, want the developer's own %q: this surface measures the build "+
				"the go command produces in their tree, and overriding this changes which code that build contains", k, got, want)
		}
	}
	if got := child["GOGC"]; got != "30" {
		t.Errorf("the scan child was given GOGC=%q, want 30", got)
	}
	if got, ok := child["GOMODCACHE"]; ok && got != os.Getenv("GOMODCACHE") {
		t.Errorf("the scan child was given GOMODCACHE=%q; this surface pins no module cache of its own", got)
	}
}

// TestScanProject_ChildKeepsTheCallersCgoSetting is the guard the consolidation
// onto scanEnv owes: project analysis loads packages with type information,
// which runs cgo for a cgo package, so this surface must go on compiling exactly
// what the developer's own build compiles.
func TestScanProject_ChildKeepsTheCallersCgoSetting(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the govulncheck stub is a POSIX shell script")
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/proj\n\ngo 1.21\n")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n\nfunc main() {}\n")
	t.Setenv("CGO_ENABLED", "1")

	if got := runProjectScanForChildEnv(t, dir)["CGO_ENABLED"]; got != "1" {
		t.Errorf("the project scan child was given CGO_ENABLED=%q, want the caller's own 1: turning cgo off here "+
			"would make a project with a cgo dependency fail to load, which is coverage lost rather than surface reduced", got)
	}
}

// runProjectScanForChildEnv runs one project-rooted scan whose govulncheck is a
// stub that records its own environment, and returns what the child was given.
func runProjectScanForChildEnv(t *testing.T, projectDir string) map[string]string {
	t.Helper()
	recorded := filepath.Join(t.TempDir(), "child.env")
	stubDir := t.TempDir()
	writeExecutable(t, filepath.Join(stubDir, "govulncheck"),
		"#!/bin/sh\nenv > "+recorded+"\nexit 0\n")
	t.Setenv("PATH", stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	var buf bytes.Buffer
	s := capturingScanner(t, &buf, 0)
	if _, err := s.ScanProject(t.Context(), ports.ProjectScanRequest{
		ProjectDir: projectDir,
		Snapshot:   fixtureSnapshot(t),
	}); err != nil {
		t.Fatalf("ScanProject: %v\nlogs:\n%s", err, buf.String())
	}

	raw, err := os.ReadFile(recorded) // #nosec G304 -- written by this test into its own t.TempDir()
	if err != nil {
		t.Fatalf("the scan never ran a child, so nothing about its environment was measured: %v", err)
	}
	env := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			env[k] = v
		}
	}
	return env
}

// TestProjectScanSurface_WorkspaceProjectAnalysesTheBuildTheDeveloperHas is the
// defect measured against the real toolchain rather than asserted about flags.
//
// A go.work replace is the cheapest way to make the two answers visibly
// different source trees, but the mechanism is every workspace's: a workspace
// decides which modules the build resolves, and disabling it resolves another
// build. Both loads succeed, so the old posture produced no error and no warning
// — it analysed one tree and reported about the other. The walk's own build-list
// resolver runs the go command with the ambient environment, so it saw the
// workspace's answer while the scan of the same directory saw the go.mod's.
func TestProjectScanSurface_WorkspaceProjectAnalysesTheBuildTheDeveloperHas(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("the go toolchain is not on PATH; this test measures real resolution")
	}
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOWORK", "")

	root := t.TempDir()
	for _, which := range []string{"A", "B"} {
		dep := filepath.Join(root, "dep"+which)
		writeFile(t, filepath.Join(dep, "go.mod"), "module example.com/dep\n\ngo 1.21\n")
		writeFile(t, filepath.Join(dep, "d.go"), "package dep\n\n// Which names the tree this build compiled.\nconst Which = \"dep"+which+"\"\n")
	}
	proj := filepath.Join(root, "proj")
	writeFile(t, filepath.Join(proj, "go.mod"),
		"module example.com/proj\n\ngo 1.21\n\nrequire example.com/dep v1.0.0\n\nreplace example.com/dep => ../depA\n")
	writeFile(t, filepath.Join(proj, "main.go"),
		"package main\n\nimport \"example.com/dep\"\n\nfunc main() { println(dep.Which) }\n")
	writeFile(t, filepath.Join(root, "go.work"), "go 1.21\n\nuse ./proj\n\nreplace example.com/dep => ./depB\n")

	developers := resolvedDepDir(t, proj, os.Environ())
	if want := filepath.Join(root, "depB"); developers != want {
		t.Fatalf("the developer's own build resolved %q, want %q — the fixture does not pose the question", developers, want)
	}

	_, env := projectScanSurface(proj, false)
	scanned := resolvedDepDir(t, proj, env)

	if scanned != developers {
		t.Errorf("the project scan analysed %q while the developer's build compiles %q; a verdict about a build "+
			"the project does not have is a verdict about nothing", scanned, developers)
	}
}

// resolvedDepDir reports the directory a load of proj under env resolves
// example.com/dep to, which is the question "which bytes did this analysis
// actually read" in its shortest measurable form.
func resolvedDepDir(t *testing.T, proj string, env []string) string {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", "-f", `{{if eq .ImportPath "example.com/dep"}}{{.Dir}}{{end}}`, "./...") // #nosec G204 -- fixed binary, literal arguments
	cmd.Dir = proj
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("loading the fixture: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	t.Fatal("the load named no directory for example.com/dep")
	return ""
}

// TestProjectScanSurface_VendorBranchesStillDisableTheWorkspace is the other half
// of the decision, and the reason it is not "the project surface never overrides
// anything". Both vendor-tree branches keep GOWORK=off, each for a measured
// reason: workspace mode refuses -mod=mod, and -mod=vendor under a workspace
// reads the workspace's vendor tree rather than this project's.
func TestProjectScanSurface_VendorBranchesStillDisableTheWorkspace(t *testing.T) {
	dir := writeVendoredFixture(t)

	for _, tc := range []struct {
		name         string
		wantVendored bool
	}{
		{"vendored", true},
		{"vendored surface declined", false},
	} {
		_, env := projectScanSurface(dir, tc.wantVendored)
		if got := envMap(env)["GOWORK"]; got != "off" {
			t.Errorf("%s: GOWORK = %q, want off", tc.name, got)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("creating %q: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %q: %v", path, err)
	}
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil { // #nosec G306 -- a binary this test execs must be executable
		t.Fatalf("writing %q: %v", path, err)
	}
}
