package builder

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests exercise the toolchain-backed paths (New/goBin, findMainPackages,
// Probe for binary and library targets, readSymbolTable). They build tiny
// synthetic modules with the real `go` toolchain — no external dependencies,
// so they run offline.

func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", full, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
	return root
}

const goMod = "module example.com/probe\n\ngo 1.22\n"

func TestNew_GoBinDefaultAndOverride(t *testing.T) {
	if got := New("").goBin(); got != "go" {
		t.Errorf("empty goBinary: goBin() = %q, want %q", got, "go")
	}
	if got := New("/opt/go/bin/go").goBin(); got != "/opt/go/bin/go" {
		t.Errorf("override: goBin() = %q, want %q", got, "/opt/go/bin/go")
	}
}

func TestFindMainPackages_BinaryModule(t *testing.T) {
	root := writeModule(t, map[string]string{
		"go.mod":  goMod,
		"main.go": "package main\n\nfunc main() {}\n",
	})
	mains, err := findMainPackages(context.Background(), root, "go")
	if err != nil {
		t.Fatalf("findMainPackages: %v", err)
	}
	if len(mains) != 1 || mains[0] != "example.com/probe" {
		t.Errorf("mains = %v, want [example.com/probe]", mains)
	}
}

func TestFindMainPackages_LibraryModuleHasNoMain(t *testing.T) {
	root := writeModule(t, map[string]string{
		"go.mod":     goMod,
		"lib/lib.go": "package lib\n\nfunc Exported() {}\n",
	})
	mains, err := findMainPackages(context.Background(), root, "go")
	if err != nil {
		t.Fatalf("findMainPackages: %v", err)
	}
	if len(mains) != 0 {
		t.Errorf("mains = %v, want empty for library-only module", mains)
	}
}

func TestFindMainPackages_NotAGoModule(t *testing.T) {
	root := t.TempDir() // no go.mod
	if _, err := findMainPackages(context.Background(), root, "go"); err == nil {
		t.Fatal("expected error for non-module directory")
	}
}

func TestProbe_BinaryTarget(t *testing.T) {
	root := writeModule(t, map[string]string{
		"go.mod": goMod,
		"main.go": "package main\n\n" +
			"func ProbeMarkerFunc() string { return \"x\" }\n\n" +
			"func main() { _ = ProbeMarkerFunc() }\n",
	})

	res, err := New("").Probe(context.Background(), root)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.Kind != "binary" {
		t.Errorf("Kind = %q, want %q", res.Kind, "binary")
	}
	if len(res.BinarySymbols) == 0 {
		t.Fatal("expected non-empty symbol table")
	}
	if !hasSymbolContaining(res.BinarySymbols, "ProbeMarkerFunc") {
		t.Error("expected ProbeMarkerFunc in symbol table")
	}
	// Binary target must not create the library harness dir.
	if _, err := os.Stat(filepath.Join(root, probeHarnessDir)); !os.IsNotExist(err) {
		t.Errorf("harness dir should not exist for binary target (stat err=%v)", err)
	}
}

func TestProbe_LibraryTarget(t *testing.T) {
	root := writeModule(t, map[string]string{
		"go.mod": goMod,
		"lib/lib.go": "package lib\n\n" +
			"type Widget struct{}\n\n" +
			"func ProbeLibFunc() int { return 1 }\n\n" +
			"func (w *Widget) ProbeLibMethod() {}\n",
	})

	res, err := New("").Probe(context.Background(), root)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.Kind != "library" {
		t.Errorf("Kind = %q, want %q", res.Kind, "library")
	}
	if !hasSymbolContaining(res.BinarySymbols, "ProbeLibFunc") {
		t.Error("expected ProbeLibFunc retained via synthetic harness")
	}
	if !hasSymbolContaining(res.BinarySymbols, "ProbeLibMethod") {
		t.Error("expected ProbeLibMethod retained via synthetic harness")
	}
	// Library harness dir must be cleaned up after Probe returns.
	if _, err := os.Stat(filepath.Join(root, probeHarnessDir)); !os.IsNotExist(err) {
		t.Errorf("harness dir should be cleaned up (stat err=%v)", err)
	}
}

func TestReadSymbolTable_InvalidBinary(t *testing.T) {
	root := t.TempDir()
	bogus := filepath.Join(root, "not-a-binary")
	if err := os.WriteFile(bogus, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readSymbolTable(context.Background(), root, bogus, "go")
	if err == nil {
		t.Fatal("expected error from go tool nm on non-binary input")
	}
	if !strings.Contains(err.Error(), "go tool nm") {
		t.Errorf("expected wrapped 'go tool nm' error, got: %v", err)
	}
}

func hasSymbolContaining(symbols map[string]struct{}, substr string) bool {
	for s := range symbols {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// twoMainModule is a workspace with two main packages. markerAlpha is linked
// only into cmd/alpha and markerBeta only into cmd/beta, so a probe that builds
// one main alone cannot see the other's marker.
func twoMainModule(t *testing.T, betaBody string) string {
	t.Helper()
	return writeModule(t, map[string]string{
		"go.mod": goMod,
		"lib/lib.go": "package lib\n\n" +
			"func ProbeMarkerAlpha() string { return \"a\" }\n\n" +
			"func ProbeMarkerBeta() string { return \"b\" }\n",
		"cmd/alpha/main.go": "package main\n\nimport \"example.com/probe/lib\"\n\n" +
			"func main() { _ = lib.ProbeMarkerAlpha() }\n",
		"cmd/beta/main.go": betaBody,
	})
}

const betaMainGood = "package main\n\nimport \"example.com/probe/lib\"\n\n" +
	"func main() { _ = lib.ProbeMarkerBeta() }\n"

// The probe builds every main, not the first one alone: a symbol linked only
// into the second binary must appear in the union, attributed to that binary.
func TestProbe_TwoMains_SymbolInSecondIsFound(t *testing.T) {
	root := twoMainModule(t, betaMainGood)

	res, err := New("").Probe(context.Background(), root)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.Kind != "binary" {
		t.Errorf("Kind = %q, want %q", res.Kind, "binary")
	}
	if !hasSymbolContaining(res.BinarySymbols, "ProbeMarkerBeta") {
		t.Error("ProbeMarkerBeta missing from the union; only the first main was built")
	}
	if !hasSymbolContaining(res.BinarySymbols, "ProbeMarkerAlpha") {
		t.Error("ProbeMarkerAlpha missing from the union")
	}
	if len(res.Binaries) != 2 {
		t.Fatalf("Binaries = %d, want 2", len(res.Binaries))
	}
	if res.Binaries[0].ImportPath != "example.com/probe/cmd/alpha" ||
		res.Binaries[1].ImportPath != "example.com/probe/cmd/beta" {
		t.Fatalf("Binaries = %q/%q, want alpha then beta",
			res.Binaries[0].ImportPath, res.Binaries[1].ImportPath)
	}
	for _, b := range res.Binaries {
		if b.BuildError != "" {
			t.Errorf("binary %q: BuildError = %q, want empty", b.ImportPath, b.BuildError)
		}
	}
	// Attribution: each marker belongs to exactly its own binary.
	if hasSymbolContaining(res.Binaries[0].Symbols, "ProbeMarkerBeta") {
		t.Error("alpha's symbol table carries ProbeMarkerBeta; attribution is not per binary")
	}
	if !hasSymbolContaining(res.Binaries[1].Symbols, "ProbeMarkerBeta") {
		t.Error("beta's symbol table does not carry ProbeMarkerBeta")
	}
}

// A main that fails to build does not fail the probe. The binaries that did
// build still answer, and the failure is carried against its import path.
func TestProbe_TwoMains_UnbuildableSecondIsNotFatal(t *testing.T) {
	root := twoMainModule(t,
		"package main\n\nfunc main() { thisIdentifierDoesNotExist() }\n")

	res, err := New("").Probe(context.Background(), root)
	if err != nil {
		t.Fatalf("Probe: %v (an unbuildable main must not fail the probe)", err)
	}
	if !hasSymbolContaining(res.BinarySymbols, "ProbeMarkerAlpha") {
		t.Error("ProbeMarkerAlpha missing; the buildable main did not answer")
	}
	if len(res.Binaries) != 2 {
		t.Fatalf("Binaries = %d, want 2 (both mains named, built or not)", len(res.Binaries))
	}
	if res.Binaries[0].BuildError != "" {
		t.Errorf("alpha: BuildError = %q, want empty", res.Binaries[0].BuildError)
	}
	beta := res.Binaries[1]
	if beta.ImportPath != "example.com/probe/cmd/beta" {
		t.Fatalf("second binary = %q, want example.com/probe/cmd/beta", beta.ImportPath)
	}
	if beta.BuildError == "" {
		t.Fatal("beta: BuildError is empty; the unprobed binary would be silent")
	}
	if !strings.Contains(beta.BuildError, "thisIdentifierDoesNotExist") {
		t.Errorf("beta: BuildError = %q, want the compiler's own message", beta.BuildError)
	}
	if len(beta.Symbols) != 0 {
		t.Errorf("beta: Symbols = %d, want none for a binary that did not build", len(beta.Symbols))
	}
}

// Every main failing is a different case: there is no symbol table at all, and
// reporting "absent" off a build that never happened is the false negative this
// probe exists to avoid.
func TestProbe_AllMainsUnbuildable_IsAnError(t *testing.T) {
	root := writeModule(t, map[string]string{
		"go.mod":            goMod,
		"cmd/alpha/main.go": "package main\n\nfunc main() { nopeAlpha() }\n",
	})

	if _, err := New("").Probe(context.Background(), root); err == nil {
		t.Fatal("expected an error when no main package could be probed")
	}
}
