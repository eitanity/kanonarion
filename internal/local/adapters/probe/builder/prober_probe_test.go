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
