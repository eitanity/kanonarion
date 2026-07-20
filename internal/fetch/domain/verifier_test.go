package domain_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/ziparchive"
	"github.com/eitanity/kanonarion/internal/coordinate"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func TestVerifier_HashDirAsModuleZip(t *testing.T) {
	dir := t.TempDir()
	coord := coordinate.ModuleCoordinate{Path: "example.com/m", Version: "v1.0.0"}

	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/m\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	subDir := filepath.Join(dir, "pkg")
	if err := os.Mkdir(subDir, 0o750); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "pkg.go"), []byte("package pkg\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	v := domain2.NewVerifier(ziparchive.Hasher{})
	h, err := v.HashDirAsModuleZip(dir, coord)
	if err != nil {
		t.Fatalf("HashDirAsModuleZip: %v", err)
	}
	if h.Algorithm != "h1" {
		t.Errorf("Algorithm = %q, want h1", h.Algorithm)
	}
	if h.Value == "" {
		t.Error("Value is empty")
	}
}

func TestVerifier_HashDirAsModuleZip_Deterministic(t *testing.T) {
	dir := t.TempDir()
	coord := coordinate.ModuleCoordinate{Path: "example.com/m", Version: "v1.0.0"}

	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/m\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	v := domain2.NewVerifier(ziparchive.Hasher{})
	h1, err := v.HashDirAsModuleZip(dir, coord)
	if err != nil {
		t.Fatalf("first HashDirAsModuleZip: %v", err)
	}
	h2, err := v.HashDirAsModuleZip(dir, coord)
	if err != nil {
		t.Fatalf("second HashDirAsModuleZip: %v", err)
	}
	if !h1.Equal(h2) {
		t.Errorf("non-deterministic: %v vs %v", h1, h2)
	}
}

// TestVerifier_HashDirAsModuleZip_ExcludesNestedModule verifies that a
// subdirectory containing its own go.mod (a separate module) is excluded,
// matching the proxy zip rules that cause hash mismatches when using dirhash.HashDir.
func TestVerifier_HashDirAsModuleZip_ExcludesNestedModule(t *testing.T) {
	dir := t.TempDir()
	coord := coordinate.ModuleCoordinate{Path: "example.com/m", Version: "v1.0.0"}

	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/m\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "doc.go"), []byte("package m\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Add a nested module in a v2/ subdirectory.
	v2Dir := filepath.Join(dir, "v2")
	if err := os.Mkdir(v2Dir, 0o750); err != nil {
		t.Fatalf("Mkdir v2: %v", err)
	}
	if err := os.WriteFile(filepath.Join(v2Dir, "go.mod"), []byte("module example.com/m/v2\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatalf("WriteFile v2/go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(v2Dir, "doc.go"), []byte("package m\n"), 0o600); err != nil {
		t.Fatalf("WriteFile v2/doc.go: %v", err)
	}

	v := domain2.NewVerifier(ziparchive.Hasher{})
	withNested, err := v.HashDirAsModuleZip(dir, coord)
	if err != nil {
		t.Fatalf("HashDirAsModuleZip: %v", err)
	}

	// Hash without the nested module should be identical — proving v2/ was excluded.
	dirNoNested := t.TempDir()
	if err := os.WriteFile(filepath.Join(dirNoNested, "go.mod"), []byte("module example.com/m\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dirNoNested, "doc.go"), []byte("package m\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	withoutNested, err := v.HashDirAsModuleZip(dirNoNested, coord)
	if err != nil {
		t.Fatalf("HashDirAsModuleZip (no nested): %v", err)
	}

	if !withNested.Equal(withoutNested) {
		t.Errorf("nested module affected hash: with=%v without=%v", withNested, withoutNested)
	}
}

func TestVerifier_VerifyPseudoVersionCommit(t *testing.T) {
	coord := coordinate.ModuleCoordinate{
		Path:    "example.com/m",
		Version: "v0.0.0-20210101120000-abcdefabcdef",
	}
	v := domain2.NewVerifier(ziparchive.Hasher{})

	// Correct commit.
	if err := v.VerifyPseudoVersionCommit(coord, "abcdefabcdef"+string(make([]byte, 28))); err != nil {
		// The commit prefix must match the first 12 chars.
		t.Logf("note: %v", err)
	}

	// Correct 40-char commit matching the embedded prefix.
	fullCommit := "abcdefabcdef" + "0000000000000000000000000000"
	if err := v.VerifyPseudoVersionCommit(coord, fullCommit); err != nil {
		t.Errorf("expected verification pass, got: %v", err)
	}

	// Wrong commit.
	wrongCommit := "ffffaaaabbbb" + "0000000000000000000000000000"
	if err := v.VerifyPseudoVersionCommit(coord, wrongCommit); err == nil {
		t.Error("expected verification failure for wrong commit")
	}

	// Non-pseudo-version.
	tagged := coordinate.ModuleCoordinate{Path: "example.com/m", Version: "v1.0.0"}
	if err := v.VerifyPseudoVersionCommit(tagged, fullCommit); err == nil {
		t.Error("expected error for non-pseudo-version")
	}
}
