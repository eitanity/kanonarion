package domain_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// failingHasher is the fault seam for the hash leg of HashDirAsModuleZip: the
// zip is built fine and hashing is what fails. It exists to prove the error is
// reported rather than swallowed into a zero hash, which would read downstream
// as "reproduced from git and matched nothing".
type failingHasher struct{ err error }

func (h failingHasher) HashModuleZip([]byte) (string, error) { return "", h.err }

// unparseableHasher returns a syntactically invalid h1 string, exercising the
// ParseModuleHash leg on the way out.
type unparseableHasher struct{}

func (unparseableHasher) HashModuleZip([]byte) (string, error) { return "not-a-hash", nil }

func TestVerifier_HashDirAsModuleZip_ZipCreationFailureIsReported(t *testing.T) {
	// An invalid module version makes modzip.CreateFromDir reject the request
	// before reading the tree, so the zip leg is what fails.
	coord := coordinate.ModuleCoordinate{Path: "example.com/m", Version: "not-a-semver"}
	v := domain2.NewVerifier(failingHasher{err: errors.New("never reached")})

	_, err := v.HashDirAsModuleZip(t.TempDir(), coord)
	if err == nil {
		t.Fatal("HashDirAsModuleZip succeeded for an invalid module version")
	}
	if !strings.Contains(err.Error(), "creating module zip from checkout") {
		t.Errorf("error = %v, want it to name the zip-creation step", err)
	}
}

func TestVerifier_HashDirAsModuleZip_HashFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	writeGoMod(t, dir, "module example.com/m\n\ngo 1.21\n")
	coord := coordinate.ModuleCoordinate{Path: "example.com/m", Version: "v1.0.0"}
	sentinel := errors.New("disk gave out mid-hash")
	v := domain2.NewVerifier(failingHasher{err: sentinel})

	got, err := v.HashDirAsModuleZip(dir, coord)
	if err == nil {
		t.Fatal("HashDirAsModuleZip succeeded despite a failing hasher")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("error = %v, want it to wrap the hasher's error", err)
	}
	if !got.IsZero() {
		t.Errorf("returned hash %v on failure, want the zero value", got)
	}
}

func TestVerifier_HashDirAsModuleZip_UnparseableHashIsReported(t *testing.T) {
	dir := t.TempDir()
	writeGoMod(t, dir, "module example.com/m\n\ngo 1.21\n")
	coord := coordinate.ModuleCoordinate{Path: "example.com/m", Version: "v1.0.0"}
	v := domain2.NewVerifier(unparseableHasher{})

	if _, err := v.HashDirAsModuleZip(dir, coord); err == nil {
		t.Fatal("HashDirAsModuleZip accepted a malformed hash string")
	}
}

// TestVerifier_VerifyPseudoVersionCommit_ShortCommitIsRejected covers the
// length guard. Without it, commitHash[:12] would panic on a truncated hash
// instead of reporting an unusable input.
func TestVerifier_VerifyPseudoVersionCommit_ShortCommitIsRejected(t *testing.T) {
	coord := coordinate.ModuleCoordinate{
		Path:    "example.com/m",
		Version: "v0.0.0-20210101120000-abcdefabcdef",
	}
	v := domain2.NewVerifier(unparseableHasher{})

	for _, short := range []string{"", "abc", "abcdefabcde"} {
		err := v.VerifyPseudoVersionCommit(coord, short)
		if err == nil {
			t.Errorf("VerifyPseudoVersionCommit(%q) = nil, want an error", short)
			continue
		}
		if !strings.Contains(err.Error(), "too short") {
			t.Errorf("VerifyPseudoVersionCommit(%q) = %v, want it to name the length problem", short, err)
		}
	}
}

// TestVCSHostAllowlist_IsDefault_ExplicitDefaultSet covers the positive end of
// the comparison: an allowlist configured with exactly the built-in hosts is
// reported as the default, so a policy that restates the defaults is not
// reported as an override.
func TestVCSHostAllowlist_IsDefault_ExplicitDefaultSet(t *testing.T) {
	defaults := domain2.VCSHostAllowlist{}.Hosts()
	if len(defaults) == 0 {
		t.Fatal("built-in default host set is empty")
	}

	explicit, err := domain2.NewVCSHostAllowlist(defaults)
	if err != nil {
		t.Fatalf("NewVCSHostAllowlist(%v): %v", defaults, err)
	}
	if !explicit.IsDefault() {
		t.Errorf("IsDefault() = false for an allowlist of exactly the default hosts %v", defaults)
	}

	// A same-sized set with one host swapped out must not read as the default.
	swapped := append([]string{"git.example.com"}, defaults[1:]...)
	other, err := domain2.NewVCSHostAllowlist(swapped)
	if err != nil {
		t.Fatalf("NewVCSHostAllowlist(%v): %v", swapped, err)
	}
	if other.IsDefault() {
		t.Errorf("IsDefault() = true for %v, which is not the default set", swapped)
	}
}

func writeGoMod(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
}
