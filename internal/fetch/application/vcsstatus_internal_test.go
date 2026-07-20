package application

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/ziparchive"
	"github.com/eitanity/kanonarion/internal/coordinate"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// toolMissingVCS reports the VCS tool as absent on every operation, wrapping the
// ports sentinel the way the gitexec adapter does.
type toolMissingVCS struct{}

func (toolMissingVCS) ResolveTag(context.Context, string, string) (string, error) {
	return "", fmt.Errorf("resolve: %w", ports.ErrVCSToolMissing)
}

func (toolMissingVCS) CheckoutToDir(context.Context, string, string, string) error {
	return fmt.Errorf("checkout: %w", ports.ErrVCSToolMissing)
}

// genericFailVCS fails without signalling tool-absence — the "ran but could not
// confirm" case that must stay UnverifiedNoVCS, not UnverifiedVCSToolMissing.
type genericFailVCS struct{}

func (genericFailVCS) ResolveTag(context.Context, string, string) (string, error) {
	return "", fmt.Errorf("network unreachable")
}

func (genericFailVCS) CheckoutToDir(context.Context, string, string, string) error {
	return fmt.Errorf("commit not found")
}

// A missing VCS tool on the tag-resolution path is classified as the distinct
// "tool missing" status, not the generic "checkout could not run" status.
func TestResolveGitRef_ToolMissing(t *testing.T) {
	uc := &FetchModuleUseCase{vcs: toolMissingVCS{}}
	coord := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	_, status, _ := uc.resolveGitRef(context.Background(), slog.Default(), coord, ports.ModuleInfo{})
	if status != domain2.UnverifiedVCSToolMissing {
		t.Errorf("status = %q, want UnverifiedVCSToolMissing", status)
	}
}

func TestResolveGitRef_GenericFailureStaysNoVCS(t *testing.T) {
	uc := &FetchModuleUseCase{vcs: genericFailVCS{}}
	coord := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	_, status, _ := uc.resolveGitRef(context.Background(), slog.Default(), coord, ports.ModuleInfo{})
	if status != domain2.UnverifiedNoVCS {
		t.Errorf("status = %q, want UnverifiedNoVCS", status)
	}
}

// A proxy Origin pointing at a dangerous transport (ext::) must never be
// trusted as Verified or reach the git subprocess. Resolution falls back to the
// inferred-URL path, where the tool-less fake reports the absence honestly.
func TestResolveGitRef_RejectsMaliciousOrigin(t *testing.T) {
	uc := &FetchModuleUseCase{vcs: toolMissingVCS{}}
	coord := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	info := ports.ModuleInfo{Origin: &ports.ModuleOrigin{
		URL:  `ext::sh -c "touch /tmp/pwned"`,
		Hash: "--upload-pack=touch",
	}}

	gitRef, status, detail := uc.resolveGitRef(context.Background(), slog.Default(), coord, info)
	if status == domain2.Verified {
		t.Fatal("malicious Origin must not be trusted as Verified")
	}
	if strings.HasPrefix(gitRef.URL, "ext::") {
		t.Errorf("malicious Origin URL leaked into GitReference: %q", gitRef.URL)
	}
	// The detail must name the refused Origin as the cause, not a misleading
	// "could not infer VCS URL" — the status degraded because we refused
	// untrusted metadata.
	if !strings.Contains(detail, "refused") {
		t.Errorf("detail %q does not explain the Origin was refused", detail)
	}
}

// A well-formed proxy Origin on an allowlisted https host is still trusted.
func TestResolveGitRef_AcceptsValidOrigin(t *testing.T) {
	uc := &FetchModuleUseCase{vcs: toolMissingVCS{}}
	coord := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	info := ports.ModuleInfo{Origin: &ports.ModuleOrigin{
		URL:  "https://github.com/foo/bar",
		Ref:  "refs/tags/v1.0.0",
		Hash: strings.Repeat("a", 40),
	}}

	gitRef, status, _ := uc.resolveGitRef(context.Background(), slog.Default(), coord, info)
	if status != domain2.Verified {
		t.Fatalf("valid Origin should resolve Verified, got %q", status)
	}
	if gitRef.URL != "https://github.com/foo/bar" {
		t.Errorf("GitReference URL = %q, want the Origin URL", gitRef.URL)
	}
}

// A missing VCS tool on the checkout path is classified as the distinct "tool
// missing" status, and the detail carries the actionable message.
func TestCrossVerify_ToolMissing(t *testing.T) {
	uc := &FetchModuleUseCase{vcs: toolMissingVCS{}}
	coord := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	status, detail := uc.crossVerify(context.Background(), slog.Default(),
		coord, "https://github.com/foo/bar", strings.Repeat("a", 40), domain2.ModuleHash{})
	if status != domain2.UnverifiedVCSToolMissing {
		t.Errorf("status = %q, want UnverifiedVCSToolMissing", status)
	}
	if !strings.Contains(detail, ports.ErrVCSToolMissing.Error()) {
		t.Errorf("detail %q does not carry the tool-missing classification", detail)
	}
}

func TestCrossVerify_GenericFailureStaysNoVCS(t *testing.T) {
	uc := &FetchModuleUseCase{vcs: genericFailVCS{}}
	coord := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	status, _ := uc.crossVerify(context.Background(), slog.Default(),
		coord, "https://github.com/foo/bar", strings.Repeat("a", 40), domain2.ModuleHash{})
	if status != domain2.UnverifiedNoVCS {
		t.Errorf("status = %q, want UnverifiedNoVCS", status)
	}
}

// subdirLayoutVCS simulates a repo where the target module lives in a named
// subdirectory of the repo root (Go major-version-subdirectory convention).
// CheckoutToDir writes:
//   - root go.mod (rootModule) and root LICENSE
//   - subdir/go.mod (subModule) + stub Go file (no LICENSE in subdir)
//
// This mirrors real-world repos like gitlab.com/cznic/gc where the root has
// LICENSE and the v3/ subdir does not.
type subdirLayoutVCS struct {
	rootModule string
	subModule  string
	subdir     string
}

func (v subdirLayoutVCS) ResolveTag(_ context.Context, _, _ string) (string, error) {
	return strings.Repeat("a", 40), nil
}

func (v subdirLayoutVCS) CheckoutToDir(_ context.Context, _, _, dir string) error {
	rootGoMod := "module " + v.rootModule + "\ngo 1.20\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(rootGoMod), 0o600); err != nil {
		return fmt.Errorf("writing root go.mod: %w", err)
	}
	// Root-level LICENSE (no LICENSE in subdir — proxy copies this into the zip).
	if err := os.WriteFile(filepath.Join(dir, "LICENSE"), []byte("MIT License\n"), 0o600); err != nil {
		return fmt.Errorf("writing root LICENSE: %w", err)
	}
	sub := filepath.Join(dir, v.subdir)
	if err := os.MkdirAll(sub, 0o750); err != nil {
		return fmt.Errorf("creating subdir: %w", err)
	}
	subGoMod := "module " + v.subModule + "\ngo 1.20\n"
	if err := os.WriteFile(filepath.Join(sub, "go.mod"), []byte(subGoMod), 0o600); err != nil {
		return fmt.Errorf("writing sub go.mod: %w", err)
	}
	if err := os.WriteFile(filepath.Join(sub, "foo.go"), []byte("package foo\n"), 0o600); err != nil {
		return fmt.Errorf("writing stub go file: %w", err)
	}
	return nil
}

// TestCrossVerify_MajorVersionSubdir_Verified exercises the major-version-
// subdirectory case: the module lives in v3/ of the checked-out repo, not at
// the root. Without the subdir-detection fix, crossVerify would hash the root
// (which declares a different module path) and return UnverifiedHashMismatch.
// The fixture also includes a root LICENSE file (but no LICENSE in the subdir),
// mirroring the modernc.org/gc/v3 layout where the proxy copies the root
// LICENSE into the module zip via CreateFromVCS behaviour.
func TestCrossVerify_MajorVersionSubdir_Verified(t *testing.T) {
	coord := coordinate.ModuleCoordinate{Path: "example.com/foo/v3", Version: "v3.1.0"}

	// Build a fixture directory that matches what subdirLayoutVCS.CheckoutToDir
	// will write, then compute the expected hash from the subdir WITH the copied
	// root LICENSE — matching what crossVerify now does after the fix.
	fixtureDir := t.TempDir()
	vcs := subdirLayoutVCS{rootModule: "example.com/foo", subModule: coord.Path, subdir: "v3"}
	if err := vcs.CheckoutToDir(context.Background(), "", "", fixtureDir); err != nil {
		t.Fatalf("setting up fixture: %v", err)
	}

	// Replicate copyRootLicenseIfMissing so the expected hash matches.
	v3Dir := filepath.Join(fixtureDir, "v3")
	if err := os.WriteFile(filepath.Join(v3Dir, "LICENSE"),
		[]byte("MIT License\n"), 0o600); err != nil {
		t.Fatalf("copying root LICENSE into v3 for expected-hash computation: %v", err)
	}

	verifier := domain2.NewVerifier(ziparchive.Hasher{})
	expectedHash, err := verifier.HashDirAsModuleZip(v3Dir, coord)
	if err != nil {
		t.Fatalf("computing expected hash from subdir: %v", err)
	}

	uc := &FetchModuleUseCase{vcs: vcs, verifier: verifier}
	status, detail := uc.crossVerify(context.Background(), slog.Default(),
		coord, "https://example.com/foo", strings.Repeat("a", 40), expectedHash)

	if status != domain2.Verified {
		t.Errorf("status = %q (detail: %q), want Verified", status, detail)
	}
}

// TestCrossVerify_MajorVersionSubdir_RootHashMismatch confirms that the root
// directory hash differs from the expected (proxy) hash, proving the regression
// test would have caught the bug before the fix.
func TestCrossVerify_MajorVersionSubdir_RootHashMismatch(t *testing.T) {
	coord := coordinate.ModuleCoordinate{Path: "example.com/foo/v3", Version: "v3.1.0"}

	fixtureDir := t.TempDir()
	vcs := subdirLayoutVCS{rootModule: "example.com/foo", subModule: coord.Path, subdir: "v3"}
	if err := vcs.CheckoutToDir(context.Background(), "", "", fixtureDir); err != nil {
		t.Fatalf("setting up fixture: %v", err)
	}

	verifier := domain2.NewVerifier(ziparchive.Hasher{})

	// The proxy-equivalent hash: subdir + root LICENSE copied in.
	v3Dir := filepath.Join(fixtureDir, "v3")
	if err := os.WriteFile(filepath.Join(v3Dir, "LICENSE"),
		[]byte("MIT License\n"), 0o600); err != nil {
		t.Fatalf("copying root LICENSE for proxy-equivalent hash: %v", err)
	}
	proxyEquivHash, err := verifier.HashDirAsModuleZip(v3Dir, coord)
	if err != nil {
		t.Fatalf("computing proxy-equivalent hash: %v", err)
	}

	// The root hash is what crossVerify produced before the fix.
	rootHash, err := verifier.HashDirAsModuleZip(fixtureDir, coord)
	if err != nil {
		t.Fatalf("computing root hash: %v", err)
	}

	if proxyEquivHash.Equal(rootHash) {
		t.Error("root hash should differ from the proxy-equivalent subdir hash; " +
			"the pre-fix code path would not have produced a detectable mismatch")
	}
}
