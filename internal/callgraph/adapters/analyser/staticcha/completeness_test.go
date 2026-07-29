package staticcha_test

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// TestAnalyseDir_TypeOnlyWhenNoBodiesBuild is the producer test for
// CompletenessTypeOnly.
//
// The state it names is reachable and is not contrived: a package whose import
// cannot be resolved still type-checks far enough for go/packages to return a
// *types.Package, so it is REGISTERED with the SSA program — but the SSA builder
// then panics with "unsatisfied import" because the dependency's package was
// never created. Types are known; no body was built.
//
// Before this, the analyser collapsed that into BUILT_WITH_BODIES, which claimed
// a fidelity the run never reached, and a "no callers" answer over such a module
// would have read as a confident negative.
func TestAnalyseDir_TypeOnlyWhenNoBodiesBuild(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/typeonly\n\ngo 1.24\n")
	writeFile(t, filepath.Join(dir, "pkg", "a.go"), `package pkg

import "example.com/absent/missing"

// Use keeps the import live so the package cannot type-check without it.
func Use() string { return missing.Name() }
`)

	rec := analyseDir(t, dir, "example.com/typeonly")

	if rec.Completeness != domain.CompletenessTypeOnly {
		t.Fatalf("completeness = %q, want %q (failure detail: %s)",
			rec.Completeness, domain.CompletenessTypeOnly, rec.FailureDetail)
	}
	// The scope of the incompleteness is still carried per package, and the status
	// still says the graph is incomplete — the level is a claim about fidelity, not
	// a replacement for either.
	if rec.OverallStatus != domain.CallGraphStatusPartial {
		t.Errorf("overall status = %s, want Partial", rec.OverallStatus)
	}
	if len(rec.FailedPackages) == 0 {
		t.Error("a graph with no built bodies named no failed packages")
	}
}

// TestAnalyseDir_BuiltWithBodiesWhenAPackageBuilds is the control. Without it,
// the test above would pass just as well if the analyser reported TYPE_ONLY for
// everything.
func TestAnalyseDir_BuiltWithBodiesWhenAPackageBuilds(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/ok\n\ngo 1.24\n")
	writeFile(t, filepath.Join(dir, "pkg", "a.go"), `package pkg

// Use is an ordinary function with a body the builder can construct.
func Use() string { return "ok" }
`)

	rec := analyseDir(t, dir, "example.com/ok")

	if rec.Completeness != domain.CompletenessBuiltWithBodies {
		t.Fatalf("completeness = %q, want %q (failure detail: %s)",
			rec.Completeness, domain.CompletenessBuiltWithBodies, rec.FailureDetail)
	}
}

// TestAnalyseDir_NamesItsSourceAndIdentifiesTheTree pins both halves of what a
// worktree record must carry: which KIND of thing was analysed, and WHICH tree.
//
// The second is what a coordinate cannot supply — every checkout of a module path
// shares one — so without it two trees are one record.
func TestAnalyseDir_NamesItsSourceAndIdentifiesTheTree(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/tree\n\ngo 1.24\n")
	writeFile(t, filepath.Join(dir, "pkg", "a.go"), "package pkg\n\n// Use does nothing.\nfunc Use() {}\n")

	first := analyseDir(t, dir, "example.com/tree")
	if first.AnalysisSource != domain.AnalysisSourceWorktree {
		t.Fatalf("analysis source = %q, want %q", first.AnalysisSource, domain.AnalysisSourceWorktree)
	}
	if first.WorktreeDigest == "" {
		t.Fatal("a worktree analysis recorded no tree digest, so two checkouts would be one record")
	}
	if first.ArtefactIdentity != "" {
		t.Errorf("a worktree analysis named an artefact %q; nothing was fetched", first.ArtefactIdentity)
	}

	// Re-analysing the unchanged tree must produce the SAME digest, or every run
	// would look like a different tree and the ledger would never compose.
	again := analyseDir(t, dir, "example.com/tree")
	if again.WorktreeDigest != first.WorktreeDigest {
		t.Fatalf("the same tree hashed twice: %s vs %s", first.WorktreeDigest, again.WorktreeDigest)
	}

	// Changing a Go file must move it, which is the whole point.
	writeFile(t, filepath.Join(dir, "pkg", "a.go"), "package pkg\n\n// Use does nothing at all.\nfunc Use() {}\n")
	changed := analyseDir(t, dir, "example.com/tree")
	if changed.WorktreeDigest == first.WorktreeDigest {
		t.Fatal("editing a source file did not change the tree digest")
	}
}

// TestAnalyse_NamesTheModuleZipSource: a zip analysis must say so on every return
// path, including the failures. A record that says nothing about what it read is
// indistinguishable from one written before the field existed.
func TestAnalyse_NamesTheModuleZipSource(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("example.com/absent", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	a := staticcha.New("0.3.0", "", testLogger())
	// A path that is not a zip: the extraction fails, and the failure record is
	// still an answer about a module zip.
	rec, err := a.Analyse(context.Background(), filepath.Join(t.TempDir(), "not-a.zip"), coord)
	if err != nil {
		t.Fatalf("Analyse returned an infrastructure error: %v", err)
	}
	if rec.AnalysisSource != domain.AnalysisSourceModuleZip {
		t.Fatalf("a failed zip analysis recorded source %q, want %q",
			rec.AnalysisSource, domain.AnalysisSourceModuleZip)
	}
	if rec.Completeness != domain.CompletenessFailed {
		t.Errorf("completeness = %q, want %q", rec.Completeness, domain.CompletenessFailed)
	}
}

func analyseDir(t *testing.T, dir, modulePath string) domain.CallGraphRecord {
	t.Helper()
	coord, err := coordinate.NewLocalCoordinate(modulePath)
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}
	a := staticcha.New("0.3.0", "", testLogger())
	rec, err := a.AnalyseDir(context.Background(), dir, coord)
	if err != nil {
		t.Fatalf("AnalyseDir: %v", err)
	}
	return rec
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
}
