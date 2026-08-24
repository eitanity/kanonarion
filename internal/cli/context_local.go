package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	localimporter "github.com/eitanity/kanonarion/internal/local/adapters/importer/golist"
	localsnapshot "github.com/eitanity/kanonarion/internal/local/adapters/snapshot/walkdir"
	localsymbols "github.com/eitanity/kanonarion/internal/local/adapters/symbols/gopackages"
	localapp "github.com/eitanity/kanonarion/internal/local/application"
	localdomain "github.com/eitanity/kanonarion/internal/local/domain"
)

// -- local workspace context output types --

type localWorkspaceInfo struct {
	Root          string `json:"root"`
	Module        string `json:"module"`
	VersionID     string `json:"version_id"`
	AnalysisLevel string `json:"analysis_level"`
	// TestsExcluded states which files the dependency list was measured over,
	// emitted on every answer because a tree with no test-only user renders the
	// same either way. It is a bool rather than a scope name so its zero is
	// right: false is exactly the default scope.
	TestsExcluded bool `json:"tests_excluded"`
}

type localImportedModule struct {
	Path             string   `json:"path"`
	Version          string   `json:"version"`
	ImportedPackages []string `json:"imported_packages"`
	UsedSymbols      []string `json:"used_symbols,omitempty"`
	// TestOnly reports that only test files reach this module. Emitted always,
	// false included: an absent field reads as "not measured", which is not the
	// same fact as "reached by production code".
	TestOnly bool `json:"test_only"`
}

type localContextOutput struct {
	Workspace    localWorkspaceInfo    `json:"workspace"`
	Dependencies []localImportedModule `json:"dependencies"`
	Reachability *reachabilityOutput   `json:"reachability,omitempty"`
}

// isLocalPath returns true when arg looks like a filesystem path rather than a
// module coordinate. Module coordinates always contain "@"; local paths start
// with ".", "..", or "/".
func isLocalPath(arg string) bool {
	return arg == "." || arg == ".." ||
		strings.HasPrefix(arg, "./") ||
		strings.HasPrefix(arg, "../") ||
		strings.HasPrefix(arg, "/")
}

// runContextLocal builds a local workspace context using progressive analysis.
// The default level is import (go list -json); --symbol enables type-checking.
//
// A working-tree context is a different document from a stored-record context:
// it reports the tree's imported modules and has no interface, call-graph or
// example sections. The flags that shape those sections, and the flags that
// select modules out of a walk, are therefore refused here by name rather than
// parsed and dropped — every one of them previously left the output
// byte-identical.
func runContextLocal(ctx context.Context, dir string, f contextFlags, stdout, stderr io.Writer) error {
	refused := append(contextWalkOnlyFlags(f), contextRenderFlags(f)...)
	refused = append(refused, contextGoModOnlyFlags(f)...)
	refused = append(refused, contextStreamFlag(f)...)
	if err := refuseInapplicableFlags("context <local path>", refused); err != nil {
		return err
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolving path %q: %w", dir, err)
	}

	level := localdomain.AnalysisLevelImport
	if f.symbol {
		level = localdomain.AnalysisLevelSymbol
	}

	uc := localapp.NewLocalContextUseCase(
		localsnapshot.Builder{},
		localimporter.New(""),
		localsymbols.New(),
	)

	lctx, err := uc.Execute(ctx, localapp.LocalContextRequest{
		Root:          abs,
		AnalysisLevel: level,
		ExcludeTests:  f.excludeTests,
	})
	if err != nil {
		return fmt.Errorf("local workspace analysis: %w", err)
	}

	deps := make([]localImportedModule, 0, len(lctx.Modules))
	for _, m := range lctx.Modules {
		deps = append(deps, localImportedModule{
			Path:             m.Path,
			Version:          m.Version,
			ImportedPackages: m.ImportedPackages,
			UsedSymbols:      m.UsedSymbols,
			TestOnly:         m.TestOnly(),
		})
	}

	out := localContextOutput{
		Workspace: localWorkspaceInfo{
			Root:          lctx.Root,
			Module:        lctx.ModulePath,
			VersionID:     lctx.VersionID,
			AnalysisLevel: string(lctx.AnalysisLevel),
			TestsExcluded: lctx.TestsExcluded,
		},
		Dependencies: deps,
	}

	if f.reachability {
		reach, err := runLocalReachabilityInner(ctx, abs, stderr)
		if err != nil {
			return fmt.Errorf("local reachability: %w", err)
		}
		out.Reachability = &reach
	}

	// --size-only asks what this document costs before pulling it. The answer
	// measures the same JSON the --json path writes — the one definition of
	// "context size" every surface of the command reports.
	if f.sizeOnly {
		return printDocumentSize(out, jsonOut, stdout)
	}

	if !jsonOut {
		return printLocalContextText(out, stdout)
	}

	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding local context: %w", err)
	}
	if _, err := fmt.Fprintf(stdout, "%s\n", raw); err != nil {
		return fmt.Errorf("writing local context: %w", err)
	}
	return nil
}

// printLocalContextText renders the working-tree context as a human-readable
// summary, mirroring the module-coordinate text form. The full structured
// detail (per-symbol findings, matched symbols) remains available via --json.
func printLocalContextText(out localContextOutput, stdout io.Writer) error {
	w := &errWriter{w: stdout}

	w.printf("%s\n", out.Workspace.Module)
	w.printf("  Root:            %s\n", out.Workspace.Root)
	w.printf("  Version:         %s\n", out.Workspace.VersionID)
	w.printf("  Analysis level:  %s\n", out.Workspace.AnalysisLevel)
	w.printf("  Test scope:      %s\n", localTestScopeLine(out.Workspace.TestsExcluded))

	w.printf("  Dependencies:    %d module(s) %s\n",
		len(out.Dependencies), localCountVerb(out.Workspace.AnalysisLevel))
	for _, d := range out.Dependencies {
		ver := d.Version
		if ver == "" {
			ver = "(no version)"
		}
		w.printf("    %s@%s  (%d package(s)", d.Path, ver, len(d.ImportedPackages))
		if len(d.UsedSymbols) > 0 {
			w.printf(", %d symbol(s)", len(d.UsedSymbols))
		}
		w.printf(")")
		if d.TestOnly {
			w.printf("  [test]")
		}
		w.printf("\n")
	}

	if out.Reachability != nil {
		printLocalReachabilityText(w, out.Reachability)
	}

	if w.err != nil {
		return fmt.Errorf("writing local context: %w", w.err)
	}
	return nil
}

// localCountVerb names what the dependency count counted. Symbol level counts
// modules whose exported symbols are referenced, and a blank import is imported
// while referencing nothing — "imported" there names a set the answer excludes.
func localCountVerb(analysisLevel string) string {
	if analysisLevel == string(localdomain.AnalysisLevelSymbol) {
		return "referenced"
	}
	return "imported"
}

// localTestScopeLine states which files the answer was measured over, on every
// answer rather than only a narrowed one: a tree with no test-only users is
// otherwise indistinguishable from one whose test-only users were dropped.
func localTestScopeLine(testsExcluded bool) string {
	if testsExcluded {
		return "excluded — production code only (--" + testScopeFlagName + " was given)"
	}
	return "included — users declared only in test files are tagged [test]"
}

// printLocalReachabilityText renders the reachability section of a working-tree
// context. A populated Notice (no stored findings) is surfaced verbatim so the
// caller learns which command would populate findings; an analysed-but-empty
// result is reported as such rather than as a confident "no findings".
//
// The seed restriction prints above both, and before the early return: it
// qualifies "no stored findings" exactly as much as it qualifies a list of them,
// and it is on the "nothing found" path that a silent narrowing would mislead
// most.
func printLocalReachabilityText(w *errWriter, r *reachabilityOutput) {
	w.printf("  Reachability:\n")
	if r.SeedRestriction != "" {
		w.printf("    notice: %s\n", r.SeedRestriction)
	}
	if r.Notice != "" {
		w.printf("    %s\n", r.Notice)
		return
	}
	if len(r.Modules) == 0 {
		w.printf("    no affected modules in the analysed closure\n")
		return
	}
	for _, m := range r.Modules {
		w.printf("    %s@%s\n", m.Path, m.Version)
		for _, f := range m.Findings {
			w.printf("      %s  %s\n", f.CVEID, localVerdictLabel(f))
		}
	}
}
