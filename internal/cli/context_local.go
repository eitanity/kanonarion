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
}

type localImportedModule struct {
	Path             string   `json:"path"`
	Version          string   `json:"version"`
	ImportedPackages []string `json:"imported_packages"`
	UsedSymbols      []string `json:"used_symbols,omitempty"`
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
func runContextLocal(ctx context.Context, dir string, f contextFlags, stdout, stderr io.Writer) error {
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
		})
	}

	out := localContextOutput{
		Workspace: localWorkspaceInfo{
			Root:          lctx.Root,
			Module:        lctx.ModulePath,
			VersionID:     lctx.VersionID,
			AnalysisLevel: string(lctx.AnalysisLevel),
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

	w.printf("  Dependencies:    %d module(s) imported\n", len(out.Dependencies))
	for _, d := range out.Dependencies {
		ver := d.Version
		if ver == "" {
			ver = "(no version)"
		}
		w.printf("    %s@%s  (%d package(s)", d.Path, ver, len(d.ImportedPackages))
		if len(d.UsedSymbols) > 0 {
			w.printf(", %d symbol(s)", len(d.UsedSymbols))
		}
		w.printf(")\n")
	}

	if out.Reachability != nil {
		printLocalReachabilityText(w, out.Reachability)
	}

	if w.err != nil {
		return fmt.Errorf("writing local context: %w", w.err)
	}
	return nil
}

// printLocalReachabilityText renders the reachability section of a working-tree
// context. A populated Notice (no stored findings) is surfaced verbatim so the
// caller learns which command would populate findings; an analysed-but-empty
// result is reported as such rather than as a confident "no findings".
func printLocalReachabilityText(w *errWriter, r *reachabilityOutput) {
	w.printf("  Reachability:\n")
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
			w.printf("      %s  %s\n", f.CVEID, f.Verdict)
		}
	}
}
