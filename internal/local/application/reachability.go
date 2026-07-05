package application

import (
	"context"
	"fmt"
	"strings"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/local/domain"
	"github.com/eitanity/kanonarion/internal/local/ports"
)

// LocalReachabilityUseCase determines whether known CVE-affected symbols will
// ship in the binary produced from the local workspace by building a probe
// binary with inlining disabled and reading its symbol table.
type LocalReachabilityUseCase struct {
	snapshot   ports.SnapshotBuilder
	imports    ports.ImportAnalyser
	vulnLoader ports.VulnFindingLoader
	prober     ports.SymbolTableProber
}

// NewLocalReachabilityUseCase constructs a LocalReachabilityUseCase.
func NewLocalReachabilityUseCase(
	snapshot ports.SnapshotBuilder,
	imports ports.ImportAnalyser,
	vulnLoader ports.VulnFindingLoader,
	prober ports.SymbolTableProber,
) *LocalReachabilityUseCase {
	return &LocalReachabilityUseCase{
		snapshot:   snapshot,
		imports:    imports,
		vulnLoader: vulnLoader,
		prober:     prober,
	}
}

// Execute runs the symbol table probe and returns per-CVE reachability verdicts.
//
// Flow:
// 1. Build snapshot → VersionID + module path
// 2. Run import-level analysis to find dependency module coordinates
// 3. Load stored CVE findings for those coordinates
// 4. Build probe binary (inlining disabled) and read its symbol table
// 5. For each module with findings, check which affected symbols are present
func (uc *LocalReachabilityUseCase) Execute(ctx context.Context, root string) (domain.LocalReachabilityResult, error) {
	snap, err := uc.snapshot.Build(ctx, root)
	if err != nil {
		return domain.LocalReachabilityResult{}, fmt.Errorf("building workspace snapshot: %w", err)
	}
	modulePath, err := domain.SnapshotModulePath(snap)
	if err != nil {
		return domain.LocalReachabilityResult{}, fmt.Errorf("locating go.mod in snapshot: %w", err)
	}

	importedMods, err := uc.imports.AnalyseImports(ctx, root)
	if err != nil {
		return domain.LocalReachabilityResult{}, fmt.Errorf("analysing imports: %w", err)
	}

	// Build coordinate list for vuln lookup.
	coords := make([]fetchdomain.ModuleCoordinate, 0, len(importedMods))
	for _, m := range importedMods {
		coord, cerr := fetchdomain.NewModuleCoordinate(m.Path, m.Version)
		if cerr != nil {
			continue
		}
		coords = append(coords, coord)
	}

	findings, err := uc.vulnLoader.LoadFindings(ctx, coords)
	if err != nil {
		return domain.LocalReachabilityResult{}, fmt.Errorf("loading vuln findings: %w", err)
	}
	if len(findings) == 0 {
		// No stored findings for any dependency — skip the expensive probe.
		return domain.LocalReachabilityResult{
			Root:       root,
			ModulePath: modulePath,
			VersionID:  snap.VersionID,
			ProbeKind:  "",
			Modules:    nil,
			Notice: fmt.Sprintf("no stored vulnerability findings for the %d analysed dependency module(s); "+
				"run 'kanonarion walk' then 'kanonarion vuln-scan' for these coordinates to populate findings", len(coords)),
		}, nil
	}

	// The symbol table probe is only meaningful when at least one matched
	// finding carries AffectedSymbols. A full probe-binary build (~8s) that
	// can yield nothing but "unknown" is wasted work, so elide it.
	anySymbols := false
	for _, cveFindings := range findings {
		for _, f := range cveFindings {
			if len(f.AffectedSymbols) > 0 {
				anySymbols = true
				break
			}
		}
		if anySymbols {
			break
		}
	}

	var (
		binarySymbols map[string]struct{}
		probeKind     = "skipped"
		notice        string
	)
	if anySymbols {
		probe, perr := uc.prober.Probe(ctx, root)
		if perr != nil {
			return domain.LocalReachabilityResult{}, fmt.Errorf("building symbol probe: %w", perr)
		}
		binarySymbols = probe.BinarySymbols
		probeKind = probe.Kind
	} else {
		notice = "no matched finding carried affected symbols; skipped the probe-binary build " +
			"and fell back to stored govulncheck reachability where available"
	}

	var modResults []domain.ModuleProbeResult
	for coord, cveFindings := range findings {
		modResult := domain.ModuleProbeResult{
			Path:    coord.Path,
			Version: coord.Version,
		}
		for _, f := range cveFindings {
			finding := probeOneFinding(f, coord.Path, binarySymbols)
			modResult.Findings = append(modResult.Findings, finding)
		}
		modResults = append(modResults, modResult)
	}

	domain.SortProbeModules(modResults)
	return domain.LocalReachabilityResult{
		Root:       root,
		ModulePath: modulePath,
		VersionID:  snap.VersionID,
		ProbeKind:  probeKind,
		Modules:    modResults,
		Notice:     notice,
	}, nil
}

// probeOneFinding checks whether any AffectedSymbol from the CVE finding
// appears in the probe binary's symbol table for the given module.
func probeOneFinding(f ports.VulnFinding, modPath string, binarySymbols map[string]struct{}) domain.SymbolProbeFinding {
	result := domain.SymbolProbeFinding{
		CVEID:   f.ID,
		Aliases: f.Aliases,
		Summary: f.Summary,
	}
	if len(f.AffectedSymbols) == 0 {
		// No symbols to probe. Fall back to govulncheck's own reachability
		// verdict from the stored scan if it captured one.
		switch {
		case f.Reachable == nil:
			result.Verdict = domain.SymbolProbeUnknown
			result.VerdictSource = domain.VerdictSourceNone
			result.Reason = "stored scan recorded no affected symbols and no govulncheck reachability"
		case *f.Reachable:
			result.Verdict = domain.SymbolProbeReachable
			result.VerdictSource = domain.VerdictSourceGovulncheck
		default:
			result.Verdict = domain.SymbolProbeUnreachable
			result.VerdictSource = domain.VerdictSourceGovulncheck
		}
		return result
	}

	for _, affSym := range f.AffectedSymbols {
		if matched := findInBinary(affSym, modPath, binarySymbols); matched != "" {
			result.MatchedSymbols = append(result.MatchedSymbols, matched)
		}
	}

	result.VerdictSource = domain.VerdictSourceSymbolTable
	if len(result.MatchedSymbols) > 0 {
		result.Verdict = domain.SymbolProbePresent
	} else {
		result.Verdict = domain.SymbolProbeAbsent
	}
	return result
}

// findInBinary looks for an nm symbol belonging to modPath whose unqualified
// name matches affSym (govulncheck-style: "FuncName" or "(*Type).Method").
// Returns the full nm symbol name if found, or "".
func findInBinary(affSym, modPath string, binarySymbols map[string]struct{}) string {
	rootPrefix := modPath + "."
	subPrefix := modPath + "/"

	for sym := range binarySymbols {
		var unqualified string
		switch {
		case strings.HasPrefix(sym, rootPrefix):
			unqualified = sym[len(rootPrefix):]
		case strings.HasPrefix(sym, subPrefix):
			// e.g. "github.com/foo/bar/sub.(*Type).Method"
			rest := sym[len(subPrefix):]
			// Find the first '.' after the last '/' to locate the package boundary.
			lastSlash := strings.LastIndex(rest, "/")
			var afterLastSlash string
			if lastSlash < 0 {
				afterLastSlash = rest
			} else {
				afterLastSlash = rest[lastSlash+1:]
			}
			dotIdx := strings.Index(afterLastSlash, ".")
			if dotIdx < 0 {
				continue
			}
			unqualified = afterLastSlash[dotIdx+1:]
		default:
			continue
		}

		if unqualified == affSym {
			return sym
		}
	}
	return ""
}
