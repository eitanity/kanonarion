package application

import (
	"context"
	"fmt"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/local/domain"
	"github.com/eitanity/kanonarion/internal/local/ports"
)

// LocalReachabilityUseCase determines whether known CVE-affected symbols will
// ship in the binary produced from the local workspace by building a probe
// binary with inlining disabled and reading its symbol table.
type LocalReachabilityUseCase struct {
	snapshot   ports.SnapshotBuilder
	build      ports.BuildModuleLister
	vulnLoader ports.VulnFindingLoader
	prober     ports.SymbolTableProber
	clock      ports.Clock
}

// NewLocalReachabilityUseCase constructs a LocalReachabilityUseCase.
//
// The module set comes from a BuildModuleLister, not an ImportAnalyser: the
// probe measures a binary containing the whole build, so scoping its finding
// lookup to the workspace's direct imports left every transitive module — and
// any stored finding against one — out of the answer with nothing said.
func NewLocalReachabilityUseCase(
	snapshot ports.SnapshotBuilder,
	build ports.BuildModuleLister,
	vulnLoader ports.VulnFindingLoader,
	prober ports.SymbolTableProber,
	clk ports.Clock,
) *LocalReachabilityUseCase {
	return &LocalReachabilityUseCase{
		snapshot:   snapshot,
		build:      build,
		vulnLoader: vulnLoader,
		prober:     prober,
		clock:      clk,
	}
}

// Execute runs the symbol table probe and returns per-CVE reachability verdicts.
//
// Flow:
//  1. Build snapshot → VersionID + module path
//  2. Enumerate every module the local build resolves
//  3. Load stored CVE findings for those coordinates, keeping which coordinates
//     the store held a record for at all
//  4. Build probe binary (inlining disabled) and read its symbol table
//  5. For each module with findings, check which affected symbols are present
//  6. State the coverage: what the answer speaks about, and what it does not
func (uc *LocalReachabilityUseCase) Execute(ctx context.Context, root string) (domain.LocalReachabilityResult, error) {
	takenAt := uc.clock.Now().UTC()
	snap, err := uc.snapshot.Build(ctx, root)
	if err != nil {
		return domain.LocalReachabilityResult{}, fmt.Errorf("building workspace snapshot: %w", err)
	}
	modulePath, err := domain.SnapshotModulePath(snap)
	if err != nil {
		return domain.LocalReachabilityResult{}, fmt.Errorf("locating go.mod in snapshot: %w", err)
	}

	buildMods, err := uc.build.BuildModules(ctx, root)
	if err != nil {
		return domain.LocalReachabilityResult{}, fmt.Errorf("listing build modules: %w", err)
	}

	// Build the coordinate list. A module the build resolves without a version
	// names no coordinate; it is recorded as uncovered rather than dropped,
	// because "the store said nothing about it" and "nothing asked the store
	// about it" are not the same claim.
	coords := make([]coordinate.ModuleCoordinate, 0, len(buildMods))
	var uncovered []domain.UncoveredModule
	for _, m := range buildMods {
		coord, cerr := coordinate.NewModuleCoordinate(m.Path, m.Version)
		if cerr != nil {
			uncovered = append(uncovered, domain.UncoveredModule{
				Path: m.Path, Version: m.Version, Reason: domain.UncoveredNoCoordinate,
			})
			continue
		}
		coords = append(coords, coord)
	}

	set, err := uc.vulnLoader.LoadFindings(ctx, coords)
	if err != nil {
		return domain.LocalReachabilityResult{}, fmt.Errorf("loading vuln findings: %w", err)
	}
	for _, coord := range coords {
		if _, ok := set.Scanned[coord]; !ok {
			uncovered = append(uncovered, domain.UncoveredModule{
				Path: coord.Path(), Version: coord.Version(), Reason: domain.UncoveredNoStoredRecord,
			})
		}
	}
	domain.SortUncovered(uncovered)
	coverage := domain.ProbeCoverage{
		TakenAt:      takenAt,
		BuildModules: len(buildMods),
		Queried:      len(coords),
		Covered:      len(set.Scanned),
		WithFindings: len(set.Findings),
		Uncovered:    uncovered,
	}

	findings := set.Findings
	if len(findings) == 0 {
		// No stored findings for any dependency — skip the expensive probe.
		return domain.LocalReachabilityResult{
			Root:       root,
			ModulePath: modulePath,
			VersionID:  snap.VersionID,
			ProbeKind:  "",
			Modules:    nil,
			Coverage:   coverage,
			Notice: fmt.Sprintf("no stored vulnerability findings for the %d module(s) of this build the store holds a record for",
				len(set.Scanned)),
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
			Path:    coord.Path(),
			Version: coord.Version(),
		}
		for _, f := range cveFindings {
			finding := probeOneFinding(f, coord.Path(), binarySymbols)
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
		Coverage:   coverage,
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
		case f.AdvisoryNamesNoSymbols:
			// The advisory names no symbol for this module path, so no symbol-level
			// determination was ever possible — not by this probe and not by the
			// stored scan either. Falling through to the stored verdict would report
			// "unreachable" on the strength of a search that had no target.
			result.Verdict = domain.SymbolProbeUnknown
			result.VerdictSource = domain.VerdictSourceNone
			result.Reason = "the advisory names no symbols for this module path, so symbol-level reachability is not determinable; the module is affected at package level"
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
