package application

import (
	"context"
	"fmt"
	"sort"
	"strings"

	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate"

	"code.eitanity.com/kanonarion/internal/local/domain"
	"code.eitanity.com/kanonarion/internal/local/ports"
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
	frame      cgdomain.BuildFrame
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

// WithFrame states the build frame the lister and prober were wired for, so
// the result names the frame it was measured in.
func (uc *LocalReachabilityUseCase) WithFrame(f cgdomain.BuildFrame) *LocalReachabilityUseCase {
	uc.frame = f
	return uc
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
	//
	// A replace is looked up under the coordinate the walk resolved and
	// scanned, the replacement; origin keeps the module it stands in for, whose
	// path the linked symbols are named under.
	coords := make([]coordinate.ModuleCoordinate, 0, len(buildMods))
	origin := make(map[coordinate.ModuleCoordinate]domain.BuildModule, len(buildMods))
	var (
		uncovered []domain.UncoveredModule
		replaced  []domain.ReplacedModule
	)
	for _, m := range buildMods {
		coord, cerr := buildCoordinate(m)
		if cerr != nil {
			uncovered = append(uncovered, domain.UncoveredModule{
				Path: m.Path, Version: m.Version, Reason: domain.UncoveredNoCoordinate,
			})
			continue
		}
		coords = append(coords, coord)
		origin[coord] = m
		if r := replaces(m); r != "" {
			replaced = append(replaced, domain.ReplacedModule{Path: coord.Path(), Version: coord.Version(), Replaces: r})
		}
	}

	// The tree's own module path is the frame the seed is anchored to. It comes
	// from the snapshot's go.mod — the same authority that names the tree
	// everywhere else in this result — so the probe and its seed cannot disagree
	// about which tree is being measured.
	set, err := uc.vulnLoader.LoadFindings(ctx, coords, modulePath)
	if err != nil {
		return domain.LocalReachabilityResult{}, fmt.Errorf("loading vuln findings: %w", err)
	}
	uncovered = appendUnservedCoordinates(uncovered, coords, set)
	domain.SortUncovered(uncovered)
	coverage := domain.ProbeCoverage{
		TakenAt:      takenAt,
		BuildModules: len(buildMods),
		Queried:      len(coords),
		Covered:      len(set.Scanned),
		WithFindings: len(set.Findings),
		Uncovered:    uncovered,
		Replaced:     replaced,
	}

	findings := set.Findings
	if len(findings) == 0 {
		// No stored findings for any dependency — skip the expensive probe.
		return domain.LocalReachabilityResult{
			Root:            root,
			ModulePath:      modulePath,
			VersionID:       snap.VersionID,
			ProbeKind:       "",
			Frame:           uc.frame,
			Modules:         nil,
			Coverage:        coverage,
			SeedRestriction: set.Restriction,
			SeedSetAside:    set.SetAside,
			Notice: fmt.Sprintf("no stored vulnerability findings for the %d module(s) of this build the store holds a record for",
				len(set.Scanned)),
		}, nil
	}

	// The symbol table probe is only meaningful when at least one matched
	// finding carries AffectedSymbols. A full probe-binary build (~8s) that
	// can yield nothing but "unknown" is wasted work, so elide it.
	anySymbols := anyAffectedSymbols(findings)

	var (
		binarySymbols map[string]struct{}
		binaries      []ports.ProbedBinary
		omitted       int
		probeKind     = domain.ProbeKindSkipped
		builder       string
		notice        string
	)
	if anySymbols {
		probe, perr := uc.prober.Probe(ctx, root)
		if perr != nil {
			return domain.LocalReachabilityResult{}, fmt.Errorf("building symbol probe: %w", perr)
		}
		binarySymbols = probe.BinarySymbols
		binaries = probe.Binaries
		probeKind = probe.Kind
		builder = probe.Builder
		coverage.Binaries = coverageBinaries(binaries)
		coverage.HarnessOmitted = probe.HarnessOmitted
		omitted = len(probe.HarnessOmitted)
	} else {
		notice = "no matched finding carried affected symbols; skipped the probe-binary build " +
			"and fell back to stored govulncheck reachability where available"
	}

	var modResults []domain.ModuleProbeResult
	for coord, cveFindings := range findings {
		modResult := domain.ModuleProbeResult{
			Path:     coord.Path(),
			Version:  coord.Version(),
			Replaces: replaces(origin[coord]),
		}
		symbolPath := coord.Path()
		if m, ok := origin[coord]; ok {
			symbolPath = m.Path
		}
		for _, f := range cveFindings {
			finding := probeOneFinding(f, symbolPath, probeKind, binarySymbols, binaries, omitted)
			modResult.Findings = append(modResult.Findings, finding)
		}
		modResults = append(modResults, modResult)
	}

	domain.SortProbeModules(modResults)
	return domain.LocalReachabilityResult{
		Root:            root,
		ModulePath:      modulePath,
		VersionID:       snap.VersionID,
		ProbeKind:       probeKind,
		ProbeBuilder:    builder,
		Frame:           uc.frame,
		Modules:         modResults,
		Coverage:        coverage,
		SeedRestriction: set.Restriction,
		SeedSetAside:    set.SetAside,
		Notice:          notice,
	}, nil
}

// buildCoordinate is the coordinate a build module's record is stored under:
// the one a replace makes the walk record, when one applies.
func buildCoordinate(m domain.BuildModule) (coordinate.ModuleCoordinate, error) {
	if m.ReplacePath != "" {
		return coordinate.NewModuleCoordinate(m.ReplacePath, m.ReplaceVersion)
	}
	return coordinate.NewModuleCoordinate(m.Path, m.Version)
}

// replaces names the module@version a replacement stands in for, or "".
func replaces(m domain.BuildModule) string {
	if m.ReplacePath == "" {
		return ""
	}
	return m.Path + "@" + m.Version
}

// appendUnservedCoordinates records each queried coordinate the store held no
// servable scan for, with the reason it did not.
func appendUnservedCoordinates(uncovered []domain.UncoveredModule, coords []coordinate.ModuleCoordinate, set ports.FindingSet) []domain.UncoveredModule {
	for _, coord := range coords {
		if _, ok := set.Scanned[coord]; ok {
			continue
		}
		reason := domain.UncoveredNoStoredRecord
		switch {
		case setContains(set.OtherFrameOnly, coord):
			reason = domain.UncoveredOtherFrameOnly
		case setContains(set.SupersededOnly, coord):
			reason = domain.UncoveredSupersededPipeline
		case setContains(set.SetAsideOnly, coord):
			reason = domain.UncoveredSetAside
		case setContains(set.NotInSeedWalk, coord):
			reason = domain.UncoveredNotInSeedWalk
		case setContains(set.ScanIncomplete, coord):
			reason = domain.UncoveredScanIncomplete
		case setContains(set.NotAnalysed, coord):
			reason = domain.UncoveredNotAnalysed
		}
		uncovered = append(uncovered, domain.UncoveredModule{
			Path: coord.Path(), Version: coord.Version(), Reason: reason,
		})
	}
	return uncovered
}

// anyAffectedSymbols reports whether any finding names an affected symbol.
func anyAffectedSymbols(findings map[coordinate.ModuleCoordinate][]ports.VulnFinding) bool {
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
	return anySymbols
}

// coverageBinaries projects the prober's per-binary result onto the coverage
// block: which main packages the build declares, and which of them the answer
// could not be drawn from.
func coverageBinaries(binaries []ports.ProbedBinary) []domain.ProbedBinary {
	if len(binaries) == 0 {
		return nil
	}
	out := make([]domain.ProbedBinary, 0, len(binaries))
	for _, b := range binaries {
		out = append(out, domain.ProbedBinary{ImportPath: b.ImportPath, Builder: b.Builder, BuildError: b.BuildError})
	}
	domain.SortProbedBinaries(out)
	return out
}

// probeOneFinding checks whether any AffectedSymbol from the CVE finding
// appears in the probe binary's symbol table for the given module.
//
// binarySymbols is the union across every binary that built, and settles the
// verdict: a vulnerable symbol shipping in any one of a project's binaries
// ships in the product. binaries carries the same tables per main package and
// settles the attribution — which artefact to look in.
func probeOneFinding(f ports.VulnFinding, modPath, probeKind string, binarySymbols map[string]struct{}, binaries []ports.ProbedBinary, omitted int) domain.SymbolProbeFinding {
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
			result.Reason = seededReason(f.ReachableBasis)
		default:
			result.Verdict = domain.SymbolProbeUnreachable
			result.VerdictSource = domain.VerdictSourceGovulncheck
			result.Reason = seededReason(f.ReachableBasis)
			// The negative was not measured here, so the rung is the one the stored
			// scan's own answer earns, carried across with it. Deriving a rung for
			// this probe's instrument would state the soundness of a search this
			// verdict did not come from.
			result.Soundness = f.ReachableSoundness
			result.SoundnessReason = f.ReachableSoundnessReason
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
		result.MatchedBinaries = matchingBinaries(result.MatchedSymbols, binaries)
	} else {
		result.Verdict = domain.SymbolProbeAbsent
		// A negative this probe measured itself, so it states the rung its own
		// instrument earns rather than the stored scan's.
		result.Soundness, result.SoundnessReason = absentSoundness(probeKind, binaries, omitted)
	}
	return result
}

// absentSoundness states the rung a symbol-table absence earns and what it was
// read from. Only an absence from every main, each built by go build, is
// confirmed; a partial probe, a library harness and a TinyGo build keep their
// own unconfirmed reasons so the weakest cannot read as the strongest.
func absentSoundness(probeKind string, binaries []ports.ProbedBinary, omitted int) (soundness, reason string) {
	if probeKind == domain.ProbeKindLibrary {
		return domain.ProbeSoundnessUnconfirmed, domain.LibraryAbsentReason(omitted)
	}
	allGo := len(binaries) > 0
	for _, b := range binaries {
		if b.BuildError != "" {
			return domain.ProbeSoundnessUnconfirmed, domain.ProbeAbsentPartialReason
		}
		allGo = allGo && b.Builder == domain.ProbeBuilderGo
	}
	if probeKind == domain.ProbeKindBinary && allGo {
		return domain.ProbeSoundnessConfirmed, domain.ProbeAbsentConfirmedReason
	}
	return domain.ProbeSoundnessUnconfirmed, domain.ProbeAbsentReason
}

// seededReason states that a verdict was carried from a stored scan rather than
// measured here, and names the basis that scan recorded — the instrument, how
// well it could see, and the build it was rooted at.
//
// A seeded verdict and a probed one are printed identically otherwise, and they
// are not the same claim: one is a measurement of this tree's binary and the
// other is a judgment made about some build, possibly an earlier one of this
// tree, possibly the module built alone.
func seededReason(basis string) string {
	if basis == "" {
		return "carried from the stored scan, which recorded no derivation for its reachability answer"
	}
	return "carried from the stored scan (" + basis + ")"
}

// matchingBinaries names the probed binaries whose symbol table carries at
// least one of syms, sorted by import path.
func matchingBinaries(syms []string, binaries []ports.ProbedBinary) []string {
	var matched []string
	for _, b := range binaries {
		for _, sym := range syms {
			if _, ok := b.Symbols[sym]; ok {
				matched = append(matched, b.ImportPath)
				break
			}
		}
	}
	sort.Strings(matched)
	return matched
}

// findInBinary looks for an nm symbol belonging to modPath whose unqualified
// name matches affSym (govulncheck-style: "FuncName" or "(*Type).Method").
// Returns the full nm symbol name if found, or "".
//
// Several symbols can match: a module and its own /vN major-version line share a
// path prefix, so both are candidates for a name declared in both. The smallest
// is returned rather than whichever the map handed over first, because map
// iteration order is random and the first-match form made two probes of one
// unchanged tree report different matched_symbols. A probe whose answer moves
// without its input moving is not a measurement.
func findInBinary(affSym, modPath string, binarySymbols map[string]struct{}) string {
	rootPrefix := modPath + "."
	subPrefix := modPath + "/"

	best := ""
	for sym := range binarySymbols {
		// A generic instantiation's type arguments can hold paths and dots of
		// their own, so they go before the package boundary is looked for.
		name := stripTypeArgs(sym)
		var unqualified string
		switch {
		case strings.HasPrefix(name, rootPrefix):
			unqualified = name[len(rootPrefix):]
		case strings.HasPrefix(name, subPrefix):
			// e.g. "github.com/foo/bar/sub.(*Type).Method"
			rest := name[len(subPrefix):]
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

		if symbolMatches(normalizeReceiver(unqualified), normalizeReceiver(affSym)) {
			if best == "" || sym < best {
				best = sym
			}
		}
	}
	return best
}

// symbolMatches compares a normalised nm name with an advisory symbol. An
// advisory's "init" names every initialiser of the package, and the compiler
// links a package's func init() blocks as init.0, init.1 and so on.
func symbolMatches(unqualified, affSym string) bool {
	if unqualified == affSym {
		return true
	}
	if affSym != "init" {
		return false
	}
	n, ok := strings.CutPrefix(unqualified, "init.")
	return ok && n != "" && strings.Trim(n, "0123456789") == ""
}

// stripTypeArgs drops every bracketed type-argument list, nested ones with it,
// so "pkg.(*Box[go.shape.string]).Get" reads "pkg.(*Box).Get".
func stripTypeArgs(sym string) string {
	if !strings.Contains(sym, "[") {
		return sym
	}
	var b strings.Builder
	depth := 0
	for _, r := range sym {
		switch {
		case r == '[':
			depth++
		case r == ']' && depth > 0:
			depth--
		case depth == 0:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// normalizeReceiver rewrites a method symbol's pointer-receiver spelling to the
// bare "Type.Method" form so the three spellings in play compare equal: the
// symbol table mangles a method on *Parser as "(*Parser).Method", the stored
// finding writes "*Parser.Method", and OSV's canonical form is "Parser.Method".
// A value receiver's "Parser.Method" and a package-level function pass through
// unchanged; a spelling that opens a receiver without closing it is returned
// verbatim rather than guessed at.
func normalizeReceiver(sym string) string {
	if rest, ok := strings.CutPrefix(sym, "(*"); ok {
		typ, method, ok := strings.Cut(rest, ").")
		if !ok {
			return sym
		}
		return typ + "." + method
	}
	if rest, ok := strings.CutPrefix(sym, "*"); ok && strings.Contains(rest, ".") {
		return rest
	}
	return sym
}

// setContains is membership in one of the loader's coordinate sets, tolerating
// a nil map — a loader that predates a set still answers, and answers "no".
func setContains(m map[coordinate.ModuleCoordinate]struct{}, coord coordinate.ModuleCoordinate) bool {
	_, ok := m[coord]
	return ok
}
