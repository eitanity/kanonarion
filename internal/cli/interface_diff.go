package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"
)

// interfaceDiffCoverageNote is the standing statement of what this comparison
// does and does not measure. It is printed on every run, including the runs that
// find nothing, because a zero is exactly when a reader is most likely to read
// more into the answer than it holds.
const interfaceDiffCoverageNote = "coverage: exported Go declarations and their signatures, compared between two " +
	"stored interface records. Behaviour, string-keyed registries, struct-tag semantics and " +
	"anything decided at run time are outside this comparison; source positions are not compared."

// usedByCoverageNote states the limit of the call-graph join. A symbol reported
// as not reached is not a symbol proved unused: the graph records call edges, so
// a reference that is not a call is not in it to be found.
const usedByCoverageNote = "coverage: reached/not-reached is measured over recorded CALL EDGES in the stored " +
	"call graph. Method values (a method referenced as a value rather than called) are not " +
	"recorded as edges, so a symbol shown as not reached may still be referenced that way. " +
	"Types, constants and variables have no call-graph node at all and are reported as " +
	"unmeasured rather than as unreached."

type interfaceDiffFlags struct {
	usedBy string
}

// -- interface-diff command --

func newInterfaceDiffCmd(stdout, stderr io.Writer) *cobra.Command {
	var f interfaceDiffFlags

	cmd := &cobra.Command{
		Use:   "interface-diff <module>@<versionA> <module>@<versionB>",
		Short: "Report exported API changes between two versions of a module",
		Long: `interface-diff compares two stored interface records and reports the exported
declarations added, removed and changed between them.

A signature that changed only in a spelling the language treats as identical —
interface{} rewritten as any, a result that stopped being named — is reported
separately as a spelling change and is NOT counted as breaking.

The count is a count of exported signatures. It is not a claim about behaviour:
a release that changes no signature at all can still change what the code does.

Both records must already be extracted — run 'kanonarion interface' first.`,
		Example: `  kanonarion interface-diff github.com/spf13/cast@v1.4.1 github.com/spf13/cast@v1.10.0
  kanonarion interface-diff github.com/spf13/cast@v1.4.1 github.com/spf13/cast@v1.10.0 --json
  kanonarion interface-diff github.com/spf13/cast@v1.4.1 github.com/spf13/cast@v1.10.0 --used-by ./go.mod`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return usageErr(cmd)
			}
			return runInterfaceDiff(cmd.Context(), args[0], args[1], f, stdout, stderr)
		},
	}

	// A value-taking flag and nothing else: no NoOptDefVal, so "--used-by
	// ./go.mod" is the grammar and a bare --used-by is rejected rather than
	// silently swallowing the next positional.
	cmd.Flags().StringVar(&f.usedBy, "used-by", "",
		"join the delta against the stored call graph of the project this go.mod declares")

	return cmd
}

func runInterfaceDiff(ctx context.Context, argA, argB string, f interfaceDiffFlags, stdout, stderr io.Writer) error {
	coordA, err := parseCoordinate(argA)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", argA, err)
	}
	coordB, err := parseCoordinate(argB)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", argB, err)
	}

	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer func() { _ = cleanup() }()

	return interfaceDiffWith(ctx, ctr, coordA, coordB, f, stdout)
}

// interfaceDiffWith holds the interface-diff logic over an injected Container:
// it runs the diff, maps a missing record to ExitNotFound (absence is surfaced,
// never reported as "no change"), optionally joins the delta against a stored
// call graph, and selects JSON vs text rendering.
func interfaceDiffWith(
	ctx context.Context,
	ctr *Container,
	coordA, coordB coordinate.ModuleCoordinate,
	f interfaceDiffFlags,
	stdout io.Writer,
) error {
	diff, err := ctr.DiffInterface.Diff(ctx, coordA, coordB)
	if err != nil {
		if notFound, ok := errors.AsType[*ifaceapp.ErrInterfaceRecordNotFound](err); ok {
			return &exitError{code: ExitNotFound, msg: notFound.Error()}
		}
		return fmt.Errorf("diffing interface records: %w", err)
	}

	var used *usedByResult
	if f.usedBy != "" {
		used, err = joinUsedBy(ctx, ctr, diff, f.usedBy)
		if err != nil {
			return err
		}
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(toInterfaceDiffJSON(diff, used)); encErr != nil {
			return fmt.Errorf("encoding JSON: %w", encErr)
		}
		return usedSetBreakingErr(used)
	}

	if perr := printInterfaceDiff(diff, used, stdout); perr != nil {
		return perr
	}
	return usedSetBreakingErr(used)
}

// -- the used-by join --

// usedSymbol is one breaking delta together with what the consumer's own code
// does with it.
type usedSymbol struct {
	Symbol ifacedomain.SymbolID
	// Removed distinguishes the two breaking classes for display.
	Removed bool
	// Measurable is false for a declaration that has no call-graph node — a
	// type, a constant, a variable. Such a symbol is not "unused"; it is not a
	// question the call graph can answer.
	Measurable bool
	// SymbolID is the call-graph node ID this was looked up under, empty when
	// not measurable.
	NodeID string
	// Sites is the number of recorded call edges from the consumer's own code.
	Sites int
	// Callers are the consumer's own functions that call it, with the position
	// their declaration sits at, sorted by ID.
	Callers []usedCaller
}

type usedCaller struct {
	ID   string
	File string
	Line int
}

// usedByResult is the join of a delta against one project's stored call graph.
type usedByResult struct {
	GoMod  string
	WalkID string
	// WalkFrame is the GOOS/GOARCH the answering walk resolved for, or
	// "unrecorded" for a walk written before the frame was projected. GOOS gates
	// which files build, so the scope this answer is filtered against is one
	// platform's build list.
	WalkFrame string
	Consumer  coordinate.ModuleCoordinate
	// ScopeSize is how many module versions the walk pins.
	ScopeSize int
	// Symbols covers every breaking delta, reached or not, in delta order.
	Symbols []usedSymbol
	// CallGraphFound is false when the consumer module has no stored call graph
	// at all — in which case every "not reached" below is an absence of
	// evidence, not evidence of absence, and the command says so.
	CallGraphFound bool
}

// Reached returns the symbols the consumer's own code actually calls.
func (r *usedByResult) Reached() []usedSymbol {
	var out []usedSymbol
	for _, s := range r.Symbols {
		if s.Sites > 0 {
			out = append(out, s)
		}
	}
	return out
}

// joinUsedBy resolves a go.mod to the latest succeeded project walk for the
// module it declares — the same resolution `callers --gomod` performs — and asks
// the stored call graph which of the breaking deltas that project's own code
// calls.
//
// It never parses the consumer's source. The answer is a read of what was
// already measured and recorded, so it is reproducible and it cannot disagree
// with what `callers` would say about the same symbol.
func joinUsedBy(ctx context.Context, ctr *Container, diff ifacedomain.InterfaceDiff, gomod string) (*usedByResult, error) {
	walkSum, gomodPath, err := latestWalkForGoMod(ctx, ctr.QueryWalks, gomod)
	if err != nil {
		return nil, err
	}
	walkID := walkSum.ID
	rec, err := ctr.QueryWalks.GetWalk(ctx, walkID)
	if err != nil {
		return nil, fmt.Errorf("loading walk %q: %w", walkID, err)
	}
	scope := walkModuleSet(rec)

	res := &usedByResult{
		GoMod:     gomodPath,
		WalkID:    walkID,
		WalkFrame: rec.Graph.BuildEnv.Frame(),
		Consumer:  rec.Target,
		ScopeSize: scope.Len(),
	}

	positions, found, err := consumerNodePositions(ctx, ctr.QueryCallGraph, rec.Target)
	if err != nil {
		return nil, err
	}
	res.CallGraphFound = found

	for _, sym := range breakingSymbols(diff) {
		entry := usedSymbol{Symbol: sym.Symbol, Removed: sym.Removed}
		nodeID, measurable := callGraphNodeID(sym.Symbol, sym.PtrReceiver)
		entry.Measurable = measurable
		entry.NodeID = nodeID
		if measurable {
			refs, ferr := ctr.QueryCallGraph.FindCallers(ctx, nodeID, cgapp.PipelineVersion, scope, cgports.EdgeQueryOptions{})
			if ferr != nil {
				return nil, fmt.Errorf("finding callers of %s: %w", nodeID, ferr)
			}
			entry.Sites, entry.Callers = consumerCallers(refs, rec.Target, positions)
		}
		res.Symbols = append(res.Symbols, entry)
	}
	return res, nil
}

// breakingDelta is a removed or changed declaration, in the order the delta
// lists them.
type breakingDelta struct {
	Symbol      ifacedomain.SymbolID
	PtrReceiver bool
	Removed     bool
}

// breakingSymbols enumerates what the join asks about: the removals and the
// real signature changes. Spelling changes are excluded — there is nothing for a
// consumer to be broken by, so asking whether it reaches them would produce a
// finding out of a non-finding.
func breakingSymbols(diff ifacedomain.InterfaceDiff) []breakingDelta {
	out := make([]breakingDelta, 0, diff.BreakingCount())
	for _, s := range diff.Removed {
		out = append(out, breakingDelta{Symbol: s.ID, PtrReceiver: s.PtrReceiver, Removed: true})
	}
	for _, c := range diff.Changed {
		out = append(out, breakingDelta{Symbol: c.Symbol, PtrReceiver: c.PtrReceiver})
	}
	return out
}

// callGraphNodeID renders the call-graph node ID for a declaration, and whether
// the declaration has one at all.
//
// The node-ID convention is "pkg/path.Func" for a function and
// "pkg/path.(*Recv).Method" or "pkg/path.(Recv).Method" for a method, which is
// why the receiver form is carried through the diff: the wrong form finds
// nothing and would read as "not called".
func callGraphNodeID(id ifacedomain.SymbolID, ptrReceiver bool) (string, bool) {
	switch id.Kind {
	case ifacedomain.SymbolFunc:
		return id.Package + "." + id.Name, true
	case ifacedomain.SymbolMethod:
		dot := strings.LastIndex(id.Name, ".")
		if dot < 0 {
			return "", false
		}
		recv, method := id.Name[:dot], id.Name[dot+1:]
		if ptrReceiver {
			return id.Package + ".(*" + recv + ")." + method, true
		}
		return id.Package + ".(" + recv + ")." + method, true
	case ifacedomain.SymbolType, ifacedomain.SymbolConst, ifacedomain.SymbolVar:
		return "", false
	}
	return "", false
}

// consumerNodePositions loads the consumer module's own call graph and indexes
// its nodes by ID, so a caller can be reported with the file and line it is
// declared at. Returns found=false when the project has no stored graph.
func consumerNodePositions(ctx context.Context, uc QueryCallGraphUseCase, consumer coordinate.ModuleCoordinate) (map[string]cgdomain.SourcePosition, bool, error) {
	rec, found, err := uc.GetCallGraphRecord(ctx, consumer, cgapp.PipelineVersion)
	if err != nil {
		return nil, false, fmt.Errorf("loading call graph for %s: %w", consumer, err)
	}
	if !found {
		return nil, false, nil
	}
	positions := make(map[string]cgdomain.SourcePosition, len(rec.Nodes))
	for _, n := range rec.Nodes {
		positions[n.ID] = n.Position
	}
	return positions, true, nil
}

// consumerCallers keeps the edges owned by the consumer's own module and
// summarises them: how many call sites, and which of its functions they are in.
//
// The filter is what makes the answer "your code", not "some code in your
// build": an edge owned by another dependency is a call the consumer did not
// write and cannot fix.
func consumerCallers(refs []cgports.CallEdgeRef, consumer coordinate.ModuleCoordinate, positions map[string]cgdomain.SourcePosition) (int, []usedCaller) {
	sites := 0
	byID := map[string]struct{}{}
	for _, r := range refs {
		if r.ModulePath != consumer.Path() {
			continue
		}
		sites++
		byID[r.FromID] = struct{}{}
	}
	callers := make([]usedCaller, 0, len(byID))
	for id := range byID {
		c := usedCaller{ID: id}
		if pos, ok := positions[id]; ok {
			c.File, c.Line = pos.File, pos.Line
		}
		callers = append(callers, c)
	}
	sort.Slice(callers, func(i, j int) bool { return callers[i].ID < callers[j].ID })
	if len(callers) == 0 {
		return sites, nil
	}
	return sites, callers
}

// usedSetBreakingErr is the gate --used-by was asked for: the command ran to
// completion, measured the stored call graph, and found the consumer's own code
// calling a declaration this version bump removes or changes.
//
// That is ExitPolicy rather than ExitFailed or ExitConfig by the taxonomy's own
// logic: the work completed (so not 1/2/3), every record it named exists (so not
// 4), the invocation was well formed (so not 20), and the evidence is not in
// doubt (so not 10). What happened is that a gate the caller asked to enforce
// fired on real findings, which is exactly what 5 means — and a CI step must be
// able to route it to a human rather than to whoever fixes broken invocations.
func usedSetBreakingErr(used *usedByResult) error {
	if used == nil {
		return nil
	}
	reached := used.Reached()
	if len(reached) == 0 {
		return nil
	}
	names := make([]string, 0, len(reached))
	for _, s := range reached {
		names = append(names, s.Symbol.String())
	}
	return &exitError{code: ExitPolicy, msg: fmt.Sprintf(
		"breaking within the used set: %d of %d breaking change(s) are called by %s: %v",
		len(reached), len(used.Symbols), used.Consumer.Path(), names)}
}

// -- text output --

func printInterfaceDiff(diff ifacedomain.InterfaceDiff, used *usedByResult, stdout io.Writer) error {
	a := diff.RecordA.Coordinate
	b := diff.RecordB.Coordinate

	// The headline states the fact and the scope it holds over, on one line. A
	// zero here is "no exported signature changed" and nothing else: a measured
	// zero-breaking bump can still change what the code does, so the line must
	// not offer the reader a verdict it has not earned.
	if _, err := fmt.Fprintf(stdout,
		"%d breaking change(s) among exported Go declarations (%s@%s → %s@%s); "+
			"behaviour and string-keyed registries are outside this comparison\n",
		diff.BreakingCount(), a.Path(), a.Version(), b.Path(), b.Version()); err != nil {
		return fmt.Errorf("writing headline: %w", err)
	}
	if _, err := fmt.Fprintf(stdout, "added: %d  removed: %d  changed: %d  spelling: %d\n",
		len(diff.Added), len(diff.Removed), len(diff.Changed), len(diff.Spelling)); err != nil {
		return fmt.Errorf("writing counts: %w", err)
	}

	if err := printPackageDelta(diff, stdout); err != nil {
		return err
	}
	if err := printSymbolSection(stdout, "Removed", "-", diff.Removed); err != nil {
		return err
	}
	if err := printChangeSection(stdout, "Changed", diff.Changed); err != nil {
		return err
	}
	if err := printSymbolSection(stdout, "Added", "+", diff.Added); err != nil {
		return err
	}
	if err := printChangeSection(stdout,
		"Spelling (type-alias-equivalent, not breaking)", diff.Spelling); err != nil {
		return err
	}
	if err := printRegistrySection(diff, stdout); err != nil {
		return err
	}
	if err := printExcludedSection(diff, stdout); err != nil {
		return err
	}
	if err := printUsedBySection(used, stdout); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(stdout, "\n%s\n", interfaceDiffCoverageNote); err != nil {
		return fmt.Errorf("writing coverage note: %w", err)
	}
	// A +incompatible side is a version the module system resolves under
	// pre-modules rules, so the two coordinates being compared are not two points
	// on one module's version line in the way the rest of this output implies.
	return writePreModulesCaveatForSet(stdout, []coordinate.ModuleCoordinate{
		diff.RecordA.Coordinate, diff.RecordB.Coordinate,
	})
}

func printPackageDelta(diff ifacedomain.InterfaceDiff, stdout io.Writer) error {
	for _, p := range diff.PackagesRemoved {
		if _, err := fmt.Fprintf(stdout, "\npackage removed: %s\n", p); err != nil {
			return fmt.Errorf("writing package delta: %w", err)
		}
	}
	for _, p := range diff.PackagesAdded {
		if _, err := fmt.Fprintf(stdout, "\npackage added: %s\n", p); err != nil {
			return fmt.Errorf("writing package delta: %w", err)
		}
	}
	return nil
}

func printSymbolSection(stdout io.Writer, title, marker string, syms []ifacedomain.Symbol) error {
	if len(syms) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(stdout, "\n%s (%d):\n", title, len(syms)); err != nil {
		return fmt.Errorf("writing section header: %w", err)
	}
	for _, s := range syms {
		if _, err := fmt.Fprintf(stdout, "  %s %s\n", marker, s.ID.String()); err != nil {
			return fmt.Errorf("writing symbol: %w", err)
		}
		if s.Signature != "" {
			if _, err := fmt.Fprintf(stdout, "      %s\n", ifacedomain.NormalizeSignature(s.Signature)); err != nil {
				return fmt.Errorf("writing signature: %w", err)
			}
		}
	}
	return nil
}

func printChangeSection(stdout io.Writer, title string, changes []ifacedomain.SignatureChange) error {
	if len(changes) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(stdout, "\n%s (%d):\n", title, len(changes)); err != nil {
		return fmt.Errorf("writing section header: %w", err)
	}
	for _, c := range changes {
		if _, err := fmt.Fprintf(stdout, "  ~ %s\n      - %s\n      + %s\n",
			c.Symbol.String(),
			ifacedomain.NormalizeSignature(c.From),
			ifacedomain.NormalizeSignature(c.To)); err != nil {
			return fmt.Errorf("writing change: %w", err)
		}
	}
	return nil
}

func printRegistrySection(diff ifacedomain.InterfaceDiff, stdout io.Writer) error {
	if len(diff.Registries) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(stdout,
		"\nString-keyed registries (%d) — a contract outside this comparison:\n",
		len(diff.Registries)); err != nil {
		return fmt.Errorf("writing registry header: %w", err)
	}
	for _, r := range diff.Registries {
		if _, err := fmt.Fprintf(stdout, "  ! %s → %s  [in %s]\n",
			r.Symbol.String(), r.Shape, r.Side); err != nil {
			return fmt.Errorf("writing registry surface: %w", err)
		}
	}
	if _, err := fmt.Fprintln(stdout,
		"    The keys are strings resolved at run time; this command does not read them, "+
			"so a key renamed or dropped is not in any count above."); err != nil {
		return fmt.Errorf("writing registry note: %w", err)
	}
	return nil
}

func printExcludedSection(diff ifacedomain.InterfaceDiff, stdout io.Writer) error {
	if len(diff.ExcludedTestdataPackages) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(stdout,
		"\nExcluded from the comparison (%d testdata package(s), not part of any module's API):\n",
		len(diff.ExcludedTestdataPackages)); err != nil {
		return fmt.Errorf("writing exclusion header: %w", err)
	}
	for _, p := range diff.ExcludedTestdataPackages {
		if _, err := fmt.Fprintf(stdout, "  · %s\n", p); err != nil {
			return fmt.Errorf("writing exclusion: %w", err)
		}
	}
	return nil
}

func printUsedBySection(used *usedByResult, stdout io.Writer) error {
	if used == nil {
		return nil
	}
	if _, err := fmt.Fprintf(stdout,
		"\nUsed by %s (walk %q, frame %s, %d module versions in scope):\n",
		used.Consumer.Path(), used.WalkID, used.WalkFrame, used.ScopeSize); err != nil {
		return fmt.Errorf("writing used-by header: %w", err)
	}
	// The walk was found by the module path the manifest declares, so the scope
	// above is that walk's build list and not, provably, the one this go.mod
	// resolves to now. Stated here because "your code does not call the removed
	// symbol" is exactly the answer an out-of-date scope gets wrong quietly.
	if used.GoMod != "" {
		if _, err := fmt.Fprintf(stdout, "  %s\n", strings.TrimPrefix(manifestStalenessNote(used.GoMod), "; ")); err != nil {
			return fmt.Errorf("writing used-by staleness: %w", err)
		}
	}
	if !used.CallGraphFound {
		if _, err := fmt.Fprintf(stdout,
			"  no stored call graph for %s — nothing below is a measurement of reach; "+
				"run: kanonarion local .\n", used.Consumer.Path()); err != nil {
			return fmt.Errorf("writing used-by absence: %w", err)
		}
	}
	if len(used.Symbols) == 0 {
		if _, err := fmt.Fprintln(stdout, "  no breaking change to join."); err != nil {
			return fmt.Errorf("writing used-by empty: %w", err)
		}
	}
	for _, s := range used.Symbols {
		class := "changed"
		if s.Removed {
			class = "removed"
		}
		switch {
		case !s.Measurable:
			if _, err := fmt.Fprintf(stdout, "  ? %s [%s] — unmeasured: no call-graph node for this kind\n",
				s.Symbol.String(), class); err != nil {
				return fmt.Errorf("writing used-by row: %w", err)
			}
		case s.Sites == 0:
			if _, err := fmt.Fprintf(stdout, "  · %s [%s] — no call edge recorded from %s\n",
				s.Symbol.String(), class, used.Consumer.Path()); err != nil {
				return fmt.Errorf("writing used-by row: %w", err)
			}
		default:
			if _, err := fmt.Fprintf(stdout, "  ! %s [%s] — %s\n",
				s.Symbol.String(), class, countOf(s.Sites, "call sites")); err != nil {
				return fmt.Errorf("writing used-by row: %w", err)
			}
			for _, c := range s.Callers {
				loc := c.File
				if c.Line > 0 {
					loc = fmt.Sprintf("%s:%d", c.File, c.Line)
				}
				if loc == "" {
					loc = "(position not recorded)"
				}
				if _, err := fmt.Fprintf(stdout, "      %s  %s\n", c.ID, loc); err != nil {
					return fmt.Errorf("writing used-by caller: %w", err)
				}
			}
		}
	}
	if _, err := fmt.Fprintf(stdout, "  %s\n", usedByCoverageNote); err != nil {
		return fmt.Errorf("writing used-by coverage note: %w", err)
	}
	return nil
}

// -- JSON output --

// The field names follow the interface record's own short names — funcs,
// consts, vars — because those are what interface-show emits and what the
// stored record is keyed on. Renaming them here would make the two commands
// disagree about what the same declaration is called.
type interfaceDiffJSON struct {
	ModuleA          string                `json:"module_a"`
	ModuleB          string                `json:"module_b"`
	BreakingCount    int                   `json:"breaking_count"`
	Scope            string                `json:"scope"`
	PackagesAdded    []string              `json:"packages_added"`
	PackagesRemoved  []string              `json:"packages_removed"`
	Added            []symbolDeltaJSON     `json:"added"`
	Removed          []symbolDeltaJSON     `json:"removed"`
	Changed          []signatureChangeJSON `json:"changed"`
	Spelling         []signatureChangeJSON `json:"spelling"`
	Registries       []registrySurfaceJSON `json:"registries"`
	ExcludedTestdata []string              `json:"excluded_testdata_packages"`
	UsedBy           *usedByJSON           `json:"used_by,omitempty"`
}

type symbolDeltaJSON struct {
	Package   string `json:"package"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Signature string `json:"signature,omitempty"`
}

type signatureChangeJSON struct {
	Package string `json:"package"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	From    string `json:"from"`
	To      string `json:"to"`
}

type registrySurfaceJSON struct {
	Package string `json:"package"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Shape   string `json:"shape"`
	Side    string `json:"side"`
}

type usedByJSON struct {
	GoMod  string `json:"gomod"`
	WalkID string `json:"walk_id"`
	// WalkFrame is the GOOS/GOARCH the answering walk resolved for, or
	// "unrecorded" for a walk written before the frame was projected.
	WalkFrame      string           `json:"walk_frame"`
	Consumer       string           `json:"consumer"`
	ScopeSize      int              `json:"scope_size"`
	CallGraphFound bool             `json:"call_graph_found"`
	ReachedCount   int              `json:"reached_count"`
	Symbols        []usedSymbolJSON `json:"symbols"`
	Coverage       string           `json:"coverage"`
}

type usedSymbolJSON struct {
	Package    string           `json:"package"`
	Kind       string           `json:"kind"`
	Name       string           `json:"name"`
	Class      string           `json:"class"`
	NodeID     string           `json:"node_id,omitempty"`
	Measurable bool             `json:"measurable"`
	Sites      int              `json:"sites"`
	Callers    []usedCallerJSON `json:"callers"`
}

type usedCallerJSON struct {
	ID   string `json:"id"`
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
}

func toInterfaceDiffJSON(diff ifacedomain.InterfaceDiff, used *usedByResult) interfaceDiffJSON {
	a := diff.RecordA.Coordinate
	b := diff.RecordB.Coordinate

	out := interfaceDiffJSON{
		ModuleA:       a.Path() + "@" + a.Version(),
		ModuleB:       b.Path() + "@" + b.Version(),
		BreakingCount: diff.BreakingCount(),
		Scope:         interfaceDiffCoverageNote,
		// Every collection is non-nil so the machine-readable answer spells an
		// empty result "[]" rather than "null".
		PackagesAdded:    nonNilStrings(diff.PackagesAdded),
		PackagesRemoved:  nonNilStrings(diff.PackagesRemoved),
		Added:            toSymbolDeltasJSON(diff.Added),
		Removed:          toSymbolDeltasJSON(diff.Removed),
		Changed:          toSignatureChangesJSON(diff.Changed),
		Spelling:         toSignatureChangesJSON(diff.Spelling),
		Registries:       toRegistriesJSON(diff.Registries),
		ExcludedTestdata: nonNilStrings(diff.ExcludedTestdataPackages),
	}
	if used != nil {
		out.UsedBy = toUsedByJSON(used)
	}
	return out
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func toSymbolDeltasJSON(syms []ifacedomain.Symbol) []symbolDeltaJSON {
	out := make([]symbolDeltaJSON, 0, len(syms))
	for _, s := range syms {
		out = append(out, symbolDeltaJSON{
			Package:   s.ID.Package,
			Kind:      string(s.ID.Kind),
			Name:      s.ID.Name,
			Signature: ifacedomain.NormalizeSignature(s.Signature),
		})
	}
	return out
}

func toSignatureChangesJSON(changes []ifacedomain.SignatureChange) []signatureChangeJSON {
	out := make([]signatureChangeJSON, 0, len(changes))
	for _, c := range changes {
		out = append(out, signatureChangeJSON{
			Package: c.Symbol.Package,
			Kind:    string(c.Symbol.Kind),
			Name:    c.Symbol.Name,
			From:    ifacedomain.NormalizeSignature(c.From),
			To:      ifacedomain.NormalizeSignature(c.To),
		})
	}
	return out
}

func toRegistriesJSON(surfaces []ifacedomain.RegistrySurface) []registrySurfaceJSON {
	out := make([]registrySurfaceJSON, 0, len(surfaces))
	for _, r := range surfaces {
		out = append(out, registrySurfaceJSON{
			Package: r.Symbol.Package,
			Kind:    string(r.Symbol.Kind),
			Name:    r.Symbol.Name,
			Shape:   r.Shape,
			Side:    string(r.Side),
		})
	}
	return out
}

func toUsedByJSON(used *usedByResult) *usedByJSON {
	out := &usedByJSON{
		GoMod:          used.GoMod,
		WalkID:         used.WalkID,
		WalkFrame:      used.WalkFrame,
		Consumer:       used.Consumer.Path() + "@" + used.Consumer.Version(),
		ScopeSize:      used.ScopeSize,
		CallGraphFound: used.CallGraphFound,
		ReachedCount:   len(used.Reached()),
		Symbols:        make([]usedSymbolJSON, 0, len(used.Symbols)),
		Coverage:       usedByCoverageNote,
	}
	for _, s := range used.Symbols {
		class := "changed"
		if s.Removed {
			class = "removed"
		}
		callers := make([]usedCallerJSON, 0, len(s.Callers))
		for _, c := range s.Callers {
			callers = append(callers, usedCallerJSON(c))
		}
		out.Symbols = append(out.Symbols, usedSymbolJSON{
			Package:    s.Symbol.Package,
			Kind:       string(s.Symbol.Kind),
			Name:       s.Symbol.Name,
			Class:      class,
			NodeID:     s.NodeID,
			Measurable: s.Measurable,
			Sites:      s.Sites,
			Callers:    callers,
		})
	}
	return out
}
