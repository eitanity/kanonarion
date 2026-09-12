package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// usedByCoverageNote states the limit of the call-graph join. A symbol reported
// as not reached is not a symbol proved unused: the graph records call edges, so
// a reference that is not a call is not in it to be found.
//
// It is one sentence for both commands that join a project's graph, so a reader
// who has met the limit on one meets the same words on the other.
const usedByCoverageNote = "coverage: reached/not-reached is measured over recorded CALL EDGES in the stored " +
	"call graph. Method values (a method referenced as a value rather than called) are not " +
	"recorded as edges, so a symbol shown as not reached may still be referenced that way. " +
	"Types, constants and variables have no call-graph node at all and are reported as " +
	"unmeasured rather than as unreached."

// consumerSelector is how a caller names the analysed project: a manifest, or a
// walk by id. Neither given means the working tree's own go.mod, which is what
// every --gomod flag in this CLI falls back to.
type consumerSelector struct {
	gomod     string
	walkID    string
	toolchain gotoolchain.Version
}

// consumerBinding is one analysed project resolved for a call-graph join: the
// walk that names the build, the version set it pins, and the project's own
// stored call graph together with what that graph could not see.
//
// It is shared rather than resolved per command because two commands ask the
// same question of the same project — `interface-diff --used-by` joins a version
// delta against it, `usage` joins one module's whole surface — and two
// resolutions are free to pick different walks and answer differently.
type consumerBinding struct {
	// GoMod is the manifest that named the project, empty when a walk id did.
	GoMod  string
	WalkID string
	// choice is how WalkID was arrived at: which rule picked it out of the
	// store's walks of this project, and what that rule could compare against.
	choice walkChoice
	// WalkFrame is the GOOS/GOARCH the answering walk resolved for, carrying the
	// basis that says which: "platform", "not_platform_scoped" for a
	// module-rooted walk, or "unrecorded".
	WalkFrame walkdomain.WalkFrame
	// WalkScope is the dependency scope the answering walk covered. Both these
	// joins ask what the project's own code does, so they select a code-scope
	// walk; the scope is carried so the answer names the build it came from.
	WalkScope walkdomain.WalkScope
	Consumer  coordinate.ModuleCoordinate
	// Pinned is true when the caller named the walk, so nothing was chosen for
	// them and there is no selection or manifest staleness to disclose.
	Pinned bool
	// ScopeSize is how many module versions the walk pins, and Scope is the set
	// itself, for the reads that resolve a record within one build.
	ScopeSize int
	Scope     coordinate.ModuleSet
	// Record is the project's own stored call graph. Zero when CallGraphFound is
	// false, in which case every "not reached" below it is an absence of
	// evidence rather than evidence of absence.
	Record         cgdomain.CallGraphRecord
	CallGraphFound bool
	// Positions indexes the record's nodes by ID, so a caller can be reported
	// with the file and line it is declared at.
	Positions map[string]cgdomain.SourcePosition
	// DroppedPackages are the project's own packages that failed to typecheck,
	// whose edges were therefore dropped.
	//
	// It is disclosed for the same reason 'callers' discloses it: a reach count
	// joined against this graph cannot see a call site in a package that
	// produced no SSA. Without this line the commands disagree in the worst
	// direction — one states the gap and the other prints a bare "not reached"
	// over the same missing edges.
	DroppedPackages []string
}

// bindConsumer resolves the analysed project a call-graph join answers about:
// the walk that names its build, and its own stored call graph.
//
// The code scope is the question. Both joins ask what the project's OWN code
// does, so the build they are answered in is the one that code compiles into.
// There is no flag to widen it, and a tool- or project-scope walk that happened
// to be walked more recently is not allowed to stand in for one.
//
// Nothing here parses the project's source. The answer is a read of what was
// already measured, so it is reproducible and it cannot disagree with what
// `callers` would say about the same symbol.
func bindConsumer(
	ctx context.Context,
	walks QueryWalksUseCase,
	graphs QueryCallGraphUseCase,
	sel consumerSelector,
) (*consumerBinding, error) {
	var (
		choice walkChoice
		rec    walkdomain.WalkRecord
		pinned bool
		err    error
	)
	switch {
	case sel.walkID != "":
		// The sentinel is preserved rather than answered here: a miss is reported
		// with the store-corpus statement, which is written to a channel this
		// resolution does not hold.
		if rec, err = walks.GetWalk(ctx, sel.walkID); err != nil {
			return nil, fmt.Errorf("loading walk %q: %w", sel.walkID, err)
		}
		choice, pinned = pinnedWalkChoice(rec), true
	default:
		if choice, err = latestWalkForGoMod(ctx, walks, sel.gomod, scopeCode); err != nil {
			return nil, err
		}
		if rec, err = choice.walkRecord(ctx, walks); err != nil {
			return nil, err
		}
	}

	scope := walkModuleSet(rec)
	b := &consumerBinding{
		GoMod:     choice.manifestPath,
		WalkID:    rec.ID,
		choice:    choice,
		WalkFrame: rec.Graph.Frame(),
		WalkScope: rec.Scope,
		Consumer:  rec.Target,
		Pinned:    pinned,
		ScopeSize: scope.Len(),
		Scope:     scope,
	}

	cg, found, err := graphs.GetCallGraphRecordFrom(ctx, rec.Target, cgapp.PipelineVersion,
		cgdomain.ComposeRequest{ToolchainPreference: sel.toolchain})
	if err != nil {
		return nil, fmt.Errorf("loading call graph for %s: %w", rec.Target, err)
	}
	b.CallGraphFound = found
	if !found {
		return b, nil
	}
	b.Record = cg
	b.Positions = make(map[string]cgdomain.SourcePosition, len(cg.Nodes))
	for _, n := range cg.Nodes {
		b.Positions[n.ID] = n.Position
	}
	if cg.OverallStatus == cgdomain.CallGraphStatusPartial {
		b.DroppedPackages = append(b.DroppedPackages, cg.FailedPackages...)
		sort.Strings(b.DroppedPackages)
	}
	return b, nil
}

// nodesByID indexes the project's own call-graph nodes, so an edge endpoint can
// be read for the facts an edge does not carry: which package declares it, and
// whether it is a test declaration.
func (b *consumerBinding) nodesByID() map[string]cgdomain.CallNode {
	out := make(map[string]cgdomain.CallNode, len(b.Record.Nodes))
	for _, n := range b.Record.Nodes {
		out[n.ID] = n
	}
	return out
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

// writeConsumerDroppedPackages discloses that some of the project's own packages
// failed to typecheck, so a count joined against its graph cannot see call sites
// declared in them.
//
// It exists so every command joining one project's graph says the same thing
// about the same condition. A silent "not reached" over a package that produced
// no SSA is the same false negative the edge queries refuse to print bare.
func writeConsumerDroppedPackages(stdout io.Writer, b *consumerBinding) error {
	if len(b.DroppedPackages) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(stdout,
		"  %d of %s own package(s) did not typecheck when it was analysed, so their edges were "+
			"dropped: %s. A call site declared in one of them cannot appear in any count above — "+
			"those declarations are unmeasured, not unreached.\n",
		len(b.DroppedPackages), b.Consumer.Path(), strings.Join(b.DroppedPackages, ", ")); err != nil {
		return fmt.Errorf("writing consumer dropped packages: %w", err)
	}
	return nil
}
