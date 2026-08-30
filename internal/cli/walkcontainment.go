package cli

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// walkSearchLimit is how many of the newest walks the containment search reads.
// It is a bound on cost — each candidate costs a whole walk record read — and
// not a statement that older walks hold nothing.
const walkSearchLimit = 50

// walkContainmentRule names how a coordinate question that named no walk got
// one, for the surfaces that have to state it.
type walkContainmentRule string

const (
	// walkHeldPinned is the caller naming the walk with --walk-id. Nothing was
	// ranked.
	walkHeldPinned walkContainmentRule = "pinned"
	// walkHeldByGoMod is the walk a manifest named: the latest project walk of
	// the requested scope for a --gomod path, or for the working directory's own
	// go.mod. It is the default rooting, and the only one that answers a question
	// about the build the caller is standing in.
	walkHeldByGoMod walkContainmentRule = "gomod-rooted"
	// walkHeldByConsumer is a walk rooted at a build that consumes the
	// coordinate. Reached only under --any-build.
	walkHeldByConsumer walkContainmentRule = "consumer-rooted"
	// walkHeldSelfRootedOnly is the fallback where the only walks holding the
	// coordinate are rooted AT it. The answer is then drawn from the module's own
	// dependency graph, which is a different question, so it is stated.
	walkHeldSelfRootedOnly walkContainmentRule = "self-rooted-only"
)

// walkContainment is the walk a question about a coordinate is answered in, and
// the rule that got it there — a manifest, a walk id, or the store-wide search.
//
// The rule is carried rather than discarded because it decides what the answer
// means. A walk rooted AT the coordinate holds that module's own dependency
// closure, so it answers "who depends on this" with the module's own
// dependencies — a plausible number from the one build where the question has no
// consumer in it.
type walkContainment struct {
	walkID string
	rule   walkContainmentRule
	// root is the answering walk's target: the build the answer is about.
	root coordinate.ModuleCoordinate
	// selfRootedPassedOver counts the walks rooted at the queried coordinate
	// that a consumer build outranked.
	selfRootedPassedOver int

	// manifest is the go.mod that named the build, and scope the dependency
	// scope it was read in. Set only for walkHeldByGoMod.
	manifest string
	scope    depScope
	// build renders the answering walk as `walk X (code scope, frame
	// linux/amd64)`, the form every other --gomod read states its build in.
	build string
	// choice is the selector's own account of which of the project's walks
	// answered and what it could not check. It rides along so the notice and the
	// JSON carry the staleness and toolchain clauses the sibling reads carry,
	// rather than a rooting that discloses less than vuln-show does.
	choice walkChoice
}

// gomodContainment is the containment a caller established by naming a manifest
// — with --gomod, or by standing in the project whose go.mod the read fell back
// to — together with the scope that manifest was projected into.
func gomodContainment(choice walkChoice, rec walkdomain.WalkRecord, scope depScope) walkContainment {
	return walkContainment{
		walkID:   rec.ID,
		rule:     walkHeldByGoMod,
		root:     rec.Target,
		manifest: choice.manifestPath,
		scope:    scope,
		build:    fmt.Sprintf("walk %s (%s, frame %s)", rec.ID, walkScopeLabel(rec.Scope), rec.Graph.Frame()),
		choice:   choice,
	}
}

// ambiguousBuildRefusal is the refusal a containment search returns when more
// than one consumer build holds the coordinate and the caller named none.
//
// It is a type rather than a bare error so a caller that can degrade instead of
// failing — the call-graph build-list discovery, which treats a search that
// finds nothing as no answer at all — can tell an ambiguity from an absence and
// say which one it hit. It carries ExitConfig on its chain, as every other
// "name the build you mean" refusal does.
type ambiguousBuildRefusal struct {
	coord      coordinate.ModuleCoordinate
	candidates []walkports.WalkSummary
	err        *exitError
}

func (e *ambiguousBuildRefusal) Error() string { return e.err.Error() }
func (e *ambiguousBuildRefusal) Unwrap() error { return e.err }

// buildListRefusalJSON is the refusal as a document: the builds that hold the
// coordinate, and what to name to pick one.
//
// A refusal is a document, not a sentence. When the tool cannot choose, the
// caller has to be able to see what it was choosing between — as data, the way
// the reads that DO choose carry their walk selection — because a consumer that
// has to retry cannot parse a list of candidates out of prose on stderr.
type buildListRefusalJSON struct {
	// Coordinate is the module a build list was needed for: the argument the
	// retry names, spelled as the caller passed it.
	Coordinate string `json:"coordinate"`
	// BuildCount is how many builds hold it, so a consumer can see the refusal
	// was about a choice without walking the list.
	BuildCount int `json:"build_count"`
	// Builds are the candidates, each with the walk that answers for it and the
	// build that walk is rooted at.
	Builds []buildListCandidateJSON `json:"builds"`
	// RemedyFlag is the flag that names one of them.
	RemedyFlag string `json:"remedy_flag"`
}

// buildListCandidateJSON is one build that holds the coordinate.
type buildListCandidateJSON struct {
	WalkID string `json:"walk_id"`
	Root   string `json:"root"`
}

// document renders the refusal for the answering command's JSON.
func (e *ambiguousBuildRefusal) document(remedyFlag string) *buildListRefusalJSON {
	builds := make([]buildListCandidateJSON, 0, len(e.candidates))
	for _, c := range e.candidates {
		builds = append(builds, buildListCandidateJSON{WalkID: c.ID, Root: c.Target.String()})
	}
	return &buildListRefusalJSON{
		Coordinate: e.coord.String(),
		BuildCount: len(e.candidates),
		Builds:     builds,
		RemedyFlag: remedyFlag,
	}
}

// ambiguousBuild builds that refusal, naming every build and the walk that
// would answer for it.
//
// It refuses rather than picking the newest, on the same grounds the
// vulnerability read does: newest is not yours. Serving whichever project was
// walked last answers one project's question from another project's build, at
// exit 0. The walks are named because the remedy is to pick one.
func ambiguousBuild(coord coordinate.ModuleCoordinate, remedy string, candidates []walkports.WalkSummary) error {
	msg := fmt.Sprintf("the store holds %s in %d builds, and this question names none:", coord, len(candidates))
	for _, c := range candidates {
		msg += fmt.Sprintf("\n  walk %s  rooted at %s", c.ID, c.Target)
	}
	msg += fmt.Sprintf(
		"\nwhat a coordinate is surrounded by is a property of one build, so name the build you mean:"+
			"\n  %s"+
			"\nkanonarion walk-list lists every walk in the store", remedy)
	return &ambiguousBuildRefusal{
		coord:      coord,
		candidates: candidates,
		err:        &exitError{code: ExitConfig, msg: msg},
	}
}

// findWalkContaining returns the walk a question about coord is answered in,
// out of the walks whose graph holds it.
//
// Candidates are ranked by ROOTING first and by recency only within a rooting: a
// walk rooted at a build that consumes coord outranks a walk rooted at coord
// itself, because a question about a coordinate is nearly always a question
// about it in a build and the self-rooted walk holds no consumer to name. Two
// consumer builds are two answers, so the search refuses and names them.
//
// A walk rooted at coord is still the answer where it is the only walk holding
// it — a module vetted in isolation and walked nowhere else is legitimately
// answerable only from its own graph — and the caller is told, so that answer is
// never read as one about a build.
//
// The search is bounded, and its failure says so. A negative from a search that
// did not exhaust the population is not an absence: phrased flat, "no walk found
// containing X" reads as "this store has never seen X" while the walk holding it
// sits at position 51. That is the same rule the call-graph verdict applies —
// RESOLVED-ABSENT only where the axis was measurable — on a store search.
//
// One extra row is fetched so the search knows whether its own bound bit,
// exactly as the listings do. When it did not, the population WAS exhausted and
// the negative is stated plainly: a caveat emitted unconditionally would teach
// the reader to discount it in the case where it is real.
func findWalkContaining(
	ctx context.Context,
	uc QueryWalksUseCase,
	coord coordinate.ModuleCoordinate,
	remedy string,
) (walkContainment, error) {
	summaries, err := uc.ListWalks(ctx, walkports.WalkFilter{Limit: truncationFetchLimit(walkSearchLimit)})
	if err != nil {
		return walkContainment{}, fmt.Errorf("listing walks: %w", err)
	}
	searched, bounded := truncateList(summaries, walkSearchLimit)

	var consumers, selfRooted []walkports.WalkSummary
	held := make(map[coordinate.ModuleCoordinate]bool, len(searched))
	for _, s := range searched {
		if s.Target == coord {
			// A walk's root is a node of its own graph, so a walk rooted at the
			// coordinate holds it by construction — known from the summary, at no
			// record read.
			selfRooted = append(selfRooted, s)
			continue
		}
		if held[s.Target] {
			// An older walk of a build already known to hold the coordinate can
			// neither name a build the refusal is missing nor win the recency
			// tiebreak, so it is not worth a record read.
			continue
		}
		rec, rerr := uc.GetWalk(ctx, s.ID)
		if rerr != nil {
			continue
		}
		if !graphHolds(rec.Graph, coord) {
			continue
		}
		held[s.Target] = true
		consumers = append(consumers, s)
	}

	switch {
	case len(consumers) > 1:
		return walkContainment{}, ambiguousBuild(coord, remedy, consumers)
	case len(consumers) == 1:
		return walkContainment{
			walkID:               consumers[0].ID,
			rule:                 walkHeldByConsumer,
			root:                 consumers[0].Target,
			selfRootedPassedOver: len(selfRooted),
		}, nil
	case len(selfRooted) > 0:
		return walkContainment{walkID: selfRooted[0].ID, rule: walkHeldSelfRootedOnly, root: coord}, nil
	}

	if !bounded {
		return walkContainment{}, fmt.Errorf("no walk in this store contains %s (all %d walk(s) searched)", coord, len(searched))
	}
	// Only now is the store's own size worth a read: it is what turns "the
	// search stopped" into a number the caller can act on.
	total := len(searched)
	if all, aerr := uc.ListWalks(ctx, walkports.WalkFilter{}); aerr == nil {
		total = len(all)
	}
	return walkContainment{}, fmt.Errorf("no walk containing %s among the %d most recent walks searched — the store holds %d; "+
		"name the walk to query with --walk-id, or list them with: kanonarion walk-list --limit 0",
		coord, walkSearchLimit, total)
}

// graphHolds reports whether g has coord as a node.
func graphHolds(g walkdomain.Graph, coord coordinate.ModuleCoordinate) bool {
	for _, node := range g.Nodes {
		if node.Coordinate == coord {
			return true
		}
	}
	return false
}

// statement is the line a defaulting read prints above its answer to say which
// build the answer is about, and why that walk rather than another.
//
// It is empty for the ordinary search result — one consumer build holds the
// coordinate and nothing was passed over — because the answer line already names
// the walk and a notice on every query is a notice nobody reads. It is not empty
// for the cases where the walk decides what the answer MEANS: a manifest that
// selected one of a project's several builds, and the two rankings the search
// makes on the caller's behalf.
func (c walkContainment) statement(coord coordinate.ModuleCoordinate) string {
	switch {
	case c.rule == walkHeldByGoMod:
		// Stated on every rooted answer, unlike the two below, because the manifest
		// is what the reader can check and the walk id is not: a project walked in
		// three scopes has three answers to this question, and the line is where a
		// caller sees which of them the flags selected.
		return fmt.Sprintf("notice: %s names the build, so the answer below is %s rooted at %s%s\n",
			c.manifest, c.build, c.root, c.choice.basisNotes())
	case c.rule == walkHeldSelfRootedOnly:
		return fmt.Sprintf("notice: the only walk holding %s in this store is rooted at %s itself, so the answer below is "+
			"drawn from that module's own dependency graph and names no consuming build; walk %s\n", coord, coord, c.walkID)
	case c.rule == walkHeldByConsumer && c.selfRootedPassedOver > 0:
		return fmt.Sprintf("notice: no walk was named; walk %s was chosen because it is rooted at %s, which builds %s — "+
			"%d walk(s) rooted at %s itself were passed over, since a module has no dependents inside its own graph; "+
			"pin one with --walk-id (kanonarion walk-list lists them)\n",
			c.walkID, c.root, coord, c.selfRootedPassedOver, coord)
	}
	return ""
}

// walkSelectionJSON is the machine-readable form of the same statement, for the
// documents that carry the walk id as a field.
//
// It is a field rather than a line because a consumer reading the walk id has to
// be able to tell an id the caller pinned from one the tool picked, and — where
// the tool picked — whether it picked a build that consumes the coordinate or
// fell back to the coordinate's own walk. The two answer different questions,
// and on the JSON surface the walk id alone does not say which.
type walkSelectionJSON struct {
	// Rule is "pinned", "consumer-rooted" or "self-rooted-only".
	Rule string `json:"rule"`
	// Root is the answering walk's target: the build the answer is about.
	Root string `json:"root"`
	// SelfRootedPassedOver is how many walks rooted at the queried coordinate a
	// consumer build outranked. Always 0 for the other rules.
	SelfRootedPassedOver int `json:"self_rooted_passed_over"`
	// GoMod is the manifest that named the build and Scope the dependency scope
	// it was projected into, present only for "gomod-rooted". A consumer that
	// reads the rooting has to be able to tell a code build from a tool one:
	// they hold different modules, and on this store they differ by 235 of them.
	GoMod string `json:"gomod,omitempty"`
	Scope string `json:"scope,omitempty"`
	// Choice is the selector's account of which of the project's walks answered:
	// how many were candidates, what the manifest comparison proved, and whether
	// the answering walk's toolchain is still the one the project resolves. Same
	// object the other --gomod reads publish; absent for the rules that consult
	// no manifest.
	Choice *selectionJSON `json:"choice,omitempty"`
}

// selection renders the containment for a JSON document.
func (c walkContainment) selection() walkSelectionJSON {
	out := walkSelectionJSON{
		Rule:                 string(c.rule),
		Root:                 c.root.String(),
		SelfRootedPassedOver: c.selfRootedPassedOver,
	}
	if c.rule == walkHeldByGoMod {
		choice := c.choice.selection()
		out.GoMod, out.Scope, out.Choice = c.manifest, string(c.scope), &choice
	}
	return out
}

// pinnedContainment is the containment a caller established with --walk-id.
func pinnedContainment(rec walkdomain.WalkRecord) walkContainment {
	return walkContainment{walkID: rec.ID, rule: walkHeldPinned, root: rec.Target}
}
