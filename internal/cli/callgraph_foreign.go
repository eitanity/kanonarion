package cli

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// foreignDraw is how much of one answer came from nodes belonging to a module
// the answering record is not about.
//
// Target selection for a call graph analysis admits every package under the
// analysed module's path, and Go module paths nest, so a record routinely holds
// a separately published module's code built with bodies. A query landing on
// those nodes is answered out of a PARTIAL copy of that module — the parent
// built whatever its own build reached, not the module — and the answer is not
// the one that module's own record would give. Saying so is the whole point:
// the count without the statement reads as a measurement of the named module.
type foreignDraw struct {
	// rows is how many of the answer's rows are foreign-module nodes, out of
	// total. Both are carried because "9 of 12" and "9 of 9" are different
	// answers and only the pair distinguishes them.
	rows  int
	total int
	// modules are the foreign modules the rows belong to, sorted and
	// deduplicated. They are kept as values rather than as rendered labels so the
	// JSON answer fields the path and version instead of parsing prose back out
	// of the sentence the text prints.
	modules []domain.ForeignModule
	// holders are the records that held them, rendered "path@version", sorted and
	// deduplicated. A holder is always a coordinate, so there is no unversioned
	// case to preserve.
	holders []string
}

// drawn reports whether any part of the answer came from a foreign module.
func (d foreignDraw) drawn() bool { return d.rows > 0 }

// clause renders the statement appended to an answer line. noun is the plural
// the answer counts in ("callers", "callees", "implementers").
func (d foreignDraw) clause(noun string) string {
	if !d.drawn() {
		return ""
	}
	return fmt.Sprintf("; %d of %d %s are nodes of a module the answering record is not about — %s, built with bodies inside %s — so that module's own record, not this one, is the measurement of it",
		d.rows, d.total, noun,
		joinWithOverflow(renderedModules(d.modules), 3), joinWithOverflow(d.holders, 3))
}

// renderedModules is the foreign modules as a reader sees them, in the order
// they were sorted into.
func renderedModules(mods []domain.ForeignModule) []string {
	out := make([]string, 0, len(mods))
	for _, m := range mods {
		out = append(out, m.String())
	}
	return out
}

// foreignModuleJSONs fields the foreign modules a draw touched, for a JSON
// answer.
func (d foreignDraw) foreignModuleJSONs() []foreignModuleJSON {
	if !d.drawn() {
		return nil
	}
	return toForeignModulesJSON(d.modules)
}

// foreignModuleIndex answers, for one query, which foreign modules each
// answering record built with bodies.
//
// It reads the store's denormalised column, never a composed record. That is the
// point of the column and it is the difference between qualifying an answer and
// changing what an answer costs: an edge query is served out of the edge table
// alone, and composing a record to learn one small set pays a decompress, a full
// unmarshal, an edge reconstruction and a seal check for a value that is empty on
// almost every record in the store.
//
// It caches per query because one answer's rows come from a handful of
// coordinates and the same coordinate would otherwise be asked once per row.
type foreignModuleIndex struct {
	uc    QueryCallGraphUseCase
	sc    buildScope
	byKey map[string][]domain.ForeignModule
}

func newForeignModuleIndex(uc QueryCallGraphUseCase, sc buildScope) *foreignModuleIndex {
	return &foreignModuleIndex{uc: uc, sc: sc, byKey: map[string][]domain.ForeignModule{}}
}

// forRecord returns the foreign modules the served record at this coordinate and
// pipeline version built with bodies. A coordinate the store cannot serve
// contributes none, which is the truthful reading: nothing said it held any.
func (ix *foreignModuleIndex) forRecord(ctx context.Context, modulePath, moduleVersion, pipelineVersion string) ([]domain.ForeignModule, error) {
	key := modulePath + "@" + moduleVersion + "\x00" + pipelineVersion
	if mods, ok := ix.byKey[key]; ok {
		return mods, nil
	}
	coord, err := coordinate.NewModuleCoordinate(modulePath, moduleVersion)
	if err != nil {
		return nil, fmt.Errorf("call graph record %s@%s names no module: %w", modulePath, moduleVersion, err)
	}
	mods, found, gerr := ix.uc.ForeignModulesBuilt(ctx, coord, pipelineVersion, ix.sc.toolchain)
	if gerr != nil {
		return nil, fmt.Errorf("reading which foreign modules the record for %s built: %w", coord, gerr)
	}
	if !found {
		mods = nil
	}
	ix.byKey[key] = mods
	return mods, nil
}

// foreignDrawOfEdges classifies an edge answer: how many of its rows name a node
// belonging to a module the record that holds the edge is not about.
//
// callerSide selects which end of the edge the answer is a list OF — the caller
// for a callers query, the callee for a callees query. The other end is the
// queried symbol and says nothing about where the answer came from.
func foreignDrawOfEdges(ctx context.Context, ix *foreignModuleIndex, refs []ports.CallEdgeRef, callerSide bool) (foreignDraw, error) {
	d := foreignDraw{total: len(refs)}
	modules := map[domain.ForeignModule]struct{}{}
	holders := map[string]struct{}{}
	for _, ref := range refs {
		mods, err := ix.forRecord(ctx, ref.ModulePath, ref.ModuleVersion, ref.PipelineVersion)
		if err != nil {
			return foreignDraw{}, err
		}
		if len(mods) == 0 {
			continue
		}
		id := ref.ToID
		if callerSide {
			id = ref.FromID
		}
		fm, ok := domain.ForeignModuleOwning(mods, id)
		if !ok {
			continue
		}
		d.rows++
		modules[fm] = struct{}{}
		holders[ref.ModulePath+"@"+ref.ModuleVersion] = struct{}{}
	}
	d.modules, d.holders = sortedForeignModules(modules), sortedLabels(holders)
	return d, nil
}

// foreignDrawOfNodes classifies a TRANSITIVE answer, which is a list of reached
// nodes rather than of edges.
//
// It counts nodes and not edges because that is what the answer above it lists:
// a walk reaches one node over several edges, so counting edges would state a
// proportion of a population the reader cannot see. A node introduced by more
// than one record counts as foreign when any of them says so — the reader is
// being told a partial copy answered, and one is enough for that to be true.
func foreignDrawOfNodes(ctx context.Context, ix *foreignModuleIndex, edges []ports.CallEdgeRef, nodes []string, callerSide bool) (foreignDraw, error) {
	byNode := make(map[string][]ports.CallEdgeRef, len(nodes))
	for _, ref := range edges {
		id := ref.ToID
		if callerSide {
			id = ref.FromID
		}
		byNode[id] = append(byNode[id], ref)
	}
	d := foreignDraw{total: len(nodes)}
	modules := map[domain.ForeignModule]struct{}{}
	holders := map[string]struct{}{}
	for _, id := range nodes {
		for _, ref := range byNode[id] {
			mods, err := ix.forRecord(ctx, ref.ModulePath, ref.ModuleVersion, ref.PipelineVersion)
			if err != nil {
				return foreignDraw{}, err
			}
			fm, ok := domain.ForeignModuleOwning(mods, id)
			if !ok {
				continue
			}
			d.rows++
			modules[fm] = struct{}{}
			holders[ref.ModulePath+"@"+ref.ModuleVersion] = struct{}{}
			break
		}
	}
	d.modules, d.holders = sortedForeignModules(modules), sortedLabels(holders)
	return d, nil
}

// writeForeignTransitiveAnswer is writeForeignEdgeAnswer for a transitive walk,
// whose answer is a node list.
func writeForeignTransitiveAnswer(ctx context.Context, ix *foreignModuleIndex, stdout io.Writer, kind, symbolID string, edges []ports.CallEdgeRef, nodes []string, callerSide bool) error {
	d, err := foreignDrawOfNodes(ctx, ix, edges, nodes, callerSide)
	if err != nil {
		return err
	}
	if !d.drawn() {
		return nil
	}
	if _, werr := fmt.Fprintf(stdout, "answer: RESOLVED-PRESENT — %s of %s%s\n",
		countOf(len(nodes), kind), symbolID, d.clause(kind)); werr != nil {
		return fmt.Errorf("writing answer: %w", werr)
	}
	return nil
}

// sortedForeignModules is the deterministic rendering order for a set of
// foreign modules, taken from the domain's own comparator so the answer line
// and the record's own axis list them alike.
func sortedForeignModules(set map[domain.ForeignModule]struct{}) []domain.ForeignModule {
	out := make([]domain.ForeignModule, 0, len(set))
	for m := range set {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return domain.ForeignModuleLess(out[i], out[j]) })
	return out
}

// sortedLabels is the deterministic rendering order for a set of labels.
func sortedLabels(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// writeForeignEdgeAnswer states, on a NON-EMPTY callers/callees answer, that
// part of it was drawn from a module the answering record is not about.
//
// It prints only when that happened, the way the --exclude-tests scope line
// prints only when the reader narrowed the query: there is nothing to say about
// an answer drawn wholly from the module's own nodes, and a line on every answer
// would be noise on every answer. An empty answer cannot have been drawn from
// anything, so this is not printed there and the statement is never made twice.
//
// The outcome token is RESOLVED-PRESENT, the same one the implementers query
// prints for a non-empty answer: rows were found, and what needs saying is where
// they came from, not whether they exist.
func writeForeignEdgeAnswer(ctx context.Context, ix *foreignModuleIndex, stdout io.Writer, kind, symbolID string, refs []ports.CallEdgeRef, callerSide bool) error {
	d, err := foreignDrawOfEdges(ctx, ix, refs, callerSide)
	if err != nil {
		return err
	}
	if !d.drawn() {
		return nil
	}
	if _, werr := fmt.Fprintf(stdout, "answer: RESOLVED-PRESENT — %s of %s%s\n",
		countOf(len(refs), kind), symbolID, d.clause(kind)); werr != nil {
		return fmt.Errorf("writing answer: %w", werr)
	}
	return nil
}
