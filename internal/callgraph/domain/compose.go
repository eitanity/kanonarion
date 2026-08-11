package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// ErrNoRecordsToCompose is returned by Compose when handed no records. It is a
// programming error rather than an absence: absence is reported by the store as
// "not found", and composing nothing has no meaningful answer.
var ErrNoRecordsToCompose = errors.New("no call graph records to compose")

// CallGraphConflict is two call graph records that composition must not resolve
// by picking.
//
// It reports three disagreements, and keeping them distinct is the point.
//
//   - "analysis_source": the ledger holds records built from different KINDS of
//     source — a fetched module zip and a working tree — for one coordinate, and
//     the reader did not say which it wanted. Neither supersedes the other; they
//     are answers about different bytes.
//   - "artefact_identity": two identities for one pinned module version, which
//     means the same module at the same version yielded two different sets of
//     bytes. There is no ladder between answers about different bytes.
//   - "call_graph": two records describing the SAME artefact at the SAME
//     completeness that disagree about the graph. That narrow case is evidence of
//     non-determinism in the analyser and is worth surfacing rather than absorbing.
//
// The third is deliberately narrow, and narrower than it first looks. A call
// graph is NOT a function of the module's own bytes plus the analyser version:
// devirtualisation is gated on how much of the dependency closure was built, so
// a run with more of the closure available resolves interface dispatch an
// earlier run could not, and the graph grows edges without any input changing.
// Runs that differ that way differ in COMPLETENESS, the ladder orders them, and
// the more complete graph is strictly better evidence. Only when the ladder
// cannot separate two records is a disagreement between them a finding rather
// than a refinement.
//
// It mirrors fetch's Divergence, licence's LicenceConflict and iface's
// InterfaceConflict, including reporting the content hashes of the records
// carrying each value.
//
// Every conflict names a remedy. A refusal the store rules make permanent and
// that says nothing about what to run is a dead end: the reader is left to guess
// at --force, and guessing at --force is exactly what a caller should not do.
type CallGraphConflict struct {
	// Coordinate is the module and version the disagreeing records describe.
	Coordinate coordinate.ModuleCoordinate

	// PipelineVersion is the pipeline version every conflicting record was
	// written under.
	PipelineVersion string

	// Field names what the records disagree on: one of ConflictFields.
	Field string

	// Values are the distinct values recorded for Field, sorted, so the report is
	// stable across runs.
	Values []string

	// ContentHashes name the records carrying each of Values, in the same order.
	ContentHashes []string
}

// The field names a CallGraphConflict can carry. They are constants rather than
// literals at the three sites that raise them so that Remedy, and the contract
// test that pushes every remedy line through the CLI's own parser, enumerate the
// set from the code instead of from a hand-copied list a new conflict would fall
// quietly outside of.
const (
	// ConflictFieldAnalysisSource is a record naming a kind of source this build
	// cannot read.
	ConflictFieldAnalysisSource = "analysis_source"
	// ConflictFieldArtefactIdentity is two sets of bytes for one pinned version.
	ConflictFieldArtefactIdentity = "artefact_identity"
	// ConflictFieldCallGraph is two analyses of the same artefact, at the same
	// completeness, disagreeing about the graph.
	ConflictFieldCallGraph = "call_graph"
)

// ConflictFields lists every field a CallGraphConflict reports on.
func ConflictFields() []string {
	return []string{
		ConflictFieldAnalysisSource,
		ConflictFieldArtefactIdentity,
		ConflictFieldCallGraph,
	}
}

// Remedy is what an operator should run when composition refuses: a lead
// sentence, then whole invocations.
//
// The invocations are held apart from the prose because they are a contract
// rather than decoration — a refusal that prints a command the tool then rejects
// costs the reader the round trip the refusal existed to save. Keeping them as
// data is what lets a test push every one through the CLI's argument parser.
type Remedy struct {
	// Lead introduces the invocations. It ends without punctuation of its own;
	// String supplies the colon.
	Lead string
	// Lines are whole invocations, "kanonarion" included, each parseable on its
	// own. Prose never appears here.
	Lines []string
}

// String renders the remedy as the tail of a refusal: the lead, then one
// indented invocation per line.
func (r Remedy) String() string {
	var b strings.Builder
	b.WriteString(r.Lead)
	b.WriteString(":")
	for _, l := range r.Lines {
		b.WriteString("\n  ")
		b.WriteString(l)
	}
	return b.String()
}

// Remedy names what to run about this conflict.
//
// Each field gets its own, because the routes out are genuinely different: an
// unreadable source is a build that is too old, two artefact identities are two
// sets of bytes, and two graphs at one completeness are a measurement to take
// again. None of them is --force on its own, which is why none of them says only
// that.
func (c CallGraphConflict) Remedy() Remedy {
	coord := c.Coordinate.String()
	switch c.Field {
	case ConflictFieldAnalysisSource:
		// The source to fall back to is decided by the coordinate: a project
		// coordinate's records are read off a working tree, never a module zip, so
		// naming --source zip for one directs the reader at a record that cannot
		// exist.
		readable := AnalysisSourceModuleZip
		if !IsReFetchable(c.Coordinate) {
			readable = AnalysisSourceWorktree
		}
		return Remedy{
			Lead: "A record names a kind of source this build cannot read, so it was written by a newer kanonarion. " +
				"Upgrade, or read only the sources this build names",
			Lines: []string{
				"kanonarion callgraph-show " + coord + " --history",
				"kanonarion callgraph-show " + coord + " --source " + string(readable),
			},
		}
	case ConflictFieldArtefactIdentity:
		if !IsReFetchable(c.Coordinate) {
			// A project coordinate names a working tree, not published bytes. There
			// is nothing to fetch, and two identities for it mean two trees were
			// analysed under one name — which only re-analysing the tree in hand
			// settles.
			return Remedy{
				Lead: "Two records read different bytes for one project coordinate, so two working trees were analysed under one name. " +
					"Inspect the generations, then analyse the tree you mean",
				Lines: []string{
					"kanonarion callgraph-show " + coord + " --history",
					ReanalysisCommand(c.Coordinate, ""),
				},
			}
		}
		return Remedy{
			Lead: "Two records read different bytes for one pinned version, so no re-analysis of the stored bytes settles it. " +
				"Inspect the generations, then fetch the module again and analyse what that fetch pins",
			Lines: []string{
				"kanonarion callgraph-show " + coord + " --history",
				"kanonarion fetch " + coord,
				ForcedReanalysisCommand(c.Coordinate, ""),
			},
		}
	default:
		// ConflictFieldCallGraph, and any field a later generation adds: the
		// generations are what a reader has to see, and a fresh measurement is what
		// can separate them. --force is on the analysis because a stored answer
		// already exists, so without it the run is served from cache and reads as
		// the remedy having been tried and failed.
		return Remedy{
			Lead: "Two analyses of the same artefact at the same completeness disagree about the graph. " +
				"Inspect the generations, then measure again",
			Lines: []string{
				"kanonarion callgraph-show " + coord + " --history",
				ForcedReanalysisCommand(c.Coordinate, ""),
			},
		}
	}
}

// Error renders the conflict as a message. CallGraphConflict satisfies error so
// the store can return it directly.
//
// The remedy is part of the message rather than something a caller may print
// alongside it: this error crosses the store and the ports layer before anything
// renders it, and a remedy the renderer had to remember to add is one that goes
// missing on the paths nobody thought of.
func (c CallGraphConflict) Error() string {
	return fmt.Sprintf(
		"conflicting call graph records for %s at pipeline %s: %s disagrees (%v; records %v)\n%s",
		c.Coordinate, c.PipelineVersion, c.Field, c.Values, c.ContentHashes, c.Remedy(),
	)
}

// ComposeRequest asks for the record a reader gets for one coordinate and
// pipeline version. Its zero value is the unrestricted read.
type ComposeRequest struct {
	// Source restricts composition to records built from one kind of source. The
	// zero value names none, and DefaultSource then decides.
	Source AnalysisSource
}

// Compose returns the call graph record a reader gets for one coordinate and
// pipeline version, given every record the ledger holds for it.
//
// Records must be supplied in the order they were appended, and each must
// already have verified its own content hash: a record that cannot be checked
// stops the read before it reaches here, so composition never has to decide what
// to do about an unverifiable row.
//
// The ladder is COMPLETENESS, then recency. A BUILT_WITH_BODIES graph outranks a
// METADATA_ONLY one regardless of which was written later, exactly as the fetch
// ledger serves the strongest anchor rather than the newest measurement: the
// weaker record analysed less of the same module, so it is a lesser measurement
// rather than a competing answer. Recency is only ever the last tiebreaker.
//
// The analysis source is NOT on that ladder. It is a dimension: a zip graph and
// a worktree graph answer different questions, and serving one for the other
// would answer a question the caller did not ask. Composition therefore selects
// a source first and only then ladders within it.
func Compose(records []CallGraphRecord, req ComposeRequest) (CallGraphRecord, error) {
	if len(records) == 0 {
		return CallGraphRecord{}, ErrNoRecordsToCompose
	}

	var candidates []CallGraphRecord
	if req.Source != AnalysisSourceUnrecorded {
		candidates = withSource(records, req.Source)
		if len(candidates) == 0 {
			return CallGraphRecord{}, ErrNoRecordsToCompose
		}
	} else {
		var err error
		if candidates, err = defaultSourceGroup(records); err != nil {
			return CallGraphRecord{}, err
		}
	}

	if isWorktreeSequence(candidates) {
		// A working tree pins no content — it is deliberately re-read on every run
		// — so its records are a SEQUENCE of observations of a changing tree, not
		// competing claims about one pinned artefact. The last one is the only
		// correct answer: serving a higher-completeness earlier record would hand
		// back a graph the tree no longer has, so deleting a function would
		// silently fail to register.
		//
		// "Last" is by position, not by timestamp. extracted_at persists at second
		// precision, so two runs within one second carry the same time and a
		// timestamp comparison cannot order them. The ledger is append-only and the
		// store lists in insertion order, which is the sequence.
		return candidates[len(candidates)-1], nil
	}

	candidates = identifiedOrAll(candidates)
	if c := findConflict(candidates); c != nil {
		return CallGraphRecord{}, *c
	}

	ordered := make([]CallGraphRecord, len(candidates))
	copy(ordered, candidates)
	sort.SliceStable(ordered, func(i, j int) bool { return servesBefore(ordered[i], ordered[j]) })
	return ordered[0], nil
}

// withSource keeps the records built from one kind of source.
func withSource(records []CallGraphRecord, want AnalysisSource) []CallGraphRecord {
	out := make([]CallGraphRecord, 0, len(records))
	for _, r := range records {
		if r.AnalysisSource == want {
			out = append(out, r)
		}
	}
	return out
}

// defaultSourceGroup picks which records answer a read that named no source.
//
// A module zip is what production writes on a coordinate-keyed walk, so when the
// ledger holds both kinds it is the default. A worktree record answers only when
// the ledger holds no zip record for the coordinate — otherwise `kanonarion
// local` on a project would quietly redirect every later query away from the
// graphs the walk produced.
//
// AN UNRECORDED SOURCE IS NOT A THIRD KIND OF SOURCE. It is a record that did not
// say, and the distinction is load-bearing: every record written before the field
// existed carries it. Segregating those into their own group would mean the FIRST
// re-analysis of any of them lands in a different group from the record it should
// be laddered against — and then a failed re-analysis appended today displaces a
// fully-built graph measured yesterday, which is precisely the "recency is not
// authority" defect the whole ledger exists to prevent. Road-tested: it did
// exactly that before this function distinguished the two cases.
//
// So when only ONE kind of source is named across the ledger, the records that
// name none are laddered alongside it: only one kind of source is in play, so
// they cannot be answering a different question. When two are named, a silent
// record cannot be attributed to either, and it steps aside on the same reasoning
// as identifiedOrAll — a measurement that says what it read is better evidence
// than one that does not. Nothing is deleted either way; a history read still
// returns every generation.
func defaultSourceGroup(records []CallGraphRecord) ([]CallGraphRecord, error) {
	zip := withSource(records, AnalysisSourceModuleZip)
	tree := withSource(records, AnalysisSourceWorktree)
	silent := withSource(records, AnalysisSourceUnrecorded)

	if len(zip)+len(tree)+len(silent) != len(records) {
		// A record carries a source this domain does not define — written by a newer
		// build, or corrupt. Refusing is the only honest answer: picking a group
		// would serve an answer about a source nothing here can name.
		return nil, CallGraphConflict{
			Coordinate:      records[0].Coordinate,
			PipelineVersion: records[0].PipelineVersion,
			Field:           ConflictFieldAnalysisSource,
			Values:          distinctSources(records),
			ContentHashes:   hashesForSources(records),
		}
	}

	switch {
	case len(zip) > 0 && len(tree) > 0:
		// Two questions are genuinely in play; serve the one production writes and
		// leave the silent records out, since they cannot be attributed to either.
		return zip, nil
	case len(zip) > 0:
		return inAppendOrder(records, zip, silent), nil
	case len(tree) > 0:
		return inAppendOrder(records, tree, silent), nil
	default:
		return silent, nil
	}
}

// inAppendOrder merges two subsets back into the order they were appended in.
//
// Order is not cosmetic here: composition serves the LAST observation of a
// mutating working tree, and that is by position rather than by timestamp
// because extracted_at persists at second precision. Rebuilding a group by
// concatenating subsets would put a legacy record after a newer one and hand
// back a graph the tree no longer has.
func inAppendOrder(all, a, b []CallGraphRecord) []CallGraphRecord {
	keep := make(map[string]bool, len(a)+len(b))
	for _, r := range a {
		keep[r.ContentHash] = true
	}
	for _, r := range b {
		keep[r.ContentHash] = true
	}
	out := make([]CallGraphRecord, 0, len(keep))
	for _, r := range all {
		if keep[r.ContentHash] {
			out = append(out, r)
		}
	}
	return out
}

// isWorktreeSequence reports whether these records observe a mutating working
// tree rather than a pinned artefact.
//
// Both halves matter. A worktree record is a sequence by construction. A record
// at coordinate.LocalVersion is one too even when it names no source: before the
// source field existed, that is what a local ingest looked like.
func isWorktreeSequence(records []CallGraphRecord) bool {
	// Any worktree record in the group settles it. The group can hold records that
	// name no source alongside them — see defaultSourceGroup — so testing only the
	// first would ladder a mutating tree whenever a legacy record happened to be
	// appended first.
	for _, r := range records {
		if r.AnalysisSource == AnalysisSourceWorktree {
			return true
		}
	}
	// Before the source field existed, a working-tree ingest was recognisable only
	// by its coordinate. Those records keep the sequence rule, or a branch switch
	// would serve the graph of the tree that came before it.
	return records[0].Coordinate.IsLocal()
}

// identifiedOrAll drops the records that name no artefact, unless none of them
// names one.
//
// A record written before the artefact identity existed cannot be shown to
// describe the same bytes as one that names an artefact, so composing the two
// together would assert they measured the same thing on no evidence. Once a
// measurement exists that says which bytes it read, it is the better-evidenced
// answer and the unidentified ones stop competing with it.
//
// Nothing is discarded from the ledger by this — the rows remain, and a history
// read still returns them.
func identifiedOrAll(records []CallGraphRecord) []CallGraphRecord {
	identified := make([]CallGraphRecord, 0, len(records))
	for _, r := range records {
		if r.ArtefactIdentity != "" {
			identified = append(identified, r)
		}
	}
	if len(identified) == 0 {
		return records
	}
	return identified
}

// findConflict reports the first disagreement composition must not resolve by
// picking, or nil when the records can be laddered.
func findConflict(records []CallGraphRecord) *CallGraphConflict {
	if len(records) < 2 {
		return nil
	}

	// It cannot fire on the upgrade path — identifiedOrAll has already removed the
	// records that name no artefact — so reaching here means two measurements each
	// named an artefact and named different ones.
	if c := disagreement(records, ConflictFieldArtefactIdentity,
		func(r CallGraphRecord) string { return r.ArtefactIdentity }); c != nil {
		return c
	}

	// Within one artefact, only records the ladder cannot separate can conflict. A
	// METADATA_ONLY graph disagreeing with a BUILT_WITH_BODIES one is the
	// refinement case the ladder exists to resolve; two records at the SAME
	// completeness disagreeing about the graph is non-determinism in the analyser.
	top := completenessRung(records[0])
	for _, r := range records[1:] {
		if rung := completenessRung(r); rung > top {
			top = rung
		}
	}
	tied := make([]CallGraphRecord, 0, len(records))
	for _, r := range records {
		// A failed, cancelled or excluded extraction makes no claim about the graph
		// at all, so it cannot contradict one that does. Letting it take part would
		// report every "load failed, then extracted" pair as non-determinism.
		if completenessRung(r) == top && statesAGraph(r) {
			tied = append(tied, r)
		}
	}
	return graphDisagreement(tied)
}

// graphDisagreement reports whether these records make DIFFERENT claims about
// the call graph, or nil when they make the same claim.
//
// The comparison is over the fields every one of them states, and that
// restriction is the whole of it.
//
// A record cannot contradict another on a field it predates. Every generation
// written before a field existed carries nothing for it, and a later generation
// that fills it in has REFINED the older record rather than contradicted it: the
// lineage is one measurement said twice, and the newest generation answers.
// Comparing the whole record instead reported those pairs as non-determinism in
// the analyser. Measured on the real store: ten coordinates re-analysed after
// the failure cause became recordable held two generations each — identical
// nodes, edges, status and detail, differing only in that the older one predated
// failure_cause — and every composed read of them refused.
//
// This is field-agnostic on purpose. A field added tomorrow behaves the same
// way: it is absent from the encoding of every record written before it, so it
// takes no part in comparisons against them, and it is compared normally once
// two records both state it. Naming failure_cause here instead would have bought
// exactly one field's worth of relief and left the next one to rediscover this.
//
// What it does NOT relax is a disagreement between two records that both state a
// field. Nodes and edges are stated by every generation — as empty lists when
// there are none — so a graph against an empty one is still a conflict, and two
// graphs with different nodes or edges are still a conflict.
func graphDisagreement(records []CallGraphRecord) *CallGraphConflict {
	if len(records) < 2 {
		return nil
	}

	stated := make([]map[string]json.RawMessage, len(records))
	for i, r := range records {
		fields, err := graphFields(r)
		if err != nil {
			// Which fields each record states could not be read, so whether they agree
			// was never measured. Composing them anyway would serve one graph on the
			// strength of a comparison that did not happen, so the refusal stands and
			// says why. It is the same reason GraphDigest returns a marker rather than
			// a plausible digest.
			return unmeasurableGraphs(records, err)
		}
		stated[i] = fields
	}

	shared := sharedFields(stated)
	values := make([]string, len(records))
	for i := range records {
		values[i] = digestOfFields(stated[i], shared)
	}
	c := disagreementOf(records, ConflictFieldCallGraph, values)
	if c == nil {
		return nil
	}
	return reportedAsWholeDigests(c, records)
}

// reportedAsWholeDigests restates a graph conflict in the digests
// `callgraph-show --history` prints for the same records.
//
// The comparison that DECIDES the conflict is over the fields the records share,
// and that digest appears on no other surface. The remedy sends the reader to
// --history, so the refusal has to name what --history names, or the reader is
// left holding two digests that were never going to match anything. Nothing
// collapses in the restatement: the shared-field digest is a projection of the
// whole-record one, so records that differ on the projection differ on the whole.
func reportedAsWholeDigests(c *CallGraphConflict, records []CallGraphRecord) *CallGraphConflict {
	byHash := make(map[string]CallGraphRecord, len(records))
	for _, r := range records {
		byHash[r.ContentHash] = r
	}
	type pair struct{ value, hash string }
	pairs := make([]pair, 0, len(c.ContentHashes))
	for i, hash := range c.ContentHashes {
		value := c.Values[i]
		if r, ok := byHash[hash]; ok {
			value = GraphDigest(r)
		}
		pairs = append(pairs, pair{value: value, hash: hash})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].value < pairs[j].value })
	for i, p := range pairs {
		c.Values[i], c.ContentHashes[i] = p.value, p.hash
	}
	return c
}

// unmeasurableGraphs is the conflict for records whose graph claims could not be
// read at all. Every record carries the same unmeasurable value, and each is
// named, because the refusal is about all of them rather than about a pair.
func unmeasurableGraphs(records []CallGraphRecord, err error) *CallGraphConflict {
	values := make([]string, len(records))
	hashes := make([]string, len(records))
	for i, r := range records {
		values[i] = "unmeasurable: " + err.Error()
		hashes[i] = r.ContentHash
	}
	return &CallGraphConflict{
		Coordinate:      records[0].Coordinate,
		PipelineVersion: records[0].PipelineVersion,
		Field:           ConflictFieldCallGraph,
		Values:          values,
		ContentHashes:   hashes,
	}
}

// graphFields is GraphDigest's input rather than its output: everything a record
// says about the call graph, keyed by the canonical field name that says it.
//
// A field absent from the map is one the record states nothing for — either
// because it predates the field or because the canonical encoding omits its zero
// value, which for this purpose are the same thing: neither is a claim.
func graphFields(r CallGraphRecord) (map[string]json.RawMessage, error) {
	data, err := marshalCanonical(forGraphComparison(r))
	if err != nil {
		return nil, fmt.Errorf("marshal record for graph comparison: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, fmt.Errorf("read canonical record as fields: %w", err)
	}
	return fields, nil
}

// sharedFields names the fields every record states, sorted, so a digest over
// them is stable.
func sharedFields(stated []map[string]json.RawMessage) []string {
	shared := make([]string, 0, len(stated[0]))
	for name := range stated[0] {
		inAll := true
		for _, other := range stated[1:] {
			if _, ok := other[name]; !ok {
				inAll = false
				break
			}
		}
		if inAll {
			shared = append(shared, name)
		}
	}
	sort.Strings(shared)
	return shared
}

// digestOfFields hashes one record's values for the named fields.
//
// It rebuilds a JSON object rather than hashing the values alone so that a value
// moving between fields cannot go unnoticed, and it walks the names in the order
// given so two records are hashed over the same fields in the same order.
func digestOfFields(fields map[string]json.RawMessage, names []string) string {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, name := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Quote(name))
		b.WriteByte(':')
		b.Write(fields[name])
	}
	b.WriteByte('}')
	sum := sha256.Sum256(b.Bytes())
	return "sha256:" + hex.EncodeToString(sum[:])
}

// disagreement reports the distinct values of one field across records, as a
// conflict, when there is more than one.
func disagreement(records []CallGraphRecord, field string, value func(CallGraphRecord) string) *CallGraphConflict {
	values := make([]string, len(records))
	for i, r := range records {
		values[i] = value(r)
	}
	return disagreementOf(records, field, values)
}

// disagreementOf is disagreement over values already computed, one per record in
// the same order. The graph comparison needs it because a record's value there
// depends on the other records — which fields they all state — and so cannot be
// derived from the record alone.
// Fewer than two records need no guard of their own: one value cannot be two
// distinct ones, so the count below reports no conflict.
func disagreementOf(records []CallGraphRecord, field string, values []string) *CallGraphConflict {
	seen := map[string]string{} // value -> content hash of a record carrying it
	for i, r := range records {
		v := values[i]
		if v == "" {
			continue
		}
		if _, ok := seen[v]; !ok {
			seen[v] = r.ContentHash
		}
	}
	if len(seen) < 2 {
		return nil
	}
	distinct := make([]string, 0, len(seen))
	for v := range seen {
		distinct = append(distinct, v)
	}
	sort.Strings(distinct)
	hashes := make([]string, 0, len(distinct))
	for _, v := range distinct {
		hashes = append(hashes, seen[v])
	}
	return &CallGraphConflict{
		Coordinate:      records[0].Coordinate,
		PipelineVersion: records[0].PipelineVersion,
		Field:           field,
		Values:          distinct,
		ContentHashes:   hashes,
	}
}

// distinctSources lists the sources present across records, sorted.
func distinctSources(records []CallGraphRecord) []string {
	seen := map[string]bool{}
	for _, r := range records {
		seen[r.AnalysisSource.String()] = true
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// hashesForSources names one record carrying each source in distinctSources'
// order, so a reported conflict can be examined row by row.
func hashesForSources(records []CallGraphRecord) []string {
	first := map[string]string{}
	for _, r := range records {
		if _, ok := first[r.AnalysisSource.String()]; !ok {
			first[r.AnalysisSource.String()] = r.ContentHash
		}
	}
	sources := distinctSources(records)
	out := make([]string, 0, len(sources))
	for _, s := range sources {
		out = append(out, first[s])
	}
	return out
}

// GraphDigest is a hash of everything a record says about the call graph, and of
// nothing else.
//
// It exists because ContentHash cannot answer "do these two records agree". The
// content hash covers the time of measurement and the provenance of the bytes,
// so two runs of the analyser that produced the identical graph a second apart
// carry different content hashes. Blanking those fields leaves the claim.
//
// It is NOT a second seal and is never persisted. It reuses the canonical
// marshal, so it changes only when the hashed shape does, and no stored record's
// own hash depends on it.
func GraphDigest(r CallGraphRecord) string {
	data, err := marshalCanonical(forGraphComparison(r))
	if err != nil {
		// marshalCanonical fails only on a value json.Marshal cannot encode, which
		// this shape has none of. Returning a distinct marker rather than a
		// plausible digest keeps a failure from reading as agreement.
		return "unhashable:" + err.Error()
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// forGraphComparison strips a record down to what it claims about the graph, by
// clearing what is provenance rather than claim.
func forGraphComparison(r CallGraphRecord) CallGraphRecord {
	r.ContentHash = ""
	r.ExtractedAt = time.Time{}
	// Which fetch measurement supplied the bytes is provenance, not graph. Two
	// fetch records of identical bytes carry the same artefact identity and
	// different content hashes, and this comparison only ever runs between records
	// whose artefact identity already matches.
	r.SourceContentHash = ""
	// WHICH walk's build list was offered is provenance; WHAT it pinned is the
	// claim, and that stays. Two walks that resolved the same versions produce the
	// same require directives and therefore the same graph, so comparing the walk
	// identifier would make two identical graphs disagree about nothing.
	r.BuildListSource = ""
	// A record that predates the source field did not analyse a different kind of
	// source; it analysed the only kind that existed when it was written and had
	// nowhere to say so. Comparing the absent value as if it contradicted the named
	// one made two records with identical nodes, edges and completeness disagree on
	// nothing but the field one of them predates, and the read then refused the
	// graph outright. Measured: github.com/golang-jwt/jwt/v4@v4.5.1 at pipeline
	// 0.3.0 held two records whose full contents differed only in this field, and
	// every reachability query against them failed.
	r.AnalysisSource = analysedFrom(r)
	// WHERE a tree was mounted is provenance. Two copies of one tree at two paths
	// contain the same code and produce the same graph, so comparing the root
	// would make two identical graphs disagree about nothing — the same argument
	// the digest itself is built on, applied to the field that deliberately does
	// not follow it.
	r.AnalysisRoot = ""
	return r
}

// completenessRung orders records by how much of the module the analysis
// actually built. Higher is better.
//
// It mirrors CompletenessLevels, which is the ladder this domain publishes, so a
// level added there without a rung here would silently fall to the bottom and
// lose to an unrecorded one.
// TestCompose_CompletenessRungCoversEveryLevel pins it.
//
// A stated FAILED outranks an unrecorded level, and the gap between them is the
// point: a failed extraction says "this was attempted and produced nothing",
// while an unrecorded one says nothing at all, and the first is better evidence
// than silence. It is the same ordering the vulnerability domain applies to the
// same strings.
func completenessRung(r CallGraphRecord) int {
	switch r.Completeness {
	case CompletenessBuiltWithBodies:
		return 4
	case CompletenessTypeOnly:
		return 3
	case CompletenessMetadataOnly:
		return 2
	case CompletenessFailed:
		return 1
	case CompletenessUnknown:
		return 0
	default:
		return 0
	}
}

// statesAGraph reports whether a record makes any claim about the call graph.
//
// It is deliberately NOT "rung above zero". Ordering and claiming are different
// questions: a FAILED record ranks above an unrecorded one because a stated
// failure is better evidence than silence, but it still produced no graph, so it
// cannot CONTRADICT a record that did. Conflating the two would report every
// "load failed, then extracted" pair as non-determinism in the analyser.
func statesAGraph(r CallGraphRecord) bool {
	switch r.Completeness {
	case CompletenessBuiltWithBodies, CompletenessTypeOnly, CompletenessMetadataOnly:
		return true
	case CompletenessFailed, CompletenessUnknown:
		return false
	default:
		return false
	}
}

// servesBefore orders two records by which should be served first.
func servesBefore(a, b CallGraphRecord) bool {
	if ra, rb := completenessRung(a), completenessRung(b); ra != rb {
		return ra > rb
	}
	if !a.ExtractedAt.Equal(b.ExtractedAt) {
		return a.ExtractedAt.After(b.ExtractedAt)
	}
	// Neither the ladder nor the clock separates these. The content hash is not
	// authority and is not claimed to be — it is here so the served record does
	// not depend on the order rows happen to come back in.
	return a.ContentHash < b.ContentHash
}
