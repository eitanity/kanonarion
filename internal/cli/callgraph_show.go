package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
	"github.com/spf13/cobra"
)

// callGraphShowFlags is the show command's own options.
type callGraphShowFlags struct {
	limitNodes int
	limitEdges int
	nodeFilter string
	history    bool
	diff       bool
	source     string
	toolchain  string
}

func newCallGraphShowCmd(stdout, stderr io.Writer) *cobra.Command {
	var f callGraphShowFlags

	cmd := &cobra.Command{
		Use: "callgraph-show <module>@<version>",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentRead,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "Show the full call graph record for a module",
		Example: `  kanonarion callgraph-show github.com/spf13/cobra@v1.8.1
  kanonarion callgraph-show github.com/spf13/cobra@v1.8.1 --json
  kanonarion callgraph-show github.com/spf13/cobra@v1.8.1 --node Execute
  kanonarion callgraph-show github.com/spf13/cobra@v1.8.1 --node github.com/spf13/pflag
  kanonarion callgraph-show github.com/spf13/cobra@v1.8.1 --history
  kanonarion callgraph-show github.com/spf13/cobra@v1.8.1 --diff
  kanonarion callgraph-show example.com/mod@local --source worktree
  kanonarion callgraph-show golang.org/x/tools@v0.49.0 --toolchain go1.26.6`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runCallGraphShow(cmd.Context(), args[0], f, jsonOut, ctr.QueryCallGraph, stdout)
		},
	}

	cmd.Flags().StringVar(&f.nodeFilter, "node", "", "filter to nodes whose fully-qualified ID (package path + symbol) contains this substring, case-insensitively; a module path, a package path or a bare symbol name all select")
	cmd.Flags().IntVar(&f.limitNodes, "limit-nodes", 50, "max nodes to print (0=unlimited)")
	cmd.Flags().IntVar(&f.limitEdges, "limit-edges", 100, "max edges to print (0=unlimited)")
	cmd.Flags().BoolVar(&f.history, "history", false, "show every stored generation for the module instead of the composed answer")
	cmd.Flags().BoolVar(&f.diff, "diff", false, "report what the distinct stored measurements for the module differ about, instead of the composed answer")
	cmd.Flags().StringVar(&f.source, "source", "", "restrict to graphs built from one source: zip or worktree")
	cmd.Flags().StringVar(&f.toolchain, "toolchain", "", "restrict to graphs built by one Go toolchain, in `go env GOVERSION` form (e.g. go1.26.6)")

	return cmd
}

// parseAnalysisSource maps the --source flag onto the domain value, refusing a
// name the domain does not define rather than silently answering from every
// source. A typo that widened the answer instead of narrowing it would be
// invisible in the output.
func parseAnalysisSource(v string) (domain.AnalysisSource, error) {
	switch v {
	case "":
		return domain.AnalysisSourceUnrecorded, nil
	case string(domain.AnalysisSourceModuleZip):
		return domain.AnalysisSourceModuleZip, nil
	case string(domain.AnalysisSourceWorktree):
		return domain.AnalysisSourceWorktree, nil
	default:
		return domain.AnalysisSourceUnrecorded, fmt.Errorf(
			"unknown analysis source %q: use %q (a fetched module zip) or %q (a directory on disk)",
			v, domain.AnalysisSourceModuleZip, domain.AnalysisSourceWorktree)
	}
}

func runCallGraphShow(ctx context.Context, moduleArg string, f callGraphShowFlags, jsonOut bool, uc QueryCallGraphUseCase, stdout io.Writer) error {
	coord, err := parseCoordinate(moduleArg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", moduleArg, err)
	}
	source, err := parseAnalysisSource(f.source)
	if err != nil {
		return err
	}
	if f.history {
		return runCallGraphHistory(ctx, coord, uc, stdout)
	}
	if f.diff {
		return runCallGraphDiff(ctx, coord, f, jsonOut, uc, stdout)
	}

	req := domain.ComposeRequest{Source: source, Toolchain: gotoolchain.Version(f.toolchain)}
	r, found, err := uc.GetCallGraphRecordFrom(ctx, coord, cgapp.PipelineVersion, req)
	if err != nil {
		return fmt.Errorf("getting callgraph record: %w", err)
	}
	if !found {
		if req.Toolchain.Recorded() {
			return &exitError{code: ExitNotFound, msg: fmt.Sprintf(
				"no callgraph record for %s built by %s — the ledger may hold one built by another toolchain; try --history",
				coord, req.Toolchain)}
		}
		if source != domain.AnalysisSourceUnrecorded {
			return &exitError{code: ExitNotFound, msg: fmt.Sprintf(
				"no %s-sourced callgraph record for %s — the ledger may hold one from another source; try --history",
				source, coord)}
		}
		note, nerr := supersededGenerationsNote(ctx, coord, uc)
		if nerr != nil {
			return nerr
		}
		if note != "" {
			return &exitError{code: ExitNotFound, msg: fmt.Sprintf(
				"no callgraph record for %s at pipeline %s — %s. Re-analyse it:\n  %s",
				coord, cgapp.PipelineVersion, note, domain.ReanalysisCommand(coord, ""))}
		}
		return &exitError{code: ExitNotFound, msg: fmt.Sprintf(
			"no callgraph record for %s — analyse it first:\n  %s", coord, domain.ReanalysisCommand(coord, ""))}
	}
	// Asked before --node narrows the record: the disagreement is between whole
	// generations of this coordinate, and a filtered view of the served one says
	// nothing about which library built the others.
	disagreement, disagrees, err := analyserDisagreement(ctx, coord, r, uc)
	if err != nil {
		return err
	}

	nodeFilter, limitNodes, limitEdges := f.nodeFilter, f.limitNodes, f.limitEdges

	var filter nodeFilterOutcome
	if nodeFilter != "" {
		r, filter = filterCallGraphRecord(r, nodeFilter)
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		j := toCallGraphJSON(r)
		j.NodeFilter = filter.toJSON()
		if disagrees {
			j.AnalyserDisagreement = toAnalyserDisagreementJSON(disagreement)
		}
		if err := enc.Encode(j); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}

	if err := printCallGraphRecord(r, limitNodes, limitEdges, stdout); err != nil {
		return err
	}
	if disagrees {
		if _, werr := fmt.Fprintf(stdout, "notice: %s\n", disagreement.Summary()); werr != nil {
			return fmt.Errorf("writing analyser notice: %w", werr)
		}
	}
	return writeNodeFilterNotice(stdout, coord, f.source, filter)
}

// analyserDisagreement reports whether the generations composed for a
// coordinate were parsed by more than one x/tools, and what they were.
//
// It reads the history because that is where the other generations are: the
// composed answer is ONE record, and a fact about the set it was chosen from
// cannot be recovered from it. The cost is one extra ledger read on an
// inspection command that has already paid for a composition.
//
// It states nothing where there is nothing to state — a coordinate with one
// generation, or whose generations agree, or where only one of them names an
// analyser at all — so a store built by a single binary gains no line anywhere.
//
// It never changes which generation answers. The completeness ladder decided
// that before this was asked, and a fact about the producer must not become a
// silent tiebreak; making the disagreement visible is the whole of the change.
func analyserDisagreement(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	served domain.CallGraphRecord,
	uc QueryCallGraphUseCase,
) (domain.AnalyserDisagreement, bool, error) {
	recs, err := uc.CallGraphHistory(ctx, coord, cgapp.PipelineVersion)
	if err != nil {
		return domain.AnalyserDisagreement{}, false, fmt.Errorf("reading callgraph history: %w", err)
	}
	d, ok := domain.AnalyserDisagreementAmong(recs, served)
	return d, ok, nil
}

// runCallGraphHistory prints every generation the ledger holds for a coordinate,
// oldest first, and marks the one composition serves.
//
// It is the read that makes the ledger observable. Without it, "both records
// survive a re-analysis" is a claim about a table nobody can see, and a reported
// non-determination names two records an operator has no way to look at. Each
// row carries the graph digest — what that record says the graph IS, with the
// measurement time and the fetch provenance blanked — because the content hash
// cannot answer "do these two agree": two analyses a second apart that produced
// the identical graph carry different content hashes.
func runCallGraphHistory(ctx context.Context, coord coordinate.ModuleCoordinate, uc QueryCallGraphUseCase, stdout io.Writer) error {
	recs, err := uc.CallGraphHistory(ctx, coord, cgapp.PipelineVersion)
	if err != nil {
		return fmt.Errorf("reading callgraph history: %w", err)
	}
	if len(recs) == 0 {
		// The history view is where an operator lands after a bump, so it must
		// distinguish a coordinate the store has never held from one whose every
		// generation this build has stopped serving.
		note, nerr := supersededGenerationsNote(ctx, coord, uc)
		if nerr != nil {
			return nerr
		}
		line := fmt.Sprintf("no callgraph records for %s at pipeline %s", coord, cgapp.PipelineVersion)
		if note != "" {
			line += " — " + note + ".\n  re-analyse it: " + domain.ReanalysisCommand(coord, "")
		}
		if _, werr := fmt.Fprintln(stdout, line); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
		return nil
	}

	// A conflict is reported, not hidden: the history view is precisely where an
	// operator goes to see why the composed read refused to pick.
	servedHash := ""
	served, found, gerr := uc.GetCallGraphRecord(ctx, coord, cgapp.PipelineVersion)
	switch {
	case gerr != nil:
		if _, werr := fmt.Fprintf(stdout, "composed answer: unavailable — %v\n\n", gerr); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
	case found:
		servedHash = served.ContentHash
	}

	if _, werr := fmt.Fprintf(stdout, "%d generation(s) for %s at pipeline %s:\n",
		len(recs), coord, cgapp.PipelineVersion); werr != nil {
		return fmt.Errorf("writing output: %w", werr)
	}
	for _, r := range recs {
		marker := " "
		if r.ContentHash != "" && r.ContentHash == servedHash {
			marker = "*"
		}
		if _, werr := fmt.Fprintf(stdout,
			"%s %s  %-16s %-17s %d node(s) / %d edge(s)\n    source:   %s\n    toolchain:%s\n    analyser: %s\n    from:     %s\n%s    graph:    %s\n    record:   %s\n",
			marker, r.ExtractedAt.UTC().Format(time.RFC3339), r.OverallStatus.String(),
			r.Completeness.String(), r.NodeCount, r.EdgeCount,
			r.AnalysisSource.String(), " "+domain.RecordToolchain(r).String(), r.Analyser.String(),
			historyOrigin(r), historyFailure(r), domain.GraphDigest(r), r.ContentHash); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
	}
	if _, werr := fmt.Fprintln(stdout,
		"\n* served by the composed read (highest completeness, then most recent, within one analysis source)"); werr != nil {
		return fmt.Errorf("writing output: %w", werr)
	}
	return nil
}

// historyFailure renders how a generation's analysis failed, as its own line,
// or nothing when it did not.
//
// It is here because composition deliberately does NOT report two generations
// that recorded different failures as a conflict — their graphs agree, so no
// answer depends on the difference, and refusing over it left coordinates
// permanently unreadable. Dropping the refusal must not drop the signal too:
// "these two analyses of one artefact failed for different reasons" is worth
// knowing, and the history view is where an operator goes to see the
// generations side by side. Silent everywhere would be the wrong trade.
func historyFailure(r domain.CallGraphRecord) string {
	if r.FailureDetail == "" && r.FailureCause == domain.FailureCauseUnrecorded {
		return ""
	}
	detail := r.FailureDetail
	if detail == "" {
		detail = "(no detail recorded)"
	}
	if r.FailureCause == domain.FailureCauseUnrecorded {
		return "    failure:  " + detail + "\n"
	}
	return "    failure:  " + r.FailureCause.String() + ": " + detail + "\n"
}

// historyOrigin renders what a generation was computed from: the artefact for a
// zip, the tree digest for a working tree.
//
// The two are not interchangeable and are not shown under one label. A worktree
// record has no artefact identity because nothing was fetched — inapplicable,
// not missing — and printing "(none)" there would read as a defect rather than
// as the truth about a directory on disk.
func historyOrigin(r domain.CallGraphRecord) string {
	if r.AnalysisSource == domain.AnalysisSourceWorktree {
		if r.WorktreeDigest == "" {
			return "(worktree, no digest recorded)"
		}
		return "tree " + r.WorktreeDigest
	}
	origin := r.ArtefactIdentity
	if origin == "" {
		origin = "(no artefact recorded)"
	}
	// The artefact names the published bytes. When a go.mod was synthesised the
	// analysis read those bytes PLUS a file kanonarion wrote, and a provenance
	// line that named only the artefact would claim the graph describes it.
	if !r.SynthesisedGoMod.IsZero() {
		origin += " + " + r.SynthesisedGoMod.String()
	}
	return origin
}

// callNodeJSON is the curated snake_case shape of a call graph node plus a
// computed Role field. Raw domain.CallNode is never marshalled directly so the
// public CLI surface stays stable and snake_cased.
type callNodeJSON struct {
	ID            string `json:"id"`
	Module        string `json:"module"`
	Package       string `json:"package"`
	Symbol        string `json:"symbol"`
	Receiver      string `json:"receiver,omitempty"`
	IsExternal    bool   `json:"is_external"`
	IsExportedAPI bool   `json:"is_exported_api"`
	PositionFile  string `json:"position_file,omitempty"`
	PositionLine  int    `json:"position_line,omitempty"`
	IsTest        bool   `json:"is_test"`
	Role          string `json:"role"`
}

type callEdgeJSON struct {
	FromID       string `json:"from_id"`
	ToID         string `json:"to_id"`
	CallSiteFile string `json:"call_site_file,omitempty"`
	CallSiteLine int    `json:"call_site_line,omitempty"`
	Confidence   string `json:"confidence"`
	// Kind says whether the edge is an invocation or a place the callee's value
	// was taken. It is spelled out on every edge rather than omitted for calls:
	// the whole point of the axis is that a registration must not read as a
	// call, and an absent field would put the reader back where they started.
	// The domain's zero value is a call and every edge stored before the axis
	// existed is one, so "Call" is a true statement about all of them.
	Kind string `json:"kind"`
}

// edgeKindJSON renders an edge kind for the curated shape, naming the zero
// value instead of emitting it as the empty string.
func edgeKindJSON(k domain.EdgeKind) string {
	if k.IsReference() {
		return string(domain.EdgeKindReference)
	}
	return "Call"
}

type coordinateJSON struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

// callGraphRunJSON is what THIS RUN states about the record it printed: the
// choice it refused to make for the caller, and where the answer came from.
//
// It is beside the record rather than in it. The record is a sealed artefact
// about a module; these are facts about one invocation, which is why they are
// absent from `callgraph-show` — that command serves a stored record and states
// nothing about how this run got it.
type callGraphRunJSON struct {
	// BuildListRefusal is present only when the run needed a build list, found
	// the coordinate in more than one build, and refused to pick one.
	BuildListRefusal *buildListRefusalJSON `json:"build_list_refusal,omitempty"`
	// Derivations say, one per answer, whether this run measured it or served a
	// record it already held.
	Derivations []derivationJSON `json:"derivations,omitempty"`
}

// derivationJSON is one answer's provenance: measured here, or served.
//
// The two print the same summary line above it, so without a field a consumer
// cannot tell a fresh measurement from a stored one — and that distinction is
// what decides whether the answer is about the code in front of the reader. It
// is a field and not a sentence for the same reason: the sentence is on stderr,
// which the consumer reading the document never sees.
type derivationJSON struct {
	// Answer names what was derived, in the words the statement uses.
	Answer string `json:"answer"`
	// DerivedByThisRun is the distinction itself. False means a stored record
	// was served; the two fields below then say which record and how to refuse
	// it.
	DerivedByThisRun bool `json:"derived_by_this_run"`
	// ReusedRecordExtractedAt dates the served record, so a reuse claim can be
	// checked against the record rather than taken on trust. Absent on a fresh
	// measurement, which has no earlier record to name.
	ReusedRecordExtractedAt string `json:"reused_record_extracted_at,omitempty"`
	// RemedyFlag forces the measurement to be taken again — needed by a consumer
	// that was served a record and wants the tree read. Absent where the run
	// measured, since there is nothing to force.
	RemedyFlag string `json:"remedy_flag,omitempty"`
}

// callGraphRecordJSON is the curated snake_case shape of a call graph record.
type callGraphRecordJSON struct {
	callGraphRunJSON
	SchemaVersion string         `json:"schema_version"`
	Coordinate    coordinateJSON `json:"coordinate"`
	Algorithm     string         `json:"algorithm"`
	// Completeness and AnalysisSource are emitted even when empty. A consumer
	// that cannot see the fidelity cannot tell a fully-built graph from a
	// type-only one, and one that cannot see the source cannot tell which bytes
	// the record is about; in both cases an absent field is itself the answer
	// ("not recorded") and must be visible as one.
	Completeness   string `json:"completeness"`
	AnalysisSource string `json:"analysis_source"`
	// Toolchain is the toolchain this record ESTABLISHES, on the same terms: a
	// consumer that cannot see which Go built the graph cannot tell two
	// toolchains' answers apart. A record that establishes none says so in the
	// token rather than in an empty string, which reads as an absent toolchain
	// rather than as an absent statement about one.
	Toolchain string `json:"toolchain"`
	// ToolchainStated is what the record ITSELF recorded, so a consumer can tell a
	// toolchain the analysis named from one recovered out of the graph's own
	// stdlib paths. Null when the record states none.
	ToolchainStated *string `json:"toolchain_stated"`
	WorktreeDigest  string  `json:"worktree_digest,omitempty"`
	// WorktreeScanDigest names the tree state this record was taken of, which is
	// the key a later run reuses it by. It is here so a reader can check a reuse
	// claim against the record rather than taking the run's word for it; absent on
	// every record written before the field existed, which is why those are always
	// re-derived.
	WorktreeScanDigest string `json:"worktree_scan_digest,omitempty"`
	// SynthesisedGoMod is present only when kanonarion wrote a go.mod into the
	// extracted tree, which is the case in which the graph does not describe the
	// published bytes alone. Absent means the tree was analysed as published.
	SynthesisedGoMod *synthesisedGoModJSON `json:"synthesised_go_mod,omitempty"`
	Nodes            []callNodeJSON        `json:"nodes"`
	Edges            []callEdgeJSON        `json:"edges"`
	OverallStatus    string                `json:"overall_status"`
	FailureDetail    string                `json:"failure_detail,omitempty"`
	// FailureCause says what the status is a statement about — the module, or the
	// run that tried to analyse it — and it is the axis that decides whether this
	// record answers a later extraction. A consumer reading only the detail reads
	// prose; this is the classification the detail was reduced from. Absent means
	// no cause was recorded, which is what every record written before a stage
	// classified its outcome carries.
	FailureCause    string   `json:"failure_cause,omitempty"`
	FailedPackages  []string `json:"failed_packages,omitempty"`
	ExclusionReason string   `json:"exclusion_reason,omitempty"`
	ExclusionList   []string `json:"exclusion_list,omitempty"`
	NodeCount       int      `json:"node_count"`
	EdgeCount       int      `json:"edge_count"`
	ExtractedAt     string   `json:"extracted_at"`
	PipelineVersion string   `json:"pipeline_version"`
	ContentHash     string   `json:"content_hash"`
	// TestScope says whether _test.go declarations were part of the analysis.
	// A record that makes no claim renders the token: an empty string here is
	// read as "no test code", which is the confusion the axis exists to remove.
	TestScope       string `json:"test_scope"`
	TestScopeDetail string `json:"test_scope_detail,omitempty"`
	TestNodeCount   int    `json:"test_node_count"`
	// ReferenceScope says whether the analysis looked for function-value
	// references at all, and it is the axis a confident negative rests on: the
	// text says in as many words that an empty callers answer over an unmeasured
	// one is UNRESOLVED rather than a measured absence. A record that never
	// searched renders the token, because an empty string collapses it into the
	// record that searched and found none. ReferenceEdgeCount is how many it
	// found, so the axis can be read without walking the edge list.
	ReferenceScope     string `json:"reference_scope"`
	ReferenceEdgeCount int    `json:"reference_edge_count"`
	// InterfaceCount and ImplementationCount summarise the type-level relation
	// the implementers query reads; the relation itself is listed by that
	// command rather than inlined into every record dump.
	InterfaceCount      int `json:"interface_count"`
	ImplementationCount int `json:"implementation_count"`
	// NodeFilter is present only when --node narrowed this answer. Absent means
	// the record is unfiltered, which is a different statement from a filter
	// that matched nothing.
	NodeFilter *nodeFilterJSON `json:"node_filter,omitempty"`
	// Analyser names the golang.org/x/tools that parsed the module, and how the
	// store came to state it. It is always present, including when nothing is
	// known: an absent object would read as "no analyser", which is the reading
	// the provenance exists to prevent.
	Analyser analyserJSON `json:"analyser"`
	// AnalyserDisagreement is present only when the generations composed for this
	// coordinate were not all parsed by the same analyser. Absent means they
	// agreed, or that only one of them said.
	AnalyserDisagreement *analyserDisagreementJSON `json:"analyser_disagreement,omitempty"`
}

// analyserJSON is one record's analyser identity, fielded rather than rendered,
// so a machine consumer reads the version and the strength behind it as two
// values instead of parsing a sentence.
//
// Provenance is spelled out on every record, including the empty one, for the
// reason the version is: "observed" and "inferred" are different evidence, and a
// consumer that sees only a version number cannot tell a measurement from a
// reconstruction made from a date.
type analyserJSON struct {
	// Module is the library the version names, so no consumer has to guess which
	// of a record's three versions this is.
	Module string `json:"module"`
	// Version is empty when the record states none.
	Version string `json:"version"`
	// Provenance is "observed", "inferred", or empty when there is no version.
	Provenance string `json:"provenance"`
	// Inferred is the same fact as a boolean, because it is the one a consumer
	// branches on and a string comparison is a place to be wrong.
	Inferred bool `json:"inferred"`
}

func toAnalyserJSON(a domain.AnalyserIdentity) analyserJSON {
	return analyserJSON{
		Module:     domain.AnalyserModulePath,
		Version:    string(a.Version),
		Provenance: string(a.Provenance),
		Inferred:   a.IsInferred(),
	}
}

// analyserDisagreementJSON carries what the text notice states: which analysers
// the composed generations name, and which of them the served answer came from.
type analyserDisagreementJSON struct {
	Analysers []analyserJSON `json:"analysers"`
	Served    analyserJSON   `json:"served"`
}

func toAnalyserDisagreementJSON(d domain.AnalyserDisagreement) *analyserDisagreementJSON {
	out := &analyserDisagreementJSON{Served: toAnalyserJSON(d.Served)}
	for _, id := range d.Identities {
		out.Analysers = append(out.Analysers, toAnalyserJSON(id))
	}
	return out
}

// synthesisedGoModJSON reports the go.mod kanonarion wrote into an extracted
// module that shipped none, so a machine consumer can see that the analysed tree
// is not the published tree and under which language semantics it was built.
type synthesisedGoModJSON struct {
	ModulePath  string `json:"module_path"`
	GoDirective string `json:"go_directive"`
	// Requires are the require directives written into that file, pinned from a
	// walk's resolved build list rather than resolved by the toolchain. They are
	// SCAN INPUTS — what the analysis was pointed at — and never resolved
	// dependency edges of the module: nothing in the module system validated the
	// pre-modules go.mod they stand in for.
	Requires          []synthesisedRequireJSON `json:"requires,omitempty"`
	VendorTreePresent bool                     `json:"vendor_tree_present"`
	// BuildListSource names the walk those versions were read from, so a reader
	// can tell two analyses pinned by different builds apart.
	BuildListSource string `json:"build_list_source,omitempty"`
}

// synthesisedRequireJSON is one pinned require directive.
type synthesisedRequireJSON struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

func synthesisedGoModToJSON(s domain.SynthesisedGoMod, buildListSource string) *synthesisedGoModJSON {
	if s.IsZero() {
		return nil
	}
	reqs := make([]synthesisedRequireJSON, 0, len(s.Requires))
	for _, r := range s.Requires {
		reqs = append(reqs, synthesisedRequireJSON{Path: r.Path, Version: r.Version})
	}
	if len(reqs) == 0 {
		reqs = nil
	}
	return &synthesisedGoModJSON{
		ModulePath:        s.ModulePath,
		GoDirective:       s.GoDirective,
		Requires:          reqs,
		VendorTreePresent: s.VendorTreePresent,
		BuildListSource:   buildListSource,
	}
}

func callNodeRole(n domain.CallNode) string {
	if n.IsExternal {
		return "external"
	}
	if n.IsTest {
		return "test"
	}
	if n.IsExportedAPI {
		return "api"
	}
	return "internal"
}

func toCallGraphJSON(r domain.CallGraphRecord) callGraphRecordJSON {
	nodes := make([]callNodeJSON, len(r.Nodes))
	for i, n := range r.Nodes {
		nodes[i] = callNodeJSON{
			ID:            n.ID,
			Module:        n.Module,
			Package:       n.Package,
			Symbol:        n.Symbol,
			Receiver:      n.Receiver,
			IsExternal:    n.IsExternal,
			IsExportedAPI: n.IsExportedAPI,
			PositionFile:  n.Position.File,
			PositionLine:  n.Position.Line,
			IsTest:        n.IsTest,
			Role:          callNodeRole(n),
		}
	}
	edges := make([]callEdgeJSON, len(r.Edges))
	for i, e := range r.Edges {
		edges[i] = callEdgeJSON{
			FromID:       e.FromID,
			ToID:         e.ToID,
			CallSiteFile: e.CallSite.File,
			CallSiteLine: e.CallSite.Line,
			Confidence:   string(e.Confidence),
			Kind:         edgeKindJSON(e.Kind),
		}
	}
	testNodes := 0
	for i := range r.Nodes {
		if r.Nodes[i].IsTest {
			testNodes++
		}
	}
	return callGraphRecordJSON{
		SchemaVersion:      r.SchemaVersion,
		Coordinate:         coordinateJSON{Path: r.Coordinate.Path(), Version: r.Coordinate.Version()},
		Algorithm:          string(r.Algorithm),
		Completeness:       string(r.Completeness),
		AnalysisSource:     string(r.AnalysisSource),
		Toolchain:          orNotRecorded(domain.RecordToolchain(r).Key()),
		ToolchainStated:    statedToolchain(r),
		WorktreeDigest:     r.WorktreeDigest,
		WorktreeScanDigest: r.WorktreeScanDigest,

		SynthesisedGoMod: synthesisedGoModToJSON(r.SynthesisedGoMod, r.BuildListSource),

		Nodes:           nodes,
		Edges:           edges,
		OverallStatus:   r.OverallStatus.String(),
		FailureDetail:   r.FailureDetail,
		FailureCause:    string(r.FailureCause),
		FailedPackages:  r.FailedPackages,
		ExclusionReason: r.ExclusionReason,
		ExclusionList:   r.ExclusionList,
		NodeCount:       r.NodeCount,
		EdgeCount:       r.EdgeCount,
		ExtractedAt:     isoTime(r.ExtractedAt),
		PipelineVersion: r.PipelineVersion,
		ContentHash:     r.ContentHash,

		Analyser: toAnalyserJSON(r.Analyser),

		TestScope:           orNotRecorded(string(r.TestScope)),
		TestScopeDetail:     r.TestScopeDetail,
		TestNodeCount:       testNodes,
		ReferenceScope:      orNotRecorded(string(r.ReferenceScope)),
		ReferenceEdgeCount:  referenceEdgeCount(r),
		InterfaceCount:      len(r.Interfaces),
		ImplementationCount: len(r.Implementations),
	}
}

// writeFidelityLine reports, on every record, how much of the module was built
// and what the analysis read.
//
// Both were stored and neither was ever printed, which made the completeness
// ladder unobservable from the tool: an operator could not tell a graph built
// with bodies from one that only had types, and the two answer "no callers" very
// differently. The source is on the same line because it decides which QUESTION
// the record answers — a working tree and a published zip are different bytes —
// and a record that does not say is reported as not recording it rather than
// silently reading as a zip.
func writeFidelityLine(stdout io.Writer, r domain.CallGraphRecord) error {
	line := fmt.Sprintf("  fidelity: %s   source: %s   toolchain: %s",
		r.Completeness.String(), r.AnalysisSource.String(), domain.RecordToolchain(r).String())
	if r.AnalysisSource == domain.AnalysisSourceWorktree && r.WorktreeDigest != "" {
		line += "  (tree " + r.WorktreeDigest + ")"
	}
	// A synthesised go.mod means the analysed tree is the published bytes plus a
	// file kanonarion invented. Printing the source without it would let the
	// record read as a description of the artefact it was sealed against.
	if !r.SynthesisedGoMod.IsZero() {
		line += "  [" + r.SynthesisedGoMod.String() + "]"
	}
	if _, err := fmt.Fprintln(stdout, line); err != nil {
		return fmt.Errorf("writing fidelity: %w", err)
	}
	return nil
}

// writeAnalyserLine names the library that PARSED the module, beside the
// algorithm that walked the result and the toolchain that compiled it.
//
// It is printed on every record, including the ones that state nothing, for the
// reason the test-scope line is: a reader who sees no analyser line reads it as
// "the usual one", and the whole value of the axis is that a graph built by a
// library predating a language construct can be silently short. An inferred
// value says so in as many words on this line — see domain.AnalyserIdentity —
// because a bare version number here would be read as a measurement.
func writeAnalyserLine(stdout io.Writer, r domain.CallGraphRecord) error {
	line := "  analyser: " + r.Analyser.String()
	if !r.Analyser.Recorded() {
		line += " — this record does not name the library that type-checked it and built its SSA"
	}
	if _, err := fmt.Fprintln(stdout, line); err != nil {
		return fmt.Errorf("writing analyser: %w", err)
	}
	return nil
}

// writeTestScopeLine reports the test axis on every record, including when it
// was not measured. A record that says nothing about test scope is read by a
// human as one where test code simply did not appear, which is exactly the
// confusion the axis exists to remove.
func writeTestScopeLine(stdout io.Writer, r domain.CallGraphRecord) error {
	testNodes := 0
	for i := range r.Nodes {
		if r.Nodes[i].IsTest {
			testNodes++
		}
	}
	var line string
	switch {
	case r.TestScope.IsMeasured():
		line = fmt.Sprintf("  test scope: analysed — %d of %d nodes are test declarations", testNodes, r.NodeCount)
	case r.TestScope == domain.TestScopeExcluded:
		line = "  test scope: EXCLUDED — _test.go declarations were not analysed"
		if r.TestScopeDetail != "" {
			line += " (" + r.TestScopeDetail + ")"
		}
	default:
		line = "  test scope: not recorded — this record makes no claim about _test.go declarations"
	}
	if _, err := fmt.Fprintln(stdout, line); err != nil {
		return fmt.Errorf("writing test scope: %w", err)
	}
	return nil
}

// referenceEdgeCount is how many of a record's edges record a function value
// being taken rather than called.
func referenceEdgeCount(r domain.CallGraphRecord) int {
	n := 0
	for i := range r.Edges {
		if r.Edges[i].Kind.IsReference() {
			n++
		}
	}
	return n
}

// writeReferenceScopeLine reports the reference axis on every record, including
// when it was not measured.
//
// It is the axis a confident negative rests on: `callers` may only answer
// RESOLVED-ABSENT when both calls and references were measurable, so a reader
// who cannot see the axis on the record cannot tell whether the verdict they
// got was entitled to be confident. The axis was stored and never printed,
// which is the same defect writeTestScopeLine exists to fix, on the other axis.
func writeReferenceScopeLine(stdout io.Writer, r domain.CallGraphRecord) error {
	var line string
	if r.ReferenceScope.IsMeasured() {
		line = fmt.Sprintf("  reference scope: analysed — %d of %d edges record a function value being taken, not called",
			referenceEdgeCount(r), r.EdgeCount)
	} else {
		line = "  reference scope: not recorded — this record never looked for function-value references, " +
			"so an empty callers answer over it is UNRESOLVED, not a measured absence"
	}
	if _, err := fmt.Fprintln(stdout, line); err != nil {
		return fmt.Errorf("writing reference scope: %w", err)
	}
	return nil
}

// writeModuleMembershipLine reports the packages this record attributed to the
// module by PATH PREFIX rather than by the toolchain's own answer.
//
// It prints only when there are some. Membership is normally taken from
// go/packages' Package.Module.Path, and a line saying so on every record would
// be noise; a reconstruction, though, has to be readable, because "in module"
// derived from a path prefix and "in module" derived from the build are the same
// words behind two different amounts of evidence.
func writeModuleMembershipLine(stdout io.Writer, r domain.CallGraphRecord) error {
	if len(r.PrefixAttributedPackages) == 0 {
		return nil
	}
	line := fmt.Sprintf("  module membership: %d package(s) attributed by PATH PREFIX — the toolchain placed them in no module: %s",
		len(r.PrefixAttributedPackages), joinWithOverflow(r.PrefixAttributedPackages, 5))
	if _, err := fmt.Fprintln(stdout, line); err != nil {
		return fmt.Errorf("writing module membership: %w", err)
	}
	return nil
}

// joinWithOverflow renders at most n of ss, naming how many were not shown.
func joinWithOverflow(ss []string, n int) string {
	if len(ss) <= n {
		return strings.Join(ss, ", ")
	}
	return strings.Join(ss[:n], ", ") + fmt.Sprintf(", and %d more", len(ss)-n)
}

// nodeFilterOutcome records what a --node pattern was compared against and how
// much of the record it selected.
//
// It exists so an unmatched filter cannot be served as an empty graph. "0 nodes"
// answers two different questions — the region really is empty, or the pattern
// never matched anything — and a tool whose empty answers state their scope has
// to say which one it is, and against what the comparison was made.
type nodeFilterOutcome struct {
	// pattern is empty when no filter was applied; the zero value therefore
	// means "unfiltered" and nothing is claimed about matching.
	pattern string
	// matched counts the nodes whose ID matched. Connected nodes pulled in by
	// an edge are not matches and are not counted here.
	matched int
	// candidates counts the nodes the pattern was compared against, before
	// filtering.
	candidates int
	// example is one node ID from the unfiltered record, so the refusal can
	// show the shape the pattern is compared against rather than describe it.
	example string
}

// applied reports whether a --node pattern was given at all.
func (o nodeFilterOutcome) applied() bool { return o.pattern != "" }

// nodeFilterJSON is the machine-readable form of the same statement the text
// refusal makes: what was compared, against how many nodes, and how many
// matched. A JSON consumer that saw only "nodes": [] could not tell an
// unmatched pattern from an empty region either.
type nodeFilterJSON struct {
	Pattern         string `json:"pattern"`
	ComparedAgainst string `json:"compared_against"`
	CandidateNodes  int    `json:"candidate_nodes"`
	MatchedNodes    int    `json:"matched_nodes"`
}

func (o nodeFilterOutcome) toJSON() *nodeFilterJSON {
	if !o.applied() {
		return nil
	}
	return &nodeFilterJSON{
		Pattern:         o.pattern,
		ComparedAgainst: nodeFilterComparand,
		CandidateNodes:  o.candidates,
		MatchedNodes:    o.matched,
	}
}

// nodeFilterComparand names, in one phrase reused by both renderings, what the
// --node pattern is matched against.
const nodeFilterComparand = "fully-qualified node ID (package path + symbol)"

// writeNodeFilterNotice states an unmatched --node filter instead of letting the
// empty node and edge lists speak for it.
//
// An operator filtering by module path — the natural way to ask "what does my
// project touch in this dependency" — used to get a confident zero with nothing
// to distinguish a pattern that never matched from a region that is genuinely
// empty. The line names the comparand and how many nodes it was compared
// against, and the remedy is an invocation this CLI parses.
func writeNodeFilterNotice(stdout io.Writer, coord coordinate.ModuleCoordinate, source string, o nodeFilterOutcome) error {
	if !o.applied() || o.matched > 0 {
		return nil
	}
	line := fmt.Sprintf(
		"\nno node matched %q — the pattern is compared, case-insensitively and as a substring, against the %s of all %d node(s) in this record, not against the bare symbol name",
		o.pattern, nodeFilterComparand, o.candidates)
	if o.example != "" {
		line += fmt.Sprintf(" (e.g. %s)", o.example)
	}
	remedy := fmt.Sprintf("kanonarion callgraph-show %s", coord)
	if source != "" {
		remedy += " --source " + source
	}
	remedy += " --limit-nodes 0"
	if _, err := fmt.Fprintf(stdout, "%s\n  to list every node: %s\n", line, remedy); err != nil {
		return fmt.Errorf("writing node filter notice: %w", err)
	}
	return nil
}

// exampleNodeID picks a node ID that shows the shape the --node pattern is
// compared against.
//
// It prefers an ID carrying a package path, because that is the part an operator
// filtering by a module or a package is aiming at. Not every node has one — a
// function whose package the analyser could not attribute is rendered from its
// signature alone — and offering one of those as the example would illustrate
// exactly the spelling the refusal is telling the reader not to expect.
func exampleNodeID(nodes []domain.CallNode) string {
	for _, n := range nodes {
		if strings.Contains(n.ID, "/") {
			return n.ID
		}
	}
	if len(nodes) > 0 {
		return nodes[0].ID
	}
	return ""
}

// filterCallGraphRecord narrows a record to the nodes a pattern selects plus
// everything directly connected to them, and reports what the pattern was
// compared against.
//
// The comparison is against the fully-qualified node ID, not the bare symbol
// name. The ID carries the package path — and with it the module path it
// extends — so a module path, a package path and a symbol name all select the
// nodes a reader expects from one pattern. Matching the bare symbol made the
// most natural filter of all, "the dependency I care about", return a silent
// zero.
func filterCallGraphRecord(r domain.CallGraphRecord, sym string) (domain.CallGraphRecord, nodeFilterOutcome) {
	// Keep the matched nodes plus all nodes and edges directly connected to them.
	symLower := strings.ToLower(sym)
	outcome := nodeFilterOutcome{pattern: sym, candidates: len(r.Nodes), example: exampleNodeID(r.Nodes)}
	wantIDs := make(map[string]bool)
	for _, n := range r.Nodes {
		if strings.Contains(strings.ToLower(n.ID), symLower) {
			wantIDs[n.ID] = true
		}
	}
	outcome.matched = len(wantIDs)
	var edges []domain.CallEdge
	edgeIDs := make(map[string]bool)
	for _, e := range r.Edges {
		if wantIDs[e.FromID] || wantIDs[e.ToID] {
			edges = append(edges, e)
			edgeIDs[e.FromID] = true
			edgeIDs[e.ToID] = true
		}
	}
	var nodes []domain.CallNode
	for _, n := range r.Nodes {
		if wantIDs[n.ID] || edgeIDs[n.ID] {
			nodes = append(nodes, n)
		}
	}
	r.Nodes = nodes
	r.Edges = edges
	r.NodeCount = len(nodes)
	r.EdgeCount = len(edges)
	r.ContentHash = ""
	return r, outcome
}

func printCallGraphRecord(r domain.CallGraphRecord, limitNodes, limitEdges int, stdout io.Writer) error {
	if _, err := fmt.Fprintf(stdout, "%s@%s  [%s]  %s\n",
		r.Coordinate.Path(), r.Coordinate.Version(),
		string(r.Algorithm), r.OverallStatus.String(),
	); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}
	if r.FailureDetail != "" {
		if _, err := fmt.Fprintf(stdout, "  failure: %s\n", r.FailureDetail); err != nil {
			return fmt.Errorf("writing failure detail: %w", err)
		}
	}
	if err := writeFailedPackages(stdout, r); err != nil {
		return err
	}
	if err := writeExclusionInfo(stdout, r); err != nil {
		return err
	}

	if err := writeFidelityLine(stdout, r); err != nil {
		return err
	}
	if err := writeAnalyserLine(stdout, r); err != nil {
		return err
	}
	if err := writeTestScopeLine(stdout, r); err != nil {
		return err
	}
	if err := writeReferenceScopeLine(stdout, r); err != nil {
		return err
	}
	if err := writeModuleMembershipLine(stdout, r); err != nil {
		return err
	}
	if len(r.Interfaces) > 0 {
		if _, err := fmt.Fprintf(stdout, "  interfaces: %d declared, %d implementations recorded (query with 'kanonarion implementers')\n",
			len(r.Interfaces), len(r.Implementations)); err != nil {
			return fmt.Errorf("writing interface summary: %w", err)
		}
	}

	if _, err := fmt.Fprintf(stdout, "Legend: [api] exported symbol  [external] outside this module  [test] declared in a _test.go file  (no tag) unexported\n"); err != nil {
		return fmt.Errorf("writing legend: %w", err)
	}

	nodes := r.Nodes
	if limitNodes > 0 && len(nodes) > limitNodes {
		nodes = nodes[:limitNodes]
	}
	if _, err := fmt.Fprintf(stdout, "\nNodes (%d total, showing %d):\n", r.NodeCount, len(nodes)); err != nil {
		return fmt.Errorf("writing nodes header: %w", err)
	}
	for _, n := range nodes {
		ext := ""
		if n.IsExternal {
			ext = " [external]"
		}
		api := ""
		if n.IsExportedAPI {
			api = " [api]"
		}
		test := ""
		if n.IsTest {
			test = " [test]"
		}
		if _, err := fmt.Fprintf(stdout, "  %s%s%s%s\n", n.ID, ext, api, test); err != nil {
			return fmt.Errorf("writing node: %w", err)
		}
	}

	edges := r.Edges
	if limitEdges > 0 && len(edges) > limitEdges {
		edges = edges[:limitEdges]
	}
	if _, err := fmt.Fprintf(stdout, "\nEdges (%d total, showing %d):\n", r.EdgeCount, len(edges)); err != nil {
		return fmt.Errorf("writing edges header: %w", err)
	}
	for _, e := range edges {
		if _, err := fmt.Fprintf(stdout, "  %s → %s  [%s]\n", e.FromID, e.ToID, string(e.Confidence)); err != nil {
			return fmt.Errorf("writing edge: %w", err)
		}
	}
	return nil
}

// supersededGenerationsNote describes the generations the store holds for a
// coordinate under pipeline versions this build no longer serves, or "" when it
// holds none. It is the difference between "this was never analysed" and "this
// was analysed by logic that has since been superseded", which are different
// facts with different remedies.
//
// Which pipeline versions a coordinate exists under is a question about the
// ledger's KEYS, so it is asked of the coordinates. Asked of the composing
// listing it spent eight seconds reconstructing fifteen generations of one
// module's edge set to read a version string off each — to say that a version
// nobody analysed was not analysed.
func supersededGenerationsNote(ctx context.Context, coord coordinate.ModuleCoordinate, uc QueryCallGraphUseCase) (string, error) {
	sums, err := uc.ListCallGraphCoordinates(ctx, ports.CallGraphFilter{ModulePath: coord.Path()})
	if err != nil {
		return "", fmt.Errorf("listing stored generations for %s: %w", coord, err)
	}
	seen := make(map[string]bool)
	var versions []string
	for _, s := range sums {
		if s.ModuleVersion != coord.Version() || s.PipelineVersion == cgapp.PipelineVersion {
			continue
		}
		if !seen[s.PipelineVersion] {
			seen[s.PipelineVersion] = true
			versions = append(versions, s.PipelineVersion)
		}
	}
	if len(versions) == 0 {
		return "", nil
	}
	sort.Strings(versions)
	return fmt.Sprintf("the store holds it at superseded pipeline %s, which this build does not serve",
		strings.Join(versions, ", ")), nil
}

// statedToolchain is the toolchain the record itself named, or nil when it named
// none. It is a pointer so that "the record states no toolchain" is a null a
// consumer can branch on rather than an empty string standing in for a state.
func statedToolchain(r domain.CallGraphRecord) *string {
	if !r.Toolchain.Recorded() {
		return nil
	}
	v := string(r.Toolchain)
	return &v
}
