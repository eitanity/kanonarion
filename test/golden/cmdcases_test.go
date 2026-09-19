package golden_test

// The recorded surfaces, and what each case exists to detect.
//
// Coverage here is partial, and the gaps are NAMED rather than left to be
// discovered. A detector whose coverage is unstated is one whose silence gets
// read as an all-clear.
//
// COVERED, by command:
//
//	audit                 --json and text; POPULATED (the whole derivation, run
//	                      offline against a fixture module cache and a fixture
//	                      advisory database), the same run under GOPROXY=off with
//	                      no --from-modcache, empty scope, missing go.mod.
//	latest                --json and text; populated, the no-publication-date
//	                      zero, an empty scope, the GOPROXY=off answer served
//	                      from the ledger, and the GOPROXY=off refusal for a
//	                      module the ledger has nothing for.
//	context               --json and text; populated (divergent), populated
//	                      (clean), go.mod-only, absent coordinate, missing store,
//	                      bad coordinate.
//	reachability          --json and text; a stored reachable verdict, an advisory
//	                      the scan never saw, an empty store, a query with no target.
//	vuln-show --history   --json and text; two snapshots of one coordinate, the
//	                      go.mod-only module, an absent coordinate, an empty store.
//	callgraph-show        --history text, composed --json and text, an absent
//	                      coordinate, a source-scoped refusal, an empty store.
//	vuln-scan-show        --json and text; both fixture runs, an absent run, an
//	                      empty store.
//	vuln-scan-diff        --json and text; two runs, and a run against itself.
//	vuln-scan-history     --json.
//	vuln-scan-list        --json.
//	walk-diff             --json and text; two walks, a walk against itself, an
//	                      empty store.
//	walk-show             --json.
//	walk-list             --json.
//	license-compat        --json and text; a pinned closure, the unpinned read
//	                      that must state which walk it chose, an absent target.
//	vuln-by-id            --json; an advisory, a RETRACTED advisory, an absent one.
//	verification-coverage --json.
//	dependents            --json under --any-build, and the refusal a question that
//	                      names no build gets.
//	sbom                  the CycloneDX document itself, which has one channel and
//	                      not two; POPULATED (every component licensed, including a
//	                      NON-GO component under pkg:generic with its evidence block
//	                      and its dependsOn edge), the caller-supplied timestamp
//	                      basis as its control, the exit-1 document a licence-less
//	                      component produces, a walk that brought nothing in, an
//	                      absent walk, and an invocation that names no scope.
//	sbom-list             --json and text; the records two generations left behind,
//	                      the zero where none has been generated, and the FILTERED
//	                      zero that must not read like it.
//	sbom-show             the absent identifier. Its populated case is deliberately
//	                      absent — see sbom_show_absent for why.
//	capability            text; a coordinate the store has analysed, and one it has
//	                      not — the refusal whose exit code and printed remedy are
//	                      the subject.
//	fetch                 text; the GOPROXY=off refusal only. It is here for the
//	                      REMEDY it prints, which is rendered per command: the
//	                      shared one named a flag fetch rejects.
//	notice                the THIRD-PARTY-LICENSES document; POPULATED (identity,
//	                      copyright and verbatim text read back out of each stored
//	                      artefact, with an Apache NOTICE headed as a notice), the
//	                      --json no-op that must keep returning the same bytes, the
//	                      exit-5 review gate that publishes nothing, the walk that
//	                      brought nothing in, an absent walk, and a positional that
//	                      is not a walk id.
//
// NOT COVERED, and named rather than implied:
//
//	interface-show / interface-diff / interface-list
//	examples-* / symbol-* / implementers / callers / callees
//	inspect / vuln-scan / vuln / walk / extract / license / callgraph
//	fips / godebug / directives / vendor / provenance / use
//	store / config / policy / local / vuln-snapshot-list / vuln-snapshot-show
//	callgraph-list / license-list / license-diff / callgraph traversal reads
//
//	interface-diff in particular is a composed read of the same class as the ones
//	covered here, and it is absent for one reason: the fixture store holds no
//	interface records, so covering it means seeding that domain rather than
//	writing another case. It is the next one to add.
//
// Each surface carries a POPULATED, an EMPTY and an ERROR-SHAPED case wherever
// the command has all three. The last two are not padding: an output regression
// on a not-found or a store-read failure is the one nobody notices by hand,
// because nobody runs those paths on purpose.
//
// The populated cases were chosen by what they COMPOSE. A read that answers from
// one record changes shape only when that record's struct changes; a read that
// combines several changes when the rule for combining them changes, and that
// rule can move with no struct moving at all. Hence two artefact measurements of
// one version, two advisory snapshots, two call-graph generations, two scan runs
// and two walks — each paired with the zero (a run diffed against itself, a walk
// diffed against itself, a coordinate with nothing stored) so that "no change" is
// recorded as an answer and not only assumed.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli"
)

// TestCommandGolden records what each covered command prints and compares it
// against the stored copy.
func TestCommandGolden(t *testing.T) {
	restore := cli.SetClockForTest(fixtureNow)
	t.Cleanup(restore)

	storeRoot := buildFixtureStore(t)
	emptyStore := t.TempDir()
	project := buildFixtureProject(t)
	home := t.TempDir()

	audit := buildAuditFixture(t)

	base := [][2]string{
		{storeRoot, "$STORE"},
		{emptyStore, "$EMPTY_STORE"},
		{project, "$PROJECT"},
		{audit.project, "$AUDIT_PROJECT"},
		{audit.modcache, "$MODCACHE"},
		{home, "$HOME"},
	}
	norm := &normaliser{replacements: base}
	// The second normaliser additionally generalises the values a run mints —
	// walk and scan-run identifiers, and the host's Go toolchain version. Only
	// the audit cases use it; see cmdCase.mintedValues for why it is not global.
	mintedNorm := &normaliser{replacements: base, patterns: mintedValuePatterns()}

	// The whole run is offline and homeless: no case may reach the operator's
	// store, and a case that tries to reach the network fails rather than
	// recording a live answer.
	t.Setenv("HOME", home)
	t.Setenv("GOTOOLCHAIN", "local")

	for _, c := range commandCases(t, emptyStore, project, audit) {
		t.Run(c.name, func(t *testing.T) {
			root := c.storeRoot
			if root == "" {
				root = storeRoot
			}
			n := norm
			if c.mintedValues {
				n = mintedNorm
			}
			runPriming(t, c, root)
			res := runCommand(t, c, root)
			recorded := record(c, res, n)
			assertNoTempPaths(t, c.name, recorded)
			checkGolden(t, c, recorded)
		})
	}
}

// commandCases is the whole recorded set.
func commandCases(t *testing.T, emptyStore, project string, audit *auditFixture) []cmdCase {
	t.Helper()
	gomod := filepath.Join(project, "go.mod")
	// Two offline postures, and the difference between them is deliberate.
	//
	// `off` is an operator's declaration that this environment does no module
	// fetching. Most commands that construct a proxy adapter REFUSE under it
	// before consulting anything recorded. `latest` and `audit` do not: they
	// answer the staleness column from the ledger, so `off` carries an answer
	// case and a refusal case here rather than refusals alone.
	//
	// unroutable is a proxy address that resolves to nothing: the adapter
	// constructs, and any request made through it fails immediately without
	// leaving the machine. Every served case runs under it, so a case that
	// stops being served from the store records a connection failure instead of
	// quietly measuring the internet.
	refusesNetwork := map[string]string{"GOPROXY": "off"}
	unroutable := map[string]string{"GOPROXY": "https://127.0.0.1:1"}

	var cases []cmdCase
	cases = append(cases, latestCases(gomod, unroutable, refusesNetwork)...)
	cases = append(cases, contextCases(emptyStore)...)
	cases = append(cases, reachabilityCases(emptyStore)...)
	cases = append(cases, vulnShowHistoryCases(emptyStore)...)
	cases = append(cases, callGraphShowCases(emptyStore)...)
	cases = append(cases, composedReadCases(emptyStore)...)
	cases = append(cases, configShowCases(emptyStore)...)
	cases = append(cases, auditCases(t, gomod, project, unroutable, audit)...)
	cases = append(cases, sbomCases(t)...)
	cases = append(cases, printedRemedyCases(t, emptyStore)...)
	// One store for the read-only document cases. The sbom cases above each
	// build their own, because generating a document writes one.
	cases = append(cases, noticeCases(buildDocumentStore(t))...)
	return cases
}

// configShowCases record what is in force in a store nobody has configured.
//
// Both channels, because the two directions of one decision meet here. The text
// is recorded byte for byte: it already said the file is absent and marked every
// defaulted value, and adding the same facts to the document must not have moved
// a byte of it. The document is recorded because it is the leg that was wrong —
// a consumer reading `preferences.json: false` could not tell a shipped default
// from an operator's choice.
//
// The store is read, never written: `config init` or `config set` here would
// leave a config.yaml behind for every other case that shares this root.
func configShowCases(emptyStore string) []cmdCase {
	return []cmdCase{
		{
			name:      "config_show_text_no_file",
			args:      []string{"config", "show"},
			storeRoot: emptyStore,
			why: "no config file: the text says so and marks every value (default). Recorded byte for " +
				"byte — the per-value provenance was added to the document beneath it, and this channel " +
				"must be unchanged.",
		},
		{
			name:      "config_show_json_no_file",
			args:      []string{"config", "show", "--json"},
			storeRoot: emptyStore,
			why: "the same store as data: config_file.present says the file is absent, and settings[] " +
				"says per key whether the value in force came from the file or from a built-in default.",
		},
	}
}

// latestCases cover the surface the change this detector exists for actually
// broke: a module with no publication date stopped emitting latest_date at all.
func latestCases(gomod string, unroutable, refusesNetwork map[string]string) []cmdCase {
	// The populated and no-date rows are served from the staleness ledger, so
	// no request is made at all.
	return []cmdCase{
		{
			name: "latest_json_populated",
			args: []string{"latest", "example.com/mod", "--json"},
			env:  unroutable,
			why:  "populated: a module with a publication date, served from the staleness ledger.",
		},
		{
			name: "latest_text_populated",
			args: []string{"latest", "example.com/mod"},
			env:  unroutable,
			why:  "populated, text: the same answer on the human channel.",
		},
		{
			name: "latest_json_no_publication_date",
			args: []string{"latest", "example.com/quiet", "--json"},
			env:  unroutable,
			why: "THE ZERO CASE: the proxy supplied no publication date. latest_date must be ABSENT " +
				"rather than emitted as 0001-01-01T00:00:00Z, and latest_release_age_days must be null. " +
				"This is the shape that regressed unseen, and it is why this fixture exists.",
		},
		{
			name: "latest_text_no_publication_date",
			args: []string{"latest", "example.com/quiet"},
			env:  unroutable,
			why:  "the zero case on the text channel: no age is claimed for a release with no date.",
		},
		{
			name: "latest_json_empty_scope",
			args: []string{"latest", "--gomod", gomod, "--json"},
			env:  unroutable,
			why:  "empty: a go.mod with no dependencies answers [] rather than prose or nothing.",
		},
		{
			name: "latest_json_no_network",
			args: []string{"latest", "example.com/unknown", "--json"},
			env:  refusesNetwork,
			why: "error-shaped: nothing recorded for this module and the environment forbids the network. " +
				"The refusal must name THAT — no recorded lookup inside the TTL — and not offer " +
				"--from-modcache or `use --recursive`, which supply module bytes and cannot answer @latest.",
		},
		{
			name: "latest_json_offline_served",
			args: []string{"latest", "example.com/mod", "--json"},
			env:  refusesNetwork,
			why: "THE OFFLINE ANSWER: GOPROXY=off with a ledger row inside the TTL. The module is answered " +
				"from the store, served_from_store is true and looked_up_at is the ORIGINAL lookup, not this run. " +
				"It must match latest_json_populated byte for byte: a declared air gap changes where the answer " +
				"comes from, never what it says.",
		},
		{
			name: "latest_json_unprobed_major",
			args: []string{"latest", "example.com/unprobed", "--json"},
			env:  refusesNetwork,
			why: "THE UNANSWERED QUESTION: a ledger row whose major probe never ran. major_probed is " +
				"false with newer_major_module absent, which is a DIFFERENT state from probed-and-none.",
		},
		{
			name: "latest_text_unprobed_major",
			args: []string{"latest", "example.com/unprobed"},
			env:  refusesNetwork,
			why: "the unanswered question on the human channel: the row states that the newer-major " +
				"question was not answered. Its control is latest_text_offline_served, whose probe DID " +
				"run and found nothing — the two rendered identically until this case existed.",
		},
		{
			name: "latest_text_offline_served",
			args: []string{"latest", "example.com/mod"},
			env:  refusesNetwork,
			why:  "the offline answer on the human channel: the same line, with the as-of date that dates it.",
		},
	}
}

// contextCases cover the surface that gained findings[].withdrawn_at unseen.
func contextCases(emptyStore string) []cmdCase {
	return []cmdCase{
		{
			name: "context_json_populated",
			args: []string{"context", "example.com/mod@v1.2.0", "--json"},
			why: "populated: one coordinate with TWO artefact measurements, a licence, a call graph, " +
				"and vulnerability findings from two snapshots. A change to how those compose shows here.",
		},
		{
			name: "context_text_populated",
			args: []string{"context", "example.com/mod@v1.2.0"},
			why:  "populated, text: the same document on the human channel.",
		},
		{
			name: "context_json_clean_module",
			args: []string{"context", "example.com/clean@v1.0.0", "--json"},
			why: "populated, and NOT divergent: one artefact measurement, verified, scanned and clean. " +
				"It is the control for context_json_populated, whose coordinate holds two measurements " +
				"of one version and therefore reads as a divergence.",
		},
		{
			name: "context_json_gomod_only_module",
			args: []string{"context", "example.com/shallow@v1.0.0", "--json"},
			why: "the go.mod-only module: held with a verified go.mod and no zip, and unscannable for " +
				"that reason. A per-module go.sum classification has a non-uniform value to report here.",
		},
		{
			name: "context_json_absent_module",
			args: []string{"context", "example.com/absent@v9.9.9", "--json"},
			why:  "empty: nothing is stored for this coordinate; every section must say so rather than be omitted.",
		},
		{
			name:      "context_json_store_missing",
			args:      []string{"context", "example.com/mod@v1.2.0", "--json"},
			storeRoot: emptyStore,
			why:       "error-shaped: the store read fails because there is no store.",
		},
		{
			name: "context_json_bad_coordinate",
			args: []string{"context", "not-a-coordinate", "--json"},
			why:  "error-shaped: a malformed coordinate is refused before any store is opened.",
		},
	}
}

// reachabilityCases cover the surface that gained withdrawn_at AND a new
// verdict enum value in the same unseen change.
func reachabilityCases(emptyStore string) []cmdCase {
	return []cmdCase{
		{
			name: "reachability_json_populated",
			args: []string{"reachability", "example.com/mod@v1.2.0", "--vuln", "GO-2026-0001", "--json"},
			why:  "populated: a stored, reachable answer with a versioned route, a fidelity and a rooting.",
		},
		{
			name: "reachability_text_populated",
			args: []string{"reachability", "example.com/mod@v1.2.0", "--vuln", "GO-2026-0001"},
			why:  "populated, text: the same answer on the human channel.",
		},
		{
			name: "reachability_json_unknown_vuln",
			args: []string{"reachability", "example.com/mod@v1.2.0", "--vuln", "GO-2099-9999", "--json"},
			why:  "empty: the coordinate was scanned and this advisory is not among its findings.",
		},
		// The headline of the soundness work: a negative a search CONFIRMED, on the
		// --json surface. Before this, the search over an application's graph was
		// rooted at every function the module owns, so the vulnerable symbol was
		// itself a root, every search reached it in zero hops, and this rung could
		// not be produced for any record in any store. Measured on a working store
		// at the time: 37 negatives, every one inferred, zero confirmed.
		{
			name: "reachability_json_confirmed_negative",
			args: []string{"reachability", "example.com/mod@v1.2.0", "--vuln", "GO-2026-0003", "--json"},
		},
		{
			name: "reachability_text_confirmed_negative",
			args: []string{"reachability", "example.com/mod@v1.2.0", "--vuln", "GO-2026-0003"},
		},
		// The other half of the same rule: a search that could NOT be made says so.
		// Here the graph loads and holds none of the symbols the advisory names, so
		// there was nothing to look for — which is not a search that came back
		// empty, and must not read like one.
		{
			name: "reachability_json_search_skipped",
			args: []string{"reachability", "example.com/mod@v1.2.0", "--vuln", "GO-2026-0004", "--json"},
		},
		{
			name:      "reachability_json_store_missing",
			args:      []string{"reachability", "example.com/mod@v1.2.0", "--vuln", "GO-2026-0001", "--json"},
			storeRoot: emptyStore,
			why:       "error-shaped: nothing is stored, so no answer can be served.",
		},
		{
			name: "reachability_json_no_target",
			args: []string{"reachability", "--vuln", "GO-2026-0001", "--json"},
			why:  "error-shaped: a query with no coordinate to answer about.",
		},
	}
}

// vulnShowHistoryCases cover the read where multi-row composition is VISIBLE.
// The point-in-time reads hide it behind selection; a history lists the rows.
func vulnShowHistoryCases(emptyStore string) []cmdCase {
	return []cmdCase{
		{
			name: "vuln_show_text_populated",
			args: []string{"vuln-show", "example.com/mod@v1.2.0"},
			why: "populated, text, per-finding: the ONE case that records printFindingLines. " +
				"The history views print a line per scan record and the JSON views a key per " +
				"finding, so neither pins what a person reads under a finding — which is where " +
				"the reachability state and the instrument that produced it are stated.",
		},
		{
			name: "vuln_show_history_json_populated",
			args: []string{"vuln-show", "example.com/mod@v1.2.0", "--history", "--json"},
			why: "populated: ONE coordinate scanned against TWO advisory snapshots. A change to how " +
				"records compose into an answer moves these rows; a one-record-per-coordinate fixture would not.",
		},
		{
			name: "vuln_show_history_text_populated",
			args: []string{"vuln-show", "example.com/mod@v1.2.0", "--history"},
			why:  "populated, text: one line per stored scan record, with the frame each was measured in.",
		},
		{
			name: "vuln_show_history_json_gomod_only",
			args: []string{"vuln-show", "example.com/shallow@v1.0.0", "--history", "--json"},
			why:  "the go.mod-only module's history: unscannable, with the reason named.",
		},
		{
			name: "vuln_show_history_json_absent",
			args: []string{"vuln-show", "example.com/absent@v9.9.9", "--history", "--json"},
			why:  "empty: no records at any generation for this coordinate.",
		},
		{
			name:      "vuln_show_history_json_store_missing",
			args:      []string{"vuln-show", "example.com/mod@v1.2.0", "--history", "--json"},
			storeRoot: emptyStore,
			why:       "error-shaped: an empty store answers not-found rather than an empty list.",
		},
	}
}

// callGraphShowCases cover the read where MULTI-GENERATION composition is
// visible. The fixture coordinate holds two generations at different
// completeness levels, and the weaker one was written last: composition serves
// the highest completeness before the most recent, so the served marker in the
// history listing is what a change to that ladder moves.
//
// The graph digest on each history row is derived from the record's hashed
// shape with the measurement time blanked. That makes it deterministic under
// the pinned clock, and it also means a change to the call-graph record's shape
// moves these files. That is correct: it is a change to what the answer is. Do
// not read a moved digest as timestamp noise.
func callGraphShowCases(emptyStore string) []cmdCase {
	return []cmdCase{
		{
			name: "callgraph_show_history_text_populated",
			args: []string{"callgraph-show", "example.com/mod@v1.2.0", "--history"},
			why: "populated: TWO generations of one coordinate at different completeness levels, the " +
				"weaker written last. The * marks the generation the composed read serves, which must be " +
				"the built graph and not the newest one.",
		},
		{
			name: "callgraph_show_json_populated",
			args: []string{"callgraph-show", "example.com/mod@v1.2.0", "--json"},
			why: "populated, --json: the COMPOSED answer, carrying completeness and analysis_source " +
				"unconditionally — an absent value is itself the answer and has to be visible as one.",
		},
		{
			name: "callgraph_show_text_populated",
			args: []string{"callgraph-show", "example.com/mod@v1.2.0"},
			why:  "populated, text: the composed record with its fidelity line.",
		},
		{
			name: "callgraph_show_history_text_absent",
			args: []string{"callgraph-show", "example.com/absent@v9.9.9", "--history"},
			why:  "empty: no generation at any completeness for this coordinate.",
		},
		{
			name: "callgraph_show_json_source_scoped_empty",
			args: []string{"callgraph-show", "example.com/mod@v1.2.0", "--source", "worktree", "--json"},
			why: "empty, scoped: the ledger holds generations for this coordinate but none from the " +
				"worktree. The refusal must name the source rather than report the module unknown.",
		},
		{
			name:      "callgraph_show_json_store_missing",
			args:      []string{"callgraph-show", "example.com/mod@v1.2.0", "--json"},
			storeRoot: emptyStore,
			why:       "error-shaped: there is no store to read a generation from.",
		},
	}
}

// printedRemedyCases record the two things a refusal owes its reader: the exit
// code that says WHICH kind of refusal it is, and a remedy that runs as printed.
//
// They are grouped because one defect produced both. `capability` refused a
// coordinate nothing had analysed with the code that means "you invoked this
// wrongly", and named the remedy as a placeholder no parser accepts. `fetch`
// printed a remedy built from a string shared with the commands that DO define
// --from-modcache, and rejected it with "unknown flag" when the operator ran it.
//
// Both renderings of the offline remedy are recorded, here and in
// audit_text_no_network: `audit` declares the flag and is told to pass it,
// `fetch` declares none and is told what to run instead. A shared string that
// drifted back into both would move one of the two files.
func printedRemedyCases(t *testing.T, emptyStore string) []cmdCase {
	t.Helper()
	return []cmdCase{
		{
			name: "capability_text_populated",
			args: []string{"capability", "example.com/mod@v1.2.0"},
			why: "populated: the coordinate the fixture store holds a call graph for. It is the CONTROL " +
				"for the refusal below — the same command, the same store, and the only difference is " +
				"whether the record is there.",
		},
		{
			name: "capability_text_no_callgraph",
			args: []string{"capability", "example.com/clean@v1.0.0"},
			why: "THE REFUSAL: a well-formed coordinate the store has no call graph for. It must exit 4, " +
				"not 20 — the request was fine and the store was empty — and the remedy must name THIS " +
				"coordinate rather than a <module>@<version> placeholder, because a template is not " +
				"something a caller can run.",
		},
		{
			name:      "capability_text_bad_coordinate",
			args:      []string{"capability", "not-a-coordinate"},
			storeRoot: emptyStore,
			why: "the control for the exit code above: a malformed coordinate is the invocation being " +
				"wrong, and stays 20. Without this case, moving every capability refusal to 4 would look right.",
		},
		{
			name:      "fetch_text_no_network",
			args:      []string{"fetch", "example.com/mod@v1.2.0"},
			storeRoot: t.TempDir(),
			env:       map[string]string{"GOPROXY": "off"},
			why: "THE REMEDY: GOPROXY=off stops the run, and what it prints must be runnable BY FETCH. " +
				"fetch defines no --from-modcache, so naming it sent the operator to `unknown flag`. " +
				"Its control is audit_text_no_network, whose command does define the flag and is told " +
				"to pass it. A shared string that named one flag to both would move one of these files.",
		},
	}
}

// composedReadCases cover the reads that build one answer out of SEVERAL stored
// records. They are grouped because that is what they have in common and why
// they were chosen ahead of easier surfaces: a single-record read changes shape
// only when its own struct changes, whereas a composed read changes when the
// rule for combining records changes — and that rule can move without any
// struct moving, which is the change a golden is uniquely able to see.
func composedReadCases(emptyStore string) []cmdCase {
	return []cmdCase{
		// vuln-scan-show renders a run from the records it PINNED, not from
		// whatever the coordinate holds now. The two fixture runs differ in
		// snapshot and in module set, so a change to that resolution moves one
		// of these files rather than both.
		{
			name: "vuln_scan_show_json_populated",
			args: []string{"vuln-scan-show", fixtureScanRunID2, "--json"},
			why: "populated: the later run, which pinned three modules against the second snapshot — " +
				"one affected, one clean, one unscannable.",
		},
		{
			name: "vuln_scan_show_text_populated",
			args: []string{"vuln-scan-show", fixtureScanRunID2},
			why:  "populated, text: the same run on the human channel.",
		},
		{
			name: "vuln_scan_show_json_earlier_run",
			args: []string{"vuln-scan-show", fixtureScanRunID, "--json"},
			why: "the CONTROL for the run above: the earlier run pinned ONE module against the first " +
				"snapshot. A composition that served the coordinate's current records instead of the " +
				"ones this run pinned would make the two runs agree.",
		},
		{
			name: "vuln_scan_show_json_absent",
			args: []string{"vuln-scan-show", "01JSCANRUN0ABSENT00000001", "--json"},
			why:  "empty: no run with this identifier.",
		},
		{
			name:      "vuln_scan_show_json_store_missing",
			args:      []string{"vuln-scan-show", fixtureScanRunID2, "--json"},
			storeRoot: emptyStore,
			why:       "error-shaped: there is no store to resolve the run in.",
		},

		// vuln-scan-diff composes TWO runs. A fixture with one run per walk can
		// express no diff at all.
		{
			name: "vuln_scan_diff_json_populated",
			args: []string{"vuln-scan-diff", fixtureScanRunID, fixtureScanRunID2, "--json"},
			why: "populated: two runs of one walk against two snapshots. Modules enter the scanned set " +
				"and an advisory appears, so both axes of the diff carry a value.",
		},
		{
			name: "vuln_scan_diff_text_populated",
			args: []string{"vuln-scan-diff", fixtureScanRunID, fixtureScanRunID2},
			why:  "populated, text: the same comparison on the human channel.",
		},
		{
			name: "vuln_scan_diff_json_same_run",
			args: []string{"vuln-scan-diff", fixtureScanRunID2, fixtureScanRunID2, "--json"},
			why: "the ZERO paired with the populated diff above: a run compared with itself must report " +
				"no change. Without it a diff that reported everything as changed would still look right.",
		},
		{
			name: "vuln_scan_history_json_populated",
			args: []string{"vuln-scan-history", fixtureWalkID, "--json"},
			why:  "populated: every run of one walk, in order, which is where the snapshot axis is visible.",
		},
		{
			name: "vuln_scan_list_json_populated",
			args: []string{"vuln-scan-list", "--json"},
			why:  "populated: the runs the store holds, across walks.",
		},

		// walk-diff composes two walk records. The second fixture walk drops a
		// module and moves another, so the diff has both a removal and a change.
		{
			name: "walk_diff_json_populated",
			args: []string{"walk-diff", fixtureWalkID, fixtureWalkID2, "--json"},
			why: "populated: two walks of one target. One module leaves the graph and another moves " +
				"version, so the added/removed/changed axes are not all empty.",
		},
		{
			name: "walk_diff_text_populated",
			args: []string{"walk-diff", fixtureWalkID, fixtureWalkID2},
			why:  "populated, text: the same comparison on the human channel.",
		},
		{
			name: "walk_diff_json_same_walk",
			args: []string{"walk-diff", fixtureWalkID, fixtureWalkID, "--json"},
			why:  "the ZERO for walk-diff: a walk compared with itself reports nothing changed.",
		},
		{
			name:      "walk_diff_json_store_missing",
			args:      []string{"walk-diff", fixtureWalkID, fixtureWalkID2, "--json"},
			storeRoot: emptyStore,
			why:       "error-shaped: neither walk can be read.",
		},
		{
			name: "walk_show_json_populated",
			args: []string{"walk-show", fixtureWalkID, "--json"},
			why:  "populated: the whole sealed walk record, which every composed read above is scoped by.",
		},
		{
			name: "walk_list_json_populated",
			args: []string{"walk-list", "--json"},
			why:  "populated: both walks, which is what makes the diff above addressable.",
		},

		// license-compat composes a licence per module across a walk's closure.
		// One module in the closure has no licence record at all, so the
		// unresolved half of that answer is exercised rather than avoided.
		{
			name: "license_compat_json_populated",
			args: []string{"license-compat", "example.com/app@v1.0.0", "--walk-id", fixtureWalkID, "--json"},
			why: "populated: a closure holding TWO DIFFERENT detected licences plus a module with no " +
				"licence record at all, so the compatible pair and the undetermined module are both " +
				"judged. A closure of one licence repeated composes to the same answer under any rule.",
		},
		{
			name: "license_compat_text_populated",
			args: []string{"license-compat", "example.com/app@v1.0.0", "--walk-id", fixtureWalkID},
			why:  "populated, text: the same closure on the human channel.",
		},
		{
			name: "license_compat_text_ambiguous_walk",
			args: []string{"license-compat", "example.com/app@v1.0.0"},
			why: "the UNPINNED read: the store holds two walks of this target, so the command must say " +
				"which one it chose and why before it answers. Naming no walk is what an operator does.",
		},
		{
			name: "license_compat_json_absent",
			args: []string{"license-compat", "example.com/absent@v9.9.9", "--json"},
			why:  "empty: no walk is stored for this coordinate, so there is no closure to judge.",
		},

		// vuln-by-id composes across coordinates rather than within one.
		{
			name: "vuln_by_id_json_populated",
			args: []string{"vuln-by-id", "GO-2026-0001", "--json"},
			why:  "populated: every coordinate a single advisory reaches, ranked by finding.",
		},
		{
			name: "vuln_by_id_json_withdrawn",
			args: []string{"vuln-by-id", "GO-2026-0002", "--json"},
			why: "the RETRACTED advisory: it is carried by a record and must still be answerable, with " +
				"its retraction stated rather than the coordinate reported clean.",
		},
		{
			name: "vuln_by_id_json_absent",
			args: []string{"vuln-by-id", "GO-2099-9999", "--json"},
			why:  "empty: no stored record carries this advisory.",
		},

		{
			name: "verification_coverage_json_populated",
			args: []string{"verification-coverage", fixtureWalkID, "--json"},
			why: "populated: the walk's verification aggregate, composed from one fetch record per node " +
				"— including the go.mod-only module, which has no zip to verify.",
		},
		{
			name: "dependents_json_populated",
			args: []string{"dependents", "example.com/shallow@v1.0.0", "--any-build", "--json"},
			why: "populated: which modules in a stored walk depend on this one, read off the graph edges. " +
				"--any-build is the store-wide search; it is what this case has always recorded, and it " +
				"is now the flag that reaches it.",
		},
		{
			name: "dependents_text_root_excluded",
			args: []string{"dependents", "example.com/mod@v1.2.0", "--walk-id", fixtureWalkID},
			why: "the defect state, on the channel that never had it wrong: the walk root is the only " +
				"module with an edge to the target and it is out of scope by default, so the answer is " +
				"empty and says so in the same sentence. Recorded byte-for-byte because the JSON leg was " +
				"added underneath it and must not have moved it.",
		},
		{
			name: "dependents_json_root_excluded",
			args: []string{"dependents", "example.com/mod@v1.2.0", "--walk-id", fixtureWalkID, "--json"},
			why: "the same state on the channel that DID have it wrong: \"dependents\": [] reads as a " +
				"confirmed negative, so root_scope states what the search left out and the flag that " +
				"puts it back.",
		},
		{
			name: "dependents_text_unrooted",
			args: []string{"dependents", "example.com/shallow@v1.0.0"},
			why: "error-shaped: no walk id, no manifest and no go.mod here, so there is no build for the " +
				"question to be about. The refusal names all three ways to give one instead of searching.",
		},
	}
}

// auditCases cover audit: the surface this whole detector exists for, and the
// one phase one could not record.
//
// The populated cases run the WHOLE derivation — a real walk, a real licence
// extraction, a real vulnerability scan — against the fixture module cache and
// the fixture advisory database, with GOPROXY=off. Nothing is projected: every
// key audit emits is in the golden, so a field added to the audit row moves one
// of these files. See auditfixture_test.go for how that is made hermetic.
func auditCases(t *testing.T, gomod, project string, unroutable map[string]string, audit *auditFixture) []cmdCase {
	t.Helper()
	populated := func(name, why string, args ...string) cmdCase {
		return cmdCase{
			name:         name,
			args:         args,
			env:          audit.env(),
			storeRoot:    audit.newStore(t),
			mintedValues: true,
			why:          why,
		}
	}
	// The command every populated audit case runs. The reused case names it twice
	// — once to prime the store and once to be recorded — so the two runs cannot
	// drift apart into a comparison of different command lines.
	auditArgs := []string{"audit", "--gomod", audit.gomod(), "--from-modcache=" + audit.modcache}
	// The same command under --json. The reused JSON case names it twice for the
	// reason the text one does: the priming run and the recorded run must be the
	// same invocation, or the recording compares two different commands.
	auditJSONArgs := append(append([]string{}, auditArgs...), "--json")

	return []cmdCase{
		populated("audit_json_populated",
			"POPULATED: the whole derivation, offline. Two dependencies plus the standard library, "+
				"one affected by the fixture advisory and one clean, one staleness row served from the "+
				"ledger and one unmeasured. Every key the audit row emits is recorded here, so adding a "+
				"field to that row moves this file.",
			"audit", "--gomod", audit.gomod(), "--from-modcache="+audit.modcache, "--json"),
		populated("audit_text_populated",
			"populated, text: the same audit on the human channel, where the table and the stderr "+
				"basis lines are the interface rather than the array.",
			"audit", "--gomod", audit.gomod(), "--from-modcache="+audit.modcache),
		{
			name: "audit_text_reused_scan",
			args: auditArgs,
			// PRIMED: the same command, run first against this case's own empty
			// store and discarded. What it leaves behind — a walk, licences and a
			// completed scan run against the fixture snapshot — is what makes the
			// recorded run a SERVED one.
			prime:        [][]string{auditArgs},
			env:          audit.env(),
			storeRoot:    audit.newStore(t),
			mintedValues: true,
			why: "REUSED: the same audit run a second time against the store the first one wrote. It is the " +
				"only recording of what the tool says about work it did NOT do — the walk re-resolved and found " +
				"identical, the scan served from a stored run, and what that run's reachability answers rest on. " +
				"The date and the run identifier below are recorded literally, so a change to WHICH stored run " +
				"answers moves this file. Its control is audit_text_populated, which must keep reading " +
				"`derived by this run`.",
		},
		{
			name: "audit_json_reused_scan",
			args: auditJSONArgs,
			// PRIMED exactly as audit_text_reused_scan is: the first run leaves a
			// walk, licences and a completed scan run behind, and the recorded run
			// is the one that serves them.
			prime:        [][]string{auditJSONArgs},
			env:          audit.env(),
			storeRoot:    audit.newStore(t),
			mintedValues: true,
			why: "REUSED, json: the run-level facts on the machine channel when the answer was NOT measured " +
				"by this invocation — the walk re-resolved and found identical, the scan served from a stored " +
				"run, and its reachability answers resting on source this run did not read. Its control is " +
				"audit_json_populated, which must keep reading `\"reused\": false` and " +
				"`\"source_read_by_this_run\": true` for the same fixture. The pair is what shows the fields " +
				"track the run rather than being constants.",
		},
		populated("audit_text_no_network",
			"GOPROXY=off WITHOUT --from-modcache: the run no longer refuses at proxy construction for the "+
				"sake of one column. It proceeds, and the staleness column reports what the ledger holds "+
				"and `unmeasured (offline)` for what it does not — which is the whole point, because it "+
				"is measured here on a run that then FAILS. The bytes are not in this store, so the walk "+
				"cannot fetch them, no licence is determined, and the licence policy blocks with exit 5. "+
				"That is a different obstacle from the one that used to stop the command, and it names "+
				"itself. Its control is audit_text_populated, the same audit under --from-modcache.",
			"audit", "--gomod", audit.gomod()),
		{
			name: "audit_json_empty_scope",
			args: []string{"audit", "--gomod", gomod, "--json"},
			env:  unroutable,
			why:  "empty: a go.mod with no dependencies answers [] before the store or the proxy is opened.",
		},
		{
			name: "audit_text_empty_scope",
			args: []string{"audit", "--gomod", gomod},
			env:  unroutable,
			why:  "empty, text: prose on the human channel, never an empty array.",
		},
		{
			name: "audit_json_missing_gomod",
			args: []string{"audit", "--gomod", filepath.Join(project, "absent", "go.mod"), "--json"},
			env:  unroutable,
			why:  "error-shaped: the named go.mod does not exist.",
		},
	}
}

// buildFixtureProject writes a module with NO dependencies, which is what the
// empty-scope cases audit and resolve. It is a real module: the scope resolution
// under test shells out to the go command, and a directory that is not a module
// would exercise a different refusal.
func buildFixtureProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":  "module example.com/emptyproj\n\ngo 1.26.6\n",
		"main.go": "package main\n\nfunc main() {}\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("writing fixture project %s: %v", name, err)
		}
	}
	return dir
}

// sbomCases cover the CycloneDX document — the artefact kanonarion exists to
// hand to somebody else — and the two listings over the records it leaves.
//
// It is the strongest instance of the composition argument this file makes
// elsewhere. An SBOM is assembled from the walk graph, the licence records, the
// fetch ledger's origin data, the vendored tree, the stdlib custody facts and
// the native-component records — six sources, combined by rules that live in the
// generator and in no struct. A change to any of those rules moves no record's
// shape and no other recorded surface.
//
// Every case here gets its OWN store. `sbom` persists a record and appends an
// assurance event, so a shared root would make the listings answer differently
// depending on which case ran first — the dependency prime exists to keep inside
// one case.
func sbomCases(t *testing.T) []cmdCase {
	t.Helper()
	return []cmdCase{
		{
			name:      "sbom_populated",
			args:      []string{"sbom", docWalkID},
			storeRoot: buildDocumentStore(t),
			why: "POPULATED: every component carries a licence identity, so the document publishes and the " +
				"command exits 0. It holds the NON-GO component — a C library a cgo module compiles in from " +
				"source its own zip ships — as a pkg:generic entry with a CycloneDX evidence block naming the " +
				"file and the verbatim declaration its version was read from, and a dependsOn edge from the " +
				"host module. A change to how six sources compose into one inventory moves this file and " +
				"nothing else in the suite.",
		},
		{
			name:      "sbom_caller_supplied_timestamp",
			args:      []string{"sbom", docWalkID, "--generated-at", "2026-03-01T09:00:00Z"},
			storeRoot: buildDocumentStore(t),
			why: "THE OTHER TIMESTAMP BASIS, and the control for sbom_populated. metadata.timestamp has two " +
				"sources and the document states which one it used: a creation time the caller supplied, or " +
				"the newest licence extraction time among its inputs when none was. The generator reads no " +
				"clock on either path. The pair is what shows the basis property tracks the invocation " +
				"rather than being a constant. A stamped document is also ephemeral — it is generated, not " +
				"served, and not stored.",
		},
		{
			name:      "sbom_undetermined_licences",
			args:      []string{"sbom", docWalkGapID},
			storeRoot: buildDocumentStore(t),
			why: "ERROR-SHAPED, and the shape a release pipeline branches on: one component carries no " +
				"licence identity. The document IS written — exit 1 with the whole inventory on stdout — and " +
				"the refusal names the component and the command that supplies the record it lacks. The exit " +
				"code is in this golden, so a change that turned the gap into a silent zero would move it.",
		},
		{
			name:      "sbom_no_dependencies",
			args:      []string{"sbom", docWalkBareID},
			storeRoot: buildDocumentStore(t),
			why: "THE ZERO: a walk that brought nothing in. The document still names its subject and says so " +
				"in one component rather than answering with an empty list or nothing at all.",
		},
		{
			name:      "sbom_unknown_walk",
			args:      []string{"sbom", "01ARZ3NDEKTSV4RRFFQ69G5FZZ"},
			storeRoot: buildDocumentStore(t),
			why: "error-shaped: no walk with this identifier, so there is no graph to inventory. The exit " +
				"code is 20, and it was the HELP TEXT that was wrong about it — `sbom --help` stated `4  " +
				"the walk or package scope named does not exist` while the command returned 20, and the " +
				"help was corrected in the same change as this case. docs/cli/conventions.md holds the " +
				"authoritative table and lists neither sbom nor notice in its exit-4 row: a walk id is " +
				"minted by a run, so a refusal naming one can print no command to produce it and the " +
				"invocation is what has to change. Pinned here and in the exit-code contract test, " +
				"because the temptation on reading that mismatch is to correct the other side.",
		},
		{
			name:      "sbom_no_scope",
			args:      []string{"sbom"},
			storeRoot: buildDocumentStore(t),
			why: "error-shaped: neither a walk id nor --package, so the command is not told what to " +
				"inventory. Refused before the store is opened.",
		},
		{
			name: "sbom_list_json_populated",
			args: []string{"sbom-list", "--json"},
			// PRIMED: two documents generated into this case's own store. What
			// they leave behind is what the listing reads, so the recorded rows
			// depend on this case and not on declaration order.
			prime:     [][]string{{"sbom", docWalkID}, {"sbom", docWalkBareID}},
			storeRoot: buildDocumentStore(t),
			why: "populated: the records two generations left behind, across walks, and they TIE on " +
				"generated_at — see sbom_list_text_populated for why that is the fixture's point rather " +
				"than its accident. licenses_incomplete is written at every row: it is the condition " +
				"behind the non-zero exit, and a caller that cannot read it per record cannot tell a " +
				"complete artefact from an incomplete one without opening every document.",
		},
		{
			name:      "sbom_list_text_populated",
			args:      []string{"sbom-list"},
			prime:     [][]string{{"sbom", docWalkID}, {"sbom", docWalkBareID}},
			storeRoot: buildDocumentStore(t),
			why: "populated, text, OVER A TIE: both documents carry the same generated_at, because a " +
				"document generated with no --generated-at is stamped with the newest licence extraction " +
				"time among its inputs and this fixture has one licence basis. That is the state two " +
				"documents are in by construction, not a coincidence. The listing orders on generated_at " +
				"and then on append order, so the document produced LATER comes first — and this file is " +
				"the check that the tie is broken rather than resolved by whatever the store returned.",
		},
		{
			name:      "sbom_list_json_empty",
			args:      []string{"sbom-list", "--json"},
			storeRoot: buildDocumentStore(t),
			why: "empty: the store holds walks and no SBOM has been generated from any of them. The zero " +
				"says how many records were considered and what to run to produce one, rather than " +
				"answering [] and leaving the reader to guess whether the filter or the store was empty.",
		},
		{
			name:      "sbom_list_json_unknown_walk",
			args:      []string{"sbom-list", "--json", "--walk", "01ARZ3NDEKTSV4RRFFQ69G5FZZ"},
			prime:     [][]string{{"sbom", docWalkID}},
			storeRoot: buildDocumentStore(t),
			why: "the FILTERED zero, and the control for sbom_list_json_empty: records exist and none " +
				"matches this walk. The two zeros must not read alike — one says nothing was generated, the " +
				"other says nothing matched — and the filtered one names the field it filtered on.",
		},
	}
}

// noticeCases cover the THIRD-PARTY-LICENSES document.
//
// It leaves the building the way the SBOM does, and it composes differently: the
// licence records supply the identity and the copyright, and the verbatim text
// is read back out of each module's stored artefact. A document that named every
// licence correctly and reproduced none of the text would satisfy every
// record-shaped assertion in the suite.
//
// The store is shared here because notice only READS. Nothing a notice case does
// is visible to the next one.
func noticeCases(docStore string) []cmdCase {
	return []cmdCase{
		{
			name:      "notice_text_populated",
			args:      []string{"notice", docWalkID},
			storeRoot: docStore,
			why: "POPULATED: two dependencies and the subject, each with its identity, its copyright " +
				"statements and its licence text reproduced verbatim from the stored artefact. One module " +
				"carries an Apache NOTICE beside its LICENSE, headed as a notice rather than as a grant — " +
				"section 4(d) makes it travel with the work whether or not the detector classified it.",
		},
		{
			name:      "notice_json_populated",
			args:      []string{"notice", docWalkID, "--json"},
			storeRoot: docStore,
			why: "THE DOCUMENTED NO-OP: --json returns the same document, by decision. An attribution " +
				"document has no separate machine-readable projection, and the flag that means " +
				"machine-readable everywhere else must not be the one that WITHHOLDS the deliverable. " +
				"Recorded so that adding a second rendering moves a file rather than passing green; its " +
				"control is notice_text_populated, which it must match byte for byte.",
		},
		{
			name:      "notice_text_review_gate",
			args:      []string{"notice", docWalkGapID},
			storeRoot: docStore,
			why: "ERROR-SHAPED: one module in the walk has no licence record, so the document is NOT " +
				"published. The gate exits 5 — a policy gate on real findings, distinct from 20 for a bad " +
				"invocation — so a pipeline can route it to a person rather than to a build fixer. The " +
				"review list names the module and the reason, and stdout stays empty: a partial NOTICE is " +
				"worse than none.",
		},
		{
			name:      "notice_text_no_dependencies",
			args:      []string{"notice", docWalkBareID},
			storeRoot: docStore,
			why: "THE ZERO: a walk that brought nothing in. The document is the subject's own attribution " +
				"and nothing else, and the scope line still states which walk answered.",
		},
		{
			name:      "notice_text_unknown_walk",
			args:      []string{"notice", "01ARZ3NDEKTSV4RRFFQ69G5FZZ"},
			storeRoot: docStore,
			why:       "error-shaped: no walk with this identifier, so there is no module set to attribute.",
		},
		{
			name:      "notice_text_not_a_walk_id",
			args:      []string{"notice", "THIRD-PARTY-LICENSES"},
			storeRoot: docStore,
			why: "error-shaped, and the one that matters most on this command: a positional that is not a " +
				"walk id is REFUSED by name. Accepted and discarded, notice would fall through to the " +
				"working tree's go.mod and answer a question nobody asked, with an exit code.",
		},
		{
			name:      "sbom_show_absent",
			args:      []string{"sbom-show", "sbom-000000000000000000000000"},
			storeRoot: docStore,
			why: "error-shaped: no stored document with this identifier. sbom-show's POPULATED case is " +
				"deliberately absent: the record id is derived from the walk id and the SBOM pipeline " +
				"version, so a literal one here would turn a version bump into a not-found rather than into " +
				"a readable diff, and the bytes it would print are already recorded by sbom_populated.",
		},
	}
}
