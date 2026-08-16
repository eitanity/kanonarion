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
//	dependents            --json.
//
// NOT COVERED, and named rather than implied:
//
//	interface-show / interface-diff / interface-list
//	examples-* / symbol-* / implementers / callers / callees
//	sbom / sbom-show / sbom-list / notice
//	inspect / vuln-scan / vuln / fetch / walk / extract / license / callgraph
//	capability / fips / godebug / directives / vendor / provenance / use
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
	cases = append(cases, auditCases(t, gomod, project, unroutable, audit)...)
	return cases
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
			why:  "populated: a stored, reachable verdict with a versioned route, a fidelity and a rooting.",
		},
		{
			name: "reachability_text_populated",
			args: []string{"reachability", "example.com/mod@v1.2.0", "--vuln", "GO-2026-0001"},
			why:  "populated, text: the same verdict on the human channel.",
		},
		{
			name: "reachability_json_unknown_vuln",
			args: []string{"reachability", "example.com/mod@v1.2.0", "--vuln", "GO-2099-9999", "--json"},
			why:  "empty: the coordinate was scanned and this advisory is not among its findings.",
		},
		{
			name:      "reachability_json_store_missing",
			args:      []string{"reachability", "example.com/mod@v1.2.0", "--vuln", "GO-2026-0001", "--json"},
			storeRoot: emptyStore,
			why:       "error-shaped: nothing is stored, so no verdict can be served.",
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
			args: []string{"dependents", "example.com/shallow@v1.0.0", "--json"},
			why:  "populated: which modules in a stored walk depend on this one, read off the graph edges.",
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
				"identical, the scan served from a stored run, and what that run's reachability verdicts rest on. " +
				"The date and the run identifier below are recorded literally, so a change to WHICH stored run " +
				"answers moves this file. Its control is audit_text_populated, which must keep reading " +
				"`derived by this run`.",
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
