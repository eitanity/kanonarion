package golden_test

// The recorded surfaces, and what each case exists to detect.
//
// Coverage here is deliberately partial, and the gaps are NAMED rather than
// left to be discovered. A detector whose coverage is unstated is one whose
// silence gets read as an all-clear.
//
// COVERED, by command:
//
//	latest              --json and text; populated, the no-publication-date zero,
//	                    an empty scope, and the GOPROXY=off refusal.
//	context             --json and text; populated (divergent), populated (clean),
//	                    go.mod-only, absent coordinate, missing store, bad coordinate.
//	reachability        --json and text; a stored reachable verdict, an advisory the
//	                    scan never saw, an empty store, a query with no target.
//	vuln-show --history --json and text; two snapshots of one coordinate, the
//	                    go.mod-only module, an absent coordinate, an empty store.
//	audit               the EMPTY and ERROR paths only — see below.
//
// NOT COVERED, and why:
//
//	audit (populated)   audit derives a live walk and a live vulnerability scan
//	                    before it prints a row. Its output carries generated
//	                    ULIDs, the operator's username, wall-clock durations and
//	                    a toolchain-dependent judgment, none of which a fixture
//	                    store can supply. Measured: an added field on the audit
//	                    row struct moves NO golden in this package today.
//	every other command every remaining --json surface, and the text surfaces of
//	                    vuln-scan, inspect and vuln. They are repetition against
//	                    this harness rather than new design, and they are the
//	                    next piece of work, not an accident.
//
// Each surface carries a POPULATED, an EMPTY and an ERROR-SHAPED case. The last
// two are not padding: an output regression on a not-found or a store-read
// failure is the one nobody notices by hand, because nobody runs those paths on
// purpose.

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

	norm := &normaliser{replacements: [][2]string{
		{storeRoot, "$STORE"},
		{emptyStore, "$EMPTY_STORE"},
		{project, "$PROJECT"},
		{home, "$HOME"},
	}}

	// The whole run is offline and homeless: no case may reach the operator's
	// store, and a case that tries to reach the network fails rather than
	// recording a live answer.
	t.Setenv("HOME", home)
	t.Setenv("GOTOOLCHAIN", "local")

	for _, c := range commandCases(emptyStore, project) {
		t.Run(c.name, func(t *testing.T) {
			root := c.storeRoot
			if root == "" {
				root = storeRoot
			}
			res := runCommand(t, c, root)
			recorded := record(c, res, norm)
			assertNoTempPaths(t, c.name, recorded)
			checkGolden(t, c, recorded)
		})
	}
}

// commandCases is the whole recorded set.
func commandCases(emptyStore, project string) []cmdCase {
	gomod := filepath.Join(project, "go.mod")
	// Two offline postures, and the difference between them is deliberate.
	//
	// `off` is an operator's declaration that this environment does no module
	// fetching. Commands that construct a proxy adapter REFUSE under it, before
	// they consult anything recorded, so it can only be used for a case whose
	// subject is that refusal.
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
	cases = append(cases, auditCases(gomod, project, unroutable)...)
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
			why:  "error-shaped: nothing recorded for this module and the environment forbids the network.",
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

// auditCases cover the two audit paths that are answerable without deriving a
// walk and a scan. The populated path is NOT recorded — it runs a live walk and
// a live vulnerability scan, and its output carries generated ULIDs, the
// operator's username and wall-clock durations. See COVERAGE.md.
func auditCases(gomod, project string, unroutable map[string]string) []cmdCase {
	return []cmdCase{
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
