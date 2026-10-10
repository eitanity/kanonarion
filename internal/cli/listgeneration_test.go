package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	exapp "github.com/eitanity/kanonarion/internal/example/application"
	exports "github.com/eitanity/kanonarion/internal/example/ports"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	licports "github.com/eitanity/kanonarion/internal/license/ports"
	nativedomain "github.com/eitanity/kanonarion/internal/native/domain"
	nativeports "github.com/eitanity/kanonarion/internal/native/ports"
)

// The five per-coordinate listings keep one generation contract: the default
// lists the generation this build serves, one row per coordinate;
// --all-generations adds the earlier rows and marks each; every row states its
// generation and whether it is superseded; the conflict check sees only the
// rows listed; and both renderings say which generation answered.

// supersededGen is the earlier generation every fixture below holds beside the
// served one.
const supersededGen = "0.0.1-earlier"

// generationSurface is one listing driven over a store holding two coordinates
// at the served generation and one of them again at supersededGen.
type generationSurface struct {
	name    string
	served  string
	subject string
	// genField is the row's generation key: native-list calls it generation.
	genField string
	// run lists the store; conflictOld puts a disputed row at supersededGen.
	run func(t *testing.T, all, conflictOld bool, limit, offset int, asJSON bool) (string, string, error)
	// filtered runs with a filter that keeps only example.com/a; nil where the
	// listing takes no filter.
	filtered func(t *testing.T, asJSON bool) (string, string, error)
}

func generationSurfaces(t *testing.T) []generationSurface {
	t.Helper()
	return []generationSurface{
		interfaceGenerationSurface(), examplesGenerationSurface(), callGraphGenerationSurface(),
		licenseGenerationSurface(), nativeGenerationSurface(t),
	}
}

func interfaceGenerationSurface() generationSurface {
	fixture := func(conflictOld bool) *testfakes.FakeQueryInterface {
		old := ifaceports.InterfaceSummary{ModulePath: "example.com/a", ModuleVersion: "v1.0.0", PipelineVersion: supersededGen, PackageCount: 1}
		if conflictOld {
			old.Conflict = fmt.Errorf("%w: at pipeline %s", ifaceports.ErrInterfaceConflict, supersededGen)
		}
		uc := testfakes.NewFakeQueryInterface()
		uc.SetList([]ifaceports.InterfaceSummary{
			{ModulePath: "example.com/a", ModuleVersion: "v1.0.0", PipelineVersion: ifaceapp.PipelineVersion, PackageCount: 2},
			old,
			{ModulePath: "example.com/b", ModuleVersion: "v1.0.0", PipelineVersion: ifaceapp.PipelineVersion, PackageCount: 3},
		})
		return uc
	}
	return generationSurface{
		name: "interface-list", served: ifaceapp.PipelineVersion, subject: "interface records", genField: "pipeline_version",
		run: func(t *testing.T, all, conflictOld bool, limit, offset int, asJSON bool) (string, string, error) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			err := interfaceListWith(context.Background(), limit, offset, all, fixture(conflictOld), &stdout, &stderr)
			return stdout.String(), stderr.String(), err
		},
	}
}

func examplesGenerationSurface() generationSurface {
	fixture := func(conflictOld bool) *testfakes.FakeQueryExamples {
		old := exports.ExampleSummary{ModulePath: "example.com/a", ModuleVersion: "v1.0.0", PipelineVersion: supersededGen, ExampleCount: 1}
		if conflictOld {
			old.Conflict = fmt.Errorf("%w: at pipeline %s", exports.ErrExampleConflict, supersededGen)
		}
		uc := testfakes.NewFakeQueryExamples()
		uc.SetList([]exports.ExampleSummary{
			{ModulePath: "example.com/a", ModuleVersion: "v1.0.0", PipelineVersion: exapp.PipelineVersion, ExampleCount: 2},
			old,
			{ModulePath: "example.com/b", ModuleVersion: "v1.0.0", PipelineVersion: exapp.PipelineVersion, ExampleCount: 3},
		})
		return uc
	}
	return generationSurface{
		name: "examples-list", served: exapp.PipelineVersion, subject: "example records", genField: "pipeline_version",
		run: func(t *testing.T, all, conflictOld bool, limit, offset int, asJSON bool) (string, string, error) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			err := runExamplesList(context.Background(), limit, offset, all, fixture(conflictOld), &stdout, &stderr)
			return stdout.String(), stderr.String(), err
		},
	}
}

// callgraph-list has no conflict on its rows, so conflictOld changes nothing.
func callGraphGenerationSurface() generationSurface {
	fixture := func() *testfakes.FakeQueryCallGraph {
		uc := testfakes.NewFakeQueryCallGraph()
		uc.SetList([]cgports.CallGraphSummary{
			{ModulePath: "example.com/a", ModuleVersion: "v1.0.0", PipelineVersion: cgapp.PipelineVersion, NodeCount: 2},
			{ModulePath: "example.com/a", ModuleVersion: "v1.0.0", PipelineVersion: supersededGen, NodeCount: 1},
			{ModulePath: "example.com/b", ModuleVersion: "v1.0.0", PipelineVersion: cgapp.PipelineVersion, NodeCount: 3},
		})
		return uc
	}
	run := func(t *testing.T, module string, all bool, limit, offset int, asJSON bool) (string, string, error) {
		t.Helper()
		withJSON(t, asJSON)
		var stdout, stderr bytes.Buffer
		err := runCallGraphList(context.Background(), module, limit, offset, all, fixture(), &stdout, &stderr)
		return stdout.String(), stderr.String(), err
	}
	return generationSurface{
		name: "callgraph-list", served: cgapp.PipelineVersion, subject: "call graph records", genField: "pipeline_version",
		run: func(t *testing.T, all, _ bool, limit, offset int, asJSON bool) (string, string, error) {
			t.Helper()
			return run(t, "", all, limit, offset, asJSON)
		},
		filtered: func(t *testing.T, asJSON bool) (string, string, error) {
			t.Helper()
			return run(t, "example.com/a", false, 50, 0, asJSON)
		},
	}
}

func licenseGenerationSurface() generationSurface {
	fixture := func(conflictOld bool) *testfakes.FakeQueryLicense {
		old := listSummary("example.com/a", supersededGen, licdomain.CopyrightStatusFound)
		if conflictOld {
			old.Conflict = fmt.Errorf("%w: at pipeline %s", licports.ErrLicenceConflict, supersededGen)
		}
		uc := testfakes.NewFakeQueryLicense()
		uc.SetList([]licports.LicenseSummary{
			listSummary("example.com/a", licapp.PipelineVersion, licdomain.CopyrightStatusFound),
			old,
			listSummary("example.com/b", licapp.PipelineVersion, licdomain.CopyrightStatusNoneFound),
		})
		return uc
	}
	run := func(t *testing.T, f licenseListFlags, conflictOld, asJSON bool) (string, string, error) {
		t.Helper()
		withJSON(t, asJSON)
		var stdout, stderr bytes.Buffer
		err := runLicenseList(context.Background(), f, nil, fixture(conflictOld),
			licdomain.NewLicenseOverrideSet(nil), &stdout, &stderr)
		return stdout.String(), stderr.String(), err
	}
	return generationSurface{
		name: "license-list", served: licapp.PipelineVersion, subject: "license records", genField: "pipeline_version",
		run: func(t *testing.T, all, conflictOld bool, limit, offset int, asJSON bool) (string, string, error) {
			t.Helper()
			return run(t, licenseListFlags{limit: limit, offset: offset, allGenerations: all}, conflictOld, asJSON)
		},
		filtered: func(t *testing.T, asJSON bool) (string, string, error) {
			t.Helper()
			return run(t, licenseListFlags{limit: 50, copyrightStatus: []licdomain.CopyrightStatus{licdomain.CopyrightStatusFound}}, false, asJSON)
		},
	}
}

func nativeGenerationSurface(t *testing.T) generationSurface {
	t.Helper()
	fixture := func(conflictOld bool) []nativeports.NativeSummary {
		old := nativeSummaryFixture(t, "example.com/a", nativedomain.PresenceIdentified)
		old.Generation = supersededGen
		if conflictOld {
			old.Conflict = fmt.Errorf("%w: at generation %s", nativeports.ErrNativeConflict, supersededGen)
		}
		return []nativeports.NativeSummary{
			nativeSummaryFixture(t, "example.com/a", nativedomain.PresenceAbsent),
			old,
			nativeSummaryFixture(t, "example.com/b", nativedomain.PresenceIdentified),
		}
	}
	return generationSurface{
		name: "native-list", served: nativedomain.PipelineFingerprint(), subject: "native records", genField: "generation",
		run: func(t *testing.T, all, conflictOld bool, limit, offset int, asJSON bool) (string, string, error) {
			t.Helper()
			return runNativeListFor(t, fixture(conflictOld), nativeListFlags{limit: limit, offset: offset, allGenerations: all}, asJSON)
		},
		filtered: func(t *testing.T, asJSON bool) (string, string, error) {
			t.Helper()
			return runNativeListFor(t, fixture(false),
				nativeListFlags{limit: 50, presence: []string{string(nativedomain.PresenceAbsent)}}, asJSON)
		},
	}
}

// generationDoc decodes a listing document with the generation fields typed.
type generationDoc struct {
	Records    []map[string]any `json:"records"`
	Subject    string           `json:"subject"`
	Truncated  bool             `json:"truncated"`
	ZeroResult *listZeroJSON    `json:"zero_result"`
	Generation *struct {
		Served         string  `json:"served"`
		AllGenerations bool    `json:"all_generations"`
		Remedy         *string `json:"remedy"`
	} `json:"generation"`
}

func decodeGenerationDoc(t *testing.T, stdout string) generationDoc {
	t.Helper()
	var doc generationDoc
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("stdout is not one listing document: %v\n%s", err, stdout)
	}
	if doc.Records == nil {
		t.Fatalf("records is not an array:\n%s", stdout)
	}
	return doc
}

// The default lists the served generation only, one row per coordinate, and
// says so; --all-generations is the control that the store did hold the earlier
// row, and it marks that row and only that row.
func TestGenerationListings_DefaultServesOneGenerationAndAllGenerationsMarksTheRest(t *testing.T) {
	for _, s := range generationSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			text, _, err := s.run(t, false, false, 50, 0, false)
			if err != nil {
				t.Fatalf("default listing: %v", err)
			}
			if got := strings.Count(text, "example.com/a@v1.0.0"); got != 1 {
				t.Errorf("example.com/a listed %d times by default, want once:\n%s", got, text)
			}
			if strings.Contains(text, supersededGen) {
				t.Errorf("the default listing shows the superseded generation:\n%s", text)
			}
			if !strings.Contains(text, "listing "+s.subject+" at ") || !strings.Contains(text, s.served+", the ") ||
				!strings.Contains(text, "(--all-generations)") {
				t.Errorf("the default listing does not say which generation it drew from:\n%s", text)
			}

			all, _, err := s.run(t, true, false, 50, 0, false)
			if err != nil {
				t.Fatalf("--all-generations: %v", err)
			}
			if got := strings.Count(all, "example.com/a@v1.0.0"); got != 2 {
				t.Errorf("--all-generations listed example.com/a %d times, want twice:\n%s", got, all)
			}
			if got := strings.Count(all, "[superseded generation "+supersededGen+"]"); got != 1 {
				t.Errorf("--all-generations marked %d rows, want the one superseded row:\n%s", got, all)
			}
			if strings.Contains(all, "[superseded generation "+s.served+"]") {
				t.Errorf("a served row was marked superseded:\n%s", all)
			}
			if !strings.Contains(all, "1 of 3 listed record(s) were ") {
				t.Errorf("--all-generations does not count what it marked:\n%s", all)
			}
		})
	}
}

// Both halves of the pair are on every row: a served row states superseded
// false, the superseded row true, and every row names its generation.
func TestGenerationListings_EveryRowStatesItsGenerationAndSupersession(t *testing.T) {
	for _, s := range generationSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			stdout, _, err := s.run(t, true, false, 50, 0, true)
			if err != nil {
				t.Fatalf("--all-generations --json: %v", err)
			}
			doc := decodeGenerationDoc(t, stdout)
			if len(doc.Records) != 3 {
				t.Fatalf("listed %d rows, want 3", len(doc.Records))
			}
			trueRows, falseRows := 0, 0
			for _, row := range doc.Records {
				sup, present := row["superseded"]
				if !present {
					t.Errorf("row %v carries no superseded", row["module"])
					continue
				}
				gen := optAs[string](t, row[s.genField])
				switch sup {
				case true:
					trueRows++
					if gen != supersededGen {
						t.Errorf("superseded row states %s %q, want %q", s.genField, gen, supersededGen)
					}
				case false:
					falseRows++
					if gen != s.served {
						t.Errorf("served row states %s %q, want %q", s.genField, gen, s.served)
					}
				}
			}
			if trueRows != 1 || falseRows != 2 {
				t.Errorf("superseded true on %d rows and false on %d, want 1 and 2", trueRows, falseRows)
			}
		})
	}
}

// A disagreement inside a generation this build does not serve fails only the
// listing that lists it. The control is the same store under
// --all-generations, which must exit 10.
func TestGenerationListings_ConflictCheckSeesOnlyTheListedRows(t *testing.T) {
	for _, s := range generationSurfaces(t) {
		if s.name == "callgraph-list" {
			continue // its rows carry no conflict
		}
		t.Run(s.name, func(t *testing.T) {
			for _, asJSON := range []bool{false, true} {
				if _, _, err := s.run(t, false, true, 50, 0, asJSON); err != nil {
					t.Errorf("json=%v: the default listing failed over a conflict it does not list: %v", asJSON, err)
				}
				_, _, err := s.run(t, true, true, 50, 0, asJSON)
				if code := ExitCodeForError(err); code != ExitIntegrity {
					t.Errorf("json=%v: --all-generations over a superseded conflict exited %d (%v), want %d",
						asJSON, code, err, ExitIntegrity)
				}
			}
		})
	}
}

// The document states the generation in every state a listing can be in, and
// keeps the listing conventions there: one object, records an array, nothing on
// stderr, the zero and paging statements where they apply.
func TestGenerationListings_DocumentStatesTheGenerationInEveryState(t *testing.T) {
	for _, s := range generationSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			type state struct {
				name            string
				run             func() (string, string, error)
				all             bool
				rows            int
				zero, pagedPast bool
				truncated       bool
			}
			states := []state{
				{name: "served", run: func() (string, string, error) { return s.run(t, false, false, 50, 0, true) }, rows: 2},
				{name: "all generations", run: func() (string, string, error) { return s.run(t, true, false, 50, 0, true) }, all: true, rows: 3},
				{name: "truncated", run: func() (string, string, error) { return s.run(t, false, false, 1, 0, true) }, rows: 1, truncated: true},
				{name: "over-paged", run: func() (string, string, error) { return s.run(t, false, false, 50, 10, true) }, zero: true, pagedPast: true},
			}
			if s.filtered != nil {
				states = append(states, state{name: "filtered", run: func() (string, string, error) { return s.filtered(t, true) }, rows: 1})
			}
			for _, st := range states {
				stdout, stderr, err := st.run()
				if err != nil {
					t.Fatalf("%s: %v", st.name, err)
				}
				if strings.TrimSpace(stderr) != "" {
					t.Errorf("%s: wrote to stderr under --json: %q", st.name, stderr)
				}
				doc := decodeGenerationDoc(t, stdout)
				if len(doc.Records) != st.rows {
					t.Errorf("%s: %d rows, want %d", st.name, len(doc.Records), st.rows)
				}
				if doc.Truncated != st.truncated {
					t.Errorf("%s: truncated = %v, want %v", st.name, doc.Truncated, st.truncated)
				}
				if doc.Subject != s.subject {
					t.Errorf("%s: subject %q, want the bare plural %q", st.name, doc.Subject, s.subject)
				}
				if (doc.ZeroResult != nil) != st.zero {
					t.Errorf("%s: zero_result present = %v, want %v", st.name, doc.ZeroResult != nil, st.zero)
				}
				if st.pagedPast && (doc.ZeroResult == nil || !doc.ZeroResult.PagedPast) {
					t.Errorf("%s: the zero statement does not name the paging: %+v", st.name, doc.ZeroResult)
				}
				if st.pagedPast && doc.ZeroResult != nil && doc.ZeroResult.RecordsConsidered != 2 {
					t.Errorf("%s: records_considered = %d, want the 2 at the served generation",
						st.name, doc.ZeroResult.RecordsConsidered)
				}
				g := doc.Generation
				if g == nil {
					t.Errorf("%s: the document carries no generation", st.name)
					continue
				}
				if g.Served != s.served || g.AllGenerations != st.all {
					t.Errorf("%s: generation = %+v, want served %s all_generations %v", st.name, *g, s.served, st.all)
				}
				switch {
				case st.all && g.Remedy != nil:
					t.Errorf("%s: remedy %q under --all-generations, want it omitted", st.name, *g.Remedy)
				case !st.all && (g.Remedy == nil || *g.Remedy != "--all-generations"):
					t.Errorf("%s: remedy = %v, want --all-generations", st.name, g.Remedy)
				}
			}
		})
	}
}

// A zero over a store holding only superseded records is a store-empty answer
// at the served generation, and --all-generations is the control that lists
// them.
func TestGenerationListings_EmptyServedGenerationIsAZeroWithItsGeneration(t *testing.T) {
	uc := testfakes.NewFakeQueryInterface()
	uc.SetList([]ifaceports.InterfaceSummary{
		{ModulePath: "example.com/a", ModuleVersion: "v1.0.0", PipelineVersion: supersededGen, PackageCount: 1},
	})
	withJSON(t, true)
	var stdout, stderr bytes.Buffer
	if err := interfaceListWith(context.Background(), 50, 0, false, uc, &stdout, &stderr); err != nil {
		t.Fatalf("interfaceListWith: %v", err)
	}
	doc := decodeGenerationDoc(t, stdout.String())
	if len(doc.Records) != 0 || doc.ZeroResult == nil || doc.Generation == nil {
		t.Fatalf("want an empty page with a zero statement and a generation, got %s", stdout.String())
	}
	stdout.Reset()
	if err := interfaceListWith(context.Background(), 50, 0, true, uc, &stdout, &stderr); err != nil {
		t.Fatalf("interfaceListWith --all-generations: %v", err)
	}
	if doc := decodeGenerationDoc(t, stdout.String()); len(doc.Records) != 1 {
		t.Errorf("--all-generations listed %d rows, want the 1 superseded record", len(doc.Records))
	}
}

// The ranged truncation line reads the bare plural: native-list's subject used
// to carry its generation and rendered "showing native records at generation X
// 3-4".
func TestNativeList_PagedLineNamesTheBarePlural(t *testing.T) {
	rows := make([]nativeports.NativeSummary, 0, 6)
	for i := range 6 {
		rows = append(rows, nativeSummaryFixture(t, fmt.Sprintf("example.com/m%d", i), nativedomain.PresenceAbsent))
	}
	text, _, err := runNativeListFor(t, rows, nativeListFlags{limit: 2, offset: 2}, false)
	if err != nil {
		t.Fatalf("native-list: %v", err)
	}
	if !strings.Contains(text, "showing native records 3-4 — more exist") {
		t.Errorf("the paged line does not read the bare plural:\n%s", text)
	}
}

// The store is asked for the served generation by default and for every
// generation under --all-generations, on the listings whose port takes it.
func TestGenerationListings_AskTheStoreForTheGeneration(t *testing.T) {
	ifaceUC := testfakes.NewFakeQueryInterface()
	exUC := testfakes.NewFakeQueryExamples()
	for _, all := range []bool{false, true} {
		withJSON(t, true)
		var out bytes.Buffer
		if err := interfaceListWith(context.Background(), 50, 0, all, ifaceUC, &out, &out); err != nil {
			t.Fatalf("interfaceListWith: %v", err)
		}
		if err := runExamplesList(context.Background(), 50, 0, all, exUC, &out, &out); err != nil {
			t.Fatalf("runExamplesList: %v", err)
		}
	}
	wantFirst := [2]string{ifaceapp.PipelineVersion, exapp.PipelineVersion}
	if got := ifaceUC.ListFilters[0].PipelineVersion; got != wantFirst[0] {
		t.Errorf("interface-list asked for generation %q by default, want %q", got, wantFirst[0])
	}
	if got := exUC.ListFilters[0].PipelineVersion; got != wantFirst[1] {
		t.Errorf("examples-list asked for generation %q by default, want %q", got, wantFirst[1])
	}
	if got := ifaceUC.ListFilters[len(ifaceUC.ListFilters)-1].PipelineVersion; got != "" {
		t.Errorf("interface-list --all-generations asked for generation %q, want every generation", got)
	}
	if got := exUC.ListFilters[len(exUC.ListFilters)-1].PipelineVersion; got != "" {
		t.Errorf("examples-list --all-generations asked for generation %q, want every generation", got)
	}
}
