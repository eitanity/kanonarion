package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	directivedomain "github.com/eitanity/kanonarion/internal/directive/domain"
	exports "github.com/eitanity/kanonarion/internal/example/ports"
	extractports "github.com/eitanity/kanonarion/internal/extract/ports"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// The defect this file pins: paging gave a bare "no records found" a second
// cause it could not name. Three listings already said which of the three
// causes emptied their page — the store holds none, a filter excluded them, or
// the page starts past the last record — and five did not, on both renderings.
// `extract list` was the worst: it printed column headings and no statement at
// all, so the answer was not merely unexplained, it was unwritten.
//
// Every assertion below is on the wording the three adopters already ship;
// nothing here is a second vocabulary for the same statement.

// decodeZeroNotice reads the structured notice off a listing's stderr. It is a
// hard failure rather than a skip: an absent notice is exactly the defect.
func decodeZeroNotice(t *testing.T, stderr string) listZeroJSON {
	t.Helper()
	var notice listZeroJSON
	if err := json.Unmarshal([]byte(stderr), &notice); err != nil {
		t.Fatalf("stderr carried no JSON zero-result notice: %v\nstderr: %q", err, stderr)
	}
	return notice
}

func populatedInterfaceList() *testfakes.FakeQueryInterface {
	uc := testfakes.NewFakeQueryInterface()
	uc.SetList([]ifaceports.InterfaceSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", PackageCount: 2},
		{ModulePath: "example.com/dep", ModuleVersion: "v2.0.0", PackageCount: 1},
	})
	return uc
}

func populatedExamplesList() *testfakes.FakeQueryExamples {
	uc := testfakes.NewFakeQueryExamples()
	uc.SetList([]exports.ExampleSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", ExampleCount: 3},
		{ModulePath: "example.com/dep", ModuleVersion: "v2.0.0", ExampleCount: 1},
	})
	return uc
}

func populatedExtractionList() *testfakes.FakeQueryExtraction {
	uc := testfakes.NewFakeQueryExtraction()
	uc.SetList([]extractports.ExtractionRunSummary{
		{ID: "run-0", WalkID: "walk-0", ModuleCount: 7, StartedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		{ID: "run-1", WalkID: "walk-1", ModuleCount: 4, StartedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)},
	})
	return uc
}

func populatedWalkList(t *testing.T) *testfakes.FakeQueryWalks {
	t.Helper()
	uc := testfakes.NewFakeQueryWalks()
	uc.SetSummaries([]walkports.WalkSummary{
		{
			ID: "walk-0", Target: mustCoord(t, "example.com/app", "v1.0.0"),
			Scope: walkdomain.WalkScopeCode, Depth: walkdomain.WalkDepthFull,
			StartedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			OverallStatus: walkdomain.WalkSucceeded, NodeCount: 2,
		},
		{
			ID: "walk-1", Target: mustCoord(t, "example.com/dep", "v2.0.0"),
			Scope: walkdomain.WalkScopeCode, Depth: walkdomain.WalkDepthFull,
			StartedAt:     time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
			OverallStatus: walkdomain.WalkSucceeded, NodeCount: 1,
		},
	})
	return uc
}

func directivesContainer(scans []directivedomain.Record) *Container {
	return &Container{QueryDirectives: &testfakes.FakeQueryDirectives{Scans: scans}}
}

func populatedDirectivesScans() []directivedomain.Record {
	return []directivedomain.Record{
		{ID: "scan-0", ProjectModulePath: "example.com/proj", ContentHash: "sha256:a"},
		{ID: "scan-1", ProjectModulePath: "example.com/proj", ContentHash: "sha256:b"},
	}
}

// zeroCase is one listing's answer to one cause, on both renderings.
type zeroCase struct {
	name string
	// run drives the listing at the given output mode.
	run func(t *testing.T, asJSON bool) (stdout, stderr string)
	// wantText is every fragment the prose statement must carry.
	wantText []string
	// notText is every fragment it must not: the wrong cause, or the header a
	// listing used to print in place of an answer.
	notText []string
	// wantNotice is the structured statement the same zero must carry.
	wantNotice listZeroJSON
	// wantFilter, when set, is the filter half of the structured statement.
	wantFilter *listZeroFilterJSON
	// statementOnStderr marks a surface that is not a paged listing and so has
	// no listing document to carry its statement: `vuln-snapshot-list` renders
	// one array with no --limit and no --offset, and its zero still travels on
	// stderr. The flag is here rather than a second harness so the wording stays
	// asserted in one place.
	statementOnStderr bool
}

func runZeroCases(t *testing.T, cases []zeroCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, _ := tc.run(t, false)
			for _, want := range tc.wantText {
				if !strings.Contains(stdout, want) {
					t.Errorf("the text statement is missing %q, got:\n%s", want, stdout)
				}
			}
			for _, unwanted := range tc.notText {
				if strings.Contains(stdout, unwanted) {
					t.Errorf("the text statement must not carry %q, got:\n%s", unwanted, stdout)
				}
			}

			jsonStdout, jsonStderr := tc.run(t, true)
			if tc.statementOnStderr {
				checkZeroNotice(t, decodeZeroNotice(t, jsonStderr), tc)
				return
			}
			doc := decodeListingDocument(t, jsonStdout)
			if len(doc.Records) != 0 {
				t.Errorf("the records array must be empty, got %d rows", len(doc.Records))
			}
			if strings.TrimSpace(jsonStderr) != "" {
				t.Errorf("the statement belongs in the document, not on stderr: %q", jsonStderr)
			}
			if doc.ZeroResult == nil {
				t.Fatalf("the document does not say why the page is empty:\n%s", jsonStdout)
			}
			checkZeroNotice(t, *doc.ZeroResult, tc)
		})
	}
}

// checkZeroNotice asserts one structured zero statement, wherever it travelled.
func checkZeroNotice(t *testing.T, notice listZeroJSON, tc zeroCase) {
	t.Helper()
	if notice.Subject != tc.wantNotice.Subject {
		t.Errorf("subject = %q, want %q", notice.Subject, tc.wantNotice.Subject)
	}
	if notice.RecordsConsidered != tc.wantNotice.RecordsConsidered {
		t.Errorf("records_considered = %d, want %d", notice.RecordsConsidered, tc.wantNotice.RecordsConsidered)
	}
	if notice.StoreEmpty != tc.wantNotice.StoreEmpty {
		t.Errorf("store_empty = %v, want %v", notice.StoreEmpty, tc.wantNotice.StoreEmpty)
	}
	if notice.PagedPast != tc.wantNotice.PagedPast {
		t.Errorf("paged_past = %v, want %v", notice.PagedPast, tc.wantNotice.PagedPast)
	}
	if len(notice.Remedy) == 0 || notice.Remedy[0] != tc.wantNotice.Remedy[0] {
		t.Errorf("remedy = %v, want %v", notice.Remedy, tc.wantNotice.Remedy)
	}
	switch {
	case tc.wantFilter == nil && notice.Filter != nil:
		t.Errorf("an unfiltered listing claimed a filter: %+v", notice.Filter)
	case tc.wantFilter != nil && notice.Filter == nil:
		t.Errorf("the filter that emptied the page is not named: %+v", notice)
	case tc.wantFilter != nil && *notice.Filter != *tc.wantFilter:
		t.Errorf("filter = %+v, want %+v", *notice.Filter, *tc.wantFilter)
	}
}

// interface-list takes no filter — a module argument routes to the
// single-module rendering, which fails with ExitNotFound — so it has two causes
// to tell apart, and used to answer both with "no interface records found".
func TestRunInterfaceList_ZeroNamesItsScope(t *testing.T) {
	run := func(uc QueryInterfaceUseCase, offset int) func(*testing.T, bool) (string, string) {
		return func(t *testing.T, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := interfaceListWith(context.Background(), 20, offset, uc, &stdout, &stderr); err != nil {
				t.Fatalf("interfaceListWith: %v", err)
			}
			return stdout.String(), stderr.String()
		}
	}
	runZeroCases(t, []zeroCase{
		{
			name:     "empty store",
			run:      run(testfakes.NewFakeQueryInterface(), 0),
			wantText: []string{"the store holds no interface record at all", "to produce one: kanonarion interface <module>@<version>"},
			notText:  []string{"no interface records found", "starts past the last one"},
			wantNotice: listZeroJSON{
				Subject: "interface record", RecordsConsidered: 0, StoreEmpty: true,
				Remedy: []string{"kanonarion interface <module>@<version>"},
			},
		},
		{
			name: "paged past the end",
			run:  run(populatedInterfaceList(), 99),
			wantText: []string{
				"no interface record on this page — the store holds 2 interface record(s), and --offset 99 starts past the last one",
				"to list from the start: kanonarion interface-list",
			},
			notText: []string{"no interface records found", "holds no interface record at all"},
			wantNotice: listZeroJSON{
				Subject: "interface record", RecordsConsidered: 2, PagedPast: true,
				Remedy: []string{"kanonarion interface-list"},
			},
		},
	})
}

// examples-list has the same two causes and the same defect.
func TestRunExamplesList_ZeroNamesItsScope(t *testing.T) {
	run := func(uc QueryExamplesUseCase, offset int) func(*testing.T, bool) (string, string) {
		return func(t *testing.T, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := runExamplesList(context.Background(), 20, offset, uc, &stdout, &stderr); err != nil {
				t.Fatalf("runExamplesList: %v", err)
			}
			return stdout.String(), stderr.String()
		}
	}
	runZeroCases(t, []zeroCase{
		{
			name:     "empty store",
			run:      run(testfakes.NewFakeQueryExamples(), 0),
			wantText: []string{"the store holds no example record at all", "to produce one: kanonarion examples <module>@<version>"},
			notText:  []string{"no example records found", "starts past the last one"},
			wantNotice: listZeroJSON{
				Subject: "example record", RecordsConsidered: 0, StoreEmpty: true,
				Remedy: []string{"kanonarion examples <module>@<version>"},
			},
		},
		{
			name: "paged past the end",
			run:  run(populatedExamplesList(), 99),
			wantText: []string{
				"no example record on this page — the store holds 2 example record(s), and --offset 99 starts past the last one",
				"to list from the start: kanonarion examples-list",
			},
			notText: []string{"no example records found", "holds no example record at all"},
			wantNotice: listZeroJSON{
				Subject: "example record", RecordsConsidered: 2, PagedPast: true,
				Remedy: []string{"kanonarion examples-list"},
			},
		},
	})
}

// `extract list` printed a table header and nothing under it, so a caller who
// piped it to a human read column names as the answer. The notice replaces the
// header rather than following it.
func TestRunExtractList_ZeroNamesItsScope(t *testing.T) {
	run := func(uc QueryExtractionUseCase, offset int) func(*testing.T, bool) (string, string) {
		return func(t *testing.T, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := runExtractList(context.Background(), 20, offset, uc, &stdout, &stderr); err != nil {
				t.Fatalf("runExtractList: %v", err)
			}
			return stdout.String(), stderr.String()
		}
	}
	runZeroCases(t, []zeroCase{
		{
			name:     "empty store",
			run:      run(testfakes.NewFakeQueryExtraction(), 0),
			wantText: []string{"the store holds no extraction run at all", "to produce one: kanonarion extract <walk-id>"},
			notText:  []string{"RUN ID", "WALK ID", "starts past the last one"},
			wantNotice: listZeroJSON{
				Subject: "extraction run", RecordsConsidered: 0, StoreEmpty: true,
				Remedy: []string{"kanonarion extract <walk-id>"},
			},
		},
		{
			name: "paged past the end",
			run:  run(populatedExtractionList(), 99),
			wantText: []string{
				"no extraction run on this page — the store holds 2 extraction run(s), and --offset 99 starts past the last one",
				"to list from the start: kanonarion extract list",
			},
			notText: []string{"RUN ID", "holds no extraction run at all"},
			wantNotice: listZeroJSON{
				Subject: "extraction run", RecordsConsidered: 2, PagedPast: true,
				Remedy: []string{"kanonarion extract list"},
			},
		},
	})
}

// walk-list is the one listing of the five that can reach all three causes: it
// carries filters as well as paging.
func TestRunWalkList_ZeroNamesItsScope(t *testing.T) {
	run := func(uc QueryWalksUseCase, status string, offset int) func(*testing.T, bool) (string, string) {
		return func(t *testing.T, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := runWalkList(context.Background(), "", "", status, "", "", 20, offset, false, false,
				uc, &stdout, &stderr); err != nil {
				t.Fatalf("runWalkList: %v", err)
			}
			return stdout.String(), stderr.String()
		}
	}
	runZeroCases(t, []zeroCase{
		{
			name:     "empty store",
			run:      run(testfakes.NewFakeQueryWalks(), "", 0),
			wantText: []string{"the store holds no walk record at all", "to produce one: kanonarion walk <module>@<version>"},
			notText:  []string{"no walk records found", "starts past the last one"},
			wantNotice: listZeroJSON{
				Subject: "walk record", RecordsConsidered: 0, StoreEmpty: true,
				Remedy: []string{"kanonarion walk <module>@<version>"},
			},
		},
		{
			name: "a filter excluded every record",
			run: func(t *testing.T, asJSON bool) (string, string) {
				t.Helper()
				return run(populatedWalkList(t), "failed", 0)(t, asJSON)
			},
			wantText: []string{
				`no walk record matched overall status "failed"`,
				"compared for exact equality against the overall status of all 2 walk record(s) in the store",
				"to list every walk record: kanonarion walk-list",
			},
			notText: []string{"no walk records found", "starts past the last one", "to produce one"},
			wantNotice: listZeroJSON{
				Subject: "walk record", RecordsConsidered: 2,
				Remedy: []string{"kanonarion walk-list"},
			},
			wantFilter: &listZeroFilterJSON{
				Name: "overall status", Value: "failed",
				ComparedAgainst: "overall status", Match: matchExact,
			},
		},
		{
			name: "paged past the end",
			run: func(t *testing.T, asJSON bool) (string, string) {
				t.Helper()
				return run(populatedWalkList(t), "", 99)(t, asJSON)
			},
			wantText: []string{
				"no walk record on this page — the store holds 2 walk record(s), and --offset 99 starts past the last one",
				"to list from the start: kanonarion walk-list",
			},
			notText: []string{"no walk records found", "holds no walk record at all"},
			wantNotice: listZeroJSON{
				Subject: "walk record", RecordsConsidered: 2, PagedPast: true,
				Remedy: []string{"kanonarion walk-list"},
			},
		},
	})
}

// `directives list` already named the project; what it could not say was
// whether the project had never been scanned or the page started past its last
// scan, and — once it could see past the project — whether anything had ever
// been scanned at all.
//
// The framing follows the project's own count, because the two cases are about
// different corpora. With scans for the project, the project IS the corpus and
// the only remaining cause is paging, so it stays in the subject. With none,
// the project is what excluded them, so it moves to the filter slot and the
// count becomes the store's — measured by CountScans, never inferred from the
// project-keyed read, which would report the whole store empty on one project's
// evidence.
func TestDirectivesList_ZeroNamesItsScope(t *testing.T) {
	run := func(scans []directivedomain.Record, offset int) func(*testing.T, bool) (string, string) {
		return func(t *testing.T, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := directivesListWith(context.Background(), directivesContainer(scans),
				"example.com/proj", 20, offset, &stdout, &stderr); err != nil {
				t.Fatalf("directivesListWith: %v", err)
			}
			return stdout.String(), stderr.String()
		}
	}
	runZeroCases(t, []zeroCase{
		{
			name: "nothing has ever been scanned",
			run:  run(nil, 0),
			wantText: []string{
				`the store holds no directive scan at all, so project "example.com/proj" is not what made this empty`,
				"to produce one: kanonarion directives",
			},
			notText: []string{"starts past the last one"},
			wantNotice: listZeroJSON{
				Subject: "directive scan", RecordsConsidered: 0, StoreEmpty: true,
				Remedy: []string{"kanonarion directives"},
			},
			wantFilter: &listZeroFilterJSON{
				Name: "project", Value: "example.com/proj",
				ComparedAgainst: "project module path", Match: matchExact,
			},
		},
		{
			name: "paged past the end",
			run:  run(populatedDirectivesScans(), 99),
			wantText: []string{
				"no directive scan for example.com/proj on this page — the store holds 2 directive scans for example.com/proj, and --offset 99 starts past the last one",
				// The project is carried into the remedy: a bare re-run infers
				// it from the working tree, which is not necessarily the one
				// the reader asked about.
				"to list from the start: kanonarion directives list --project example.com/proj",
			},
			notText: []string{"holds no directive scan for example.com/proj at all"},
			wantNotice: listZeroJSON{
				Subject: "directive scan for example.com/proj", RecordsConsidered: 2, PagedPast: true,
				Remedy: []string{"kanonarion directives list --project example.com/proj"},
			},
		},
	})
}

// The adjacent-fuzz sweep, run over the same corpus the truncation work paged:
// every listing that caps its rows states why its page came back empty, on both
// renderings. It is driven by the surfaces rather than by the five that were
// measured, so a listing added later cannot ship silent.
func TestListings_EveryOverPagedListingNamesItsScope(t *testing.T) {
	surfaces := listingSurfaces(t)
	if len(surfaces) < 8 {
		t.Fatalf("the sweep covers %d listings, want the 8 that cap their rows", len(surfaces))
	}
	for _, s := range surfaces {
		t.Run(s.name, func(t *testing.T) {
			offset := s.population + 5
			stdout, _ := s.run(t, 3, offset, false)
			for _, want := range []string{
				fmt.Sprintf("--offset %d starts past the last one", offset),
				fmt.Sprintf("the store holds %d ", s.population),
				"to list from the start:",
			} {
				if !strings.Contains(stdout, want) {
					t.Errorf("the over-paged text answer is missing %q, got:\n%s", want, stdout)
				}
			}

			jsonStdout, jsonStderr := s.run(t, 3, offset, true)
			doc := decodeListingDocument(t, jsonStdout)
			if len(doc.Records) != 0 {
				t.Errorf("a page past the population returned %d rows", len(doc.Records))
			}
			if strings.TrimSpace(jsonStderr) != "" {
				t.Errorf("the statement belongs in the document, not on stderr: %q", jsonStderr)
			}
			if doc.ZeroResult == nil {
				t.Fatalf("the document does not say why the page is empty:\n%s", jsonStdout)
			}
			notice := *doc.ZeroResult
			if !notice.PagedPast {
				t.Errorf("paged_past = false on a page past the population: %+v", notice)
			}
			if notice.StoreEmpty {
				t.Errorf("store_empty = true over a populated store: %+v", notice)
			}
			if notice.RecordsConsidered != s.population {
				t.Errorf("records_considered = %d, want the population %d", notice.RecordsConsidered, s.population)
			}
			if notice.Subject == "" || len(notice.Remedy) == 0 {
				t.Errorf("the notice names neither its subject nor a remedy: %+v", notice)
			}
		})
	}
}

// The zero-paired control. A listing that returned rows carries no zero-result
// statement on either channel, so a test that would pass on a notice emitted
// unconditionally fails here instead.
func TestListings_PopulatedPageCarriesNoZeroNotice(t *testing.T) {
	for _, s := range listingSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			stdout, stderr := s.run(t, 3, 0, false)
			for _, unwanted := range []string{"starts past the last one", "to list from the start:", "the store holds no"} {
				if strings.Contains(stdout, unwanted) {
					t.Errorf("a populated page carried %q on stdout:\n%s", unwanted, stdout)
				}
			}
			if strings.Contains(stderr, "store_empty") {
				t.Errorf("a populated page carried a zero-result notice on stderr:\n%s", stderr)
			}

			_, jsonStderr := s.run(t, 3, 0, true)
			if strings.Contains(jsonStderr, "store_empty") || strings.Contains(jsonStderr, "records_considered") {
				t.Errorf("a populated JSON page carried a zero-result notice on stderr:\n%s", jsonStderr)
			}
		})
	}
}

// walk-list encoded a nil slice, so its stdout was `null` on an empty page and
// an array on a populated one — the one listing whose data channel changed type
// with the row count. The sweep pins the property for all of them at every row
// count a caller can ask for.
func TestListings_JSONRecordsIsAnArrayAtEveryRowCount(t *testing.T) {
	for _, s := range listingSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			for _, offset := range []int{0, s.population - 1, s.population, s.population + 5} {
				stdout, _ := s.run(t, 3, offset, true)
				// Decoded into `any` rather than into a slice: `null` unmarshals
				// into a []T without complaint, so a test that decoded into the
				// row type would have passed on exactly the defect.
				var doc map[string]any
				if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
					t.Fatalf("stdout at --offset %d is not one JSON object: %v\nstdout: %q", offset, err, stdout)
				}
				records, ok := doc["records"]
				if !ok {
					t.Fatalf("stdout at --offset %d carries no records field\nstdout: %q", offset, stdout)
				}
				if _, ok := records.([]any); !ok {
					t.Errorf("records at --offset %d is %T, want a JSON array at every row count\nstdout: %q",
						offset, records, stdout)
				}
			}
		})
	}
}

// emptyListingSurfaces is the same eight listings over an empty store. It is the
// corpus for the case an --offset makes reachable everywhere at once: a page
// past the end of nothing.
func emptyListingSurfaces(t *testing.T) []listingSurface {
	t.Helper()
	surface := func(name string, run func(t *testing.T, limit, offset int, asJSON bool) (string, string)) listingSurface {
		return listingSurface{name: name, population: 0, run: run, rows: countJSONRows}
	}
	return []listingSurface{
		surface("license-list", func(t *testing.T, limit, offset int, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := runLicenseList(context.Background(), "", "", limit, offset,
				testfakes.NewFakeQueryLicense(), licdomain.LicenseOverrideSet{}, &stdout, &stderr); err != nil {
				t.Fatalf("runLicenseList: %v", err)
			}
			return stdout.String(), stderr.String()
		}),
		surface("interface-list", func(t *testing.T, limit, offset int, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := interfaceListWith(context.Background(), limit, offset,
				testfakes.NewFakeQueryInterface(), &stdout, &stderr); err != nil {
				t.Fatalf("interfaceListWith: %v", err)
			}
			return stdout.String(), stderr.String()
		}),
		surface("examples-list", func(t *testing.T, limit, offset int, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := runExamplesList(context.Background(), limit, offset,
				testfakes.NewFakeQueryExamples(), &stdout, &stderr); err != nil {
				t.Fatalf("runExamplesList: %v", err)
			}
			return stdout.String(), stderr.String()
		}),
		surface("callgraph-list", func(t *testing.T, limit, offset int, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := runCallGraphList(context.Background(), "", limit, offset,
				testfakes.NewFakeQueryCallGraph(), &stdout, &stderr); err != nil {
				t.Fatalf("runCallGraphList: %v", err)
			}
			return stdout.String(), stderr.String()
		}),
		surface("vuln-scan-list", func(t *testing.T, limit, offset int, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := runScanList(context.Background(), "", limit, offset,
				testfakes.NewFakeQueryScanRuns(), &stdout, &stderr); err != nil {
				t.Fatalf("runScanList: %v", err)
			}
			return stdout.String(), stderr.String()
		}),
		surface("walk-list", func(t *testing.T, limit, offset int, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := runWalkList(context.Background(), "", "", "", "", "", limit, offset, false, false,
				testfakes.NewFakeQueryWalks(), &stdout, &stderr); err != nil {
				t.Fatalf("runWalkList: %v", err)
			}
			return stdout.String(), stderr.String()
		}),
		surface("extract list", func(t *testing.T, limit, offset int, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := runExtractList(context.Background(), limit, offset,
				testfakes.NewFakeQueryExtraction(), &stdout, &stderr); err != nil {
				t.Fatalf("runExtractList: %v", err)
			}
			return stdout.String(), stderr.String()
		}),
		surface("directives list", func(t *testing.T, limit, offset int, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := directivesListWith(context.Background(), directivesContainer(nil),
				"example.com/proj", limit, offset, &stdout, &stderr); err != nil {
				t.Fatalf("directivesListWith: %v", err)
			}
			return stdout.String(), stderr.String()
		}),
	}
}

// An --offset over an empty store still reports an empty store. Paging is only
// an explanation when there were records to page past; claiming it over a corpus
// of nothing sends the reader to lower an offset that never excluded anything,
// and hides the one remedy that would have helped.
//
// Measured on the live store first: `directives list --limit 5 --offset 9000`
// for a project with no scans answered "the store holds 0 directive scans …,
// and --offset 9000 starts past the last one". The same guard was missing on
// all eight, including the three listings that shipped the notice.
func TestListings_OffsetOverAnEmptyStoreIsNotPagedPast(t *testing.T) {
	for _, s := range emptyListingSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			stdout, _ := s.run(t, 3, 9000, false)
			if !strings.Contains(stdout, "the store holds no ") {
				t.Errorf("an empty store did not say so:\n%s", stdout)
			}
			if strings.Contains(stdout, "starts past the last one") {
				t.Errorf("an empty store was reported as a page past the end:\n%s", stdout)
			}
			if !strings.Contains(stdout, "to produce one:") {
				t.Errorf("an empty store was not offered the produce-a-record remedy:\n%s", stdout)
			}

			jsonStdout, jsonStderr := s.run(t, 3, 9000, true)
			if strings.TrimSpace(jsonStderr) != "" {
				t.Errorf("the statement belongs in the document, not on stderr: %q", jsonStderr)
			}
			doc := decodeListingDocument(t, jsonStdout)
			if doc.ZeroResult == nil {
				t.Fatalf("the document does not say why the page is empty:\n%s", jsonStdout)
			}
			notice := *doc.ZeroResult
			if notice.PagedPast {
				t.Errorf("paged_past = true over an empty store: %+v", notice)
			}
			if !notice.StoreEmpty || notice.RecordsConsidered != 0 {
				t.Errorf("want store_empty over zero records, got %+v", notice)
			}
		})
	}
}

// walk-list carries four filters, and every one that was set is named. Dropping
// one from the statement would send the reader to check a value that was not
// the one that excluded their walk.
func TestRunWalkList_EveryAppliedFilterIsNamed(t *testing.T) {
	withJSON(t, false)
	var stdout, stderr bytes.Buffer
	if err := runWalkList(context.Background(), "example.com/absent@v9.9.9", "", "cancelled", "tool", "",
		20, 0, false, false, populatedWalkList(t), &stdout, &stderr); err != nil {
		t.Fatalf("runWalkList: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		"target and overall status and walk scope",
		`"example.com/absent@v9.9.9 / cancelled / tool"`,
		"against the target coordinate, then the overall status, then the walk scope",
		"of all 2 walk record(s) in the store",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the statement is missing %q, got:\n%s", want, out)
		}
	}
	// Three exact-equality filters are one kind of comparison, not three.
	if strings.Contains(out, "for exact equality then for exact equality") {
		t.Errorf("identical match kinds must be stated once, got:\n%s", out)
	}
}

// ---- the residue: the four surfaces the adoption left behind ---------------

// `directives list` could report the project's own history and nothing else,
// because ListScans is keyed on the project. A caller who mistyped the path and
// one whose project has genuinely never been scanned got the same sentence, and
// there was no read on the port that could tell them apart. CountScans is that
// read, and the notice spends it only where it changes the answer.
func TestDirectivesList_ZeroSeparatesThisProjectFromTheWholeStore(t *testing.T) {
	run := func(uc *testfakes.FakeQueryDirectives) func(*testing.T, bool) (string, string) {
		return func(t *testing.T, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := directivesListWith(context.Background(), &Container{QueryDirectives: uc},
				"example.com/proj", 20, 0, &stdout, &stderr); err != nil {
				t.Fatalf("directivesListWith: %v", err)
			}
			return stdout.String(), stderr.String()
		}
	}
	runZeroCases(t, []zeroCase{
		{
			// The case the port could not see: this project has nothing, other
			// projects do. The sentence must not say the store is empty, and
			// the count must be the store's, not the project's.
			name: "other projects have been scanned",
			run:  run(&testfakes.FakeQueryDirectives{StoreScans: 7}),
			wantText: []string{
				`no directive scan matched project "example.com/proj"`,
				"compared for exact equality against the project module path of all 7 directive scan(s) in the store",
				"to list every directive scan: kanonarion directives list --project <module-path>",
			},
			notText: []string{"the store holds no directive scan at all", "starts past the last one"},
			wantNotice: listZeroJSON{
				Subject: "directive scan", RecordsConsidered: 7, StoreEmpty: false,
				Remedy: []string{"kanonarion directives list --project <module-path>"},
			},
			wantFilter: &listZeroFilterJSON{
				Name: "project", Value: "example.com/proj",
				ComparedAgainst: "project module path", Match: matchExact,
			},
		},
	})
}

// The two counts are measured separately, and the store-wide one is never
// inferred from the project-keyed read. A fake whose project read returns
// nothing while the store holds seven is exactly the shape the previous
// implementation could not represent: it would have reported the whole store
// empty on one project's evidence.
func TestDirectivesList_StoreCountIsNotInferredFromTheProject(t *testing.T) {
	withJSON(t, false)
	uc := &testfakes.FakeQueryDirectives{StoreScans: 7}
	var stdout, stderr bytes.Buffer
	if err := directivesListWith(context.Background(), &Container{QueryDirectives: uc},
		"example.com/absent", 20, 0, &stdout, &stderr); err != nil {
		t.Fatalf("directivesListWith: %v", err)
	}
	if strings.Contains(stdout.String(), "holds no directive scan at all") {
		t.Errorf("a store holding 7 scans was reported empty on one project's evidence:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "all 7 directive scan(s) in the store") {
		t.Errorf("the store-wide count is missing:\n%s", stdout.String())
	}
}

// A count that fails is surfaced, not absorbed: every sentence the notice can
// render carries a number, so a scope it could not size has nothing honest to
// say, and a zero substituted for a failed count asserts the one reading that
// is certainly wrong.
func TestDirectivesList_ZeroSurfacesAFailedStoreCount(t *testing.T) {
	withJSON(t, false)
	uc := &testfakes.FakeQueryDirectives{CountErr: errors.New("store unreadable")}
	var stdout, stderr bytes.Buffer
	err := directivesListWith(context.Background(), &Container{QueryDirectives: uc},
		"example.com/proj", 20, 0, &stdout, &stderr)
	if err == nil {
		t.Fatal("a failed store count was absorbed into a notice that could not have been measured")
	}
	if !strings.Contains(err.Error(), "store unreadable") {
		t.Errorf("the failure does not name its cause: %v", err)
	}
}

// vuln-snapshot-list answered `no snapshots found` — no subject, no count, no
// remedy. It takes neither a filter nor an offset, so it has exactly one cause
// it can have, and it states that one rather than borrowing clauses it cannot
// support.
func TestRunSnapshotList_ZeroNamesItsScope(t *testing.T) {
	run := func(uc QueryScanRunsUseCase) func(*testing.T, bool) (string, string) {
		return func(t *testing.T, asJSON bool) (string, string) {
			t.Helper()
			var stdout, stderr bytes.Buffer
			if err := runSnapshotList(context.Background(), asJSON, uc, &stdout, &stderr); err != nil {
				t.Fatalf("runSnapshotList: %v", err)
			}
			return stdout.String(), stderr.String()
		}
	}
	runZeroCases(t, []zeroCase{
		{
			name:              "empty store",
			run:               run(testfakes.NewFakeQueryScanRuns()),
			statementOnStderr: true,
			wantText: []string{
				"the store holds no vulnerability database snapshot at all",
				"to produce one: kanonarion vuln-scan <walk-id>",
			},
			// The bare line it used to print, and the two causes it cannot have:
			// there is no --limit and no filter on this command.
			notText: []string{"no snapshots found", "starts past the last one", "matched"},
			wantNotice: listZeroJSON{
				Subject: "vulnerability database snapshot", RecordsConsidered: 0, StoreEmpty: true,
				Remedy: []string{"kanonarion vuln-scan <walk-id>"},
			},
		},
	})
}

// The zero-paired control for the surface that has no --limit: a populated run
// carries no statement on either channel, and its rows are unchanged.
func TestRunSnapshotList_PopulatedCarriesNoZeroNotice(t *testing.T) {
	for _, asJSON := range []bool{false, true} {
		uc := testfakes.NewFakeQueryScanRuns()
		uc.AddSnapshot(fixtureSnap)
		var stdout, stderr bytes.Buffer
		if err := runSnapshotList(context.Background(), asJSON, uc, &stdout, &stderr); err != nil {
			t.Fatalf("runSnapshotList(json=%v): %v", asJSON, err)
		}
		if strings.Contains(stdout.String(), "the store holds no") {
			t.Errorf("json=%v: a populated answer carried a zero-result statement:\n%s", asJSON, stdout.String())
		}
		if stderr.Len() != 0 {
			t.Errorf("json=%v: a populated answer wrote to stderr:\n%s", asJSON, stderr.String())
		}
		if !strings.Contains(stdout.String(), "govulndb") {
			t.Errorf("json=%v: the rows are missing:\n%s", asJSON, stdout.String())
		}
	}
}

// walkSelectorMissText drives one of walk-list's single-record selectors and
// returns the message it failed with, having checked the exit code it carries.
func walkSelectorMissText(t *testing.T, uc QueryWalksUseCase, walkID string, latestSuccess bool) (string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	limit := 20
	if latestSuccess {
		limit = 1
	}
	status := ""
	if latestSuccess {
		status = "succeeded"
	}
	err := runWalkList(context.Background(), "", "", status, "", walkID, limit, 0, false, latestSuccess,
		uc, &stdout, &stderr)
	if err == nil {
		t.Fatal("a selector that matched nothing returned a nil error")
	}
	if code := ExitCodeForError(err); code != ExitNotFound {
		t.Errorf("exit code = %d, want %d for a record that is not there", code, ExitNotFound)
	}
	if stdout.Len() != 0 {
		t.Errorf("the data channel carried prose:\n%s", stdout.String())
	}
	return err.Error(), stderr.String()
}

// `walk-list --walk-id 01NOPE` said `walk 01NOPE not found` — a flat negative
// that reads as "this store has never seen one" whether the store holds nothing
// or holds fifty. It now names what was searched and what would list it, on the
// same terms as the walk-containment search.
func TestRunWalkList_WalkIDMissNamesWhatWasSearched(t *testing.T) {
	t.Run("over a populated store", func(t *testing.T) {
		withJSON(t, false)
		msg, _ := walkSelectorMissText(t, populatedWalkList(t), "01NOPE", false)
		for _, want := range []string{
			`no walk record matched walk id "01NOPE"`,
			"compared for exact equality against the walk id of all 2 walk record(s) in the store",
			"(e.g. walk-0)",
			"to list every walk record: kanonarion walk-list --limit 0",
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("the message is missing %q, got: %q", want, msg)
			}
		}
		if strings.Contains(msg, "walk 01NOPE not found") {
			t.Errorf("the flat negative survived: %q", msg)
		}
	})

	t.Run("over an empty store", func(t *testing.T) {
		withJSON(t, false)
		msg, _ := walkSelectorMissText(t, testfakes.NewFakeQueryWalks(), "01NOPE", false)
		for _, want := range []string{
			`the store holds no walk record at all, so walk id "01NOPE" is not what made this empty`,
			"to produce one: kanonarion walk <module>@<version>",
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("the message is missing %q, got: %q", want, msg)
			}
		}
	})

	t.Run("the machine reader gets the same counts", func(t *testing.T) {
		withJSON(t, true)
		_, stderr := walkSelectorMissText(t, populatedWalkList(t), "01NOPE", false)
		notice := decodeZeroNotice(t, stderr)
		if notice.Subject != "walk record" || notice.RecordsConsidered != 2 || notice.StoreEmpty {
			t.Errorf("notice = %+v, want the walk-record corpus sized at 2", notice)
		}
		if notice.Filter == nil || notice.Filter.Name != "walk id" || notice.Filter.Value != "01NOPE" {
			t.Errorf("the selector that missed is not named: %+v", notice)
		}
		if len(notice.Remedy) == 0 || notice.Remedy[0] != "kanonarion walk-list --limit 0" {
			t.Errorf("remedy = %v, want the unfiltered listing", notice.Remedy)
		}
	})
}

// --latest-success failed with `no succeeded walk found`, which is the same flat
// negative one selector along: it never said how many walks it looked at, and a
// store full of failed walks answered identically to an empty one.
func TestRunWalkList_LatestSuccessMissNamesWhatWasSearched(t *testing.T) {
	failedWalks := func(t *testing.T) *testfakes.FakeQueryWalks {
		t.Helper()
		uc := testfakes.NewFakeQueryWalks()
		uc.SetSummaries([]walkports.WalkSummary{{
			ID: "walk-0", Target: mustCoord(t, "example.com/app", "v1.0.0"),
			Scope: walkdomain.WalkScopeCode, Depth: walkdomain.WalkDepthFull,
			StartedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			OverallStatus: walkdomain.WalkFailed, NodeCount: 2,
		}})
		return uc
	}

	t.Run("walks exist but none succeeded", func(t *testing.T) {
		withJSON(t, false)
		msg, _ := walkSelectorMissText(t, failedWalks(t), "", true)
		for _, want := range []string{
			`no walk record matched overall status "succeeded"`,
			"compared for exact equality against the overall status of all 1 walk record(s) in the store",
			"(e.g. failed)",
			"to list every walk record: kanonarion walk-list --limit 0",
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("the message is missing %q, got: %q", want, msg)
			}
		}
		if strings.Contains(msg, "no succeeded walk found") {
			t.Errorf("the flat negative survived: %q", msg)
		}
	})

	t.Run("the machine reader gets the same counts", func(t *testing.T) {
		withJSON(t, true)
		_, stderr := walkSelectorMissText(t, failedWalks(t), "", true)
		notice := decodeZeroNotice(t, stderr)
		if notice.RecordsConsidered != 1 || notice.StoreEmpty {
			t.Errorf("notice = %+v, want the walk corpus sized at 1", notice)
		}
		if notice.Filter == nil || notice.Filter.Name != "overall status" || notice.Filter.Value != "succeeded" {
			t.Errorf("the selector that missed is not named: %+v", notice)
		}
	})
}

// The control the notice's cost never had. Every zero-scope function re-lists
// the corpus unfiltered to size it, and that is affordable only because it is
// unreachable when rows came back — a property held by nothing but the position
// of one `len == 0` guard. A refactor that hoisted a scope call above that guard
// would keep every other test in this file green while paying a full unfiltered
// read on every listing in the CLI.
//
// Demonstrated failing before the fix by hoisting the scope call in
// directivesListWith above its emptiness guard: this test reported
// `directives list read the store 2 times, want exactly 1`, and no other test
// in the package moved.
func TestListings_PopulatedPageReadsTheStoreOnce(t *testing.T) {
	for _, s := range listingSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			if s.listCalls == nil {
				t.Fatal("this listing cannot report how many times it read the store")
			}
			for _, asJSON := range []bool{false, true} {
				before := s.listCalls()
				stdout, _ := s.run(t, 3, 0, asJSON)
				if got := s.listCalls() - before; got != 1 {
					t.Errorf("json=%v: %s read the store %d times, want exactly 1 — the zero-result "+
						"survey is being paid on a page that returned rows\nstdout:\n%s",
						asJSON, s.name, got, stdout)
				}
			}
		})
	}
}

// The other half of the same property: the survey read IS paid on a zero, so a
// test that passed by never surveying at all would fail here. Without it, a
// "reads the store once" assertion is satisfied by deleting the notice.
func TestListings_ZeroPageSurveysTheCorpus(t *testing.T) {
	for _, s := range listingSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			before := s.listCalls()
			s.run(t, 3, s.population+5, false)
			if got := s.listCalls() - before; got < 2 {
				t.Errorf("%s read the store %d times on an empty page — the notice's count "+
					"cannot have been measured", s.name, got)
			}
		})
	}
}

// The two single-record reads that sit in the same files as the four surfaces
// above answered with the same flat negative, and both had the count they
// needed within reach: `vuln-snapshot-show` had already read the corpus, and
// `directives show` gained the store-wide count with the port method. Left
// alone they would have kept teaching the reading the notice exists to stop.
func TestSingleRecordMisses_NameTheCorpusTheySearched(t *testing.T) {
	t.Run("directives show", func(t *testing.T) {
		withJSON(t, false)
		ctr := &Container{QueryDirectives: &testfakes.FakeQueryDirectives{StoreScans: 7}}
		var stdout, stderr bytes.Buffer
		err := directivesShowWith(context.Background(), ctr, "missing-scan", &stdout, &stderr)
		if err == nil {
			t.Fatal("a missing scan id returned a nil error")
		}
		if code := ExitCodeForError(err); code != ExitNotFound {
			t.Errorf("exit code = %d, want %d", code, ExitNotFound)
		}
		for _, want := range []string{
			`no directive scan matched scan id "missing-scan"`,
			"of all 7 directive scan(s) in the store",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the message is missing %q, got: %v", want, err)
			}
		}
		if strings.Contains(err.Error(), "directive scan not found:") {
			t.Errorf("the flat negative survived: %v", err)
		}
	})

	t.Run("directives show, machine reader", func(t *testing.T) {
		withJSON(t, true)
		ctr := &Container{QueryDirectives: &testfakes.FakeQueryDirectives{StoreScans: 7}}
		var stdout, stderr bytes.Buffer
		if err := directivesShowWith(context.Background(), ctr, "missing-scan", &stdout, &stderr); err == nil {
			t.Fatal("a missing scan id returned a nil error")
		}
		notice := decodeZeroNotice(t, stderr.String())
		if notice.RecordsConsidered != 7 || notice.Filter == nil || notice.Filter.Name != "scan id" {
			t.Errorf("notice = %+v, want the store sized at 7 with the scan id named", notice)
		}
	})

	t.Run("vuln-snapshot-show, machine reader", func(t *testing.T) {
		uc := testfakes.NewFakeQueryScanRuns()
		uc.AddSnapshot(fixtureSnap)
		var stdout, stderr bytes.Buffer
		if err := runSnapshotShow(context.Background(), "govulndb", "v9999-01-01T00-00-00", true,
			uc, &stdout, &stderr); err == nil {
			t.Fatal("a missing snapshot returned a nil error")
		}
		notice := decodeZeroNotice(t, stderr.String())
		if notice.RecordsConsidered != 1 || notice.StoreEmpty {
			t.Errorf("notice = %+v, want the snapshot corpus sized at 1", notice)
		}
		if notice.Filter == nil || notice.Filter.Name != "source and version" {
			t.Errorf("the selector that missed is not named: %+v", notice)
		}
	})
}

// The zero-paired control for the two selectors: one that finds its record
// emits no statement of scope on either channel and pays no survey read. A
// notice emitted unconditionally, or a scope computed before the lookup
// succeeded, fails here rather than in production.
func TestRunWalkList_FoundSelectorsCarryNoNoticeAndNoSurveyRead(t *testing.T) {
	fixture := func(t *testing.T) *testfakes.FakeQueryWalks {
		t.Helper()
		uc := populatedWalkList(t)
		uc.AddWalk(walkdomain.WalkRecord{
			ID:             "walk-0",
			Target:         mustCoord(t, "example.com/app", "v1.0.0"),
			StartedAt:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			OverallStatus:  walkdomain.WalkSucceeded,
			Scope:          walkdomain.WalkScopeCode,
			Depth:          walkdomain.WalkDepthFull,
			PerNodeResults: map[coordinate.ModuleCoordinate]walkdomain.NodeResult{},
		})
		return uc
	}

	t.Run("--walk-id reads nothing but the record", func(t *testing.T) {
		withJSON(t, false)
		uc := fixture(t)
		var stdout, stderr bytes.Buffer
		if err := runWalkList(context.Background(), "", "", "", "", "walk-0", 20, 0, false, false,
			uc, &stdout, &stderr); err != nil {
			t.Fatalf("runWalkList: %v", err)
		}
		if uc.ListCalls != 0 {
			t.Errorf("a selector that found its record listed the store %d times", uc.ListCalls)
		}
		if stderr.Len() != 0 {
			t.Errorf("a found record carried a statement of scope:\n%s", stderr.String())
		}
	})

	t.Run("--latest-success lists once", func(t *testing.T) {
		withJSON(t, false)
		uc := fixture(t)
		var stdout, stderr bytes.Buffer
		if err := runWalkList(context.Background(), "", "", "succeeded", "", "", 1, 0, false, true,
			uc, &stdout, &stderr); err != nil {
			t.Fatalf("runWalkList: %v", err)
		}
		if uc.ListCalls != 1 {
			t.Errorf("--latest-success read the store %d times, want exactly 1", uc.ListCalls)
		}
		if stderr.Len() != 0 {
			t.Errorf("a found record carried a statement of scope:\n%s", stderr.String())
		}
	})
}
