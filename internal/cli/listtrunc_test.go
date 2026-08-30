package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	directivedomain "github.com/eitanity/kanonarion/internal/directive/domain"
	exports "github.com/eitanity/kanonarion/internal/example/ports"
	extractports "github.com/eitanity/kanonarion/internal/extract/ports"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	licports "github.com/eitanity/kanonarion/internal/license/ports"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// The defect this file pins: a listing that stopped at its default limit printed
// exactly that many rows and said nothing, so counting its rows produced the
// wrong population with nothing in the output to contradict it. Measured on a
// live store at 50 of 635 license records; reproduced here at 3 of 5 so the
// fixture states the same fact in a unit test.

// listingSurface is one command's listing, in the shape every one of them shares:
// a limit goes in, rows and a scope statement come out.
type listingSurface struct {
	name string
	// population is how many records the fake store holds.
	population int
	// subject is the plural noun the truncation line must use.
	subject string
	// run invokes the listing at the given limit and offset and returns stdout
	// and stderr. Offset is part of the shape because a limit a caller cannot
	// step past leaves them re-fetching the whole population to read row 51.
	run func(t *testing.T, limit, offset int, asJSON bool) (string, string)
	// rows counts the records the JSON payload carried.
	rows func(t *testing.T, stdout string) int
	// listCalls reads how many times the run just made asked the store for its
	// rows. The zero-result notice re-lists the corpus unfiltered to size it,
	// and that read is correct only because it is unreachable when rows came
	// back; nothing but a count of the reads can hold that.
	listCalls func() int
}

func mustCoord(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("building coordinate %s@%s: %v", path, version, err)
	}
	return c
}

// withJSON sets the global output mode for one listing invocation.
func withJSON(t *testing.T, on bool) {
	t.Helper()
	prev := jsonOut
	jsonOut = on
	t.Cleanup(func() { jsonOut = prev })
}

// listingDocument is a listing's --json answer as a consumer reads it: the
// records, and what the listing knows about the request that produced them.
type listingDocument struct {
	Records []json.RawMessage `json:"records"`
	listTruncationJSON
	ZeroResult *listZeroJSON `json:"zero_result"`
}

// decodeListingDocument reads a listing's whole answer off stdout. Reading it
// from stdout is the assertion: the fact that the list is partial has to reach a
// consumer that never opens stderr.
func decodeListingDocument(t *testing.T, stdout string) listingDocument {
	t.Helper()
	var doc listingDocument
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("decoding listing document: %v\npayload: %s", err, stdout)
	}
	if doc.Records == nil {
		t.Fatalf("the document carries no records array — an empty page is an empty array, never null:\n%s", stdout)
	}
	return doc
}

// decodeListingRecords unmarshals a listing's records into the caller's row
// type, so a test that asks about the rows does not have to restate the rest of
// the document.
func decodeListingRecords(t *testing.T, stdout string, into any) {
	t.Helper()
	var doc struct {
		Records json.RawMessage `json:"records"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("decoding listing document: %v\npayload: %s", err, stdout)
	}
	if err := json.Unmarshal(doc.Records, into); err != nil {
		t.Fatalf("decoding listing records: %v\nrecords: %s", err, doc.Records)
	}
}

// countJSONRows reads the row count off a listing's stdout document. It is the
// same read the coordinator's mis-measurement was made with, which is the point:
// the count is right and the population it was taken for was not.
func countJSONRows(t *testing.T, stdout string) int {
	t.Helper()
	return len(decodeListingDocument(t, stdout).Records)
}

const truncPopulation = 5

func licenseSurface() listingSurface {
	uc := testfakes.NewFakeQueryLicense()
	sums := make([]licports.LicenseSummary, 0, truncPopulation)
	for i := range truncPopulation {
		sums = append(sums, licports.LicenseSummary{
			ModulePath: fmt.Sprintf("example.com/mod%d", i), ModuleVersion: "v1.0.0",
			PipelineVersion: "lic-1", PrimarySPDX: "MIT", OverallStatus: licdomain.LicenseStatusDetected,
		})
	}
	uc.SetList(sums)
	return listingSurface{
		name: "license-list", population: truncPopulation, subject: "license records",
		listCalls: func() int { return uc.ListCalls },
		run: func(t *testing.T, limit, offset int, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := runLicenseList(context.Background(), "", "", limit, offset, uc,
				licdomain.LicenseOverrideSet{}, &stdout, &stderr); err != nil {
				t.Fatalf("runLicenseList: %v", err)
			}
			return stdout.String(), stderr.String()
		},
		rows: countJSONRows,
	}
}

func interfaceSurface() listingSurface {
	uc := testfakes.NewFakeQueryInterface()
	sums := make([]ifaceports.InterfaceSummary, 0, truncPopulation)
	for i := range truncPopulation {
		sums = append(sums, ifaceports.InterfaceSummary{
			ModulePath: fmt.Sprintf("example.com/mod%d", i), ModuleVersion: "v1.0.0", PackageCount: 2,
		})
	}
	uc.SetList(sums)
	return listingSurface{
		name: "interface-list", population: truncPopulation, subject: "interface records",
		listCalls: func() int { return uc.ListCalls },
		run: func(t *testing.T, limit, offset int, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := interfaceListWith(context.Background(), limit, offset, uc, &stdout, &stderr); err != nil {
				t.Fatalf("interfaceListWith: %v", err)
			}
			return stdout.String(), stderr.String()
		},
		rows: countJSONRows,
	}
}

func examplesSurface() listingSurface {
	uc := testfakes.NewFakeQueryExamples()
	sums := make([]exports.ExampleSummary, 0, truncPopulation)
	for i := range truncPopulation {
		sums = append(sums, exports.ExampleSummary{
			ModulePath: fmt.Sprintf("example.com/mod%d", i), ModuleVersion: "v1.0.0", ExampleCount: 3,
		})
	}
	uc.SetList(sums)
	return listingSurface{
		name: "examples-list", population: truncPopulation, subject: "example records",
		listCalls: func() int { return uc.ListCalls },
		run: func(t *testing.T, limit, offset int, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := runExamplesList(context.Background(), limit, offset, uc, &stdout, &stderr); err != nil {
				t.Fatalf("runExamplesList: %v", err)
			}
			return stdout.String(), stderr.String()
		},
		rows: countJSONRows,
	}
}

func callGraphSurface() listingSurface {
	uc := testfakes.NewFakeQueryCallGraph()
	sums := make([]cgports.CallGraphSummary, 0, truncPopulation)
	for i := range truncPopulation {
		sums = append(sums, cgports.CallGraphSummary{
			ModulePath: fmt.Sprintf("example.com/mod%d", i), ModuleVersion: "v1.0.0",
			PipelineVersion: "cg-1", NodeCount: 4, EdgeCount: 3,
		})
	}
	uc.SetList(sums)
	return listingSurface{
		name: "callgraph-list", population: truncPopulation, subject: "call graph records",
		// Both listings, summed. The property is how many times the command reads
		// the store, and counting only one of the two reads would be satisfied by
		// a listing that switched to the other.
		listCalls: func() int { return uc.ListCalls + uc.CoordinateListCalls },
		run: func(t *testing.T, limit, offset int, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := runCallGraphList(context.Background(), "", limit, offset, uc, &stdout, &stderr); err != nil {
				t.Fatalf("runCallGraphList: %v", err)
			}
			return stdout.String(), stderr.String()
		},
		rows: countJSONRows,
	}
}

func vulnScanSurface() listingSurface {
	uc := testfakes.NewFakeQueryScanRuns()
	for i := range truncPopulation {
		uc.AddRun(vulndomain.WalkScanRun{
			ID: fmt.Sprintf("run-%d", i), WalkID: fmt.Sprintf("walk-%d", i),
			OverallStatus: vulndomain.WalkStatusAllClean,
			CompletedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		})
	}
	return listingSurface{
		name: "vuln-scan-list", population: truncPopulation, subject: "scan runs",
		listCalls: func() int { return uc.ListCalls },
		run: func(t *testing.T, limit, offset int, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := runScanList(context.Background(), "", limit, offset, uc, &stdout, &stderr); err != nil {
				t.Fatalf("runScanList: %v", err)
			}
			return stdout.String(), stderr.String()
		},
		rows: countJSONRows,
	}
}

func walkSurface(t *testing.T) listingSurface {
	t.Helper()
	uc := testfakes.NewFakeQueryWalks()
	sums := make([]walkports.WalkSummary, 0, truncPopulation)
	for i := range truncPopulation {
		sums = append(sums, walkports.WalkSummary{
			ID:     fmt.Sprintf("walk-%d", i),
			Target: mustCoord(t, fmt.Sprintf("example.com/mod%d", i), "v1.0.0"),
			Scope:  walkdomain.WalkScopeCode, Depth: walkdomain.WalkDepthFull,
			StartedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			OverallStatus: walkdomain.WalkSucceeded, NodeCount: 2,
		})
	}
	uc.SetSummaries(sums)
	return listingSurface{
		name: "walk-list", population: truncPopulation, subject: "walk records",
		listCalls: func() int { return uc.ListCalls },
		run: func(t *testing.T, limit, offset int, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := runWalkList(context.Background(), "", "", "", "", "", limit, offset, false, false,
				uc, &stdout, &stderr); err != nil {
				t.Fatalf("runWalkList: %v", err)
			}
			return stdout.String(), stderr.String()
		},
		rows: countJSONRows,
	}
}

func extractSurface() listingSurface {
	uc := testfakes.NewFakeQueryExtraction()
	sums := make([]extractports.ExtractionRunSummary, 0, truncPopulation)
	for i := range truncPopulation {
		sums = append(sums, extractports.ExtractionRunSummary{
			ID: fmt.Sprintf("run-%d", i), WalkID: fmt.Sprintf("walk-%d", i), ModuleCount: 7,
			StartedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		})
	}
	uc.SetList(sums)
	return listingSurface{
		name: "extract list", population: truncPopulation, subject: "extraction runs",
		listCalls: func() int { return uc.ListCalls },
		run: func(t *testing.T, limit, offset int, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := runExtractList(context.Background(), limit, offset, uc, &stdout, &stderr); err != nil {
				t.Fatalf("runExtractList: %v", err)
			}
			return stdout.String(), stderr.String()
		},
		rows: countJSONRows,
	}
}

func directivesSurface() listingSurface {
	scans := make([]directivedomain.Record, 0, truncPopulation)
	for i := range truncPopulation {
		scans = append(scans, directivedomain.Record{
			ID: fmt.Sprintf("scan-%d", i), ProjectModulePath: "example.com/proj",
			CompletedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			ContentHash: "sha256:abc", PipelineVersion: "dir-1",
		})
	}
	uc := &testfakes.FakeQueryDirectives{Scans: scans}
	ctr := &Container{QueryDirectives: uc}
	return listingSurface{
		name: "directives list", population: truncPopulation, subject: "directive scans",
		listCalls: func() int { return uc.ListCalls },
		run: func(t *testing.T, limit, offset int, asJSON bool) (string, string) {
			t.Helper()
			withJSON(t, asJSON)
			var stdout, stderr bytes.Buffer
			if err := directivesListWith(context.Background(), ctr, "example.com/proj", limit, offset, &stdout, &stderr); err != nil {
				t.Fatalf("directivesListWith: %v", err)
			}
			return stdout.String(), stderr.String()
		},
		rows: countJSONRows,
	}
}

// listingSurfaces is the adjacent-fuzz corpus: every listing in the CLI that
// applies a default row cap, driven by the same over-limit fixture. Six were
// measured on a live store; `extract list` and `directives list` came out of the
// sweep for the seventh and carry the identical flag.
func listingSurfaces(t *testing.T) []listingSurface {
	t.Helper()
	return []listingSurface{
		licenseSurface(), interfaceSurface(), examplesSurface(), callGraphSurface(),
		vulnScanSurface(), walkSurface(t), extractSurface(), directivesSurface(),
	}
}

// A listing that withheld rows says so on the text path, names the limit it
// applied, and names the invocation that lifts it.
func TestListings_TruncatedTextStatesTheLimit(t *testing.T) {
	for _, s := range listingSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			const limit = 3
			stdout, _ := s.run(t, limit, 0, false)
			want := fmt.Sprintf("showing first %d %s — more exist (--limit 0 for all, --offset %d for the next page)", limit, s.subject, limit)
			if !strings.Contains(stdout, want) {
				t.Errorf("truncated listing did not state its limit\nwant line: %q\ngot:\n%s", want, stdout)
			}
		})
	}
}

// The same statement on the JSON path, in the document on stdout. A consumer
// that reads only the data channel — which is every consumer that pipes the
// command into a parser — must be able to tell this list from a complete one.
func TestListings_TruncatedJSONCarriesTheMarker(t *testing.T) {
	for _, s := range listingSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			const limit = 3
			stdout, stderr := s.run(t, limit, 0, true)
			doc := decodeListingDocument(t, stdout)
			if len(doc.Records) != limit {
				t.Fatalf("payload rows = %d, want %d", len(doc.Records), limit)
			}
			if !doc.Truncated {
				t.Errorf("truncated = false on a listing that withheld %d of %d records",
					s.population-limit, s.population)
			}
			if doc.Limit != limit {
				t.Errorf("document limit = %d, want %d", doc.Limit, limit)
			}
			if doc.Subject != s.subject {
				t.Errorf("document subject = %q, want %q", doc.Subject, s.subject)
			}
			if doc.NextOffset != limit {
				t.Errorf("next_offset = %d, want %d — a reader told more exist must be able to ask for them",
					doc.NextOffset, limit)
			}
			if doc.Remedy == "" {
				t.Errorf("document names no remedy: %+v", doc.listTruncationJSON)
			}
			if strings.TrimSpace(stderr) != "" {
				t.Errorf("the answer is on stdout; stderr carried %q", stderr)
			}
		})
	}
}

// Nothing structured is left on the error stream. Two earlier fixes put these
// facts on stderr, which served the human reading a terminal and left every
// machine reader with a partial list that looked whole.
func TestListings_JSONWritesNothingToStderr(t *testing.T) {
	for _, s := range listingSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			// Truncated, exactly at the limit, unlimited, a later page, and a
			// page past the end: every shape of answer a listing can give.
			for _, c := range []struct{ limit, offset int }{
				{3, 0}, {s.population, 0}, {0, 0}, {3, 3}, {3, s.population + 90},
			} {
				_, stderr := s.run(t, c.limit, c.offset, true)
				if strings.TrimSpace(stderr) != "" {
					t.Errorf("--limit %d --offset %d wrote to stderr under --json: %q", c.limit, c.offset, stderr)
				}
			}
		})
	}
}

// A page past the end is empty and says why, in the same document. A consumer
// reading an empty records array must be able to tell "the store holds nothing"
// from "you paged past the end" without a second invocation.
func TestListings_EmptyPageStatesItsScopeInTheDocument(t *testing.T) {
	for _, s := range listingSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			stdout, _ := s.run(t, 3, s.population+90, true)
			doc := decodeListingDocument(t, stdout)
			if len(doc.Records) != 0 {
				t.Fatalf("a page past the last record returned %d rows", len(doc.Records))
			}
			if doc.ZeroResult == nil {
				t.Fatal("an empty page carries no zero_result, so nothing says why it is empty")
			}
			if doc.ZeroResult.StoreEmpty {
				t.Errorf("store_empty = true over a store holding %d records", s.population)
			}
			if !doc.ZeroResult.PagedPast {
				t.Errorf("paged_past = false on a page that starts past the last record: %+v", doc.ZeroResult)
			}
			if doc.ZeroResult.RecordsConsidered != s.population {
				t.Errorf("records_considered = %d, want the population %d",
					doc.ZeroResult.RecordsConsidered, s.population)
			}
			if len(doc.ZeroResult.Remedy) == 0 {
				t.Errorf("the zero statement names no remedy: %+v", doc.ZeroResult)
			}
		})
	}
}

// The paired control: a page that returned rows makes no zero statement, so the
// extra store read that sizes the corpus is never paid on a listing that
// answered.
func TestListings_PopulatedPageCarriesNoZeroStatement(t *testing.T) {
	for _, s := range listingSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			stdout, _ := s.run(t, 3, 0, true)
			if doc := decodeListingDocument(t, stdout); doc.ZeroResult != nil {
				t.Errorf("a page holding %d records explained why it was empty: %+v",
					len(doc.Records), doc.ZeroResult)
			}
		})
	}
}

// The paired control, and the reason the marker cannot be unconditional: a
// listing whose population fits inside its limit has withheld nothing and must
// not claim otherwise. This is the case both `vuln-scan-list` and `walk-list`
// were in on the store the defect was measured on.
func TestListings_UnderLimitDoesNotClaimTruncation(t *testing.T) {
	for _, s := range listingSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			limit := s.population + 1
			stdout, _ := s.run(t, limit, 0, false)
			if strings.Contains(stdout, "showing first") {
				t.Errorf("a listing holding fewer records than its limit claimed truncation:\n%s", stdout)
			}
			stdout, _ = s.run(t, limit, 0, true)
			doc := decodeListingDocument(t, stdout)
			if len(doc.Records) != s.population {
				t.Fatalf("payload rows = %d, want the whole population %d", len(doc.Records), s.population)
			}
			if doc.Truncated {
				t.Errorf("truncated = true on a listing that returned every record: %+v", doc.listTruncationJSON)
			}
		})
	}
}

// A listing holding exactly its limit is the boundary the off-by-one lives on:
// nothing was withheld, so nothing may be claimed.
func TestListings_ExactlyAtLimitDoesNotClaimTruncation(t *testing.T) {
	for _, s := range listingSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			stdout, _ := s.run(t, s.population, 0, false)
			if strings.Contains(stdout, "showing first") {
				t.Errorf("a listing holding exactly its limit claimed truncation:\n%s", stdout)
			}
			stdout, _ = s.run(t, s.population, 0, true)
			if doc := decodeListingDocument(t, stdout); doc.Truncated {
				t.Errorf("truncated = true at exactly the limit: %+v", doc.listTruncationJSON)
			}
		})
	}
}

// `--limit 0` lifts the cap, so there is no scope to state on either path, and
// it returns strictly more rows than the capped invocation did.
func TestListings_UnlimitedStatesNothingAndReturnsMore(t *testing.T) {
	for _, s := range listingSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			capped, _ := s.run(t, 3, 0, true)
			full, stderr := s.run(t, 0, 0, true)
			if s.rows(t, full) <= s.rows(t, capped) {
				t.Errorf("--limit 0 returned %d rows, not more than the capped %d",
					s.rows(t, full), s.rows(t, capped))
			}
			// The uncapped listing still states that it withheld nothing. The
			// whole point of the field is that a consumer reads it every time
			// rather than inferring completeness from the absence of a marker.
			if doc := decodeListingDocument(t, full); doc.Truncated {
				t.Errorf("an unlimited listing claimed truncation: %+v", doc.listTruncationJSON)
			}
			if strings.TrimSpace(stderr) != "" {
				t.Errorf("an unlimited listing has no cap to state, got stderr: %q", stderr)
			}
			textOut, _ := s.run(t, 0, 0, false)
			if strings.Contains(textOut, "showing first") {
				t.Errorf("an unlimited listing claimed truncation:\n%s", textOut)
			}
		})
	}
}

// The over-fetch is exactly one row: the extra row answers "is there more" and
// nothing pays for a count of how much more.
func TestTruncationFetchLimit_AsksForExactlyOneExtraRow(t *testing.T) {
	if got := truncationFetchLimit(50); got != 51 {
		t.Errorf("fetch limit for 50 = %d, want 51", got)
	}
	if got := truncationFetchLimit(0); got != 0 {
		t.Errorf("unlimited must stay unlimited, got %d", got)
	}
	if got := truncationFetchLimit(-1); got != 0 {
		t.Errorf("a negative limit must not become a cap, got %d", got)
	}
}

// A port that ignored the limit entirely still gets trimmed, and the listing
// still states the truth rather than assuming the over-fetch was one row.
func TestTruncateList_TrimsAnUncappedPortAndReportsIt(t *testing.T) {
	rows := []int{1, 2, 3, 4, 5, 6, 7}
	got, truncated := truncateList(rows, 3)
	if len(got) != 3 || !truncated {
		t.Errorf("truncateList(7 rows, limit 3) = %v, %v; want 3 rows and true", got, truncated)
	}
	got, truncated = truncateList(rows, 0)
	if len(got) != len(rows) || truncated {
		t.Errorf("an unlimited trim must be a no-op, got %v, %v", got, truncated)
	}
}

// The notice writers report a failing sink rather than dropping the statement.
func TestListTruncationWriters_ReportWriteFailure(t *testing.T) {
	tr := listTruncation{limit: 3, subject: "records", truncated: true}
	if err := writeListTruncationNotice(failingWriter{}, tr); err == nil {
		t.Error("expected a write error from the text notice")
	}
	if err := writeListDocument(failingWriter{}, []int{1}, tr, nil); err == nil {
		t.Error("expected a write error from the listing document")
	}
}

// The text path is byte-identical to what it printed before the document
// existed. The JSON answer changed shape deliberately; the prose one did not
// change at all, and a reader of the terminal must not be able to tell that
// anything happened. Rows and the truncation line are pinned together, trailing
// padding included, because a table whose columns moved is a changed answer.
//
// The first record's JSON is pinned beside it, in the same invocation, because
// the records are the other half of the promise: they became the contents of an
// array in a document and not one field of them moved, was added or was renamed.
func TestListings_TextIsUnchangedAndRecordsKeepTheirShape(t *testing.T) {
	want := map[string]struct{ text, firstRecord string }{
		"license-list": {
			text: `example.com/mod0@v1.0.0                            Detected     MIT                  scanner
example.com/mod1@v1.0.0                            Detected     MIT                  scanner
example.com/mod2@v1.0.0                            Detected     MIT                  scanner
showing first 3 license records — more exist (--limit 0 for all, --offset 3 for the next page)
`,
			firstRecord: `{"module":"example.com/mod0","version":"v1.0.0","status":"Detected","license":"MIT","source":"scanner"}`,
		},
		"interface-list": {
			text: `example.com/mod0@v1.0.0                            Unknown      2 package(s)  [superseded pipeline ]
example.com/mod1@v1.0.0                            Unknown      2 package(s)  [superseded pipeline ]
example.com/mod2@v1.0.0                            Unknown      2 package(s)  [superseded pipeline ]
3 of 3 listed record(s) were produced by superseded extraction logic; this build serves pipeline 0.6.0 and answers no query from them. Re-extract one:
  kanonarion interface <module>@<version>
showing first 3 interface records — more exist (--limit 0 for all, --offset 3 for the next page)
`,
			firstRecord: `{"module":"example.com/mod0","version":"v1.0.0","status":"Unknown","pipeline_version":"","superseded":true,"package_count":2}`,
		},
		"examples-list": {
			text: `example.com/mod0@v1.0.0                            Unknown      3 example(s)
example.com/mod1@v1.0.0                            Unknown      3 example(s)
example.com/mod2@v1.0.0                            Unknown      3 example(s)
showing first 3 example records — more exist (--limit 0 for all, --offset 3 for the next page)
`,
			firstRecord: `{"module":"example.com/mod0","version":"v1.0.0","status":"Unknown","example_count":3}`,
		},
		"callgraph-list": {
			text: `example.com/mod0@v1.0.0                                      cg-1         Unknown     4 nodes     3 edges
example.com/mod1@v1.0.0                                      cg-1         Unknown     4 nodes     3 edges
example.com/mod2@v1.0.0                                      cg-1         Unknown     4 nodes     3 edges
showing first 3 call graph records — more exist (--limit 0 for all, --offset 3 for the next page)
`,
			firstRecord: `{"module":"example.com/mod0","version":"v1.0.0","pipeline_version":"cg-1","status":"Unknown","node_count":4,"edge_count":3,"generations_differ":false}`,
		},
		"vuln-scan-list": {
			text: `run-0                       walk=walk-0                      status=AllClean      2026-01-01T00:00:00Z
run-1                       walk=walk-1                      status=AllClean      2026-01-01T00:00:00Z
run-2                       walk=walk-2                      status=AllClean      2026-01-01T00:00:00Z
showing first 3 scan runs — more exist (--limit 0 for all, --offset 3 for the next page)
`,
			firstRecord: `{"id":"run-0","walk_id":"walk-0","status":"AllClean","completed_at":"2026-01-01T00:00:00Z"}`,
		},
		"walk-list": {
			text: `walk-0  example.com/mod0@v1.0.0  2026-01-01T00:00:00Z  succeeded  scope=code  depth=full  nodes=2 failures=0
walk-1  example.com/mod1@v1.0.0  2026-01-01T00:00:00Z  succeeded  scope=code  depth=full  nodes=2 failures=0
walk-2  example.com/mod2@v1.0.0  2026-01-01T00:00:00Z  succeeded  scope=code  depth=full  nodes=2 failures=0
showing first 3 walk records — more exist (--limit 0 for all, --offset 3 for the next page)
`,
			firstRecord: `{"id":"walk-0","target":"example.com/mod0@v1.0.0","scope":"code","depth":"full","started_at":"2026-01-01T00:00:00Z","overall_status":"succeeded","node_count":2,"failure_count":0}`,
		},
		"extract list": {
			text: `RUN ID                     WALK ID                    STATUS     MODULES      STARTED
run-0                      walk-0                     succeeded  7            2026-01-01T00:00:00Z
run-1                      walk-1                     succeeded  7            2026-01-01T00:00:00Z
run-2                      walk-2                     succeeded  7            2026-01-01T00:00:00Z
showing first 3 extraction runs — more exist (--limit 0 for all, --offset 3 for the next page)
`,
			firstRecord: `{"id":"run-0","walk_id":"walk-0","status":"succeeded","module_count":7,"started_at":"2026-01-01T00:00:00Z","completed_at":"0001-01-01T00:00:00Z"}`,
		},
		"directives list": {
			text: `SCAN ID  COMPLETED             DIRECTIVES  CONTENT HASH
scan-0   2026-01-01T00:00:00Z  0           sha256:abc
scan-1   2026-01-01T00:00:00Z  0           sha256:abc
scan-2   2026-01-01T00:00:00Z  0           sha256:abc
showing first 3 directive scans — more exist (--limit 0 for all, --offset 3 for the next page)
`,
			firstRecord: `{"id":"scan-0","project":"example.com/proj","completed_at":"2026-01-01T00:00:00Z","directive_count":0,"content_hash":"sha256:abc","pipeline_version":"dir-1"}`,
		},
	}
	for _, s := range listingSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			pinned, ok := want[s.name]
			if !ok {
				t.Fatalf("no pinned output for %s: a listing added here must be pinned too", s.name)
			}
			if got, _ := s.run(t, 3, 0, false); got != pinned.text {
				t.Errorf("the text answer moved\n got: %q\nwant: %q", got, pinned.text)
			}
			stdout, _ := s.run(t, 3, 0, true)
			records := decodeListingDocument(t, stdout).Records
			if len(records) == 0 {
				t.Fatal("the document carries no records")
			}
			var compact bytes.Buffer
			if err := json.Compact(&compact, records[0]); err != nil {
				t.Fatalf("compacting the first record: %v", err)
			}
			if compact.String() != pinned.firstRecord {
				t.Errorf("the record object moved\n got: %s\nwant: %s", compact.String(), pinned.firstRecord)
			}
		})
	}
}
