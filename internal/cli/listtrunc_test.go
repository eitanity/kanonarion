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

// countJSONRows reads the row count off a listing's stdout array. It is the same
// read the coordinator's mis-measurement was made with, which is the point: the
// count is right and the population it was taken for was not.
func countJSONRows(t *testing.T, stdout string) int {
	t.Helper()
	var rows []json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &rows); err != nil {
		t.Fatalf("decoding listing payload: %v\npayload: %s", err, stdout)
	}
	return len(rows)
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

// The same statement on the JSON path. The array on stdout is unchanged — the
// data channel's shape must not move under existing consumers — and the marker
// rides on stderr, where the zero-result notice already lives.
func TestListings_TruncatedJSONCarriesTheMarker(t *testing.T) {
	for _, s := range listingSurfaces(t) {
		t.Run(s.name, func(t *testing.T) {
			const limit = 3
			stdout, stderr := s.run(t, limit, 0, true)
			if got := s.rows(t, stdout); got != limit {
				t.Fatalf("payload rows = %d, want %d", got, limit)
			}
			var marker listTruncationJSON
			if err := json.Unmarshal([]byte(stderr), &marker); err != nil {
				t.Fatalf("no truncation marker on stderr: %v\nstderr: %q", err, stderr)
			}
			if !marker.Truncated {
				t.Errorf("truncated = false on a listing that withheld %d of %d records",
					s.population-limit, s.population)
			}
			if marker.Limit != limit {
				t.Errorf("marker limit = %d, want %d", marker.Limit, limit)
			}
			if marker.Remedy == "" {
				t.Errorf("marker names no remedy: %+v", marker)
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
			stdout, stderr := s.run(t, limit, 0, true)
			if got := s.rows(t, stdout); got != s.population {
				t.Fatalf("payload rows = %d, want the whole population %d", got, s.population)
			}
			var marker listTruncationJSON
			if err := json.Unmarshal([]byte(stderr), &marker); err != nil {
				t.Fatalf("no truncation marker on stderr: %v\nstderr: %q", err, stderr)
			}
			if marker.Truncated {
				t.Errorf("truncated = true on a listing that returned every record: %+v", marker)
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
			_, stderr := s.run(t, s.population, 0, true)
			var marker listTruncationJSON
			if err := json.Unmarshal([]byte(stderr), &marker); err != nil {
				t.Fatalf("no truncation marker on stderr: %v\nstderr: %q", err, stderr)
			}
			if marker.Truncated {
				t.Errorf("truncated = true at exactly the limit: %+v", marker)
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
	if err := writeListTruncationJSON(failingWriter{}, tr); err == nil {
		t.Error("expected a write error from the JSON notice")
	}
	// Nothing to write, nothing to fail on.
	if err := writeListTruncation(failingWriter{}, failingWriter{}, false, listTruncation{}); err != nil {
		t.Errorf("an unlimited listing writes nothing and cannot fail: %v", err)
	}
}
