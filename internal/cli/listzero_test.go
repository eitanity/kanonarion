package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	licports "github.com/eitanity/kanonarion/internal/license/ports"
)

// populatedCallGraphList is the corpus the defect was measured against: a store
// that holds records, queried for a module path that is not among them. The bare
// "No call graph records found." made that indistinguishable from an empty store.
func populatedCallGraphList() *testfakes.FakeQueryCallGraph {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", PipelineVersion: "cg-1", NodeCount: 3, EdgeCount: 2},
		{ModulePath: "example.com/dep", ModuleVersion: "v2.0.0", PipelineVersion: "cg-1", NodeCount: 1, EdgeCount: 0},
	})
	return uc
}

// A filter that matched nothing over a non-empty store names the value, what it
// was compared against, and how many records it was compared with — the three
// facts that separate a mis-spelled filter from an absent record.
func TestRunCallGraphList_UnmatchedFilterNamesItsScope(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := runCallGraphList(context.Background(), "no-such-module-anywhere", 20, 0,
		populatedCallGraphList(), &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		`no call graph record matched module path "no-such-module-anywhere"`,
		"compared for exact equality against the module path",
		"all 2 call graph record(s) in the store",
		"e.g. example.com/app",
		"to list every call graph record: kanonarion callgraph-list",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("zero-result notice is missing %q, got: %q", want, out)
		}
	}
	// The remedy for a store that holds records is to widen the filter, not to
	// go and produce a record that is already there.
	if strings.Contains(out, "to produce one") {
		t.Errorf("a populated store must not be answered with the produce remedy, got: %q", out)
	}
}

// The two cases have different remedies, so they must not share a sentence.
func TestRunCallGraphList_EmptyStoreIsNotAnUnmatchedFilter(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := runCallGraphList(context.Background(), "no-such-module-anywhere", 20, 0,
		testfakes.NewFakeQueryCallGraph(), &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "the store holds no call graph record at all") {
		t.Errorf("expected the empty-store statement, got: %q", out)
	}
	if !strings.Contains(out, `so module path "no-such-module-anywhere" is not what made this empty`) {
		t.Errorf("expected the filter cleared of blame, got: %q", out)
	}
	if !strings.Contains(out, "to produce one: kanonarion callgraph <module>@<version>") {
		t.Errorf("expected the produce-a-record remedy, got: %q", out)
	}
	if strings.Contains(out, "matched module path") {
		t.Errorf("an empty store must not be reported as an unmatched filter, got: %q", out)
	}
}

// Paging past the end is a third cause with a third remedy, and the rows alone
// cannot tell it from either of the others.
func TestRunCallGraphList_OffsetPastTheEndSaysSo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := runCallGraphList(context.Background(), "", 20, 99,
		populatedCallGraphList(), &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "no call graph record on this page") ||
		!strings.Contains(out, "--offset 99 starts past the last one") {
		t.Errorf("expected the paging statement, got: %q", out)
	}
}

// A listing that returned rows says nothing extra: the statement exists to
// explain a zero, and printing it on every read would tell an operator nothing.
func TestRunCallGraphList_PopulatedResultPrintsNoNotice(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := runCallGraphList(context.Background(), "", 20, 0,
		populatedCallGraphList(), &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(stdout.String(), "in the store") || stderr.Len() != 0 {
		t.Errorf("a non-empty listing must carry no zero-result notice, got stdout=%q stderr=%q",
			stdout.String(), stderr.String())
	}
}

// A JSON consumer cannot read the prose, and an empty array cannot carry the
// distinction either. The statement goes to stderr as an object so stdout stays
// the same type whether or not rows came back.
func TestRunCallGraphList_JSONCarriesTheZeroScopeOnStderr(t *testing.T) {
	prev := jsonOut
	jsonOut = true
	defer func() { jsonOut = prev }()

	var stdout, stderr bytes.Buffer
	if err := runCallGraphList(context.Background(), "no-such-module-anywhere", 20, 0,
		populatedCallGraphList(), &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := strings.TrimSpace(stdout.String()); got != "[]" {
		t.Errorf("the data channel must stay an empty array, got: %q", got)
	}
	var notice listZeroJSON
	if err := json.Unmarshal(stderr.Bytes(), &notice); err != nil {
		t.Fatalf("stderr did not carry a JSON zero-result notice: %v (stderr=%q)", err, stderr.String())
	}
	if notice.Subject != "call graph record" {
		t.Errorf("subject = %q", notice.Subject)
	}
	if notice.StoreEmpty {
		t.Error("store_empty must be false when the store holds records")
	}
	if notice.RecordsConsidered != 2 {
		t.Errorf("records_considered = %d, want 2", notice.RecordsConsidered)
	}
	if notice.Filter == nil || notice.Filter.Value != "no-such-module-anywhere" ||
		notice.Filter.Name != "module path" || notice.Filter.ComparedAgainst != "module path" ||
		notice.Filter.Match != matchExact {
		t.Errorf("filter = %+v, want the applied filter named with its comparand", notice.Filter)
	}
}

// store_empty is the field a machine consumer branches on, so it has to move.
func TestRunCallGraphList_JSONEmptyStoreSaysStoreEmpty(t *testing.T) {
	prev := jsonOut
	jsonOut = true
	defer func() { jsonOut = prev }()

	var stdout, stderr bytes.Buffer
	if err := runCallGraphList(context.Background(), "anything", 20, 0,
		testfakes.NewFakeQueryCallGraph(), &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var notice listZeroJSON
	if err := json.Unmarshal(stderr.Bytes(), &notice); err != nil {
		t.Fatalf("decoding the notice: %v (stderr=%q)", err, stderr.String())
	}
	if !notice.StoreEmpty || notice.RecordsConsidered != 0 {
		t.Errorf("want store_empty with zero records considered, got %+v", notice)
	}
	if len(notice.Remedy) == 0 || !strings.HasPrefix(notice.Remedy[0], "kanonarion callgraph ") {
		t.Errorf("remedy = %v, want the produce-a-record invocation", notice.Remedy)
	}
}

// A populated JSON listing carries no notice at all.
func TestRunCallGraphList_JSONPopulatedLeavesStderrClean(t *testing.T) {
	prev := jsonOut
	jsonOut = true
	defer func() { jsonOut = prev }()

	var stdout, stderr bytes.Buffer
	if err := runCallGraphList(context.Background(), "", 20, 0,
		populatedCallGraphList(), &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr must stay clean on a populated listing, got: %q", stderr.String())
	}
}

// The sibling listings answer their own zeros the same way, or the convention is
// not one. Each is asked with a filter it cannot match over an empty store.
func TestListCommands_ZeroResultsNameTheirScope(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(stdout, stderr io.Writer) error
		want []string
	}{
		{
			name: "vuln-scan-list",
			run: func(stdout, stderr io.Writer) error {
				return runScanList(context.Background(), "DOESNOTEXIST", 20,
					testfakes.NewFakeQueryScanRuns(), stdout, stderr)
			},
			want: []string{"the store holds no scan run at all", `walk id "DOESNOTEXIST"`,
				"to produce one: kanonarion vuln-scan <walk-id>"},
		},
		{
			name: "license-list",
			run: func(stdout, stderr io.Writer) error {
				return runLicenseList(context.Background(), "NOSUCHLICENSE", "", 50,
					testfakes.NewFakeQueryLicense(), licdomain.NewLicenseOverrideSet(nil), stdout, stderr)
			},
			want: []string{"the store holds no license record at all", `SPDX identifier "NOSUCHLICENSE"`,
				"to produce one: kanonarion license <module>@<version>"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := tc.run(&stdout, &stderr); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, want := range tc.want {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("missing %q, got: %q", want, stdout.String())
				}
			}
		})
	}
}

// Both filters are named when both are set: dropping one would send the reader
// to check a spelling that was not the one that excluded their module.
func TestRunLicenseList_BothFiltersAreNamed(t *testing.T) {
	uc := testfakes.NewFakeQueryLicense()
	uc.SetList([]licports.LicenseSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", PrimarySPDX: "MIT"},
	})
	var stdout, stderr bytes.Buffer
	if err := runLicenseList(context.Background(), "Apache-2.0", "Acme Corp", 50,
		uc, licdomain.NewLicenseOverrideSet(nil), &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, `SPDX identifier and copyright holder "Apache-2.0 / Acme Corp"`) {
		t.Errorf("expected both filters named, got: %q", out)
	}
	if !strings.Contains(out, matchSubstring) || !strings.Contains(out, matchExact) {
		t.Errorf("expected both match kinds stated, got: %q", out)
	}
}

// A copyright filter is a substring test, so an SPDX identifier is the wrong
// shape to offer as an illustration of what it compares against.
func TestRunLicenseList_CopyrightFilterOffersNoSPDXExample(t *testing.T) {
	uc := testfakes.NewFakeQueryLicense()
	uc.SetList([]licports.LicenseSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", PrimarySPDX: "MIT"},
	})
	var stdout, stderr bytes.Buffer
	if err := runLicenseList(context.Background(), "", "zzz-no-such-holder", 50,
		uc, licdomain.NewLicenseOverrideSet(nil), &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(stdout.String(), "(e.g.") {
		t.Errorf("a substring filter must not be illustrated with an SPDX identifier, got: %q", stdout.String())
	}
}

// license-list filters by flag only. A stray positional used to be accepted and
// ignored, so `license-list <module>` printed the whole store and read as the
// answer for that module.
func TestLicenseList_RefusesAStrayPositional(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"license-list", "example.com/app", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err == nil {
		t.Fatalf("a positional must be refused, got stdout=%q", stdout.String())
	}
	if strings.Contains(err.Error(), "no license record") {
		t.Errorf("the refusal must be about the argument, not the store: %v", err)
	}
}

// Every remedy the notices print is an invocation this CLI's own parser accepts.
// A remedy the tool then rejects costs the caller exactly the round trip the
// notice existed to save.
func TestListZeroNotices_RemediesParse(t *testing.T) {
	scopes := []listZeroScope{
		{subject: "call graph record", produce: "kanonarion callgraph <module>@<version>", listAll: "kanonarion callgraph-list"},
		{subject: "scan run", produce: "kanonarion vuln-scan <walk-id>", listAll: "kanonarion vuln-scan-list"},
		{subject: "license record", produce: "kanonarion license <module>@<version>", listAll: "kanonarion license-list"},
		{subject: "SBOM record", produce: "kanonarion sbom <walk-id>", listAll: "kanonarion sbom-list"},
	}
	for _, s := range scopes {
		for _, line := range []string{s.produce, s.listAll} {
			if err := parseInvocation(t, line); err != nil {
				t.Errorf("remedy line %q is rejected by the CLI's own parser: %v", line, err)
			}
		}
	}
}

// The notice replaces a silent zero, so a failure to write it must be reported
// rather than swallowed back into the silence it exists to end.
func TestWriteListZeroNotice_WriteFailureIsReported(t *testing.T) {
	err := writeListZeroNotice(failingWriter{}, listZeroScope{
		subject: "call graph record", considered: 0, produce: "kanonarion callgraph <module>@<version>",
	})
	if err == nil {
		t.Fatal("expected an error from a failing writer")
	}
	if !strings.Contains(err.Error(), "zero-result notice") {
		t.Errorf("the error must name what failed, got: %v", err)
	}
}

func TestWriteListZeroNoticeJSON_WriteFailureIsReported(t *testing.T) {
	err := writeListZeroNoticeJSON(failingWriter{}, listZeroScope{subject: "scan run"})
	if err == nil {
		t.Fatal("expected an error from a failing writer")
	}
	if !strings.Contains(err.Error(), "zero-result notice") {
		t.Errorf("the error must name what failed, got: %v", err)
	}
}

// An unfiltered listing that returns nothing over a non-empty corpus is not a
// case this command can explain, and the line says exactly that rather than
// borrowing one of the explanations that would be wrong.
func TestWriteListZeroNotice_UnexplainedEmptyDoesNotGuess(t *testing.T) {
	var buf bytes.Buffer
	if err := writeListZeroNotice(&buf, listZeroScope{
		subject: "call graph record", considered: 7, listAll: "kanonarion callgraph-list",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "no call graph record was returned, though the store holds 7 call graph record(s)") {
		t.Errorf("expected the unexplained-empty statement, got: %q", out)
	}
	if strings.Contains(out, "matched") || strings.Contains(out, "holds no") {
		t.Errorf("the statement must not claim a cause it did not measure, got: %q", out)
	}
}
