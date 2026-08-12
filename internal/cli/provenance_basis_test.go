package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	coordinatetest "github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	licenseports "github.com/eitanity/kanonarion/internal/license/ports"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// holderRecord is a licence record carrying one copyright line per holder.
func holderRecord(t *testing.T, coord coordinate.ModuleCoordinate, holders ...string) licdomain.LicenseRecord {
	t.Helper()
	var stmts []licdomain.CopyrightStatement
	for _, h := range holders {
		stmts = append(stmts, licdomain.CopyrightStatement{
			Verbatim: "Copyright (c) 2017 " + h,
			Holders:  []string{h},
			Source:   "LICENSE",
		})
	}
	return licdomain.LicenseRecord{
		Coordinate:      coord,
		CopyrightStatus: licdomain.CopyrightStatusFound,
		LicenseFiles:    []licdomain.LicenseFileEntry{{Path: "LICENSE", CopyrightStatements: stmts}},
	}
}

// provenanceJSON runs the command in JSON mode and decodes the payload.
func provenanceJSON(t *testing.T, path, version string, uc QueryLicenseUseCase, walks QueryWalksUseCase) provenanceOutput {
	t.Helper()
	setJSONOut(t, true)
	var buf strings.Builder
	if err := runProvenance(context.Background(), path, version, uc, walks, &buf); err != nil {
		t.Fatalf("runProvenance: %v", err)
	}
	var out provenanceOutput
	if err := json.Unmarshal([]byte(buf.String()), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v\ngot:\n%s", err, buf.String())
	}
	return out
}

// The fork shape the copyright tier could not see: a republication carrying the
// upstream holder's line and none of its own, whose upstream module was never
// licence-analysed here. The walk holds the replace directive, which names the
// upstream regardless.
func TestRunProvenance_ReplaceDirectiveDrivesTheHolderMatch(t *testing.T) {
	fork := coordinatetest.MustNew("github.com/cortezaproject/gval", "v1.2.4")
	upstream := coordinatetest.MustNew("github.com/PaesslerAG/gval", "v1.2.1")

	f := testfakes.NewFakeQueryLicense()
	f.AddRecord(fork, licapp.PipelineVersion, holderRecord(t, fork, "Paessler AG"))
	f.SetList([]licenseports.LicenseSummary{{ModulePath: fork.Path(), ModuleVersion: fork.Version()}})

	fqw := testfakes.NewFakeQueryWalks()
	fqw.SetSummaries([]walkports.WalkSummary{{ID: "W1"}})
	fqw.AddWalk(walkdomain.WalkRecord{ID: "W1", Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{
		{Coordinate: fork, OriginalCoordinate: upstream, ResolutionSource: walkdomain.ResolutionReplace},
	}}})

	out := provenanceJSON(t, fork.Path(), "", f, fqw)
	if out.CopyrightSignal.Status != fetchdomain.CopyrightSignalRepublication.String() {
		t.Fatalf("copyright signal = %q, want republication: the fork carries only the upstream holder's line",
			out.CopyrightSignal.Status)
	}
	if len(out.CopyrightSignal.Indicators) != 1 || out.CopyrightSignal.Indicators[0].Canonical != upstream.Path() {
		t.Fatalf("indicators = %+v, want one naming %s", out.CopyrightSignal.Indicators, upstream.Path())
	}
	if !strings.Contains(out.CopyrightSignal.Indicators[0].Statement, "replace directive") {
		t.Errorf("statement does not say where the comparison came from: %q", out.CopyrightSignal.Indicators[0].Statement)
	}
}

// Without a walk store there is no replace directive to read, and the answer
// says so rather than presenting an unsearched negative as a measured one.
func TestRunProvenance_NoWalkStoreStatesWhatWasNotRead(t *testing.T) {
	fork := coordinatetest.MustNew("github.com/cortezaproject/gval", "v1.2.4")
	f := testfakes.NewFakeQueryLicense()
	f.AddRecord(fork, licapp.PipelineVersion, holderRecord(t, fork, "Paessler AG"))
	f.SetList([]licenseports.LicenseSummary{{ModulePath: fork.Path(), ModuleVersion: fork.Version()}})

	out := provenanceJSON(t, fork.Path(), "", f, nil)
	if out.CopyrightSignal.Status != fetchdomain.CopyrightSignalNone.String() {
		t.Fatalf("copyright signal = %q, want none", out.CopyrightSignal.Status)
	}
	if !strings.Contains(out.CopyrightSignal.Coverage, "replace directive") {
		t.Errorf("coverage = %q, want it to state that no replace directive was consulted", out.CopyrightSignal.Coverage)
	}
}

// twoVersionStore holds two versions of one module whose records differ, with
// the OLDER version extracted last — the ordering that let write recency answer
// a module-level question with whichever record landed most recently.
func twoVersionStore(t *testing.T) (*testfakes.FakeQueryLicense, coordinate.ModuleCoordinate, coordinate.ModuleCoordinate) {
	t.Helper()
	newer := coordinatetest.MustNew("example.com/mod", "v2.0.0")
	older := coordinatetest.MustNew("example.com/mod", "v1.0.0")

	f := testfakes.NewFakeQueryLicense()
	f.AddRecord(newer, licapp.PipelineVersion, holderRecord(t, newer, "Acme Corp"))
	f.AddRecord(older, licapp.PipelineVersion, holderRecord(t, older, "Acme Corp", "Widget Foundation"))
	// The older version is extracted LAST, which is the ordering under which
	// write recency answered a module-level question with v1.0.0.
	f.SetList([]licenseports.LicenseSummary{
		{ModulePath: newer.Path(), ModuleVersion: newer.Version(), PipelineVersion: licapp.PipelineVersion,
			ExtractedAt: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)},
		{ModulePath: older.Path(), ModuleVersion: older.Version(), PipelineVersion: licapp.PipelineVersion,
			ExtractedAt: time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC)},
	})
	return f, newer, older
}

// An unpinned read answers from the newest version, not the most recently
// extracted record. The listing is ordered with the older version last, which is
// where the recency rule read from.
func TestRunProvenance_UnpinnedReadsTheNewestVersion(t *testing.T) {
	f, newer, _ := twoVersionStore(t)

	out := provenanceJSON(t, newer.Path(), "", f, nil)
	if out.Selection.Rule != provenanceSelectionNewest {
		t.Errorf("rule = %q, want %q", out.Selection.Rule, provenanceSelectionNewest)
	}
	if out.Selection.Basis != newer.String() {
		t.Fatalf("basis = %q, want the newest version %q", out.Selection.Basis, newer)
	}
	if out.CopyrightSignal.Source != newer.String() {
		t.Errorf("source = %q, want %q", out.CopyrightSignal.Source, newer)
	}
}

// The reader is told a choice was made on their behalf, out of what, and how to
// make it themselves. Naming the coordinate alone reads as the version that
// matters rather than the one a rule picked.
func TestRunProvenance_UnpinnedStatesTheChoiceAndHowToPinIt(t *testing.T) {
	f, newer, older := twoVersionStore(t)

	setJSONOut(t, false)
	var buf strings.Builder
	if err := runProvenance(context.Background(), newer.Path(), "", f, nil, &buf); err != nil {
		t.Fatalf("runProvenance: %v", err)
	}
	got := buf.String()
	for _, want := range []string{
		"no version was named",
		"2 versions of example.com/mod",
		"the newest version",
		"pin one with: kanonarion provenance example.com/mod@<version>",
		newer.Version(),
		older.Version(),
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output does not state %q:\n%s", want, got)
		}
	}
}

// A pinned read chose nothing, and says nothing. A notice printed where there
// was no choice teaches the reader to skip it where there was one.
func TestRunProvenance_PinnedReadStatesNoChoice(t *testing.T) {
	f, _, older := twoVersionStore(t)

	setJSONOut(t, false)
	var buf strings.Builder
	if err := runProvenance(context.Background(), older.Path(), older.Version(), f, nil, &buf); err != nil {
		t.Fatalf("runProvenance: %v", err)
	}
	if strings.Contains(buf.String(), "notice:") {
		t.Errorf("a pinned read must print no selection notice:\n%s", buf.String())
	}
	out := provenanceJSON(t, older.Path(), older.Version(), f, nil)
	if out.Selection.Rule != provenanceSelectionPinned {
		t.Errorf("rule = %q, want %q", out.Selection.Rule, provenanceSelectionPinned)
	}
	if len(out.Selection.Candidates) != 0 {
		t.Errorf("candidates = %v, want none: nothing was chosen", out.Selection.Candidates)
	}
}

// Where the versions disagree about the module, the disagreement is the answer.
// Picking one of them and reporting its signal as the module's would hide that
// the store holds two answers.
func TestRunProvenance_CandidateDisagreementIsReported(t *testing.T) {
	f, newer, older := twoVersionStore(t)

	out := provenanceJSON(t, newer.Path(), "", f, nil)
	if len(out.Selection.Disagreement) != 2 {
		t.Fatalf("disagreement = %v, want one entry per candidate", out.Selection.Disagreement)
	}
	joined := strings.Join(out.Selection.Disagreement, "; ")
	if !strings.Contains(joined, newer.Version()+" "+fetchdomain.CopyrightSignalNone.String()) ||
		!strings.Contains(joined, older.Version()+" "+fetchdomain.CopyrightSignalRepublication.String()) {
		t.Errorf("disagreement = %q, want each version beside the signal it reports", joined)
	}
	if !strings.Contains(out.Selection.Statement, "disagree") {
		t.Errorf("statement does not report the disagreement: %q", out.Selection.Statement)
	}
}

// A version whose record carries no copyright lines measured nothing, and its
// silence is not the opposite answer. Counting it as a disagreement would raise
// one out of two versions that never disagreed.
func TestRunProvenance_UnmeasuredVersionIsNotADisagreement(t *testing.T) {
	newer := coordinatetest.MustNew("example.com/mod", "v2.0.0")
	older := coordinatetest.MustNew("example.com/mod", "v1.0.0")

	f := testfakes.NewFakeQueryLicense()
	f.AddRecord(newer, licapp.PipelineVersion, holderRecord(t, newer, "Acme Corp"))
	f.AddRecord(older, licapp.PipelineVersion, licdomain.LicenseRecord{
		Coordinate:      older,
		CopyrightStatus: licdomain.CopyrightStatusNoneFound,
	})
	f.SetList([]licenseports.LicenseSummary{
		{ModulePath: newer.Path(), ModuleVersion: newer.Version(), PipelineVersion: licapp.PipelineVersion},
		{ModulePath: older.Path(), ModuleVersion: older.Version(), PipelineVersion: licapp.PipelineVersion},
	})

	out := provenanceJSON(t, newer.Path(), "", f, nil)
	if len(out.Selection.Disagreement) != 0 {
		t.Errorf("disagreement = %v, want none: one version measured nothing", out.Selection.Disagreement)
	}
	if !strings.Contains(out.Selection.Statement, "so one was chosen") {
		t.Errorf("statement should still say a choice was made: %q", out.Selection.Statement)
	}
}

// Version ordering is total: a version semver cannot read must never displace
// one it can, and equal inputs must not depend on listing order.
func TestNewerVersion_Ordering(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"v2.0.0", "v1.9.9", true},
		{"v1.9.9", "v2.0.0", false},
		{"v1.0.0", "local", true},
		{"local", "v1.0.0", false},
		{"v0.0.0-20240227163752-401108e1b7e7", "v0.0.0-20230228050547-1710fef4ab10", true},
		{"v3.2.2+incompatible", "v3.2.1", true},
		{"v1.0.0", "v1.0.0", false},
		{"v1.0.0+b", "v1.0.0", true},
		{"v1.0.0", "v1.0.0+b", false},
		{"local", "canary", true},
	}
	for _, c := range cases {
		if got := newerVersion(c.a, c.b); got != c.want {
			t.Errorf("newerVersion(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// A walk store that cannot be listed has not reported an absence of replace
// directives, and the answer says which of the two it is rather than reading as
// a searched negative.
func TestRunProvenance_WalkListFailureIsStatedNotSwallowed(t *testing.T) {
	fork := coordinatetest.MustNew("github.com/cortezaproject/gval", "v1.2.4")
	f := testfakes.NewFakeQueryLicense()
	f.AddRecord(fork, licapp.PipelineVersion, holderRecord(t, fork, "Paessler AG"))
	f.SetList([]licenseports.LicenseSummary{{ModulePath: fork.Path(), ModuleVersion: fork.Version()}})

	fqw := testfakes.NewFakeQueryWalks()
	fqw.ListErr = errors.New("store closed")

	out := provenanceJSON(t, fork.Path(), "", f, fqw)
	if !strings.Contains(out.CopyrightSignal.Coverage, "could not be listed") {
		t.Errorf("coverage = %q, want the listing failure stated", out.CopyrightSignal.Coverage)
	}
}

// A walk that cannot be read back is skipped rather than aborting the search:
// the remaining walks may still hold the directive, and one unreadable record is
// not a reason to answer nothing.
func TestReplacedModulePaths_UnreadableWalkIsSkipped(t *testing.T) {
	fork := coordinatetest.MustNew("github.com/cortezaproject/gval", "v1.2.4")
	upstream := coordinatetest.MustNew("github.com/PaesslerAG/gval", "v1.2.1")

	fqw := testfakes.NewFakeQueryWalks()
	fqw.SetSummaries([]walkports.WalkSummary{{ID: "missing"}, {ID: "W1"}})
	fqw.AddWalk(walkdomain.WalkRecord{ID: "W1", Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{
		{Coordinate: fork, OriginalCoordinate: upstream, ResolutionSource: walkdomain.ResolutionReplace},
		{Coordinate: fork},
	}}})

	got, coverage := replacedModulePaths(context.Background(), fqw, fork.Path())
	if len(got) != 1 || got[0] != upstream.Path() {
		t.Fatalf("replaced paths = %v, want just %s", got, upstream.Path())
	}
	if coverage != "" {
		t.Errorf("coverage = %q, want none: every walk in the store was read", coverage)
	}
}

// A candidate whose record cannot be read has not disagreed with anything, and
// the answer reports no disagreement rather than one drawn from a partial set.
func TestRunProvenance_UnreadableCandidateReportsNoDisagreement(t *testing.T) {
	newer := coordinatetest.MustNew("example.com/mod", "v2.0.0")
	f := testfakes.NewFakeQueryLicense()
	f.AddRecord(newer, licapp.PipelineVersion, holderRecord(t, newer, "Acme Corp"))
	f.SetList([]licenseports.LicenseSummary{
		{ModulePath: "example.com/mod", ModuleVersion: "v2.0.0", PipelineVersion: licapp.PipelineVersion},
		{ModulePath: "example.com/mod", ModuleVersion: "v1.0.0", PipelineVersion: licapp.PipelineVersion},
	})

	out := provenanceJSON(t, "example.com/mod", "", f, nil)
	if len(out.Selection.Disagreement) != 0 {
		t.Errorf("disagreement = %v, want none: one candidate could not be read", out.Selection.Disagreement)
	}
	if out.Selection.Basis != newer.String() {
		t.Errorf("basis = %q, want %q", out.Selection.Basis, newer)
	}
}

// The replace search is bounded. A store holding more walks than it reads has
// not been exhausted, and the bound is stated so a "no indicators" answer is not
// read as a search that found nothing.
func TestReplacedModulePaths_BoundedSearchStatesTheBound(t *testing.T) {
	fqw := testfakes.NewFakeQueryWalks()
	sums := make([]walkports.WalkSummary, 0, walkSearchLimit+5)
	for i := range walkSearchLimit + 5 {
		sums = append(sums, walkports.WalkSummary{ID: fmt.Sprintf("W%d", i)})
	}
	fqw.SetSummaries(sums)

	got, coverage := replacedModulePaths(context.Background(), fqw, "example.com/mod")
	if len(got) != 0 {
		t.Errorf("replaced paths = %v, want none", got)
	}
	if !strings.Contains(coverage, "most recent walks") {
		t.Errorf("coverage = %q, want the bound stated", coverage)
	}
}
