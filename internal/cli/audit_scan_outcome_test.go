package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/cli/testfakes"
	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	licdomain "code.eitanity.com/kanonarion/internal/license/domain"
	vulndomain "code.eitanity.com/kanonarion/internal/vuln/domain"
	vulnports "code.eitanity.com/kanonarion/internal/vuln/ports"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// The three ways the scan leg can fall short, each as the derivation records it.
var (
	errScanNoSnapshot = errors.New("vuln scan failed: resolving snapshot: fetch vulndb.zip: GOPROXY=off")
	errScanIntegrity  = fmt.Errorf("vuln scan failed: persisting target-rooted vulnerability record for example.com/mod@v1.2.0: %w: content hash mismatch",
		vulnports.ErrVulnIntegrity)
	partialCounts = vulndomain.WalkScanCounts{Total: 4, Analysed: 3, Unscannable: 1}
)

func scanFailedDerivation() auditDerivation { return auditDerivation{scanErr: errScanNoSnapshot} }
func scanIntegrityDerivation() auditDerivation {
	return auditDerivation{scanErr: errScanIntegrity}
}

func scanPartialDerivation() auditDerivation {
	return auditDerivation{scanPartial: true, scanFacts: vulnScanRunFacts{RunID: "vscan-1", Counts: partialCounts}}
}

func TestAuditScanOutcome_SplitsFailureFromPartial(t *testing.T) {
	partialExit := &exitError{code: ExitPartial, msg: "1 of 4 modules were not analysed"}
	nothingExit := &exitError{code: ExitFailed, msg: "no module in the walk was analysed (4 of 4 unanalysed)"}
	ran := vulnScanRunFacts{RunID: "vscan-1", Counts: partialCounts}
	cases := []struct {
		name        string
		facts       vulnScanRunFacts
		err         error
		wantFailure error
		wantPartial bool
	}{
		{"answered in full", ran, nil, nil, false},
		{"partial run", ran, partialExit, nil, true},
		{"run analysed nothing", ran, nothingExit, nothingExit, false},
		{"partial code with no run", vulnScanRunFacts{}, partialExit, partialExit, false},
		{"could not start", vulnScanRunFacts{}, errScanNoSnapshot, errScanNoSnapshot, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			failure, partial := auditScanOutcome(c.facts, c.err)
			if !errors.Is(failure, c.wantFailure) || (failure == nil) != (c.wantFailure == nil) || partial != c.wantPartial {
				t.Errorf("auditScanOutcome = (%v, %v), want (%v, %v)", failure, partial, c.wantFailure, c.wantPartial)
			}
		})
	}
}

// The domain calls failures and unscannables that cover every module partial;
// audit counts that as a run that analysed nothing.
func TestAuditScanOutcome_NothingAnalysedIsAFailure(t *testing.T) {
	facts := vulnScanRunFacts{RunID: "vscan-1", Counts: vulndomain.WalkScanCounts{Total: 4, Unscannable: 1, Failed: 3}}
	failure, partial := auditScanOutcome(facts, &exitError{code: ExitPartial, msg: "4 of 4 modules were not analysed"})
	if partial || failure == nil || failure.Error() != "no module in the walk was analysed (4 of 4 unanalysed)" {
		t.Errorf("auditScanOutcome = (%v, %v), want the nothing-analysed failure", failure, partial)
	}
}

func TestAuditDerivation_ScanLineStatesFailureAndPartiality(t *testing.T) {
	reused := vulndomain.WalkScanRun{ID: "vscan-7"}
	cases := []struct {
		name    string
		d       auditDerivation
		want    string
		without string
	}{
		{"failed, reason on one line", auditDerivation{scanErr: errors.New("first\n  second")},
			"vulnerability scan: failed — first; second\n", "scan: derived"},
		{"failure outranks reuse", auditDerivation{scanReused: true, scanRun: reused, scanErr: errScanNoSnapshot},
			"vulnerability scan: failed — " + errScanNoSnapshot.Error() + "\n", "reused run"},
		{"partial derived run", scanPartialDerivation(),
			"vulnerability scan: derived by this run; it analysed 3 of 4 modules\n", "failed"},
		{"partial reused run", auditDerivation{scanReused: true, scanRun: reused, scanPartial: true, scanFacts: vulnScanRunFacts{Counts: partialCounts}},
			"(--force to re-measure); it analysed 3 of 4 modules\n", "failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := writeAuditDerivation(&out, c.d); err != nil {
				t.Fatalf("writeAuditDerivation: %v", err)
			}
			got := out.String()
			if !strings.Contains(got, c.want) || strings.Contains(got, c.without) {
				t.Errorf("derivation does not say %q (or says %q):\n%s", c.want, c.without, got)
			}
		})
	}
}

func TestAuditVulnScanJSON_StatesTheScanLine(t *testing.T) {
	cases := []struct {
		name string
		run  auditRunJSON
		want string
	}{
		{"derived", newAuditRunJSON(auditDerivation{}, nil, 0, cliNow(), nil), `{"status":"derived"}`},
		{"reused", newAuditRunJSON(auditDerivation{scanReused: true, scanRun: vulndomain.WalkScanRun{ID: "vscan-7"}}, nil, 0, cliNow(), nil),
			`{"status":"reused","run":"vscan-7"}`},
		{"failed", newAuditRunJSON(auditDerivation{scanErr: errors.New("no snapshot\nstored")}, nil, 0, cliNow(), nil),
			`{"status":"failed","reason":"no snapshot; stored"}`},
		{"partial", newAuditRunJSON(scanPartialDerivation(), nil, 0, cliNow(), nil),
			`{"status":"derived","partial":{"analysed":3,"modules":4}}`},
		{"empty scope", unauditedRunJSON(), `{"status":"not_run","reason":"no dependency was audited"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := json.Marshal(c.run.VulnerabilityScan)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Errorf("vulnerability_scan = %s, want %s", got, c.want)
			}
		})
	}
}

// A reused run whose serving then failed is not a run that answered.
func TestAuditScanJSON_AFailedServingAnswersNothing(t *testing.T) {
	d := auditDerivation{scanReused: true, scanRun: vulndomain.WalkScanRun{ID: "vscan-7"}, scanErr: errScanIntegrity}
	if got := auditScanOf(d); got.Answered || got.RunID != "" {
		t.Errorf("scan = %+v, want no run answering", got)
	}
}

// TestAuditOutcomeErr_Precedence is every scan shortfall with and without a gate
// that fired: 10 over 5 over 1, and a clean run exits 0.
func TestAuditOutcomeErr_Precedence(t *testing.T) {
	gate := auditModuleResult{Coordinate: "example.com/gated@v1.0.0", PolicyBlocking: true}
	clean := auditModuleResult{Coordinate: "example.com/clean@v1.0.0"}
	cases := []struct {
		name string
		d    auditDerivation
		want map[bool]int // gate fires -> exit
	}{
		{"scan answered", auditDerivation{}, map[bool]int{false: ExitOK, true: ExitPolicy}},
		{"scan failed", scanFailedDerivation(), map[bool]int{false: ExitPartial, true: ExitPolicy}},
		{"scan partial", scanPartialDerivation(), map[bool]int{false: ExitPartial, true: ExitPolicy}},
		{"record failed its check", scanIntegrityDerivation(), map[bool]int{false: ExitIntegrity, true: ExitIntegrity}},
	}
	for _, c := range cases {
		for _, fires := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/gate=%v", c.name, fires), func(t *testing.T) {
				rows := []auditModuleResult{clean}
				if fires {
					rows = append(rows, gate)
				}
				err := auditOutcomeErr(rows, c.d)
				if got := ExitCodeForError(err); got != c.want[fires] {
					t.Errorf("exit %d, want %d: %v", got, c.want[fires], err)
				}
			})
		}
	}
}

func TestAuditOutcomeErr_NamesTheRecordOnce(t *testing.T) {
	marked := auditModuleResult{Coordinate: "example.com/mod@v1.2.0"}
	markVulnIntegrity(&marked, fmt.Errorf("listing example.com/mod@v1.2.0: %w", vulnports.ErrVulnIntegrity))
	err := auditOutcomeErr([]auditModuleResult{marked}, scanIntegrityDerivation())
	if ExitCodeForError(err) != ExitIntegrity {
		t.Fatalf("exit %d, want %d: %v", ExitCodeForError(err), ExitIntegrity, err)
	}
	if msg := err.Error(); strings.Count(msg, "example.com/mod@v1.2.0") != 1 || !strings.Contains(msg, "1 dependency(ies)") {
		t.Errorf("message names the record more or less than once: %q", msg)
	}

	err = auditOutcomeErr([]auditModuleResult{{Coordinate: "example.com/mod@v1.2.0"}}, scanIntegrityDerivation())
	if !strings.Contains(err.Error(), errScanIntegrity.Error()) {
		t.Errorf("an unmarked integrity failure is not named: %v", err)
	}
}

func TestAuditScanExit_Messages(t *testing.T) {
	if err := auditScanExit(scanFailedDerivation()); !strings.Contains(err.Error(), "did not answer: "+errScanNoSnapshot.Error()) {
		t.Errorf("failed scan message: %v", err)
	}
	if err := auditScanExit(scanPartialDerivation()); !strings.Contains(err.Error(), "analysed 3 of 4 modules") {
		t.Errorf("partial scan message: %v", err)
	}
}

// refusingQueryVuln refuses the reads of the coordinates it names.
type refusingQueryVuln struct {
	*testfakes.FakeQueryVuln
	refuse map[string]error
	asked  []string
}

func (f *refusingQueryVuln) ListRecordsForModule(ctx context.Context, coord coordinate.ModuleCoordinate, pv string) ([]vulndomain.VulnerabilityRecord, error) {
	f.asked = append(f.asked, coord.String())
	if err, ok := f.refuse[coord.String()]; ok {
		return nil, err
	}
	return f.FakeQueryVuln.ListRecordsForModule(ctx, coord, pv)
}

func TestMarkRefusedVulnRecords_NamesOnlyTheRecordThatFailed(t *testing.T) {
	uc := &refusingQueryVuln{FakeQueryVuln: testfakes.NewFakeQueryVuln(), refuse: map[string]error{
		"example.com/mod@v1.2.0":   fmt.Errorf("listing: %w", vulnports.ErrVulnIntegrity),
		"example.com/other@v1.0.0": errors.New("disk on fire"),
	}}
	rows := []auditModuleResult{
		{Coordinate: "example.com/mod@v1.2.0", VulnStatus: "(not scanned)"},
		{Coordinate: "example.com/other@v1.0.0", VulnStatus: "(not scanned)"},
		{Coordinate: "example.com/clean@v1.0.0", VulnStatus: "(not scanned)"},
		{Coordinate: "example.com/scanned@v1.0.0", VulnStatus: "Clean"},
		{Coordinate: "not a coordinate", VulnStatus: "(not scanned)"},
	}
	markRefusedVulnRecords(t.Context(), uc, rows)

	if rows[0].VulnStatus != auditIntegrityFailed || rows[0].integrity == nil || !strings.Contains(rows[0].VulnReason, "integrity check failed") {
		t.Errorf("the refused record's row = %+v, want it marked", rows[0])
	}
	for _, r := range rows[1:] {
		if r.VulnStatus == auditIntegrityFailed || r.integrity != nil {
			t.Errorf("row %s marked although its record verified or its read failed otherwise", r.Coordinate)
		}
	}
	if strings.Contains(strings.Join(uc.asked, ","), "scanned") {
		t.Errorf("a row with a verdict was re-read: %v", uc.asked)
	}
}

// A walk-frame read that meets an altered record marks the row itself, on both
// row builders, and the run exits 10.
func TestAuditRow_VulnRecordIntegrityFailure(t *testing.T) {
	uc := testfakes.NewFakeQueryVuln()
	uc.Err = fmt.Errorf("reading: %w", vulnports.ErrVulnIntegrity)
	ctr := &Container{QueryFetch: unfetchedQueryFetch{}, QueryLicense: testfakes.NewFakeQueryLicense(), QueryVuln: uc}
	anchor := vulnFrameAnchor{walkID: "walk-1"}

	dep, err := buildAuditResult(t.Context(), walkdomain.GraphNode{Coordinate: jsonDocDep}, anchor,
		"production", licdomain.NewLicenseOverrideSet(nil), nil, ctr, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("buildAuditResult: %v", err)
	}
	std := buildStdlibAuditResult(t.Context(), coordinatetest.MustNew(coordinate.StdlibPath, "v1.27.2"), walkdomain.GraphNode{}, "production", anchor, ctr)
	for _, r := range []auditModuleResult{dep, std} {
		if r.VulnStatus != auditIntegrityFailed || r.integrity == nil {
			t.Errorf("%s: VulnStatus %q, integrity %v; want it marked", r.Coordinate, r.VulnStatus, r.integrity)
		}
	}
	if code := ExitCodeForError(auditOutcomeErr([]auditModuleResult{dep, std}, auditDerivation{})); code != ExitIntegrity {
		t.Errorf("exit %d, want %d", code, ExitIntegrity)
	}
}

// TestWriteAuditResults_ScanShortfallOnBothChannels prints each shortfall as a
// table and as JSON: the answer is written before the exit, on both.
func TestWriteAuditResults_ScanShortfallOnBothChannels(t *testing.T) {
	rows := []auditModuleResult{{Coordinate: "example.com/mod@v1.2.0", VulnStatus: "(not scanned)"}}
	cases := []struct {
		name   string
		d      auditDerivation
		status string
		code   int
	}{
		{"failed", scanFailedDerivation(), `"status": "failed"`, ExitPartial},
		{"partial", scanPartialDerivation(), `"analysed": 3`, ExitPartial},
		{"integrity", scanIntegrityDerivation(), `"status": "failed"`, ExitIntegrity},
	}
	for _, c := range cases {
		for _, asJSON := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/json=%v", c.name, asJSON), func(t *testing.T) {
				withJSON(t, asJSON)
				var out bytes.Buffer
				err := writeAuditResults(&out, envelopeScope{}, c.d, rows, nil)
				if got := ExitCodeForError(err); got != c.code {
					t.Errorf("exit %d, want %d: %v", got, c.code, err)
				}
				if !strings.Contains(out.String(), "example.com/mod@v1.2.0") {
					t.Errorf("the rows were not written:\n%s", out.String())
				}
				if asJSON && !strings.Contains(out.String(), c.status) {
					t.Errorf("JSON does not carry %s:\n%s", c.status, out.String())
				}
			})
		}
	}
}
