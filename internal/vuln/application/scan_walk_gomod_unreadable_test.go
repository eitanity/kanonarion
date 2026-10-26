package application_test

import (
	"strings"
	"testing"

	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
	"code.eitanity.com/kanonarion/internal/fetch/fetchtest"

	"code.eitanity.com/kanonarion/internal/vuln/application"
	"code.eitanity.com/kanonarion/internal/vuln/domain"
)

const goModUnreadableMsg = "the module's stored go.mod could not be read, treating it as absent"

// A recorded go.mod the scan cannot produce is stated at warn with the
// coordinate, the step and the error, and is then treated as absent exactly
// as before. A record with no go.mod hash, or none servable, stays silent.
func TestScanWalk_ARecordedGoModThatCannotBeReadIsStated(t *testing.T) {
	cases := []struct {
		name      string
		goModHash string // the dependency's stored go.mod hash
		goModBlob string // bytes held under that hash; "" holds none
		wantStep  string // "" means no warn at all
		wantErr   string
		aside     bool // depA holds only set-aside records
	}{
		{name: "hash does not parse", goModHash: "h1:", wantStep: "deriving the go.mod address", wantErr: `"h1:"`},
		{name: "blob not held", goModHash: "h1:missing=", wantStep: "opening the go.mod blob", wantErr: "missing"},
		{name: "blob does not parse", goModHash: "h1:garbled=", goModBlob: "module\x00 not a go.mod (", wantStep: "parsing the go.mod", wantErr: "go.mod"},
		{name: "control: no go.mod hash recorded", goModHash: fetchdomain.ZeroString},
		{name: "control: nothing servable", aside: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			logger, logs := captureLogs(t)
			scanner := &fakeScanner{targetRooted: true}
			f := newLoggedTargetScanFixture(t, logger, scanner)

			if tc.aside {
				assertNothingServableIsSilent(t, f, logs)
				return
			}
			seedDepAGoMod(t, f, tc.goModHash, tc.goModBlob)

			run, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester"})
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			// The fallback is unchanged: the walk still answers through the
			// target-rooted analysis, with depA covered by it.
			if scanner.targetCalls != 1 || run.OverallStatus == domain.WalkStatusFailed {
				t.Errorf("targetCalls = %d, status = %v; want the target-rooted answer unchanged", scanner.targetCalls, run.OverallStatus)
			}
			got, ok, err := f.vulnStore.GetLatestVulnerabilityRecordForWalk(ctx, f.depA, "v1", f.walkID)
			if err != nil || !ok || got.OverallStatus != domain.StatusClean {
				t.Errorf("depA record = %v ok=%v err=%v, want Clean as before", got.OverallStatus, ok, err)
			}

			var warns []logLine
			for _, l := range linesAt(logs(), "WARN", goModUnreadableMsg) {
				if l["coordinate"] == f.depA.String() {
					warns = append(warns, l)
				}
			}
			if tc.wantStep == "" {
				if len(warns) != 0 {
					t.Fatalf("a record with no go.mod hash logged %d warn lines: %v", len(warns), warns)
				}
				return
			}
			assertStepWarns(t, warns, tc.wantStep, tc.wantErr)
		})
	}
}

// seedDepAGoMod replaces depA's record with one carrying goModHash, holding
// goModBlob under it when non-empty.
func seedDepAGoMod(t *testing.T, f targetScanFixture, goModHash, goModBlob string) {
	t.Helper()
	ctx := t.Context()
	opts := []fetchtest.Option{
		fetchtest.Coordinate(f.depA),
		fetchtest.PipelineVersion("v1"),
		fetchtest.Content("zip-" + f.depA.Path()),
		func(r *fetchdomain.FactRecord) { r.GoModHash = goModHash },
	}
	if goModBlob != "" {
		if err := f.blobs.Put(ctx, fetchtest.GoModIdentity(t, fetchtest.Record(t, opts...)), strings.NewReader(goModBlob)); err != nil {
			t.Fatalf("Put go.mod blob: %v", err)
		}
	}
	if err := f.facts.PutFetchRecord(ctx, fetchtest.Sealed(t, opts...)); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}
}

// assertNothingServableIsSilent leaves depA with only set-aside records and
// checks the scan reads that as no record, without a warn.
func assertNothingServableIsSilent(t *testing.T, f targetScanFixture, logs func() []logLine) {
	t.Helper()
	f.facts.mu.Lock()
	delete(f.facts.records, f.depA.Path()+"@"+f.depA.Version()+"#v1")
	f.facts.setAside = true
	f.facts.mu.Unlock()
	if _, err := f.walkUC.Scan(t.Context(), application.ScanWalkParams{WalkID: f.walkID, Operator: "tester"}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if n := len(linesAt(logs(), "WARN", goModUnreadableMsg)); n != 0 {
		t.Errorf("warn lines = %d, want none for a coordinate with nothing servable", n)
	}
}
