package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// narratingRescan stands in for the re-scan use case and drives the caller's
// Progress callback once per module, exactly as the scan beneath it does.
type narratingRescan struct {
	coords []coordinate.ModuleCoordinate
	// gotProgress records whether a callback arrived at all, so a silent run is
	// reported as an unwired callback rather than as a passing assertion about
	// an empty stream.
	gotProgress bool
}

func (r *narratingRescan) Rescan(_ context.Context, req vulnapp.RescanRequest) (vuldomain.WalkScanRun, error) {
	for i, coord := range r.coords {
		if req.Progress == nil {
			continue
		}
		r.gotProgress = true
		req.Progress(coord, vuldomain.VulnerabilityRecord{
			Coordinate:    coord,
			OverallStatus: vuldomain.StatusClean,
		}, i+1, len(r.coords))
	}
	return vuldomain.WalkScanRun{
		ID:             "01RESCANRUN0000000000000",
		WalkID:         req.WalkID,
		Snapshot:       vulntest.MustNew("vuln.go.dev", "2026-08-01T00:00:00Z"),
		OverallStatus:  vuldomain.WalkStatusAllClean,
		CoverageStatus: vuldomain.CoverageComplete,
		FindingsStatus: vuldomain.FindingsClean,
	}, nil
}

// TestRescanWith_NarratesOnStderrAndResultsOnStdout is the re-scan's half of the
// stream contract every other scan command already keeps.
//
// Two defects met here. The `Re-scanning walk ...` line was written to stdout
// while the run was still in flight, which made this the one scan command whose
// data channel carried commentary. And the run beneath it was handed no progress
// callback, so the most expensive command the tool offers said nothing at all
// until it finished. Both are asserted together because either alone leaves the
// command unreadable: narration on the wrong stream, or no narration to route.
func TestRescanWith_NarratesOnStderrAndResultsOnStdout(t *testing.T) {
	first := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	second := coordinatetest.MustNew("example.com/other", "v2.3.4")

	var stdout, stderr bytes.Buffer
	rescan := &narratingRescan{coords: []coordinate.ModuleCoordinate{first, second}}
	req := vulnapp.RescanRequest{WalkID: "01KQDBVW092ER1HNXZ60X27CMD"}
	if err := rescanWith(context.Background(), rescan, req, "", false, &stdout, &stderr); err != nil {
		t.Fatalf("rescanWith: %v", err)
	}
	if !rescan.gotProgress {
		t.Fatal("the re-scan was driven with no Progress callback, so this run proves nothing about routing")
	}

	// The in-flight narration and every per-module line belong to stderr.
	for _, want := range []string{
		"Re-scanning walk 01KQDBVW092ER1HNXZ60X27CMD...",
		"[1/2] example.com/mod@v1.0.0",
		"[2/2] example.com/other@v2.3.4",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr missing %q, got: %q", want, stderr.String())
		}
		if strings.Contains(stdout.String(), want) {
			t.Errorf("%q was written to stdout, which is the caller's data channel: %q", want, stdout.String())
		}
	}

	// The results belong to stdout, and stay there.
	for _, want := range []string{"Run ID: 01RESCANRUN0000000000000", "Snapshot: vuln.go.dev@2026-08-01T00:00:00Z"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout missing the result line %q, got: %q", want, stdout.String())
		}
	}
}

// TestRescanWith_NoProgressSilencesTheStreamOnly pins what the flag the command
// now registers actually does: the narration and the per-module lines go, the
// results stay. A flag that also swallowed the result would be worse than none.
func TestRescanWith_NoProgressSilencesTheStreamOnly(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")

	var stdout, stderr bytes.Buffer
	rescan := &narratingRescan{coords: []coordinate.ModuleCoordinate{coord}}
	req := vulnapp.RescanRequest{WalkID: "01KQDBVW092ER1HNXZ60X27CMD"}
	if err := rescanWith(context.Background(), rescan, req, "", true, &stdout, &stderr); err != nil {
		t.Fatalf("rescanWith: %v", err)
	}
	if !rescan.gotProgress {
		t.Fatal("--no-progress must silence the stream, not unwire the callback: the roll-ups downstream are fed by it")
	}
	if stderr.Len() != 0 {
		t.Errorf("--no-progress must leave the narration stream empty, got: %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Run ID: 01RESCANRUN0000000000000") {
		t.Errorf("--no-progress silenced the result as well: %q", stdout.String())
	}
}
