package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	coordinatetest "github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// This file pins the reachability split a stored scan run's text surface states.
//
// The rule it exists to enforce is that the split is DERIVED from the domain and
// never from is_reachable alone. Measured on a 128-module run: all 33 negatives
// were unsound, so an implementation counting is_reachable renders "28
// reachable, 33 not reachable, 0 undecided" — a clean negative for 33 findings
// nothing ever searched, and an answer that would satisfy a naive reading of
// "the figures agree with --json".

// findingOnRung is one finding already carrying the rung a projection derived
// for it, which is the shape the renderer consumes.
func findingOnRung(id string, reachable bool, rung vuldomain.ReachabilitySoundness) vulnFindingJSON {
	return vulnFindingJSON{
		vulnFindingRungJSON: vulnFindingRungJSON{
			VulnerabilityFinding: vuldomain.VulnerabilityFinding{
				ID:      id,
				Summary: "fixture",
				Reachable: &vuldomain.ReachabilityResult{
					IsReachable: reachable,
					Confidence:  vuldomain.ConfidenceHigh,
				},
			},
			Soundness: rung,
		},
	}
}

// TestReachabilitySplit_EveryRungTheDomainDefinesIsRenderedUnderItsOwnName is
// the acceptance stated as a property rather than as counts.
//
// It walks ReachabilitySoundnessLevels rather than a list restated here, so a
// rung added to the type joins this test automatically — and the renderer must
// place it, name it and state it with no edit of its own. A rung landing in a
// bucket by a hardcoded name fails here.
func TestReachabilitySplit_EveryRungTheDomainDefinesIsRenderedUnderItsOwnName(t *testing.T) {
	levels := vuldomain.ReachabilitySoundnessLevels()
	if len(levels) < 2 {
		t.Fatalf("ReachabilitySoundnessLevels() returned %d rungs, want the whole ladder", len(levels))
	}

	findings := []vulnFindingJSON{findingOnRung("GO-0000-0000", true, vuldomain.SoundnessNotStated)}
	for i, rung := range levels {
		findings = append(findings, findingOnRung("GO-2026-000"+string(rune('0'+i)), false, rung))
	}
	split := reachabilitySplitOf([]scanAffectedModule{{Coordinate: "example.com/mod@v1.0.0", Findings: findings}})

	if split.total != len(levels)+1 {
		t.Errorf("split covered %d findings, want %d — every finding must land in exactly one bucket",
			split.total, len(levels)+1)
	}
	if split.reachable != 1 {
		t.Errorf("reachable = %d, want 1", split.reachable)
	}
	// Exactly one rung may be reported as a clean negative, and the domain says
	// which by answering IsConfirmed.
	if split.notReachable != 1 {
		t.Errorf("not reachable = %d, want 1: only the rung IsConfirmed admits may be counted there", split.notReachable)
	}
	if split.undecided != len(levels)-1 {
		t.Errorf("undecided = %d, want %d — every remaining negative", split.undecided, len(levels)-1)
	}

	var buf bytes.Buffer
	writeScanReachabilitySplit(&buf, split)
	out := buf.String()
	for _, rung := range levels {
		if rung.IsConfirmed() {
			continue
		}
		if !strings.Contains(out, rung.String()) {
			t.Errorf("rung %q is tallied but never named in the rendering; got:\n%s", rung.String(), out)
		}
	}
	if !strings.Contains(out, vuldomain.SoundnessDisputed.String()) {
		t.Errorf("disputed is not named; got:\n%s", out)
	}
	// disputed is a CONTRADICTED negative, not a weak one: a second analyser
	// found the path the record denies. It is the one rung an operator must not
	// act on, and folding it into a neighbour's tally is how that is lost.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, vuldomain.SoundnessDisputed.String()) &&
			strings.Contains(line, vuldomain.SoundnessInferred.String()) {
			t.Errorf("disputed was tallied on the same line as inferred: %q", line)
		}
	}
}

// TestReachabilitySplit_NoUnsoundNegativeIsCountedNotReachable is the defect in
// its own terms. Every negative on this store is unsound, so an implementation
// that counted is_reachable would put all of them in the not-reachable bucket
// and report a clean release.
func TestReachabilitySplit_NoUnsoundNegativeIsCountedNotReachable(t *testing.T) {
	findings := []vulnFindingJSON{
		findingOnRung("GO-2026-0001", false, vuldomain.SoundnessInferred),
		findingOnRung("GO-2026-0002", false, vuldomain.SoundnessUnsearchable),
		findingOnRung("GO-2026-0003", false, vuldomain.SoundnessUnconfirmed),
		findingOnRung("GO-2026-0004", false, vuldomain.SoundnessDisputed),
	}
	split := reachabilitySplitOf([]scanAffectedModule{{Coordinate: "example.com/mod@v1.0.0", Findings: findings}})
	if split.notReachable != 0 {
		t.Errorf("not reachable = %d over four unsound negatives, want 0", split.notReachable)
	}
	if split.undecided != 4 {
		t.Errorf("undecided = %d, want 4", split.undecided)
	}

	// The falsifying case: coverage and reachability are separate axes, so a run
	// whose findings are all undecided must not read as clean.
	var buf bytes.Buffer
	writeScanReachabilitySplit(&buf, split)
	if !strings.Contains(buf.String(), "undecided") || !strings.Contains(buf.String(), "none of these is a clean negative") {
		t.Errorf("an all-undecided run does not state that none of it is a clean negative; got:\n%s", buf.String())
	}
}

// TestReachabilitySplit_ConfirmedIsTheOnlyCleanNegative drives the bucket that
// cannot be driven non-zero against this store, where 147 of 147 searchable
// negatives sit on application-rooted graphs.
func TestReachabilitySplit_ConfirmedIsTheOnlyCleanNegative(t *testing.T) {
	split := reachabilitySplitOf([]scanAffectedModule{{
		Coordinate: "example.com/mod@v1.0.0",
		Findings: []vulnFindingJSON{
			findingOnRung("GO-2026-0001", false, vuldomain.SoundnessConfirmed),
			findingOnRung("GO-2026-0002", false, vuldomain.SoundnessConfirmed),
			findingOnRung("GO-2026-0003", false, vuldomain.SoundnessInferred),
		},
	}})
	if split.notReachable != 2 || split.undecided != 1 {
		t.Errorf("split = %d not reachable / %d undecided, want 2 / 1", split.notReachable, split.undecided)
	}
	var buf bytes.Buffer
	writeScanReachabilitySplit(&buf, split)
	if !strings.Contains(buf.String(), "not reachable     2") {
		t.Errorf("the confirmed negatives are not rendered as the clean bucket; got:\n%s", buf.String())
	}
}

// TestReachabilitySplit_WithdrawnFindingsStayOut keeps the split consistent with
// the report it sits in: the text already prints withdrawn advisories as "not
// counted as findings", and counting one into the undecided bucket inflates the
// single figure a reader takes as work outstanding.
func TestReachabilitySplit_WithdrawnFindingsStayOut(t *testing.T) {
	withdrawn := findingOnRung("GO-2026-0002", false, vuldomain.SoundnessInferred)
	withdrawn.WithdrawnAt = time.Date(2026, 2, 10, 0, 0, 0, 0, time.UTC)
	split := reachabilitySplitOf([]scanAffectedModule{{
		Coordinate: "example.com/mod@v1.0.0",
		Findings:   []vulnFindingJSON{findingOnRung("GO-2026-0001", true, vuldomain.SoundnessNotStated), withdrawn},
	}})
	if split.total != 1 || split.reachable != 1 || split.undecided != 0 {
		t.Errorf("split = %+v, want the withdrawn advisory excluded", split)
	}
}

// TestReachabilitySplit_NoFindingsPrintsNoBlock: a run with nothing to split
// gains no empty heading over three zeros.
func TestReachabilitySplit_NoFindingsPrintsNoBlock(t *testing.T) {
	var buf bytes.Buffer
	writeScanReachabilitySplit(&buf, reachabilitySplitOf(nil))
	if buf.Len() != 0 {
		t.Errorf("a run with no findings produced a reachability block: %q", buf.String())
	}
}

// TestRunScanShow_TextSplitAgreesWithItsOwnJSON is the cross-surface acceptance.
// The two surfaces read the same fields through the same derivation, so a
// consumer who tallies --json and a person who reads the summary must get the
// same numbers.
func TestRunScanShow_TextSplitAgreesWithItsOwnJSON(t *testing.T) {
	const runID = "vscan-reachsplit"
	app := coordinatetest.MustNew("example.com/app", coordinate.LocalVersion)
	mod := coordinatetest.MustNew("example.com/mod", "v1.2.0")

	rec := vuldomain.VulnerabilityRecord{
		Ecosystem:       "Go",
		Coordinate:      mod,
		Rooting:         vuldomain.TargetRootedAt(app),
		OverallStatus:   vuldomain.StatusAffected,
		CoverageStatus:  vuldomain.CoverageAnalysed,
		FindingsStatus:  vuldomain.FindingsRecordAffected,
		PipelineVersion: vulnPipelineVersion,
		ContentHash:     "sha256:reachsplit",
		Findings: []vuldomain.VulnerabilityFinding{
			{
				ID:              "GO-2026-0001",
				Summary:         "reachable",
				AffectedSymbols: []string{"example.com/mod.Parse"},
				Reachable: &vuldomain.ReachabilityResult{
					IsReachable: true,
					Confidence:  vuldomain.ConfidenceHigh,
					DerivedBy: vuldomain.ReachabilityDerivation{
						Analyser: vuldomain.AnalyserGovulncheck, Fidelity: "source",
					},
				},
			},
			{
				ID:              "GO-2026-0002",
				Summary:         "a negative read off an analyser's silence",
				AffectedSymbols: []string{"example.com/mod.Handle"},
				Reachable: &vuldomain.ReachabilityResult{
					IsReachable: false,
					Confidence:  vuldomain.ConfidenceHigh,
					DerivedBy: vuldomain.ReachabilityDerivation{
						Analyser: vuldomain.AnalyserGovulncheck, Fidelity: "source",
					},
				},
			},
			{
				ID:                     "GO-2026-0003",
				Summary:                "an advisory naming no symbol",
				AdvisoryNamesNoSymbols: true,
				Reachable: &vuldomain.ReachabilityResult{
					IsReachable: false,
					Confidence:  vuldomain.ConfidenceHigh,
					DerivedBy: vuldomain.ReachabilityDerivation{
						Analyser: vuldomain.AnalyserGovulncheck, Fidelity: "source",
					},
				},
			},
		},
	}

	ucRuns := testfakes.NewFakeQueryScanRuns()
	ucRuns.AddRun(vuldomain.WalkScanRun{
		ID:               runID,
		WalkID:           "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		PerModuleResults: map[coordinate.ModuleCoordinate]string{mod: "sha256:reachsplit"},
		OverallStatus:    vuldomain.WalkStatusAffected,
		PipelineVersion:  vulnPipelineVersion,
	})
	ucVuln := testfakes.NewFakeQueryVuln()
	ucVuln.AddRecord(mod, rec)

	var text bytes.Buffer
	if err := runScanShow(context.Background(), runID, false, ucRuns, ucVuln, nil, nil, &text, io.Discard); err != nil {
		t.Fatalf("runScanShow: %v", err)
	}

	jsonOut = true
	t.Cleanup(func() { jsonOut = false })
	var doc bytes.Buffer
	if err := runScanShow(context.Background(), runID, true, ucRuns, ucVuln, nil, nil, &doc, io.Discard); err != nil {
		t.Fatalf("runScanShow --json: %v", err)
	}

	var parsed struct {
		AffectedModules []struct {
			Findings []struct {
				Soundness string `json:"soundness"`
				Reachable *struct {
					IsReachable bool `json:"is_reachable"`
				} `json:"reachable"`
			} `json:"findings"`
		} `json:"affected_modules"`
	}
	if err := json.Unmarshal(doc.Bytes(), &parsed); err != nil {
		t.Fatalf("decoding --json: %v", err)
	}
	reachable, notReachable, undecided := 0, 0, 0
	for _, m := range parsed.AffectedModules {
		for _, f := range m.Findings {
			switch {
			case f.Reachable != nil && f.Reachable.IsReachable:
				reachable++
			case f.Soundness == string(vuldomain.SoundnessConfirmed):
				notReachable++
			default:
				undecided++
			}
		}
	}
	if reachable != 1 || notReachable != 0 || undecided != 2 {
		t.Fatalf("--json tallies %d/%d/%d, want 1/0/2 for this fixture", reachable, notReachable, undecided)
	}

	out := text.String()
	for _, want := range []string{"Reachability of 3 finding(s):", "reachable         1", "not reachable     0", "undecided         2"} {
		if !strings.Contains(out, want) {
			t.Errorf("the text split does not agree with --json: missing %q in:\n%s", want, out)
		}
	}
	// The rungs the domain derived for those two negatives, named in the text.
	if !strings.Contains(out, "inferred") || !strings.Contains(out, "unsearchable") {
		t.Errorf("the undecided bucket is not broken down by rung; got:\n%s", out)
	}
}

// TestRunScanShowText_DoesNoRouteRootClassification pins the cost decision the
// text path was built on. A root is per-finding detail and this is a tally, so
// the split must not drag a call-graph decode per module onto a surface that
// prints no root.
func TestRunScanShowText_DoesNoRouteRootClassification(t *testing.T) {
	const runID = "vscan-noroot"
	mod := coordinatetest.MustNew("example.com/mod", "v1.2.0")
	ucRuns := testfakes.NewFakeQueryScanRuns()
	ucRuns.AddRun(vuldomain.WalkScanRun{
		ID:               runID,
		WalkID:           "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		PerModuleResults: map[coordinate.ModuleCoordinate]string{mod: "sha256:noroot"},
		OverallStatus:    vuldomain.WalkStatusAffected,
		PipelineVersion:  vulnPipelineVersion,
	})
	ucVuln := testfakes.NewFakeQueryVuln()
	ucVuln.AddRecord(mod, vuldomain.VulnerabilityRecord{
		Ecosystem: "Go", Coordinate: mod,
		OverallStatus: vuldomain.StatusAffected, CoverageStatus: vuldomain.CoverageAnalysed,
		FindingsStatus:  vuldomain.FindingsRecordAffected,
		PipelineVersion: vulnPipelineVersion,
		ContentHash:     "sha256:noroot",
		Findings: []vuldomain.VulnerabilityFinding{{
			ID: "GO-2026-0001",
			Reachable: &vuldomain.ReachabilityResult{
				IsReachable: true,
				Routes: []vuldomain.ReachabilityRoute{{
					{ModulePath: "example.com/app", Package: "example.com/app", Symbol: "main"},
					{ModulePath: "example.com/mod", Package: "example.com/mod", Symbol: "Parse"},
				}},
			},
		}},
	})

	// A nil call-graph reader is the only reader the text path may need. If the
	// split ever reached for a root it would have to consult one, and this
	// asserts it does not by giving it none and still requiring the answer.
	var buf bytes.Buffer
	if err := runScanShow(context.Background(), runID, false, ucRuns, ucVuln, nil, nil, &buf, io.Discard); err != nil {
		t.Fatalf("runScanShow: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "reachable         1") {
		t.Errorf("the split was not rendered; got:\n%s", out)
	}
	if strings.Contains(out, "route_root") || strings.Contains(out, "ingress") {
		t.Errorf("the text surface classified a route root; got:\n%s", out)
	}
}
