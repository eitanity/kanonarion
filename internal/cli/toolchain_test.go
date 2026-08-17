package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	coordinatetest "github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

func testSnapshot(t *testing.T) vulndomain.DatabaseSnapshot {
	t.Helper()
	return vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z")
}

func checksumBypassAdvisory() vulndomain.ToolchainAdvisory {
	return vulndomain.ToolchainAdvisory{
		ID:      "GO-2026-4984",
		Summary: "Malicious module proxy can bypass checksum database in cmd/go",
		Ranges:  []vulndomain.ToolchainRange{{Introduced: "0", Fixed: "1.25.10"}, {Introduced: "1.26.0-0", Fixed: "1.26.3"}},
	}
}

func toolchainOutput(t *testing.T, j vulndomain.ToolchainJudgment) string {
	t.Helper()
	var out bytes.Buffer
	if err := writeToolchainJudgment(&out, j); err != nil {
		t.Fatalf("writeToolchainJudgment: %v", err)
	}
	return out.String()
}

// TestToolchainLine_AffectedNamesTheAdvisoryTheFixAndTheSnapshot: the line is a
// derived judgment, so it has to carry its basis. A reader acts on the fix
// version and checks the claim against the snapshot it was made from.
func TestToolchainLine_AffectedNamesTheAdvisoryTheFixAndTheSnapshot(t *testing.T) {
	j := vulndomain.JudgeToolchain("go1.26.2", testSnapshot(t),
		vulndomain.ToolchainAdvisorySet{KeyPresent: true, Advisories: []vulndomain.ToolchainAdvisory{checksumBypassAdvisory()}})

	got := toolchainOutput(t, j)
	for _, want := range []string{"toolchain:", "go1.26.2", "GO-2026-4984", "fixed in 1.26.3", "vuln.go.dev@2026-07-27T20:14:16Z", "counted in no module roll-up"} {
		if !strings.Contains(got, want) {
			t.Errorf("the toolchain line does not state %q:\n%s", want, got)
		}
	}
}

// A clear names what it was measured against. "clear" with no basis is the
// claim this whole report exists to avoid.
func TestToolchainLine_ClearNamesTheSnapshotAndWhatItJudged(t *testing.T) {
	j := vulndomain.JudgeToolchain("go1.26.5", testSnapshot(t),
		vulndomain.ToolchainAdvisorySet{KeyPresent: true, Advisories: []vulndomain.ToolchainAdvisory{checksumBypassAdvisory()}})

	got := toolchainOutput(t, j)
	for _, want := range []string{"go1.26.5", "none of the 1 toolchain advisories", "vuln.go.dev@2026-07-27T20:14:16Z"} {
		if !strings.Contains(got, want) {
			t.Errorf("the toolchain line does not state %q:\n%s", want, got)
		}
	}
}

// TestToolchainLine_UnjudgedIsStatedNotOmitted: a snapshot too old to carry the
// toolchain key must say the judgment could not be made. Printing nothing would
// read as a clear, which is the silent omission the axis exists to end.
func TestToolchainLine_UnjudgedIsStatedNotOmitted(t *testing.T) {
	j := vulndomain.JudgeToolchain("go1.26.5", testSnapshot(t), vulndomain.ToolchainAdvisorySet{})

	got := toolchainOutput(t, j)
	if strings.TrimSpace(got) == "toolchain:" || !strings.Contains(got, "was not judged") {
		t.Fatalf("an unjudgeable toolchain did not say so:\n%s", got)
	}
	if !strings.Contains(got, vulndomain.ToolchainReasonNoKey) {
		t.Errorf("the line does not name what stopped the judgment:\n%s", got)
	}
	if strings.Contains(got, "clear") {
		t.Errorf("an unjudged toolchain rendered as a clear:\n%s", got)
	}
}

// A walk that recorded no toolchain names the gap rather than printing an empty
// version, which a reader cannot tell from an unstated one.
func TestToolchainLine_AnUnrecordedVersionIsNamed(t *testing.T) {
	got := toolchainOutput(t, vulndomain.JudgeToolchain("", testSnapshot(t), vulndomain.ToolchainAdvisorySet{KeyPresent: true}))
	if !strings.Contains(got, "(unrecorded)") || !strings.Contains(got, vulndomain.ToolchainReasonNoVersion) {
		t.Errorf("an unrecorded toolchain version was not named as one:\n%s", got)
	}
}

// A retraction is reported in the withdrawn vocabulary, not as affected and not
// as clear — the same ranking a module record gets.
func TestToolchainLine_WithdrawnIsNeitherAffectedNorClear(t *testing.T) {
	retracted := checksumBypassAdvisory()
	retracted.WithdrawnAt = time.Date(2026, 4, 8, 0, 0, 0, 0, time.UTC)
	j := vulndomain.JudgeToolchain("go1.26.2", testSnapshot(t),
		vulndomain.ToolchainAdvisorySet{KeyPresent: true, Advisories: []vulndomain.ToolchainAdvisory{retracted}})

	got := toolchainOutput(t, j)
	if !strings.Contains(got, "withdrawn") || !strings.Contains(got, "GO-2026-4984") {
		t.Fatalf("the retraction was not reported:\n%s", got)
	}
	if strings.Contains(got, "is covered by 1 advisory in") {
		t.Errorf("a retracted advisory was reported as a live finding:\n%s", got)
	}
}

// TestToolchainVersionOf_ReadsTheBuildEnvNotTheStdlibNode is the authority
// decision, pinned. The walk holds two toolchain versions: the build
// environment's, which is `go env GOVERSION` — the toolchain that actually
// compiled the project — and the synthetic stdlib node's, which
// --stdlib-from-gomod pins to the go.mod directive. The judgment is about the
// toolchain that built the walk, so the directive must never answer for it.
func TestToolchainVersionOf_ReadsTheBuildEnvNotTheStdlibNode(t *testing.T) {
	stdlibNode, ok := walkdomain.StdlibNode("go1.24.0")
	if !ok {
		t.Fatal("could not build the stdlib node fixture")
	}
	rec := walkdomain.WalkRecord{Graph: walkdomain.Graph{
		BuildEnv: walkdomain.BuildEnv{GOOS: "linux", GOARCH: "amd64", GoVersion: "go1.26.5"},
		Nodes:    []walkdomain.GraphNode{stdlibNode},
	}}

	if got := toolchainVersionOf(rec); got != "go1.26.5" {
		t.Errorf("toolchain version = %q, want the effective toolchain go1.26.5 and not the pinned stdlib node", got)
	}
}

// TestToolchainAxis_NeverEntersTheModuleRollups is the ticket's regression: the
// roll-up counts a reader tallies must be identical whether the toolchain
// judgment found nothing, found an advisory, or was never made at all. The
// toolchain is not a dependency of the artefact, and one advisory against cmd/go
// must not change what the artefact's own evidence says.
func TestToolchainAxis_NeverEntersTheModuleRollups(t *testing.T) {
	affectedCoord := coordinatetest.MustNew("example.com/affected", "v1.0.0")
	cleanCoord := coordinatetest.MustNew("example.com/clean", "v1.0.0")

	baseline := func() *vulnScanRollups {
		r := newVulnScanRollups()
		r.add(affectedCoord, vulndomain.VulnerabilityRecord{
			Coordinate:     affectedCoord,
			OverallStatus:  vulndomain.StatusAffected,
			CoverageStatus: vulndomain.CoverageAnalysed,
			FindingsStatus: vulndomain.FindingsRecordAffected,
			Findings:       []vulndomain.VulnerabilityFinding{{ID: "GO-2026-0001"}},
		})
		r.add(cleanCoord, vulndomain.VulnerabilityRecord{
			Coordinate:     cleanCoord,
			OverallStatus:  vulndomain.StatusClean,
			CoverageStatus: vulndomain.CoverageAnalysed,
			FindingsStatus: vulndomain.FindingsRecordClean,
		})
		return r
	}

	run := vulndomain.WalkScanRun{
		ID:             "vscan-1",
		Snapshot:       testSnapshot(t),
		CoverageStatus: vulndomain.CoverageComplete,
		FindingsStatus: vulndomain.FindingsAffected,
		Counts:         vulndomain.WalkScanCounts{Total: 2, Analysed: 2, Affected: 1},
	}

	render := func(j *vulndomain.ToolchainJudgment) (stdout, stderr string) {
		r := baseline()
		var out, errBuf bytes.Buffer
		if j != nil {
			if err := writeToolchainJudgment(&errBuf, *j); err != nil {
				t.Fatalf("writeToolchainJudgment: %v", err)
			}
		}
		if err := printVulnScanResult(run, r.affected, r.withdrawn, r.failed, r.unscannable, vulnScanReachability{}, false, &out); err != nil {
			t.Fatalf("printVulnScanResult: %v", err)
		}
		if len(r.affected) != 1 || len(r.withdrawn) != 0 {
			t.Fatalf("roll-ups = %d affected / %d withdrawn, want 1 / 0", len(r.affected), len(r.withdrawn))
		}
		return out.String(), errBuf.String()
	}

	affected := vulndomain.JudgeToolchain("go1.26.2", testSnapshot(t),
		vulndomain.ToolchainAdvisorySet{KeyPresent: true, Advisories: []vulndomain.ToolchainAdvisory{checksumBypassAdvisory()}})
	clear := vulndomain.JudgeToolchain("go1.26.5", testSnapshot(t),
		vulndomain.ToolchainAdvisorySet{KeyPresent: true, Advisories: []vulndomain.ToolchainAdvisory{checksumBypassAdvisory()}})

	off, _ := render(nil)
	withAffected, axisOut := render(&affected)
	withClear, _ := render(&clear)

	if withAffected != off || withClear != off {
		t.Errorf("the module report changed when the toolchain axis was reported:\nwithout:\n%s\nwith an affected toolchain:\n%s", off, withAffected)
	}
	if strings.Contains(off, "GO-2026-4984") || strings.Contains(withAffected, "GO-2026-4984") {
		t.Errorf("a toolchain advisory reached the module data channel:\n%s", withAffected)
	}
	if !strings.Contains(axisOut, "GO-2026-4984") {
		t.Errorf("the toolchain axis reported nothing on its own channel:\n%s", axisOut)
	}
}
