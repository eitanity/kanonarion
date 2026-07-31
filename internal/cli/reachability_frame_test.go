package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// The coordinate and advisory below are the ones the defect was measured on: the
// consuming project's SAML callback reaches Parser.ParseUnverified, and an
// isolated build of the module alone does not.
const frameVulnID = "GO-2025-3553"

func frameCoord(t *testing.T) coordinate.ModuleCoordinate {
	t.Helper()
	return coordinatetest.MustNew("github.com/golang-jwt/jwt/v4", "v4.5.1")
}

// isolatedNotReachable is the record the walk's per-module pool wrote: the
// module built as its own main module, searched with kanonarion's own call
// graph, no consumer above it.
func isolatedNotReachable(t *testing.T, at time.Time) vuldomain.VulnerabilityRecord {
	t.Helper()
	return vuldomain.VulnerabilityRecord{
		Coordinate:            frameCoord(t),
		OverallStatus:         vuldomain.StatusAffected,
		Rooting:               vuldomain.RootingIsolated,
		CallGraphCompleteness: "BUILT_WITH_BODIES",
		ScannedAt:             at,
		Findings: []vuldomain.VulnerabilityFinding{{
			ID:              frameVulnID,
			Summary:         "excessive memory allocation during header parsing",
			AffectedSymbols: []string{"Parser.ParseUnverified"},
			Reachable: &vuldomain.ReachabilityResult{
				IsReachable: false,
				Confidence:  vuldomain.ConfidenceHigh,
				DerivedBy: vuldomain.ReachabilityDerivation{
					Analyser: vuldomain.AnalyserCallGraphBFS,
					Fidelity: "BUILT_WITH_BODIES",
					Rooting:  vuldomain.RootingIsolated,
				},
			},
		}},
	}
}

// consumerRooted is the record a govulncheck analysis rooted at the consuming
// project wrote. It carries the route and no call-graph completeness of its
// own, because the graph it searched is not one this tool built.
func consumerRooted(t *testing.T, at time.Time, reachable bool) vuldomain.VulnerabilityRecord {
	t.Helper()
	root := coordinatetest.MustNew("github.com/cortezaproject/corteza/server", coordinate.LocalVersion)
	f := vuldomain.VulnerabilityFinding{
		ID:              frameVulnID,
		Summary:         "excessive memory allocation during header parsing",
		AffectedSymbols: []string{"*Parser.ParseUnverified"},
	}
	if reachable {
		f.Reachable = &vuldomain.ReachabilityResult{
			IsReachable: true,
			Confidence:  vuldomain.ConfidenceHigh,
			Routes: []vuldomain.ReachabilityRoute{{
				{ModulePath: root.Path(), Package: root.Path() + "/auth/external", Receiver: "*externalSamlAuthHandler", Symbol: "CompleteUserAuth"},
				{ModulePath: "github.com/golang-jwt/jwt/v4", ModuleVersion: "v4.5.1", Package: "github.com/golang-jwt/jwt/v4", Receiver: "*Parser", Symbol: "ParseUnverified"},
			}},
			DerivedBy: vuldomain.ReachabilityDerivation{
				Analyser: vuldomain.AnalyserGovulncheck,
				Fidelity: "source",
				Rooting:  vuldomain.TargetRootedAt(root),
			},
		}
	}
	return vuldomain.VulnerabilityRecord{
		Coordinate:    frameCoord(t),
		OverallStatus: vuldomain.StatusAffected,
		Rooting:       vuldomain.TargetRootedAt(root),
		ScannedAt:     at,
		Findings:      []vuldomain.VulnerabilityFinding{f},
	}
}

// The whole defect, end to end through the command's own read: the ledger holds
// an isolated "not reachable" and two newer consumer-rooted records carrying the
// route, and the query answered NOT reachable at High confidence — because the
// isolated record is the only one with a call-graph completeness, and the
// compose ladder decides on that rung before it ever reaches recency.
//
// The consumer's route is the answer; the isolated verdict is reported under it,
// labelled, and is never the headline.
func TestReachabilityQuery_ConsumerRouteOutranksAnIsolatedStandDown(t *testing.T) {
	coord := frameCoord(t)
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecords(coord,
		consumerRooted(t, time.Date(2026, 7, 31, 17, 54, 8, 0, time.UTC), true),
		consumerRooted(t, time.Date(2026, 7, 31, 17, 52, 58, 0, time.UTC), true),
		isolatedNotReachable(t, time.Date(2026, 7, 31, 17, 49, 28, 0, time.UTC)),
	)

	var out bytes.Buffer
	if err := runVulnReachability(t.Context(), coord.String(), frameVulnID, false, uc, nil, &out); err != nil {
		t.Fatalf("runVulnReachability: %v", err)
	}
	got := out.String()

	if !strings.Contains(got, "is REACHABLE") {
		t.Errorf("the consumer's route was not served as the answer:\n%s", got)
	}
	if strings.Contains(got, "but is NOT reachable") {
		t.Errorf("an isolated-frame verdict was served as the answer to a consumer question:\n%s", got)
	}
	if !strings.Contains(got, "CompleteUserAuth") {
		t.Errorf("the answer does not print the route it was drawn from:\n%s", got)
	}
	for _, want := range []string{"isolated frame", "a different question", "not_reachable"} {
		if !strings.Contains(got, want) {
			t.Errorf("the isolated verdict is not reported alongside, labelled (missing %q):\n%s", want, got)
		}
	}
}

// The same ledger with no route in the consumer frame is a refusal, not a
// fallback: the isolated verdict answers a different question however confident
// it is, so the tool names it, declines to serve it, and gives the project-rooted
// commands that would produce a real answer.
func TestReachabilityQuery_NoConsumerVerdictRefusesRatherThanFallingBack(t *testing.T) {
	coord := frameCoord(t)
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecords(coord,
		consumerRooted(t, time.Date(2026, 7, 31, 17, 54, 8, 0, time.UTC), false),
		isolatedNotReachable(t, time.Date(2026, 7, 31, 17, 49, 28, 0, time.UTC)),
	)

	var out bytes.Buffer
	err := runVulnReachability(t.Context(), coord.String(), frameVulnID, false, uc, nil, &out)
	if err == nil {
		t.Fatalf("want a refusal, got an answer:\n%s", out.String())
	}
	msg := err.Error()
	if strings.Contains(msg, "scanned without --reachability") {
		t.Errorf("refusal blames a missing flag for a frame mismatch:\n%s", msg)
	}
	for _, want := range []string{
		"isolated-frame scan",
		"not_reachable",
		"a different question",
		"kanonarion vuln-scan --gomod ./go.mod --reachability",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal missing %q:\n%s", want, msg)
		}
	}
}

// A ledger holding only isolated records still answers from them. The rule is
// "do not carry a verdict across a frame boundary", not "distrust the isolated
// frame": with nothing in a consumer frame there is no boundary to cross, and
// refusing here would withhold the only measurement there is.
func TestReachabilityQuery_IsolatedOnlyLedgerStillAnswers(t *testing.T) {
	coord := frameCoord(t)
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecords(coord, isolatedNotReachable(t, time.Date(2026, 7, 31, 17, 49, 28, 0, time.UTC)))

	var out bytes.Buffer
	if err := runVulnReachability(t.Context(), coord.String(), frameVulnID, false, uc, nil, &out); err != nil {
		t.Fatalf("runVulnReachability: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "but is NOT reachable") {
		t.Errorf("the isolated measurement was withheld:\n%s", got)
	}
	if strings.Contains(got, "isolated frame (") {
		t.Errorf("the answer is reported as an aside to itself:\n%s", got)
	}
}
