package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// rootedRecord is a reachable finding with one route, the shape both presenters
// classify.
func rootedRecord() vuldomain.VulnerabilityRecord {
	return vuldomain.VulnerabilityRecord{
		Coordinate:     coordinatetest.MustNew("example.com/dep", "v1.2.0"),
		Rooting:        vuldomain.TargetRootedAt(coordinatetest.MustNew("example.com/app", "local")),
		OverallStatus:  vuldomain.StatusAffected,
		CoverageStatus: vuldomain.CoverageAnalysed,
		FindingsStatus: vuldomain.FindingsRecordAffected,
		Findings: []vuldomain.VulnerabilityFinding{{
			ID:      "GO-2026-0001",
			Summary: "a flaw",
			Reachable: &vuldomain.ReachabilityResult{
				IsReachable: true,
				Confidence:  vuldomain.ConfidenceHigh,
				Routes: []vuldomain.ReachabilityRoute{{
					{ModulePath: "example.com/app", Package: "example.com/app/handlers", Receiver: "*Server", Symbol: "ServeHTTP"},
					{ModulePath: "example.com/dep", ModuleVersion: "v1.2.0", Package: "example.com/dep", Symbol: "Parse"},
				}},
				DerivedBy: vuldomain.ReachabilityDerivation{
					Analyser: vuldomain.AnalyserGovulncheck,
					Fidelity: "source",
				},
			},
		}},
	}
}

func classifyAs(root vuldomain.RouteRoot) routeRootFunc {
	return func(vuldomain.ReachabilityRoute) vuldomain.RouteRoot { return root }
}

// TestVulnShowPutsTheTestRootOnTheVerdictLine is the ticket's non-negotiable
// rendering rule: a route whose root is test scope says so beside the verdict,
// so a test-only reach is never read as a production one. A line further down is
// a line that gets skipped.
func TestVulnShowPutsTheTestRootOnTheVerdictLine(t *testing.T) {
	var out bytes.Buffer
	printVulnRecord(&out, rootedRecord(), classifyAs(vuldomain.RouteRoot{
		Kind:   vuldomain.RootTest,
		Reason: "declared in test scope, so this route is not a production one",
		NodeID: "example.com/app/handlers.(*Server).ServeHTTP",
	}))

	heading := findLineWith(t, out.String(), "GO-2026-0001")
	if !strings.Contains(heading, "[reachable]") {
		t.Fatalf("heading lost the verdict: %q", heading)
	}
	if !strings.Contains(heading, "root: test") {
		t.Errorf("heading = %q, want the test-scope root on the same line as the verdict", heading)
	}
	if !strings.Contains(heading, "not a production one") {
		t.Errorf("heading = %q, want the consequence spelled out, not the bare kind", heading)
	}
}

// TestVulnShowPrintsTheRootEvidenceUnderTheRoute checks the other half of the
// contract: the kind is on the heading, the evidence is under the route it
// describes. A kind with no reason is a label, and a label is what turns a
// measurement into a verdict.
func TestVulnShowPrintsTheRootEvidenceUnderTheRoute(t *testing.T) {
	var out bytes.Buffer
	printVulnRecord(&out, rootedRecord(), classifyAs(vuldomain.RouteRoot{
		Kind:   vuldomain.RootInternal,
		Reason: "called from within the analysed module (3 callers), so the route begins where the analyser stopped",
		NodeID: "example.com/app/handlers.(*Server).ServeHTTP",
		Remedy: "kanonarion callers 'example.com/app/handlers.(*Server).ServeHTTP'",
	}))

	got := out.String()
	for _, want := range []string{
		"root:     internal —",
		"3 callers",
		"node:   example.com/app/handlers.(*Server).ServeHTTP",
		"next:   kanonarion callers",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

// TestVulnShowSaysNothingWhenNothingClassified holds the line the package-level
// work drew: an unclassified root prints no line at all, because "unrooted" is a
// measurement and the absence of one must not be rendered as one.
func TestVulnShowSaysNothingWhenNothingClassified(t *testing.T) {
	var out bytes.Buffer
	printVulnRecord(&out, rootedRecord(), classifyAs(vuldomain.RouteRoot{}))
	if strings.Contains(out.String(), "root:") {
		t.Errorf("an unclassified root printed a root line:\n%s", out.String())
	}
	if strings.Contains(out.String(), "not classified") {
		t.Errorf("the uncomputed case leaked into the report:\n%s", out.String())
	}
}

// TestReachabilityVerdictCarriesTheRoot checks the curated JSON shape: every
// route carries its own classification, and the reply repeats the first one so a
// consumer asking "is this a test-only reach" need not index into the list.
func TestReachabilityVerdictCarriesTheRoot(t *testing.T) {
	rec := rootedRecord()
	res, err := vulnReachabilityVerdict(rec.Coordinate, rec, true, "GO-2026-0001",
		classifyAs(vuldomain.RouteRoot{
			Kind:          vuldomain.RootIngress,
			Reason:        "an http.Handler implementation",
			ClosureRooted: true,
			Remedy:        "kanonarion vuln-scan --project --reachability",
		}))
	if err != nil {
		t.Fatalf("vulnReachabilityVerdict: %v", err)
	}
	if res.Verdict != verdictReachable {
		t.Fatalf("Verdict = %q, want the classification to qualify the verdict, never replace it", res.Verdict)
	}
	if res.RouteRoot == nil || res.RouteRoot.Kind != "ingress" {
		t.Fatalf("RouteRoot = %+v, want the first route's ingress classification", res.RouteRoot)
	}
	if len(res.Routes) != 1 || res.Routes[0].Root == nil {
		t.Fatalf("routes did not carry their own root: %+v", res.Routes)
	}
	if !res.RouteRoot.ClosureRooted {
		t.Error("the closure-rooted caveat was dropped on the way to the JSON shape")
	}

	var out bytes.Buffer
	printVulnReachability(&out, res)
	verdict := findLineWith(t, out.String(), "is REACHABLE")
	if !strings.Contains(verdict, "root: ingress, closure-rooted") {
		t.Errorf("verdict line = %q, want the root kind and its closure-rooted caveat", verdict)
	}
	if !strings.Contains(out.String(), "to go further: kanonarion vuln-scan --project") {
		t.Errorf("the command that would root the analysis at the application was not offered:\n%s", out.String())
	}
}

// TestReachabilityVerdictNeverCallsItExploitable guards the one rule the ticket
// states twice: naming the root kind is a fact, "exploitable" is not, and this
// work does not introduce it.
func TestReachabilityVerdictNeverCallsItExploitable(t *testing.T) {
	rec := rootedRecord()
	res, err := vulnReachabilityVerdict(rec.Coordinate, rec, true, "GO-2026-0001",
		classifyAs(vuldomain.RouteRoot{Kind: vuldomain.RootIngress, Reason: "an http.Handler implementation"}))
	if err != nil {
		t.Fatalf("vulnReachabilityVerdict: %v", err)
	}
	var out bytes.Buffer
	printVulnReachability(&out, res)

	var show bytes.Buffer
	printVulnRecord(&show, rec, classifyAs(vuldomain.RouteRoot{Kind: vuldomain.RootIngress, Reason: "an http.Handler implementation"}))

	for _, rendered := range []string{out.String(), show.String()} {
		for _, forbidden := range []string{"exploit", "attacker", "vulnerable to"} {
			if strings.Contains(strings.ToLower(rendered), forbidden) {
				t.Errorf("root classification rendered %q, which is a judgement this tool does not make:\n%s", forbidden, rendered)
			}
		}
	}
}

// findLineWith returns the single output line containing want.
func findLineWith(t *testing.T, out, want string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, want) {
			return line
		}
	}
	t.Fatalf("no line containing %q in:\n%s", want, out)
	return ""
}
