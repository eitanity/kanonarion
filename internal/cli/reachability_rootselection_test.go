package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestReachabilityStatesTheRootingItUsed covers the answer produced over a call
// graph that does not say whether the module builds a command. The roots are the
// library ones, and the reply says so: an unstated fallback reads as a measured
// choice, and the reader has no way to tell the two apart afterwards.
func TestReachabilityStatesTheRootingItUsed(t *testing.T) {
	caveat := cgdomain.RootSelectionCaveat(cgdomain.ArtifactNotEstablished)

	rec := negativeRecord(vuldomain.AnalyserCallGraphBFS, "BUILT_WITH_BODIES")
	rec.Findings[0].Reachable.DerivedBy.RootSelection = caveat

	res, err := vulnReachabilityVerdict(rec.Coordinate, rec, true, "GO-2025-3487", unclassifiedRoutes, nil)
	if err != nil {
		t.Fatalf("vulnReachabilityVerdict: %v", err)
	}
	if res.RootSelection != caveat {
		t.Errorf("RootSelection = %q, want %q", res.RootSelection, caveat)
	}

	var out bytes.Buffer
	printVulnReachability(&out, res)
	got := out.String()
	if !strings.Contains(got, caveat) {
		t.Errorf("the printed answer does not state the rooting it used:\n%s", got)
	}
	t.Logf("text output:\n%s", got)

	b, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var keyed map[string]any
	if err := json.Unmarshal(b, &keyed); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if keyed["root_selection"] != caveat {
		t.Errorf("root_selection = %v, want the caveat", keyed["root_selection"])
	}
	t.Logf("json root_selection: %v", keyed["root_selection"])

	// The control: an established kind states no caveat, so the key is absent and
	// the line is the one it always was.
	plain := negativeRecord(vuldomain.AnalyserCallGraphBFS, "BUILT_WITH_BODIES")
	res, err = vulnReachabilityVerdict(plain.Coordinate, plain, true, "GO-2025-3487", unclassifiedRoutes, nil)
	if err != nil {
		t.Fatalf("vulnReachabilityVerdict (control): %v", err)
	}
	if res.RootSelection != "" {
		t.Errorf("RootSelection = %q on an established kind, want empty", res.RootSelection)
	}
	b, err = json.Marshal(res)
	if err != nil {
		t.Fatalf("Marshal (control): %v", err)
	}
	if strings.Contains(string(b), "root_selection") {
		t.Errorf("the control answer carries a root_selection key: %s", b)
	}
	out.Reset()
	printVulnReachability(&out, res)
	t.Logf("control text output:\n%s", out.String())
}
