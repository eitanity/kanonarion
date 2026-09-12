package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// searchedNegativeRecord is a negative that govulncheck stamped from its own
// silence, with a read-time call-graph search attached to it — the shape every
// read surface now hands to the renderer.
func searchedNegativeRecord(search *vuldomain.NegativeSearch) vuldomain.VulnerabilityRecord {
	return scannedRecord(vuldomain.StatusAffected, vuldomain.VulnerabilityFinding{
		ID:              "GO-2021-0113",
		AffectedSymbols: []string{"Parse"},
		Reachable: &vuldomain.ReachabilityResult{
			IsReachable: false,
			Confidence:  vuldomain.ConfidenceHigh,
			DerivedBy: vuldomain.ReachabilityDerivation{
				Analyser: vuldomain.AnalyserGovulncheck,
				Fidelity: string(vuldomain.ScanModeSource),
				Rooting:  vuldomain.RootingIsolated,
			},
		},
		NegativeSearch: search,
	})
}

// decodeAnswer renders the reply through the encoder the command uses, so the
// assertions below are made on the bytes a consumer receives rather than on the
// struct behind them.
func decodeAnswer(t *testing.T, res vulnReachabilityQuery) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		t.Fatalf("encoding: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	return doc
}

// TestReachabilityJSON_ConfirmedNegativeCarriesItsRooting is the acceptance on
// the surface an agent reads. A soundness claim is meaningless without the root
// set it was made against, so the rung, the rooting and the artefact kind that
// decided the rooting travel on one payload.
func TestReachabilityJSON_ConfirmedNegativeCarriesItsRooting(t *testing.T) {
	rec := searchedNegativeRecord(&vuldomain.NegativeSearch{
		Fidelity:        "BUILT_WITH_BODIES",
		EntryPointRoots: 4,
		ArtifactKind:    "Application",
	})

	res, err := vulnReachabilityVerdict(reachCoord, rec, true, "GO-2021-0113", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	doc := decodeAnswer(t, res)

	if got := doc["soundness"]; got != string(vuldomain.SoundnessConfirmed) {
		t.Errorf("soundness = %v, want %q", got, vuldomain.SoundnessConfirmed)
	}
	search, ok := doc["negative_search"].(map[string]any)
	if !ok {
		t.Fatalf("the search that produced the rung is not on the payload: %v", doc)
	}
	if got := search["artifact_kind"]; got != "Application" {
		t.Errorf("artifact_kind = %v, want Application — a reader cannot see which rooting produced the answer", got)
	}
	if got := search["entry_point_roots"]; got != float64(4) {
		t.Errorf("entry_point_roots = %v, want 4", got)
	}
	if got := search["entry_point_path_found"]; got != false {
		t.Errorf("entry_point_path_found = %v, want false", got)
	}
	if _, present := search["whole_graph_path_found"]; !present {
		t.Error("whole_graph_path_found is absent, so the two claims cannot be told apart")
	}
	reason, _ := doc["soundness_reason"].(string)
	if !strings.Contains(reason, "entry point") {
		t.Errorf("soundness_reason does not name the root set: %q", reason)
	}
}

// TestReachabilityJSON_SoundnessIsNeverAbsentAndNeverCollapsed pins the rest of
// the acceptance: inferred, unsearchable and confirmed are three different
// answers and none of them is "not affected". A consumer that cannot tell them
// apart has been handed a verdict instead of evidence.
func TestReachabilityJSON_SoundnessIsNeverAbsentAndNeverCollapsed(t *testing.T) {
	confirmed := searchedNegativeRecord(&vuldomain.NegativeSearch{
		Fidelity: "BUILT_WITH_BODIES", EntryPointRoots: 4, ArtifactKind: "Library"})
	inferred := searchedNegativeRecord(nil)
	unsearchable := scannedRecord(vuldomain.StatusAffected, vuldomain.VulnerabilityFinding{
		ID:                     "GO-2021-0113",
		AdvisoryNamesNoSymbols: true,
		Reachable: &vuldomain.ReachabilityResult{IsReachable: false, DerivedBy: vuldomain.ReachabilityDerivation{
			Analyser: vuldomain.AnalyserGovulncheck, Fidelity: string(vuldomain.ScanModeSource)}},
	})

	seen := map[string]string{}
	for name, rec := range map[string]vuldomain.VulnerabilityRecord{
		"confirmed": confirmed, "inferred": inferred, "unsearchable": unsearchable,
	} {
		res, err := vulnReachabilityVerdict(reachCoord, rec, true, "GO-2021-0113", nil, nil)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}
		doc := decodeAnswer(t, res)
		got, present := doc["soundness"]
		if !present {
			t.Fatalf("%s: soundness is absent from the payload", name)
		}
		rung, _ := got.(string)
		if rung == "" {
			t.Errorf("%s: soundness is empty, which reads as a positive verdict", name)
		}
		if doc["reachability_state"] == verdictNotAffected {
			t.Errorf("%s: a negative was collapsed into not-affected", name)
		}
		if prev, clash := seen[rung]; clash {
			t.Errorf("%s and %s both publish soundness %q", name, prev, rung)
		}
		seen[rung] = name
	}
	if len(seen) != 3 {
		t.Errorf("three different negatives produced %d distinct rungs: %v", len(seen), seen)
	}
}

// TestReachabilityRefusalJSON_IsNotEmptyStdout pins the measured defect: a
// --json run with no stored verdict printed nothing at all on stdout, so a
// consumer could not tell a refusal from a crash.
func TestReachabilityRefusalJSON_IsNotEmptyStdout(t *testing.T) {
	var buf bytes.Buffer
	refusal := errors.New("no vulnerability record for golang.org/x/text@v0.3.7: the module has not been vuln-scanned. run: kanonarion vuln-scan")

	if err := writeReachabilityRefusalJSON(&buf, "golang.org/x/text@v0.3.7", "GO-2021-0113", refusal); err != nil {
		t.Fatalf("writing refusal: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("stdout is empty while the run had something to say")
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("the refusal is not JSON: %v\n%s", err, buf.String())
	}
	if doc["answered"] != false {
		t.Errorf("answered = %v, want false", doc["answered"])
	}
	if _, present := doc["reachability_state"]; present {
		t.Error("a refusal published a verdict; an absent answer is not 'not affected'")
	}
	if got, _ := doc["refusal"].(string); !strings.Contains(got, "vuln-scan") {
		t.Errorf("the refusal dropped the remedy the text surface names: %q", got)
	}
	if doc["module"] != "golang.org/x/text" || doc["version"] != "v0.3.7" {
		t.Errorf("the refusal does not name the coordinate asked about: %v", doc)
	}
}

// TestReachabilityJSON_ASkippedSearchSaysSoOnTheWire is the never-silent rule at
// the JSON surface. Measured on a working store before this: the one coordinate
// holding both a searchable negative and a call graph published `soundness:
// inferred` with NO `negative_search` key at all, so a consumer could not tell a
// search that was skipped from one that was never owed, and nothing named a
// remedy.
func TestReachabilityJSON_ASkippedSearchSaysSoOnTheWire(t *testing.T) {
	rec := searchedNegativeRecord(&vuldomain.NegativeSearch{
		NotSearched: "the store holds no call graph for golang.org/x/text@v0.3.7, so there was no graph to search; extract one with: kanonarion callgraph golang.org/x/text@v0.3.7",
	})

	res, err := vulnReachabilityVerdict(reachCoord, rec, true, "GO-2021-0113", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	doc := decodeAnswer(t, res)

	// The rung is unchanged — a search that did not run concludes nothing.
	if got := doc["soundness"]; got != string(vuldomain.SoundnessInferred) {
		t.Errorf("soundness = %v, want %q", got, vuldomain.SoundnessInferred)
	}
	search, ok := doc["negative_search"].(map[string]any)
	if !ok {
		t.Fatalf("a skipped search published no key at all, which is the silence this closes: %v", doc)
	}
	got, _ := search["not_searched"].(string)
	if got == "" {
		t.Error("not_searched is absent, so the skip is invisible to a machine reader")
	}
	if !strings.Contains(got, "kanonarion callgraph") {
		t.Errorf("the skip names no remedy: %q", got)
	}
	if search["entry_point_path_found"] != false || search["whole_graph_path_found"] != false {
		t.Error("a skipped search published a path claim it never measured")
	}
	if reason, _ := doc["soundness_reason"].(string); !strings.Contains(reason, got) {
		t.Errorf("the text-facing reason does not carry the skip: %q", reason)
	}
}
