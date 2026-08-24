package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	coordinatetest "github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	localdomain "github.com/eitanity/kanonarion/internal/local/domain"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// This file pins one rule across every surface that publishes a reachability
// verdict: the verdict travels with the rung that says how thorough the search
// behind it was, in text AND in JSON.
//
// The rung was carried by three of eight surface-format combinations when this
// was written. The one that stung was vuln-show, which printed it to a person
// reading a terminal and withheld it from --json — from the one consumer that
// cannot pick it out of prose.

// rungRecord is a stored record holding one negative, one positive and one
// finding the advisory named no symbols in, so a single fixture exercises every
// rung a read-time derivation can return.
func rungRecord() vuldomain.VulnerabilityRecord {
	derived := vuldomain.ReachabilityDerivation{
		Analyser: vuldomain.AnalyserGovulncheck,
		Fidelity: "source",
	}
	return vuldomain.VulnerabilityRecord{
		Ecosystem:      "Go",
		Coordinate:     coordinatetest.MustNew("golang.org/x/crypto", "v0.31.0"),
		Rooting:        vuldomain.TargetRootedAt(coordinatetest.MustNew("example.com/app", "local")),
		OverallStatus:  vuldomain.StatusAffected,
		CoverageStatus: vuldomain.CoverageAnalysed,
		FindingsStatus: vuldomain.FindingsRecordAffected,
		Findings: []vuldomain.VulnerabilityFinding{
			{
				ID:              "GO-2025-0001",
				Summary:         "the negative",
				AffectedSymbols: []string{"golang.org/x/crypto/ssh.Handshake"},
				Reachable: &vuldomain.ReachabilityResult{
					IsReachable: false,
					Confidence:  vuldomain.ConfidenceHigh,
					DerivedBy:   derived,
				},
			},
			{
				ID:              "GO-2025-0002",
				Summary:         "the positive",
				AffectedSymbols: []string{"golang.org/x/crypto/ssh.Dial"},
				Reachable: &vuldomain.ReachabilityResult{
					IsReachable: true,
					Confidence:  vuldomain.ConfidenceHigh,
					DerivedBy:   derived,
				},
			},
			{
				ID:                     "GO-2025-0003",
				Summary:                "the unsearchable one",
				AdvisoryNamesNoSymbols: true,
				Reachable: &vuldomain.ReachabilityResult{
					IsReachable: false,
					Confidence:  vuldomain.ConfidenceHigh,
					DerivedBy:   derived,
				},
			},
		},
	}
}

// decodeFindings pulls the finding objects out of an encoded record-shaped
// document, keyed by finding id.
func decodeFindings(t *testing.T, raw []byte) map[string]map[string]any {
	t.Helper()
	var doc struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decoding record document: %v\n%s", err, raw)
	}
	out := map[string]map[string]any{}
	for _, f := range doc.Findings {
		id, _ := f["id"].(string)
		out[id] = f
	}
	return out
}

// TestRecordJSONCarriesTheRung is the ticket's observable on the record-shaped
// surfaces: vuln-show, vuln-show --history and vuln-by-id all encode a stored
// record, and every finding on it must state the rung behind its reachability
// answer.
func TestRecordJSONCarriesTheRung(t *testing.T) {
	raw, err := json.Marshal(toVulnRecordJSON(rungRecord(), nil))
	if err != nil {
		t.Fatalf("marshalling projected record: %v", err)
	}
	findings := decodeFindings(t, raw)
	if len(findings) != 3 {
		t.Fatalf("projected %d finding(s), want 3: %s", len(findings), raw)
	}

	for id, want := range map[string]string{
		"GO-2025-0001": "inferred",
		"GO-2025-0002": "not stated",
		"GO-2025-0003": "unsearchable",
	} {
		f, ok := findings[id]
		if !ok {
			t.Fatalf("finding %s absent from the projection: %s", id, raw)
		}
		got, present := f["soundness"]
		if !present {
			t.Errorf("%s: no soundness key — the negative is published with no statement of what was searched", id)
			continue
		}
		if got != want {
			t.Errorf("%s: soundness = %v, want %q", id, got, want)
		}
	}
	// The reason is what turns the rung from a label into a measurement, and a
	// verdict with no absence to qualify must not invent one.
	if r, _ := findings["GO-2025-0001"]["soundness_reason"].(string); !strings.Contains(r, "govulncheck") {
		t.Errorf("the negative's reason does not name its analyser: %q", r)
	}
	if _, present := findings["GO-2025-0002"]["soundness_reason"]; present {
		t.Error("the positive carries a soundness reason; a route is its own evidence")
	}
}

// derivedRecordKeys are the keys the projection emits that the domain type's own
// marshalling does not. Each is a fact about this build's reading of the record
// rather than about the record, or a stored field the wire states unconditionally
// where the seal must omit it.
//
// The list is explicit so that adding a key is a decision. Anything not named
// here still fails the check below, which is the invention this guard exists to
// catch.
var derivedRecordKeys = map[string]struct{}{
	// True when the record was written under a pipeline version this build no
	// longer serves. It reaches the wire only through --history and vuln-by-id,
	// the two reads that span generations, and it is emitted false elsewhere so
	// a consumer can tell "current" from "not derived".
	"superseded": {},
	// A stored field, omitempty in the seal so records that predate it keep their
	// hash, and emitted on every record here: absent would be indistinguishable
	// from a producer that does not state it, and "not recorded" is the answer.
	"toolchain": {},
}

// TestRecordJSONKeepsEveryDomainField guards the projection against the failure
// its shape exists to prevent: a hand-copied field list would go silently short
// the first time the domain record grew a field, and the surface would lose it
// with nothing said.
func TestRecordJSONKeepsEveryDomainField(t *testing.T) {
	rec := rungRecord()
	bare, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshalling bare record: %v", err)
	}
	projected, err := json.Marshal(toVulnRecordJSON(rec, nil))
	if err != nil {
		t.Fatalf("marshalling projected record: %v", err)
	}

	var bareDoc, projDoc map[string]any
	if err := json.Unmarshal(bare, &bareDoc); err != nil {
		t.Fatalf("decoding bare record: %v", err)
	}
	if err := json.Unmarshal(projected, &projDoc); err != nil {
		t.Fatalf("decoding projected record: %v", err)
	}
	for k := range bareDoc {
		if _, ok := projDoc[k]; !ok {
			t.Errorf("projection dropped record key %q", k)
		}
	}
	for k := range projDoc {
		if _, ok := bareDoc[k]; ok {
			continue
		}
		if _, derived := derivedRecordKeys[k]; derived {
			continue
		}
		t.Errorf("projection invented record key %q", k)
	}

	// Only the findings are re-rendered; every other value must be byte-identical
	// to what the domain type emits, the content hash above all.
	if bareDoc["content_hash"] != projDoc["content_hash"] {
		t.Error("the projection changed the record's content hash")
	}
	bareFindings := decodeFindings(t, bare)
	for id, bf := range bareFindings {
		pf := decodeFindings(t, projected)[id]
		for k, v := range bf {
			if !jsonEqual(pf[k], v) {
				t.Errorf("finding %s: key %q changed from %v to %v", id, k, v, pf[k])
			}
		}
	}
}

func jsonEqual(a, b any) bool {
	ra, err1 := json.Marshal(a)
	rb, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(ra) == string(rb)
}

// TestScanShowFindingsCarryTheRung pins the surface whose TEXT form publishes no
// verdict at all, which makes --json the only place a consumer reads one.
func TestScanShowFindingsCarryTheRung(t *testing.T) {
	mod := scanAffectedModule{
		Coordinate: "golang.org/x/crypto@v0.31.0",
		Status:     string(vuldomain.StatusAffected),
		Findings:   toVulnFindingsJSON(rungRecord().Findings, nil),
	}
	raw, err := json.Marshal(mod)
	if err != nil {
		t.Fatalf("marshalling scan module: %v", err)
	}
	if !strings.Contains(string(raw), `"soundness":"inferred"`) {
		t.Errorf("a scan run's negative is published with no rung: %s", raw)
	}
}

// TestScanDiffCarriesTheRung pins the transition surface. The change an operator
// acts on is the one INTO a negative, and a bare "not reachable" there reads as
// a resolution.
func TestScanDiffCarriesTheRung(t *testing.T) {
	rec := rungRecord()
	diff := vuldomain.ScanRunDiff{
		ReachabilityChanges: []vuldomain.ReachabilityChange{{
			Coordinate:   rec.Coordinate,
			Finding:      rec.Findings[0],
			WasReachable: true,
			IsReachable:  false,
		}},
		NewFindings: []vuldomain.FindingDelta{{Coordinate: rec.Coordinate, Finding: rec.Findings[0]}},
	}
	raw, err := json.Marshal(toScanDiffJSON(diff))
	if err != nil {
		t.Fatalf("marshalling scan diff: %v", err)
	}
	if n := strings.Count(string(raw), `"soundness":"inferred"`); n != 2 {
		t.Errorf("scan diff carried the rung on %d finding(s), want 2: %s", n, raw)
	}
}

// TestStoredQueryAlwaysStatesTheRung pins the omitempty decision. The zero rung
// is the empty string, so omitting the key made "this answer has no absence to
// qualify" and "this producer never derived a rung" the same bytes — the very
// distinction the ladder exists to make visible.
func TestStoredQueryAlwaysStatesTheRung(t *testing.T) {
	rec := rungRecord()
	res, err := vulnReachabilityVerdict(rec.Coordinate, rec, true, "GO-2025-0002", unclassifiedRoutes, nil)
	if err != nil {
		t.Fatalf("vulnReachabilityVerdict: %v", err)
	}
	if res.Verdict != verdictReachable {
		t.Fatalf("verdict = %q, want the positive under test", res.Verdict)
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshalling reachability query: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decoding reachability query: %v", err)
	}
	if doc["soundness"] != "not stated" {
		t.Errorf("positive verdict serialised soundness as %v, want the named zero value", doc["soundness"])
	}
}

// localProbeResult is a probe answer holding one measured negative, one carried
// negative and one positive.
func localProbeResult() localdomain.LocalReachabilityResult {
	return localdomain.LocalReachabilityResult{
		Root:       "/tmp/tree",
		ModulePath: "example.com/app",
		VersionID:  "local-abc",
		ProbeKind:  localdomain.ProbeKindBinary,
		Modules: []localdomain.ModuleProbeResult{{
			Path:    "golang.org/x/crypto",
			Version: "v0.31.0",
			Findings: []localdomain.SymbolProbeFinding{
				{
					CVEID:           "GO-2025-0001",
					Summary:         "measured absent",
					Verdict:         localdomain.SymbolProbeAbsent,
					VerdictSource:   localdomain.VerdictSourceSymbolTable,
					Soundness:       localdomain.ProbeSoundnessUnconfirmed,
					SoundnessReason: localdomain.ProbeAbsentReason,
				},
				{
					CVEID:           "GO-2025-0002",
					Summary:         "carried from a stored scan",
					Verdict:         localdomain.SymbolProbeUnreachable,
					VerdictSource:   localdomain.VerdictSourceGovulncheck,
					Soundness:       string(vuldomain.SoundnessInferred),
					SoundnessReason: "govulncheck analysed this build from source",
				},
				{
					CVEID:          "GO-2025-0003",
					Summary:        "present",
					Verdict:        localdomain.SymbolProbePresent,
					VerdictSource:  localdomain.VerdictSourceSymbolTable,
					MatchedSymbols: []string{"golang.org/x/crypto/ssh.Dial"},
				},
			},
		}},
	}
}

// TestLocalProbeJSONCarriesTheRung pins the local probe's JSON: the two kinds of
// negative it publishes each state the rung their own instrument earns, and the
// positive states the named zero rather than nothing.
func TestLocalProbeJSONCarriesTheRung(t *testing.T) {
	var buf bytes.Buffer
	if err := renderLocalReachability(&buf, reachabilityResultToOutput(localProbeResult()), true); err != nil {
		t.Fatalf("rendering local probe as JSON: %v", err)
	}
	var doc struct {
		Modules []struct {
			Findings []map[string]any `json:"findings"`
		} `json:"modules"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decoding local probe: %v\n%s", err, buf.String())
	}
	got := map[string]any{}
	for _, f := range doc.Modules[0].Findings {
		id, _ := f["cve_id"].(string)
		got[id] = f["soundness"]
	}
	for id, want := range map[string]string{
		"GO-2025-0001": "unconfirmed",
		"GO-2025-0002": "inferred",
		"GO-2025-0003": "not stated",
	} {
		if got[id] != want {
			t.Errorf("%s: soundness = %v, want %q", id, got[id], want)
		}
	}
}

// TestLocalProbeRendersTextWithoutJSONFlag pins the format choice. Without
// --json this path wrote a JSON document, so the caller who followed the
// command's own documented example got machine output where every sibling
// invocation prints prose — and the rung had nowhere to be read.
func TestLocalProbeRendersTextWithoutJSONFlag(t *testing.T) {
	var buf bytes.Buffer
	if err := renderLocalReachability(&buf, reachabilityResultToOutput(localProbeResult()), false); err != nil {
		t.Fatalf("rendering local probe as text: %v", err)
	}
	out := buf.String()
	var any any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &any); err == nil {
		t.Fatalf("the local probe emitted JSON with no --json:\n%s", out)
	}
	if !strings.Contains(out, "GO-2025-0001") || !strings.Contains(out, "absent — unconfirmed") {
		t.Errorf("the measured negative's verdict line does not carry its rung:\n%s", out)
	}
	if !strings.Contains(out, localdomain.ProbeAbsentReason) {
		t.Errorf("the basis behind the rung was not printed:\n%s", out)
	}
	if !strings.Contains(out, "unreachable — inferred") {
		t.Errorf("the carried negative's verdict line does not carry its rung:\n%s", out)
	}
	// The positive states no rung: a route is its own evidence, and a "not
	// stated" line beside one would be noise.
	if strings.Contains(out, "present — ") {
		t.Errorf("a positive verdict was qualified with a rung:\n%s", out)
	}
}

// TestContextFindingsCarryTheRung pins the context report, which publishes the
// reachability boolean on both its surfaces and stated nothing about the search
// behind a false.
func TestContextFindingsCarryTheRung(t *testing.T) {
	rec := rungRecord()
	got := vulnRecordToContext(&rec, "", "")
	byID := map[string]contextCVE{}
	for _, c := range got.Findings {
		byID[c.ID] = c
	}
	if byID["GO-2025-0001"].Soundness != vuldomain.SoundnessInferred {
		t.Errorf("context negative soundness = %q, want inferred", byID["GO-2025-0001"].Soundness)
	}
	if byID["GO-2025-0002"].Soundness != vuldomain.SoundnessNotStated {
		t.Errorf("context positive soundness = %q, want the zero rung", byID["GO-2025-0002"].Soundness)
	}

	raw, err := json.Marshal(byID["GO-2025-0001"])
	if err != nil {
		t.Fatalf("marshalling context finding: %v", err)
	}
	if !strings.Contains(string(raw), `"soundness":"inferred"`) {
		t.Errorf("context JSON published a negative with no rung: %s", raw)
	}

	var buf bytes.Buffer
	w := &errWriter{w: &buf}
	printFullCVE(w, byID["GO-2025-0001"])
	if !strings.Contains(buf.String(), "Soundness: inferred") {
		t.Errorf("context text published a negative with no rung:\n%s", buf.String())
	}
}
