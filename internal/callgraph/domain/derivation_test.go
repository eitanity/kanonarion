package domain_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// TestDerivationFor_SeparatesAForcedRunFromAGatedOne is the whole point of the
// field: a --force re-measurement and a reuse gate that held nothing leave rows
// that are otherwise identical.
func TestDerivationFor_SeparatesAForcedRunFromAGatedOne(t *testing.T) {
	t.Parallel()

	gated := domain.DerivationFor(domain.ReuseGateWorktree, false)
	forced := domain.DerivationFor(domain.ReuseGateWorktree, true)

	if gated.Outcome != domain.GateOutcomeConsulted {
		t.Errorf("gated outcome = %q, want %q", gated.Outcome, domain.GateOutcomeConsulted)
	}
	if forced.Outcome != domain.GateOutcomeBypassed {
		t.Errorf("forced outcome = %q, want %q", forced.Outcome, domain.GateOutcomeBypassed)
	}
	if gated == forced {
		t.Fatal("a forced run and a gated one derive alike; the field records nothing")
	}
	if !gated.IsRecorded() || !forced.IsRecorded() {
		t.Error("a stated derivation reports itself unrecorded")
	}
	if (domain.GenerationDerivation{}).IsRecorded() {
		t.Error("an absent derivation reports itself recorded")
	}
	if got := (domain.GenerationDerivation{}).String(); got != "derivation not recorded" {
		t.Errorf("absent derivation renders %q", got)
	}
}

// TestGenerationDerivation_StringNamesGateAndOutcome: the history view prints
// this string, so it must name which gate answered and what it did.
func TestGenerationDerivation_StringNamesGateAndOutcome(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		d    domain.GenerationDerivation
		want string
	}{
		{"worktree forced", domain.DerivationFor(domain.ReuseGateWorktree, true),
			"worktree reuse gate bypassed (--force)"},
		{"ledger gated", domain.DerivationFor(domain.ReuseGateLedger, false),
			"ledger reuse gate consulted, held nothing restating this analysis"},
		{"gate unnamed", domain.GenerationDerivation{Outcome: domain.GateOutcomeBypassed},
			"unnamed reuse gate bypassed (--force)"},
		{"outcome unnamed", domain.GenerationDerivation{Gate: domain.ReuseGateLedger},
			"ledger reuse gate, outcome not recorded"},
		{"outcome from a later version", domain.GenerationDerivation{Gate: domain.ReuseGateLedger, Outcome: "invented"},
			"ledger reuse gate: invented"},
	}
	for _, tc := range cases {
		if got := tc.d.String(); got != tc.want {
			t.Errorf("%s: String() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestRecordDerivation_IsAbsentFromTheSealWhenUnrecorded: a record that states
// no derivation must marshal to bytes carrying no derived_by key at all, which
// is what keeps every generation sealed before the field verifiable.
func TestRecordDerivation_IsAbsentFromTheSealWhenUnrecorded(t *testing.T) {
	t.Parallel()

	var h domain.CallGraphRecordHasher
	data, err := h.Marshal(makeTestRecord())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("decode canonical bytes: %v", err)
	}
	if _, stated := fields["derived_by"]; stated {
		t.Error("a record stating no derivation seals a derived_by key; every stored record's hash breaks")
	}
}

// TestPreFieldRecord_StillVerifies reads the pinned canonical bytes of a record
// sealed before the derivation existed and checks today's code reproduces its
// stored hash. It is the unit-level half of the transparency proof; the other
// half is run against the live store.
func TestPreFieldRecord_StillVerifies(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/canonical_shape.json")
	if err != nil {
		t.Fatalf("reading pinned canonical bytes: %v", err)
	}
	var h domain.CallGraphRecordHasher
	rec, err := h.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if rec.DerivedBy.IsRecorded() {
		t.Errorf("a pre-field record decoded a derivation: %v", rec.DerivedBy)
	}
	if err := h.VerifyContentHash(rec); err != nil {
		t.Fatalf("a record sealed before the field no longer verifies: %v", err)
	}
	round, err := h.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(round) != string(data) {
		t.Errorf("re-marshalled bytes differ from the sealed ones:\n got %s\nwant %s", round, data)
	}
}

// TestRecordDerivation_RoundTripsThroughTheSeal: the derivation is inside the
// seal, so it survives the canonical encoding and the record still verifies.
func TestRecordDerivation_RoundTripsThroughTheSeal(t *testing.T) {
	t.Parallel()

	var h domain.CallGraphRecordHasher
	rec := makeTestRecord()
	rec.DerivedBy = domain.DerivationFor(domain.ReuseGateLedger, true)
	sealed, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	data, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := h.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.DerivedBy != rec.DerivedBy {
		t.Errorf("derivation round-tripped as %v, want %v", back.DerivedBy, rec.DerivedBy)
	}
	if err := h.VerifyContentHash(back); err != nil {
		t.Errorf("a record carrying a derivation does not verify: %v", err)
	}
	// Inside the seal means an edited derivation breaks the record's own
	// integrity check — the property that makes the answer worth reading.
	tampered := back
	tampered.DerivedBy = domain.DerivationFor(domain.ReuseGateLedger, false)
	if err := h.VerifyContentHash(tampered); err == nil {
		t.Error("editing the derivation left the seal intact")
	}
}

// TestRestatesAnalysis_IgnoresWhyTheGenerationWasAppended: dedup must not see
// the derivation. Two runs of one analysis are one measurement whether one was
// forced, and a generation written before the field must still be recognised as
// restating one that carries it — absence is not a value it can disagree with.
//
// Without the strip in withoutRunCircumstance this fails, and the first run
// after the field lands appends a duplicate of every generation the store holds.
func TestRestatesAnalysis_IgnoresWhyTheGenerationWasAppended(t *testing.T) {
	t.Parallel()

	base := makeTestRecord()
	base.AnalysisSource = domain.AnalysisSourceModuleZip
	base.ArtefactIdentity = "zip:h1:AAAA"

	derivations := map[string]domain.GenerationDerivation{
		"unrecorded":     {},
		"ledger gated":   domain.DerivationFor(domain.ReuseGateLedger, false),
		"ledger forced":  domain.DerivationFor(domain.ReuseGateLedger, true),
		"worktree gated": domain.DerivationFor(domain.ReuseGateWorktree, false),
	}
	for freshName, freshD := range derivations {
		for heldName, heldD := range derivations {
			fresh, held := base, base
			fresh.DerivedBy, held.DerivedBy = freshD, heldD

			same, err := domain.RestatesAnalysis(fresh, held)
			if err != nil {
				t.Fatalf("RestatesAnalysis(%s, %s): %v", freshName, heldName, err)
			}
			if !same {
				t.Errorf("RestatesAnalysis(%s, %s) = false; one analysis became two because of why it was appended", freshName, heldName)
			}
			same, err = domain.SameMeasurement(fresh, held)
			if err != nil {
				t.Fatalf("SameMeasurement(%s, %s): %v", freshName, heldName, err)
			}
			if !same {
				t.Errorf("SameMeasurement(%s, %s) = false", freshName, heldName)
			}
			if a, b := domain.MeasurementDigest(fresh), domain.MeasurementDigest(held); a != b {
				t.Errorf("MeasurementDigest(%s) != MeasurementDigest(%s); the generations group apart", freshName, heldName)
			}
			if a, b := domain.GraphDigest(fresh), domain.GraphDigest(held); a != b {
				t.Errorf("GraphDigest(%s) != GraphDigest(%s); a run's reason read as a disagreement about the graph", freshName, heldName)
			}
		}
	}
}

// TestRestatesAnalysis_StillSeparatesTwoRealMeasurements guards the other
// direction: stripping the derivation must not blunt the comparison.
func TestRestatesAnalysis_StillSeparatesTwoRealMeasurements(t *testing.T) {
	t.Parallel()

	base := makeTestRecord()
	base.AnalysisSource = domain.AnalysisSourceModuleZip
	base.ArtefactIdentity = "zip:h1:AAAA"

	edited := base
	edited.NodeCount = base.NodeCount + 1
	edited.DerivedBy = domain.DerivationFor(domain.ReuseGateLedger, false)

	held := base
	held.DerivedBy = domain.DerivationFor(domain.ReuseGateLedger, true)

	same, err := domain.RestatesAnalysis(edited, held)
	if err != nil {
		t.Fatalf("RestatesAnalysis: %v", err)
	}
	if same {
		t.Error("two different measurements restate each other")
	}
}
