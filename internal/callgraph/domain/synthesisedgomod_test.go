package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// TestSynthesisedGoMod_ZeroValueIsHashTransparent is the claim that lets this
// field land without a schema bump or a purge: a record that synthesised
// nothing marshals to exactly the bytes it did before the field existed, so
// every stored record keeps its content hash verifiable.
func TestSynthesisedGoMod_ZeroValueIsHashTransparent(t *testing.T) {
	t.Parallel()

	var h domain.CallGraphRecordHasher
	sealed, err := h.SetContentHash(makeTestRecord())
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	got, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(got), "synthesised_go_mod") {
		t.Errorf("a record that synthesised nothing emits the field:\n%s", got)
	}
}

// TestSynthesisedGoMod_IsSealed checks the other half. The field describes bytes
// the analysis read that the artefact does not contain, so a record must not be
// able to acquire or lose it while keeping a verifying hash.
func TestSynthesisedGoMod_IsSealed(t *testing.T) {
	t.Parallel()

	var h domain.CallGraphRecordHasher
	plain, err := h.SetContentHash(makeTestRecord())
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	synthesised := makeTestRecord()
	synthesised.SynthesisedGoMod = domain.SynthesisedGoMod{
		ModulePath:  "example.com/mod",
		GoDirective: "1.16",
	}
	sealed, err := h.SetContentHash(synthesised)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if sealed.ContentHash == plain.ContentHash {
		t.Error("a synthesised-go.mod record hashes the same as one analysed as published")
	}

	// The directive decides the language semantics the graph was built under, so
	// two graphs built under different ones are not the same claim.
	other := synthesised
	other.SynthesisedGoMod.GoDirective = "1.22"
	otherSealed, err := h.SetContentHash(other)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if otherSealed.ContentHash == sealed.ContentHash {
		t.Error("the go directive is outside the seal: two graphs built under different language semantics hash alike")
	}
}

// TestSynthesisedGoMod_SurvivesRoundTrip guards the read path: a record decoded
// from the store must still say that its tree was not the published tree.
func TestSynthesisedGoMod_SurvivesRoundTrip(t *testing.T) {
	t.Parallel()

	rec := makeTestRecord()
	rec.SynthesisedGoMod = domain.SynthesisedGoMod{
		ModulePath:        "example.com/mod",
		GoDirective:       "1.16",
		VendorTreePresent: true,
	}

	var h domain.CallGraphRecordHasher
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
	if back.SynthesisedGoMod != rec.SynthesisedGoMod {
		t.Errorf("round trip = %+v, want %+v", back.SynthesisedGoMod, rec.SynthesisedGoMod)
	}
	if err := h.VerifyContentHash(back); err != nil {
		t.Errorf("decoded record does not verify: %v", err)
	}
}

// TestSynthesisedGoMod_StringNamesTheInventedFile covers the human-readable
// rendering the provenance output appends. An empty string for the zero value is
// what lets a caller append it unconditionally.
func TestSynthesisedGoMod_StringNamesTheInventedFile(t *testing.T) {
	t.Parallel()

	if got := (domain.SynthesisedGoMod{}).String(); got != "" {
		t.Errorf("zero value renders %q, want the empty string", got)
	}
	got := domain.SynthesisedGoMod{ModulePath: "example.com/mod", GoDirective: "1.16"}.String()
	for _, want := range []string{"synthesised", "example.com/mod", "1.16"} {
		if !strings.Contains(got, want) {
			t.Errorf("rendering %q does not mention %q", got, want)
		}
	}
	vendored := domain.SynthesisedGoMod{ModulePath: "example.com/mod", GoDirective: "1.16", VendorTreePresent: true}.String()
	if !strings.Contains(vendored, "vendor") {
		t.Errorf("rendering %q does not mention the vendor tree", vendored)
	}
}
