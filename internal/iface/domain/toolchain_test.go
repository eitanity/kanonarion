package domain_test

import (
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/iface/domain"
)

// TestToolchain_IsHashTransparentForRecordsThatPredateIt is the falsifying test
// for the field: a record sealed before the toolchain existed must still verify.
// See the call-graph domain's copy for why this is asserted against the seal and
// not only against the golden shape.
func TestToolchain_IsHashTransparentForRecordsThatPredateIt(t *testing.T) {
	t.Parallel()
	var h domain2.InterfaceRecordHasher

	sealed, err := h.SetContentHash(makeTestRecord(t))
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if sealed.Toolchain.Recorded() {
		t.Fatalf("the test record states a toolchain (%q); it must not, or this proves nothing", sealed.Toolchain)
	}
	if verr := h.VerifyContentHash(sealed); verr != nil {
		t.Errorf("a record sealed without a toolchain no longer verifies: %v", verr)
	}

	stated := sealed
	stated.Toolchain = "go1.26.6"
	if verr := h.VerifyContentHash(stated); verr == nil {
		t.Error("adding a toolchain to a sealed record did not break its seal — the field is not hashed")
	}
}

// TestCompose_AttributesAnAPIDifferenceToTheToolchain: the release tags come from
// the toolchain, so a //go:build go1.N file enters or leaves the API with it.
// Where the APIs differ and the toolchains differ, naming the toolchain is better
// evidence than reporting the extractor as non-deterministic.
func TestCompose_AttributesAnAPIDifferenceToTheToolchain(t *testing.T) {
	t.Parallel()
	older := makeTestRecord(t)
	older.ArtefactIdentity = "zip:h1:same"
	older.Toolchain = "go1.26.6"
	older.ContentHash = "sha256:aaa"

	newer := makeTestRecord(t)
	newer.ArtefactIdentity = "zip:h1:same"
	newer.Toolchain = "go1.27.0"
	newer.ContentHash = "sha256:bbb"
	// An exported function that exists only under the newer release tags.
	newer.Packages[0].Funcs = append(newer.Packages[0].Funcs, domain2.FuncDecl{
		Name: "AddedUnderGo127", Signature: "func AddedUnderGo127()",
	})

	_, err := domain2.Compose([]domain2.InterfaceRecord{older, newer})
	conflict, ok := err.(domain2.InterfaceConflict) //nolint:errorlint // the domain returns the value, never a wrapper
	if !ok {
		t.Fatalf("Compose = %v, want an InterfaceConflict", err)
	}
	if conflict.Field != "toolchain" {
		t.Errorf("conflict field = %q, want toolchain", conflict.Field)
	}
	if len(conflict.Values) != 2 {
		t.Errorf("conflict values = %v, want both toolchains named", conflict.Values)
	}
}

// TestCompose_ARecordStatingNoToolchainDoesNotConflict pins the deliberate
// exception. No stored interface record carries any toolchain marker, so there
// is nothing to ladder a pre-field row to — it steps aside rather than reading
// as a second toolchain and refusing every composed read on the store.
func TestCompose_ARecordStatingNoToolchainDoesNotConflict(t *testing.T) {
	t.Parallel()
	silent := makeTestRecord(t)
	silent.ArtefactIdentity = "zip:h1:same"
	silent.ContentHash = "sha256:aaa"

	named := silent
	named.Toolchain = "go1.26.6"
	named.ContentHash = "sha256:bbb"

	if _, err := domain2.Compose([]domain2.InterfaceRecord{silent, named}); err != nil {
		t.Errorf("Compose refused a pre-field record against one that names a toolchain: %v", err)
	}
}

// TestAPIDigest_IgnoresTheToolchain: the toolchain is a dimension composition
// groups on, not something the API claims. Two records with the same API and
// different toolchains must not read as an extractor disagreeing with itself
// wherever the digest is used directly.
func TestAPIDigest_IgnoresTheToolchain(t *testing.T) {
	t.Parallel()
	a := makeTestRecord(t)
	b := a
	b.Toolchain = "go1.27.0"

	if domain2.APIDigest(a) != domain2.APIDigest(b) {
		t.Error("the API digest moved with the toolchain; it describes the API and nothing else")
	}
}

// TestCompose_TwoToolchainsHoldingOneAPIAreNotADisagreement is the other half.
// A patch bump moves no release tag, so two toolchains routinely produce the
// identical API; refusing on the label alone would refuse reads the dimension has
// nothing to say about. Measured on the call-graph ledger, that mistake made 18
// of 30 refusals byte-identical graphs.
func TestCompose_TwoToolchainsHoldingOneAPIAreNotADisagreement(t *testing.T) {
	t.Parallel()
	older := makeTestRecord(t)
	older.ArtefactIdentity = "zip:h1:same"
	older.Toolchain = "go1.26.5"
	older.ContentHash = "sha256:aaa"

	newer := older
	newer.Toolchain = "go1.26.6"
	newer.ContentHash = "sha256:bbb"

	if _, err := domain2.Compose([]domain2.InterfaceRecord{older, newer}); err != nil {
		t.Errorf("two toolchains holding one API refused: %v", err)
	}
}
