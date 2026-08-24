package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestToolchain_IsHashTransparentForRecordsThatPredateIt is the falsifying test
// for the field: a record sealed before the toolchain existed must still verify.
// See the call-graph domain's copy for why this is asserted against the seal and
// not only against the golden shape.
func TestToolchain_IsHashTransparentForRecordsThatPredateIt(t *testing.T) {
	t.Parallel()
	var h domain.VulnerabilityRecordHasher

	sealed, err := h.SetContentHash(sampleRecord(t))
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if sealed.Toolchain.Recorded() {
		t.Fatalf("the sample record states a toolchain (%q); it must not, or this proves nothing", sealed.Toolchain)
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

// TestCompose_RefusesTwoToolchainsThatReachedDifferentVerdicts: which files build
// constraints selected and which symbols the analysis reached are the
// toolchain's, so two toolchains that disagree are two verdicts about two builds
// and neither supersedes the other.
func TestCompose_RefusesTwoToolchainsThatReachedDifferentVerdicts(t *testing.T) {
	t.Parallel()
	older := sampleRecord(t)
	older.Toolchain = "go1.26.5"
	older.ContentHash = "sha256:aaa"

	newer := sampleRecord(t)
	newer.Toolchain = "go1.26.6"
	newer.ContentHash = "sha256:bbb"
	newer.OverallStatus = domain.StatusAffected
	newer.FindingsStatus = domain.FindingsRecordAffected

	_, err := domain.Compose([]domain.VulnerabilityRecord{older, newer})
	conflict, ok := err.(domain.ToolchainConflict) //nolint:errorlint // the domain returns the value, never a wrapper
	if !ok {
		t.Fatalf("Compose = %v, want a ToolchainConflict", err)
	}
	if len(conflict.Values) != 2 || conflict.Values[0] != "go1.26.5" || conflict.Values[1] != "go1.26.6" {
		t.Errorf("conflict values = %v, want both toolchains named", conflict.Values)
	}
	if conflict.Error() == "" {
		t.Error("the refusal renders no message")
	}
}

// TestCompose_TwoToolchainsReachingOneVerdictAreNotADisagreement is the other
// half. Two toolchains that reached the same answer reached the same answer, and
// refusing on the label alone would refuse reads the dimension has nothing to say
// about — the defect measured on the call-graph ledger, where 18 of 30 refusals
// held byte-identical results.
func TestCompose_TwoToolchainsReachingOneVerdictAreNotADisagreement(t *testing.T) {
	t.Parallel()
	older := sampleRecord(t)
	older.Toolchain = "go1.26.5"
	older.ContentHash = "sha256:aaa"
	newer := sampleRecord(t)
	newer.Toolchain = "go1.26.6"
	newer.ContentHash = "sha256:bbb"

	if _, err := domain.Compose([]domain.VulnerabilityRecord{older, newer}); err != nil {
		t.Errorf("two toolchains reaching one verdict refused: %v", err)
	}
}

// TestCompose_OneToolchainStillComposes is the control.
func TestCompose_OneToolchainStillComposes(t *testing.T) {
	t.Parallel()
	a := sampleRecord(t)
	a.Toolchain = "go1.26.6"
	a.ContentHash = "sha256:aaa"
	b := sampleRecord(t)
	b.Toolchain = "go1.26.6"
	b.ContentHash = "sha256:bbb"

	if _, err := domain.Compose([]domain.VulnerabilityRecord{a, b}); err != nil {
		t.Errorf("Compose refused two records from ONE toolchain: %v", err)
	}
}

// TestCompose_ARecordStatingNoToolchainDoesNotConflict pins the deliberate
// exception. No stored vulnerability record carries a toolchain, so there is
// nothing to ladder a pre-field row to and it must step aside rather than read
// as a second toolchain and refuse every composed read on the store.
func TestCompose_ARecordStatingNoToolchainDoesNotConflict(t *testing.T) {
	t.Parallel()
	silent := sampleRecord(t)
	silent.ContentHash = "sha256:aaa"
	named := sampleRecord(t)
	named.Toolchain = "go1.26.6"
	named.ContentHash = "sha256:bbb"

	if _, err := domain.Compose([]domain.VulnerabilityRecord{silent, named}); err != nil {
		t.Errorf("Compose refused a pre-field record against one that names a toolchain: %v", err)
	}
}
