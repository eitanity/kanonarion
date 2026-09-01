package domain_test

import (
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// disagreeingPair returns two records for one coordinate that reached different
// verdicts under different toolchains — the disagreement no composition path may
// resolve by picking one.
func disagreeingPair(t *testing.T, rooting domain.Rooting) (older, newer domain.VulnerabilityRecord) {
	t.Helper()
	older = sampleRecord(t)
	older.Toolchain = "go1.26.5"
	older.ContentHash = "sha256:aaa"
	older.Rooting = rooting

	newer = sampleRecord(t)
	newer.Toolchain = "go1.26.6"
	newer.ContentHash = "sha256:bbb"
	newer.Rooting = rooting
	newer.OverallStatus = domain.StatusAffected
	newer.FindingsStatus = domain.FindingsRecordAffected
	// A reachability answer on the finding: the verdict a toolchain reached
	// includes whether the symbol was reached, so the comparison has to read it.
	newer.Findings = []domain.VulnerabilityFinding{{
		ID: "GO-2026-0001", FixedIn: "v1.2.3",
		Reachable: &domain.ReachabilityResult{IsReachable: true, Confidence: domain.ConfidenceHigh},
	}}
	return older, newer
}

// TestComposeAt_RefusesTwoToolchainsWithinTheSelectedFrame. The frame is chosen
// first and the toolchain checked inside it, so a conflict is a conflict about
// ONE question. Every composition entry point owes the same refusal — a caller
// that reached the ledger by a different door must not be handed a verdict the
// front door refuses.
func TestComposeAt_RefusesTwoToolchainsWithinTheSelectedFrame(t *testing.T) {
	t.Parallel()
	older, newer := disagreeingPair(t, domain.RootingIsolated)

	_, ok, err := domain.ComposeAt([]domain.VulnerabilityRecord{older, newer}, domain.RootingIsolated)

	assertToolchainConflict(t, ok, err)
}

// TestComposeForConsumer_RefusesTwoToolchains covers both of its checks: the
// consumer frame when one exists, and the whole group when the ledger holds no
// consumer-rooted record and the question falls back to a plain ranking.
func TestComposeForConsumer_RefusesTwoToolchains(t *testing.T) {
	t.Parallel()
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")

	t.Run("within the consumer frame", func(t *testing.T) {
		t.Parallel()
		older, newer := disagreeingPair(t, domain.TargetRootedAt(coordinatetest.MustNew("example.com/app", "v1.0.0")))

		_, _, ok, err := domain.ComposeForConsumer([]domain.VulnerabilityRecord{older, newer}, coord)

		assertToolchainConflict(t, ok, err)
	})

	t.Run("with no consumer frame to select", func(t *testing.T) {
		t.Parallel()
		older, newer := disagreeingPair(t, domain.RootingIsolated)

		_, _, ok, err := domain.ComposeForConsumer([]domain.VulnerabilityRecord{older, newer}, coord)

		assertToolchainConflict(t, ok, err)
	})
}

// TestComposeForTree_RefusesTwoToolchains covers the tree probe's two doors: a
// group that states a frame, and the pre-frame fallback where no record states
// one at all.
func TestComposeForTree_RefusesTwoToolchains(t *testing.T) {
	t.Parallel()
	t.Run("within a stated frame", func(t *testing.T) {
		t.Parallel()
		older, newer := disagreeingPair(t, domain.RootingIsolated)

		_, ok, err := domain.ComposeForTree([]domain.VulnerabilityRecord{older, newer}, "example.com/tree")

		assertToolchainConflict(t, ok, err)
	})

	t.Run("with no record stating a frame at all", func(t *testing.T) {
		t.Parallel()
		older, newer := disagreeingPair(t, domain.RootingUnrecorded)

		_, ok, err := domain.ComposeForTree([]domain.VulnerabilityRecord{older, newer}, "example.com/tree")

		assertToolchainConflict(t, ok, err)
	})
}

// assertToolchainConflict holds the shape every one of those doors must produce:
// the refusal itself, naming both toolchains, and no record served alongside it.
func assertToolchainConflict(t *testing.T, ok bool, err error) {
	t.Helper()
	var conflict domain.ToolchainConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("composition returned (%t, %v), want a ToolchainConflict", ok, err)
	}
	if ok {
		t.Error("a record was served alongside the refusal")
	}
	if len(conflict.Values) != 2 || conflict.Values[0] != "go1.26.5" || conflict.Values[1] != "go1.26.6" {
		t.Errorf("conflict values = %v, want both toolchains named", conflict.Values)
	}
}

// TestToolchainConflict_ComparesTheVerdictAndNotTheLabel is the measured half of
// this dimension: two toolchains that reached the SAME answer disagree about
// nothing, and refusing on the label alone would refuse reads this dimension has
// nothing to say about. The findings are part of the verdict, so two records
// agreeing on every axis but naming different advisories still conflict.
func TestToolchainConflict_ComparesTheVerdictAndNotTheLabel(t *testing.T) {
	t.Parallel()
	same := sampleRecord(t)
	same.Toolchain = "go1.26.5"
	same.Findings = []domain.VulnerabilityFinding{{ID: "GO-2026-0001", FixedIn: "v1.2.3"}}
	other := same
	other.Toolchain = "go1.26.6"
	other.ContentHash = "sha256:bbb"

	if _, err := domain.Compose([]domain.VulnerabilityRecord{same, other}); err != nil {
		t.Fatalf("two toolchains that reached the same verdict were refused: %v", err)
	}

	differing := other
	differing.Findings = []domain.VulnerabilityFinding{{ID: "GO-2026-0002", FixedIn: "v1.2.3"}}
	if _, err := domain.Compose([]domain.VulnerabilityRecord{same, differing}); err == nil {
		t.Error("two toolchains naming different advisories were composed; the findings are the verdict")
	}
}
