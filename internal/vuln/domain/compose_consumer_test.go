package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// reachableFinding is a finding carrying a computed reachability answer, so a
// test can put a verdict in one frame and none in another.
func reachableFinding(id string, reachable bool) []domain.VulnerabilityFinding {
	return []domain.VulnerabilityFinding{{
		ID:            id,
		Summary:       "summary of " + id,
		AffectedRange: "< v2",
		Reachable:     &domain.ReachabilityResult{IsReachable: reachable, Confidence: domain.ConfidenceHigh},
	}}
}

// The defect this pins, measured on a real store: an isolated scan of
// github.com/golang-jwt/jwt/v4@v4.5.1 recorded BUILT_WITH_BODIES and
// "not reachable" at 17:49; two govulncheck analyses rooted at the consuming
// project recorded the route to the vulnerable symbol at 17:52 and 17:54 and,
// carrying no call-graph completeness of their own, lost the completeness rung
// to the older isolated row. The composed read served the stand-down.
func TestComposeForConsumer_IsolatedVerdictDoesNotOutrankANewerConsumerRecord(t *testing.T) {
	t.Parallel()
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
	consumerRoot := coordinatetest.MustNew("example.com/app", "v0.0.0")

	isolated := composeRecord(t, composeSpec{
		rooting:      domain.RootingIsolated,
		completeness: "BUILT_WITH_BODIES",
		scannedAt:    time.Date(2026, 7, 31, 17, 49, 28, 0, time.UTC),
		findings:     reachableFinding("GO-2025-3553", false),
	})
	consumer := composeRecord(t, composeSpec{
		rooting:   domain.TargetRootedAt(consumerRoot),
		scannedAt: time.Date(2026, 7, 31, 17, 54, 8, 0, time.UTC),
		findings:  reachableFinding("GO-2025-3553", true),
	})

	// Ordered isolated-first so a fix that merely relies on input order fails.
	answer, aside, hasAside, err := domain.ComposeForConsumer([]domain.VulnerabilityRecord{isolated, consumer}, coord)
	if err != nil {
		t.Fatalf("ComposeForConsumer: %v", err)
	}
	if answer.ContentHash != consumer.ContentHash {
		t.Errorf("served the wrong frame: got rooting %s, want %s", answer.Rooting, consumer.Rooting)
	}
	if !hasAside {
		t.Fatal("the isolated record was dropped instead of reported alongside")
	}
	if aside.ContentHash != isolated.ContentHash {
		t.Errorf("aside is not the isolated record: got rooting %s", aside.Rooting)
	}

	// The plain ladder is left exactly as it was: it still serves the isolated
	// row, which is what makes the frame selection above load-bearing rather
	// than incidental.
	plain, err := domain.Compose([]domain.VulnerabilityRecord{isolated, consumer})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if plain.ContentHash != isolated.ContentHash {
		t.Error("the frame-blind ladder no longer reproduces the defect; this test has stopped measuring it")
	}
}

// A frame rooted at the module ITSELF is not a consumer frame: the module is its
// own root, so no consumer entry point exists for a route to start from. It must
// not be promoted over an isolated record as though it answered the consumer's
// question.
func TestComposeForConsumer_SelfRootedFrameIsNotAConsumerFrame(t *testing.T) {
	t.Parallel()
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")

	isolated := composeRecord(t, composeSpec{
		rooting:      domain.RootingIsolated,
		completeness: "BUILT_WITH_BODIES",
		scannedAt:    time.Date(2026, 7, 31, 10, 0, 0, 0, time.UTC),
		findings:     reachableFinding("GO-2025-3553", false),
	})
	selfRooted := composeRecord(t, composeSpec{
		rooting:   domain.TargetRootedAt(coord),
		scannedAt: time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC),
		findings:  advisory("GO-2025-3553"),
	})

	answer, _, hasAside, err := domain.ComposeForConsumer([]domain.VulnerabilityRecord{isolated, selfRooted}, coord)
	if err != nil {
		t.Fatalf("ComposeForConsumer: %v", err)
	}
	if hasAside {
		t.Error("reported an aside for a group holding no consumer-rooted record")
	}
	if answer.ContentHash != isolated.ContentHash {
		t.Errorf("a self-rooted record was treated as a consumer frame: served rooting %s", answer.Rooting)
	}
}

// With nothing in a consumer frame the whole group competes exactly as the
// ladder ranks it. Narrowing to an empty frame would report "never measured"
// for a store that holds a measurement.
func TestComposeForConsumer_NoConsumerFrameFallsBackToTheLadder(t *testing.T) {
	t.Parallel()
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")

	older := composeRecord(t, composeSpec{
		rooting:   domain.RootingIsolated,
		scannedAt: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		findings:  advisory("GO-2025-3553"),
	})
	newer := composeRecord(t, composeSpec{
		rooting:   domain.RootingIsolated,
		scannedAt: time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC),
		findings:  advisory("GO-2025-3553"),
	})

	answer, _, hasAside, err := domain.ComposeForConsumer([]domain.VulnerabilityRecord{older, newer}, coord)
	if err != nil {
		t.Fatalf("ComposeForConsumer: %v", err)
	}
	if hasAside {
		t.Error("nothing was declined, so nothing should be reported as an aside")
	}
	plain, err := domain.Compose([]domain.VulnerabilityRecord{older, newer})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if answer.ContentHash != plain.ContentHash {
		t.Error("the fallback disagrees with the ladder it claims to defer to")
	}
}

// A consumer frame with no isolated record beside it reports no aside: there is
// nothing that was declined.
func TestComposeForConsumer_ConsumerFrameAloneHasNoAside(t *testing.T) {
	t.Parallel()
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
	consumerRoot := coordinatetest.MustNew("example.com/app", "v0.0.0")

	consumer := composeRecord(t, composeSpec{
		rooting:  domain.TargetRootedAt(consumerRoot),
		findings: reachableFinding("GO-2025-3553", true),
	})
	unrecorded := composeRecord(t, composeSpec{findings: advisory("GO-2025-3553")})

	answer, _, hasAside, err := domain.ComposeForConsumer([]domain.VulnerabilityRecord{consumer, unrecorded}, coord)
	if err != nil {
		t.Fatalf("ComposeForConsumer: %v", err)
	}
	if hasAside {
		t.Error("an unrecorded frame was reported as an isolated aside")
	}
	if answer.ContentHash != consumer.ContentHash {
		t.Errorf("served rooting %s, want the consumer frame", answer.Rooting)
	}
}

// Composing nothing has no answer, and absence is the store's word rather than
// a composition of zero records.
func TestComposeForConsumer_NoRecords(t *testing.T) {
	t.Parallel()
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
	if _, _, _, err := domain.ComposeForConsumer(nil, coord); !errors.Is(err, domain.ErrNoRecordsToCompose) {
		t.Fatalf("ComposeForConsumer(nil) = %v, want ErrNoRecordsToCompose", err)
	}
}
