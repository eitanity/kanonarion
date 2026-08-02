package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// The defect this pins: a probe of a working tree read the store-wide composed
// record for each of its dependencies, so on a store holding two projects' scans
// it could seed a fresh probe of THIS tree with the reachability judgment
// another project's build produced.
func TestComposeForTree_AnotherConsumersRecordIsNotServed(t *testing.T) {
	t.Parallel()
	other := domain.TargetRootedAt(coordinatetest.MustNew("example.com/other", "v0.0.0"))

	otherRec := composeRecord(t, composeSpec{
		rooting:   other,
		scannedAt: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
		findings:  reachableFinding("GO-2026-0001", true),
	})
	isolated := composeRecord(t, composeSpec{
		rooting:      domain.RootingIsolated,
		completeness: "BUILT_WITH_BODIES",
		scannedAt:    time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
		findings:     reachableFinding("GO-2026-0001", false),
	})

	got, ok, err := domain.ComposeForTree([]domain.VulnerabilityRecord{otherRec, isolated}, "example.com/app")
	if err != nil {
		t.Fatalf("ComposeForTree: %v", err)
	}
	if !ok {
		t.Fatal("nothing served — the isolated record answers a question with no consumer in it and may seed")
	}
	if got.ContentHash != isolated.ContentHash {
		t.Errorf("served rooting %s, want the isolated record", got.Rooting)
	}
}

func TestComposeForTree_OwnFrameOutranksIsolated(t *testing.T) {
	t.Parallel()
	own := domain.TargetRootedAt(coordinatetest.MustNew("example.com/app", "v0.0.0"))

	ownRec := composeRecord(t, composeSpec{
		rooting:   own,
		scannedAt: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
		findings:  reachableFinding("GO-2026-0001", true),
	})
	// Newer, and on the top completeness rung: it would win every ladder there
	// is. The frame is picked first, so it does not.
	isolated := composeRecord(t, composeSpec{
		rooting:      domain.RootingIsolated,
		completeness: "BUILT_WITH_BODIES",
		scannedAt:    time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
		findings:     reachableFinding("GO-2026-0001", false),
	})

	got, ok, err := domain.ComposeForTree([]domain.VulnerabilityRecord{isolated, ownRec}, "example.com/app")
	if err != nil || !ok {
		t.Fatalf("ComposeForTree: ok=%v err=%v", ok, err)
	}
	if got.ContentHash != ownRec.ContentHash {
		t.Errorf("served rooting %s, want the tree's own frame %s", got.Rooting, own)
	}
}

// A walk assigns the root a version the tree's go.mod never states, so the
// anchor is the module path.
func TestComposeForTree_MatchesTheRootPathAtAnyVersion(t *testing.T) {
	t.Parallel()
	for _, version := range []string{"local", "v1.2.3", "v0.0.0-20260101000000-abcdefabcdef"} {
		own := domain.TargetRootedAt(coordinatetest.MustNew("example.com/app", version))
		rec := composeRecord(t, composeSpec{rooting: own, findings: reachableFinding("GO-2026-0001", true)})

		got, ok, err := domain.ComposeForTree([]domain.VulnerabilityRecord{rec}, "example.com/app")
		if err != nil || !ok {
			t.Fatalf("root version %q: ok=%v err=%v", version, ok, err)
		}
		if got.ContentHash != rec.ContentHash {
			t.Errorf("root version %q: served the wrong record", version)
		}
	}
}

func TestComposeForTree_NothingAcceptableIsAnAbsence(t *testing.T) {
	t.Parallel()
	other := domain.TargetRootedAt(coordinatetest.MustNew("example.com/other", "v0.0.0"))
	// A bare target-rooted record names no root, so it cannot be read as this
	// tree's, and a record rooted at the dependency itself is not this build.
	bare := composeRecord(t, composeSpec{rooting: domain.RootingTargetRooted})
	self := composeRecord(t, composeSpec{
		rooting: domain.TargetRootedAt(coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")),
	})
	otherRec := composeRecord(t, composeSpec{rooting: other})

	_, ok, err := domain.ComposeForTree([]domain.VulnerabilityRecord{bare, self, otherRec}, "example.com/app")
	if err != nil {
		t.Fatalf("ComposeForTree: %v", err)
	}
	if ok {
		t.Error("served a record measured in no frame this tree may be seeded from")
	}
}

// A store not re-scanned since the frame was recorded still seeds, on the same
// narrow terms ComposeAt uses.
func TestComposeForTree_FramelessGroupStillServes(t *testing.T) {
	t.Parallel()
	older := composeRecord(t, composeSpec{scannedAt: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)})
	newer := composeRecord(t, composeSpec{scannedAt: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)})

	got, ok, err := domain.ComposeForTree([]domain.VulnerabilityRecord{older, newer}, "example.com/app")
	if err != nil || !ok {
		t.Fatalf("ComposeForTree: ok=%v err=%v", ok, err)
	}
	if got.ContentHash != newer.ContentHash {
		t.Error("served the older frameless record")
	}
}

// One record stating a frame is enough to stop the frameless ones competing:
// the group can say which question it answers, so the rows that cannot are not
// read as this tree's.
func TestComposeForTree_FramelessRecordsYieldToAStatedFrame(t *testing.T) {
	t.Parallel()
	frameless := composeRecord(t, composeSpec{
		scannedAt: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		findings:  reachableFinding("GO-2026-0001", true),
	})
	otherRec := composeRecord(t, composeSpec{
		rooting:   domain.TargetRootedAt(coordinatetest.MustNew("example.com/other", "v0.0.0")),
		scannedAt: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	})

	_, ok, err := domain.ComposeForTree([]domain.VulnerabilityRecord{frameless, otherRec}, "example.com/app")
	if err != nil {
		t.Fatalf("ComposeForTree: %v", err)
	}
	if ok {
		t.Error("a frameless record seeded the probe although the group states a frame")
	}
}

func TestComposeForTree_NoRecordsIsAProgrammingError(t *testing.T) {
	t.Parallel()
	if _, _, err := domain.ComposeForTree(nil, "example.com/app"); !errors.Is(err, domain.ErrNoRecordsToCompose) {
		t.Errorf("err = %v, want ErrNoRecordsToCompose", err)
	}
}

// A caller with no module path to anchor to gets the isolated frame and nothing
// else: no target-rooted record can be shown to be this tree's.
func TestComposeForTree_EmptyModulePathServesIsolatedOnly(t *testing.T) {
	t.Parallel()
	isolated := composeRecord(t, composeSpec{rooting: domain.RootingIsolated})
	otherRec := composeRecord(t, composeSpec{
		rooting:   domain.TargetRootedAt(coordinatetest.MustNew("example.com/other", "v0.0.0")),
		scannedAt: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
	})

	got, ok, err := domain.ComposeForTree([]domain.VulnerabilityRecord{otherRec, isolated}, "")
	if err != nil || !ok {
		t.Fatalf("ComposeForTree: ok=%v err=%v", ok, err)
	}
	if got.ContentHash != isolated.ContentHash {
		t.Errorf("served rooting %s, want the isolated record", got.Rooting)
	}
}
