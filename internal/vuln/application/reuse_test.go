package application_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// reuseFixture wires the smallest use case that can answer the reuse question:
// it needs a vulnerability store (for the snapshot and the stored runs) and a
// pipeline version, and nothing else. A scanner is deliberately absent — if the
// lookup ever reaches one, that is the defect.
func reuseFixture(t testing.TB, pipelineVersion string) (*application.ScanWalkUseCase, *fakeVulnStore) {
	t.Helper()
	vulnStore := newFakeVulnStore()
	uc := application.NewScanWalkUseCase(
		newFakeWalkStore(), vulnStore, nil, nil, nil, pipelineVersion, slog.Default(),
	)
	return uc, vulnStore
}

// seedRun stores one completed run of walkID against snapshot.
func seedRun(t testing.TB, store *fakeVulnStore, id, walkID string, snapshot domain.DatabaseSnapshot,
	pipelineVersion string, coverage domain.CoverageStatus,
) domain.WalkScanRun {
	t.Helper()
	run := domain.WalkScanRun{
		ID:              id,
		WalkID:          walkID,
		Snapshot:        snapshot,
		StartedAt:       time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC),
		CompletedAt:     time.Date(2026, 8, 1, 9, 4, 0, 0, time.UTC),
		CoverageStatus:  coverage,
		FindingsStatus:  domain.FindingsClean,
		PipelineVersion: pipelineVersion,
	}
	sealed, err := domain.WalkScanRunHasher{}.SetContentHash(run)
	if err != nil {
		t.Fatalf("sealing run: %v", err)
	}
	if perr := store.PutWalkScanRun(context.Background(), sealed); perr != nil {
		t.Fatalf("PutWalkScanRun: %v", perr)
	}
	return sealed
}

// seedSnapshot makes snapshot the store's latest, which is the one a scan
// started now would resolve.
func seedSnapshot(t testing.TB, store *fakeVulnStore, snapshot domain.DatabaseSnapshot) {
	t.Helper()
	if err := store.PutDatabaseSnapshot(context.Background(), snapshot, strings.NewReader("{}")); err != nil {
		t.Fatalf("PutDatabaseSnapshot: %v", err)
	}
}

// TestReusableRun_ServesACompletedRunAgainstTheSameSnapshot is the saving. The
// question a scan answers is fixed by the walk, the snapshot and the pipeline;
// when all three already have an answer, re-running govulncheck over the whole
// build list only reproduces it.
func TestReusableRun_ServesACompletedRunAgainstTheSameSnapshot(t *testing.T) {
	uc, store := reuseFixture(t, "v1")
	snap := vulntest.MustNew("vuln.go.dev", "2026-07-27T16:28:49Z")
	seedSnapshot(t, store, snap)
	want := seedRun(t, store, "vscan-1", "walk-1", snap, "v1", domain.CoverageComplete)

	got, ok, err := uc.ReusableRun(context.Background(), "walk-1", false)
	if err != nil {
		t.Fatalf("ReusableRun: %v", err)
	}
	if !ok {
		t.Fatal("a completed run against the current snapshot was not offered for reuse")
	}
	if got.ID != want.ID {
		t.Errorf("reused run = %s, want %s", got.ID, want.ID)
	}
}

// TestReusableRun_FreshAlwaysRescans pins the opt-out named in the flag's own
// help: --fresh asks for a live advisory snapshot, so serving a stored run
// against it would answer the opposite of what was asked.
func TestReusableRun_FreshAlwaysRescans(t *testing.T) {
	uc, store := reuseFixture(t, "v1")
	snap := vulntest.MustNew("vuln.go.dev", "2026-07-27T16:28:49Z")
	seedSnapshot(t, store, snap)
	seedRun(t, store, "vscan-1", "walk-1", snap, "v1", domain.CoverageComplete)

	if _, ok, err := uc.ReusableRun(context.Background(), "walk-1", true); err != nil {
		t.Fatalf("ReusableRun: %v", err)
	} else if ok {
		t.Error("--fresh served a stored scan run")
	}
}

// TestReusableRun_RefusesADifferentSnapshot is the correctness gate. A new
// advisory generation is a new question, and the run that predates it did not
// answer it.
func TestReusableRun_RefusesADifferentSnapshot(t *testing.T) {
	uc, store := reuseFixture(t, "v1")
	seedRun(t, store, "vscan-1", "walk-1", vulntest.MustNew("vuln.go.dev", "2026-07-27T16:28:49Z"), "v1", domain.CoverageComplete)
	seedSnapshot(t, store, vulntest.MustNew("vuln.go.dev", "2026-08-01T00:00:00Z"))

	if _, ok, err := uc.ReusableRun(context.Background(), "walk-1", false); err != nil {
		t.Fatalf("ReusableRun: %v", err)
	} else if ok {
		t.Error("a run judged against an older advisory snapshot was served for a newer one")
	}
}

// TestReusableRun_RefusesAnIncompleteRun keeps reuse from freezing a coverage
// gap. A partial run left part of the build list unanalysed; serving it would
// report coverage this invocation never established and deny the operator the
// retry they are entitled to.
func TestReusableRun_RefusesAnIncompleteRun(t *testing.T) {
	for _, coverage := range []domain.CoverageStatus{domain.CoveragePartial, domain.CoverageFailed} {
		t.Run(string(coverage), func(t *testing.T) {
			uc, store := reuseFixture(t, "v1")
			snap := vulntest.MustNew("vuln.go.dev", "2026-07-27T16:28:49Z")
			seedSnapshot(t, store, snap)
			seedRun(t, store, "vscan-1", "walk-1", snap, "v1", coverage)

			if _, ok, err := uc.ReusableRun(context.Background(), "walk-1", false); err != nil {
				t.Fatalf("ReusableRun: %v", err)
			} else if ok {
				t.Errorf("a %s run was offered for reuse", coverage)
			}
		})
	}
}

// TestReusableRun_RefusesASupersededPipeline makes a corrected scanner take
// effect on its own, exactly as the walk cache's pipeline check makes a
// corrected resolver take effect, rather than every caller having to know to
// pass a flag.
func TestReusableRun_RefusesASupersededPipeline(t *testing.T) {
	uc, store := reuseFixture(t, "v2")
	snap := vulntest.MustNew("vuln.go.dev", "2026-07-27T16:28:49Z")
	seedSnapshot(t, store, snap)
	seedRun(t, store, "vscan-1", "walk-1", snap, "v1", domain.CoverageComplete)

	if _, ok, err := uc.ReusableRun(context.Background(), "walk-1", false); err != nil {
		t.Fatalf("ReusableRun: %v", err)
	} else if ok {
		t.Error("a run from a superseded pipeline version was served")
	}
}

// TestReusableRun_ServesARunAcrossARefetchOfTheSameDatabase pins the snapshot
// comparison on WHICH database, not on when it was downloaded. A --fresh fetch
// re-downloads the same advisory generation and holds it at nanosecond
// precision, while the store round-trips retrieval times at second precision; a
// comparison that included the time made a run unequal to the very snapshot it
// was judged against, and reuse never fired again after a fresh fetch.
func TestReusableRun_ServesARunAcrossARefetchOfTheSameDatabase(t *testing.T) {
	uc, store := reuseFixture(t, "v1")

	sealed, err := vulntest.MustNew("vuln.go.dev", "2026-07-27T16:28:49Z").
		WithContentHash("sha256:" + strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("WithContentHash: %v", err)
	}

	// The run was judged against a reading carrying sub-second precision.
	withNanos, err := domain.NewDatabaseSnapshot(sealed.Source(), sealed.Version(),
		sealed.RetrievedAt().Add(454*time.Millisecond), sealed.ContentHash())
	if err != nil {
		t.Fatalf("NewDatabaseSnapshot: %v", err)
	}
	seedRun(t, store, "vscan-1", "walk-1", withNanos, "v1", domain.CoverageComplete)

	// The store hands back the same generation at second precision.
	seedSnapshot(t, store, sealed)

	if _, ok, rerr := uc.ReusableRun(context.Background(), "walk-1", false); rerr != nil {
		t.Fatalf("ReusableRun: %v", rerr)
	} else if !ok {
		t.Error("a run judged against this very advisory database was not reused because its download time differed")
	}
}

// TestReusableRun_RefusesAnotherWalksRun pins the key: verdicts belong to the
// dependency set they were derived over.
func TestReusableRun_RefusesAnotherWalksRun(t *testing.T) {
	uc, store := reuseFixture(t, "v1")
	snap := vulntest.MustNew("vuln.go.dev", "2026-07-27T16:28:49Z")
	seedSnapshot(t, store, snap)
	seedRun(t, store, "vscan-1", "walk-1", snap, "v1", domain.CoverageComplete)

	if _, ok, err := uc.ReusableRun(context.Background(), "walk-2", false); err != nil {
		t.Fatalf("ReusableRun: %v", err)
	} else if ok {
		t.Error("one walk's scan run was offered as another walk's")
	}
}
