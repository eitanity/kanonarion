package domain_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// disputeSpec is one generation of github.com/foo/bar@v1.0.0. The zero value is
// the base group: isolated, go1.27.2, pipeline v16, the January snapshot.
type disputeSpec struct {
	ids          []string
	rooting      domain.Rooting
	toolchain    gotoolchain.Version
	pipeline     string
	snapshotAt   time.Time
	completeness string
	status       domain.VulnerabilityStatus
	scannedAt    time.Time
	walkID       string
}

func disputeRecord(t *testing.T, s disputeSpec) domain.VulnerabilityRecord {
	t.Helper()
	if s.rooting == "" {
		s.rooting = domain.RootingIsolated
	}
	if s.toolchain == "" {
		s.toolchain = "go1.27.2"
	}
	if s.pipeline == "" {
		s.pipeline = "v16"
	}
	if s.snapshotAt.IsZero() {
		s.snapshotAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	if s.scannedAt.IsZero() {
		s.scannedAt = time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	}
	if s.walkID == "" {
		s.walkID = "walk-1"
	}
	if s.status == "" {
		s.status = domain.StatusClean
		if len(s.ids) > 0 {
			s.status = domain.StatusAffected
		}
	}
	var findings []domain.VulnerabilityFinding
	for _, id := range s.ids {
		findings = append(findings, domain.VulnerabilityFinding{ID: id, Summary: "summary of " + id, AffectedRange: "< v2"})
	}
	rec, err := domain.VulnerabilityRecordHasher{}.SetContentHash(domain.VulnerabilityRecord{
		Ecosystem:             fetchdomain.EcosystemGo,
		Coordinate:            coordinatetest.MustNew("github.com/foo/bar", "v1.0.0"),
		WalkID:                s.walkID,
		Findings:              findings,
		DatabaseSnapshot:      vulntest.MustNewAt("test", s.snapshotAt.Format(time.RFC3339), s.snapshotAt),
		OverallStatus:         s.status,
		ScannedAt:             s.scannedAt,
		PipelineVersion:       s.pipeline,
		CallGraphCompleteness: s.completeness,
		Rooting:               s.rooting,
		Toolchain:             s.toolchain,
	})
	if err != nil {
		t.Fatalf("sealing dispute fixture: %v", err)
	}
	return rec
}

var (
	later      = time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	newerSnap  = time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	targetRoot = domain.TargetRootedAt(coordinatetest.MustNew("example.com/app", "local"))
)

// Only two analysed, advisory-reporting records of one coordinate, pipeline,
// snapshot, frame and toolchain that report different advisories are a
// dispute. Each dimension is varied with and without a disagreement.
func TestFindingConflict_TheGroupKey(t *testing.T) {
	t.Parallel()
	base := disputeSpec{ids: []string{"GO-2026-0001", "GO-2026-0002"}}
	cases := []struct {
		name     string
		other    disputeSpec
		disputed bool
	}{
		{"same group, disagree", disputeSpec{ids: []string{"GO-2026-0001"}, scannedAt: later}, true},
		{"same group, agree", disputeSpec{ids: base.ids, scannedAt: later}, false},
		{"newer snapshot, disagree", disputeSpec{ids: []string{"GO-2026-0001"}, snapshotAt: newerSnap, scannedAt: later}, false},
		{"newer snapshot, agree", disputeSpec{ids: base.ids, snapshotAt: newerSnap, scannedAt: later}, false},
		{"other frame, disagree", disputeSpec{ids: []string{"GO-2026-0001"}, rooting: targetRoot, scannedAt: later}, false},
		{"other frame, agree", disputeSpec{ids: base.ids, rooting: targetRoot, scannedAt: later}, false},
		{"other toolchain, agree", disputeSpec{ids: base.ids, toolchain: "go1.26.4", scannedAt: later}, false},
		{"other pipeline, disagree", disputeSpec{ids: []string{"GO-2026-0001"}, pipeline: "v17", scannedAt: later}, false},
		{"other pipeline, agree", disputeSpec{ids: base.ids, pipeline: "v17", scannedAt: later}, false},
		{"other completeness, disagree", disputeSpec{ids: []string{"GO-2026-0001"}, completeness: "BUILT_WITH_BODIES", scannedAt: later}, true},
		{"other completeness, agree", disputeSpec{ids: base.ids, completeness: "BUILT_WITH_BODIES", scannedAt: later}, false},
		{"failed scan", disputeSpec{status: domain.StatusScanFailed, scannedAt: later}, false},
		{"unscannable", disputeSpec{status: domain.StatusUnscannable, scannedAt: later}, false},
		{"analysed all-clear", disputeSpec{scannedAt: later}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			recs := []domain.VulnerabilityRecord{disputeRecord(t, base), disputeRecord(t, tc.other)}
			_, err := domain.Compose(recs)
			disputed := errors.As(err, new(domain.FindingConflict))
			if disputed != tc.disputed {
				t.Fatalf("Compose = %v; disputed %v, want %v", err, disputed, tc.disputed)
			}
			if !disputed && err != nil {
				t.Fatalf("Compose = %v, want an answer", err)
			}
		})
	}
}

// A toolchain is part of the group: two toolchains that disagree are the
// toolchain refusal, and both refusals carry the one sentinel the CLI exits 10
// on.
func TestFindingConflict_TwoToolchainsAreTheToolchainRefusal(t *testing.T) {
	t.Parallel()
	recs := []domain.VulnerabilityRecord{
		disputeRecord(t, disputeSpec{ids: []string{"GO-2026-0001", "GO-2026-0002"}}),
		disputeRecord(t, disputeSpec{ids: []string{"GO-2026-0001"}, toolchain: "go1.26.4", scannedAt: later}),
	}
	_, err := domain.Compose(recs)
	if !errors.As(err, new(domain.ToolchainConflict)) {
		t.Fatalf("Compose = %v, want the toolchain refusal", err)
	}
	if !errors.Is(err, domain.ErrVulnConflict) {
		t.Errorf("a toolchain refusal does not wrap ErrVulnConflict: %v", err)
	}
}

// Two builds of one root can not legitimately report different advisories for a
// dependency: the project path adds every advisory the snapshot matches by
// coordinate. So the walk is not part of the key, and two walks of one
// target-rooted frame that disagree are disputed.
func TestFindingConflict_TwoBuildsOfOneRootAreOneGroup(t *testing.T) {
	t.Parallel()
	recs := []domain.VulnerabilityRecord{
		disputeRecord(t, disputeSpec{ids: []string{"GO-2026-0001", "GO-2026-0002"}, rooting: targetRoot, walkID: "walk-a"}),
		disputeRecord(t, disputeSpec{ids: []string{"GO-2026-0001"}, rooting: targetRoot, walkID: "walk-b", scannedAt: later}),
	}
	if _, _, err := domain.ComposeAt(recs, targetRoot); !errors.Is(err, domain.ErrVulnConflict) {
		t.Fatalf("ComposeAt = %v, want the dispute", err)
	}
}

// A dispute in a group the ladder does not serve is history: the newer
// snapshot answers as before.
func TestFindingConflict_OnlyTheServedGroupIsCompared(t *testing.T) {
	t.Parallel()
	newer := disputeRecord(t, disputeSpec{ids: []string{"GO-2026-0001"}, snapshotAt: newerSnap, scannedAt: later})
	recs := []domain.VulnerabilityRecord{
		disputeRecord(t, disputeSpec{ids: []string{"GO-2026-0001", "GO-2026-0002"}}),
		disputeRecord(t, disputeSpec{ids: []string{"GO-2026-0001"}, scannedAt: time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)}),
		newer,
	}
	got, err := domain.Compose(recs)
	if err != nil || got.ContentHash != newer.ContentHash {
		t.Fatalf("Compose = %s, %v; want the newer snapshot's record", got.ContentHash, err)
	}
}

// The refusal names every distinct finding set once, each with what it reports
// that another lacks, and the --history read; agreeing duplicates add nothing.
func TestFindingConflict_NamesTheRecordsAndTheHistory(t *testing.T) {
	t.Parallel()
	both := disputeRecord(t, disputeSpec{ids: []string{"GO-2026-0001", "GO-2026-0002", "GO-2026-0002"}})
	one := disputeRecord(t, disputeSpec{ids: []string{"GO-2026-0001"}, scannedAt: later})
	dup := disputeRecord(t, disputeSpec{ids: []string{"GO-2026-0001"}, scannedAt: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)})
	_, err := domain.Compose([]domain.VulnerabilityRecord{dup, both, one})
	c, ok := errors.AsType[domain.FindingConflict](err)
	if !ok {
		t.Fatalf("Compose = %v, want the dispute", err)
	}
	if len(c.ContentHashes) != 2 {
		t.Fatalf("named %v, want one record per finding set", c.ContentHashes)
	}
	msg := err.Error()
	for _, want := range []string{
		"conflicting vulnerability records for github.com/foo/bar@v1.0.0",
		"record " + both.ContentHash + " (scanned 2026-01-02T00:00:00Z) reports [GO-2026-0002], which another lacks",
		"record " + one.ContentHash + " (scanned 2026-01-03T00:00:00Z) reports nothing another lacks",
		"no re-scan settles it",
		"kanonarion vuln-show github.com/foo/bar@v1.0.0 --history",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal does not say %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, dup.ContentHash) {
		t.Errorf("an agreeing duplicate was named:\n%s", msg)
	}
}

// Every composition entry point refuses a dispute in the group it would serve.
func TestFindingConflict_EveryComposeRefuses(t *testing.T) {
	t.Parallel()
	consumerRoot := domain.TargetRootedAt(coordinatetest.MustNew("example.com/app", "local"))
	pair := func(rooting domain.Rooting) []domain.VulnerabilityRecord {
		return []domain.VulnerabilityRecord{
			disputeRecord(t, disputeSpec{ids: []string{"GO-2026-0001", "GO-2026-0002"}, rooting: rooting}),
			disputeRecord(t, disputeSpec{ids: []string{"GO-2026-0001"}, rooting: rooting, scannedAt: later}),
		}
	}
	self := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
	checks := map[string]func() error{
		"Compose": func() error { _, err := domain.Compose(pair(domain.RootingIsolated)); return err },
		"ComposeAt": func() error {
			_, _, err := domain.ComposeAt(pair(domain.RootingIsolated), domain.RootingIsolated)
			return err
		},
		"ComposeForIndex": func() error {
			_, _, err := domain.ComposeForIndex(pair(domain.RootingIsolated), domain.RootingIsolated)
			return err
		},
		"ComposeInFrame": func() error {
			_, _, _, _, err := domain.ComposeInFrame(pair(consumerRoot), consumerRoot)
			return err
		},
		"ComposeForConsumer": func() error {
			_, _, _, err := domain.ComposeForConsumer(pair(consumerRoot), self)
			return err
		},
		"ComposeForConsumer, no consumer frame": func() error {
			_, _, _, err := domain.ComposeForConsumer(pair(domain.RootingIsolated), self)
			return err
		},
		"ComposeForTree": func() error {
			_, _, err := domain.ComposeForTree(pair(consumerRoot), "example.com/app")
			return err
		},
		"ComposeForTree, frameless": func() error {
			_, _, err := domain.ComposeForTree(pair(domain.RootingUnrecorded), "example.com/app")
			return err
		},
	}
	for name, check := range checks {
		if err := check(); !errors.Is(err, domain.ErrVulnConflict) {
			t.Errorf("%s = %v, want the dispute", name, err)
		}
	}
}

// The index lists a disputed group whole, so a by-advisory read reaches the
// module; otherwise it lists the served record, or nothing.
func TestIndexedAt(t *testing.T) {
	t.Parallel()
	both := disputeRecord(t, disputeSpec{ids: []string{"GO-2026-0001", "GO-2026-0002"}})
	one := disputeRecord(t, disputeSpec{ids: []string{"GO-2026-0001"}, scannedAt: later})
	clean := disputeRecord(t, disputeSpec{scannedAt: later})

	got, ok, err := domain.IndexedAt([]domain.VulnerabilityRecord{both, one, clean}, domain.RootingIsolated)
	if err != nil || !ok || len(got) != 2 {
		t.Fatalf("disputed: %d records, ok %v, err %v; want both disputing records", len(got), ok, err)
	}

	got, ok, err = domain.IndexedAt([]domain.VulnerabilityRecord{both, clean}, domain.RootingIsolated)
	if err != nil || !ok || len(got) != 1 || got[0].ContentHash != both.ContentHash {
		t.Fatalf("undisputed: %v, ok %v, err %v; want the served record", got, ok, err)
	}

	if got, ok, err = domain.IndexedAt([]domain.VulnerabilityRecord{both}, targetRoot); err != nil || ok || got != nil {
		t.Fatalf("other frame: %v, ok %v, err %v; want nothing", got, ok, err)
	}
}
