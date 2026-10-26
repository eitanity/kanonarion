package domain_test

import (
	"errors"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/gotoolchain"
	"code.eitanity.com/kanonarion/internal/vuln/domain"
	"code.eitanity.com/kanonarion/internal/vuln/vulntest"
)

var (
	snapOld = vulntest.MustNewAt("vuln.go.dev", "2026-09-02T19:12:04Z", time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC))
	snapNew = vulntest.MustNewAt("vuln.go.dev", "2026-10-08T22:31:09Z", time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC))
)

// tcRecord is one scan of the sample coordinate under a toolchain, against a
// snapshot, Clean or Affected.
func tcRecord(t *testing.T, hash, toolchain string, snap domain.DatabaseSnapshot, affected bool, scanned time.Time) domain.VulnerabilityRecord {
	t.Helper()
	r := sampleRecord(t)
	r.Rooting = projectFrame()
	r.ContentHash, r.Toolchain, r.DatabaseSnapshot, r.ScannedAt = hash, gotoolchain.Version(toolchain), snap, scanned
	r.WalkID = "walk-" + hash
	if affected {
		r.OverallStatus = domain.StatusAffected
		r.FindingsStatus = domain.FindingsRecordAffected
		r.Findings = []domain.VulnerabilityFinding{{ID: "GO-2026-6603", FixedIn: "v0.58.0"}}
	}
	return r
}

// Two toolchains on two snapshots disagree because the advisory sets differ,
// which says nothing about the toolchain: the newer snapshot is served.
func TestToolchainConflict_TwoSnapshotsNeverConflict(t *testing.T) {
	t.Parallel()
	old := tcRecord(t, "sha256:old", "go1.26.5", snapOld, false, time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC))
	cur := tcRecord(t, "sha256:new", "go1.27.2", snapNew, true, time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC))
	got, err := domain.Compose([]domain.VulnerabilityRecord{old, cur})
	if err != nil {
		t.Fatalf("Compose refused records on two snapshots: %v", err)
	}
	if got.ContentHash != cur.ContentHash {
		t.Errorf("served %s, want the newer snapshot's record", got.ContentHash)
	}
}

// Two toolchains on one snapshot that reached different verdicts conflict.
func TestToolchainConflict_OneSnapshotConflicts(t *testing.T) {
	t.Parallel()
	a := tcRecord(t, "sha256:a", "go1.26.5", snapNew, false, time.Date(2026, 10, 11, 11, 0, 0, 0, time.UTC))
	b := tcRecord(t, "sha256:b", "go1.27.2", snapNew, true, time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC))
	_, err := domain.Compose([]domain.VulnerabilityRecord{a, b})
	var c domain.ToolchainConflict
	if !errors.As(err, &c) {
		t.Fatalf("Compose = %v, want a ToolchainConflict", err)
	}
	if c.NewestWalkID != b.WalkID {
		t.Errorf("NewestWalkID = %q, want %q", c.NewestWalkID, b.WalkID)
	}
}

// Only the served snapshot is compared: a disagreement on an older snapshot does
// not refuse an answer the newest snapshot gives without one.
func TestToolchainConflict_OnlyTheServedSnapshotIsCompared(t *testing.T) {
	t.Parallel()
	recs := []domain.VulnerabilityRecord{
		tcRecord(t, "sha256:o1", "go1.26.5", snapOld, false, time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)),
		tcRecord(t, "sha256:o2", "go1.27.2", snapOld, true, time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)),
		tcRecord(t, "sha256:n1", "go1.27.2", snapNew, true, time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)),
	}
	got, err := domain.Compose(recs)
	if err != nil || got.ContentHash != "sha256:n1" {
		t.Errorf("Compose = %s, %v; want sha256:n1 and no refusal", got.ContentHash, err)
	}
}

// notAnalysed turns a record into a scan that did not analyse the module.
func notAnalysed(r domain.VulnerabilityRecord, status domain.VulnerabilityStatus) domain.VulnerabilityRecord {
	r.OverallStatus = status
	r.CoverageStatus = domain.DetermineRecordCoverageStatus(status)
	if status == domain.StatusUnscannable {
		r.UnscanReason = domain.UnscanReasonGeneratedAssets
	} else {
		r.ErrorDetail = "govulncheck exited with error"
	}
	return r
}

// A scan that analysed nothing and found nothing makes no claim, so it cannot
// contradict a Clean record on the same snapshot: the Clean record is served.
func TestToolchainConflict_ARecordWithNoClaimTakesNoPart(t *testing.T) {
	t.Parallel()
	for _, status := range []domain.VulnerabilityStatus{domain.StatusScanFailed, domain.StatusUnscannable} {
		gap := notAnalysed(tcRecord(t, "sha256:gap", "go1.27.1", snapNew, false, time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)), status)
		clean := tcRecord(t, "sha256:clean", "go1.27.2", snapNew, false, time.Date(2026, 10, 11, 11, 0, 0, 0, time.UTC))
		got, err := domain.Compose([]domain.VulnerabilityRecord{gap, clean})
		if err != nil || got.ContentHash != clean.ContentHash {
			t.Errorf("%s beside Clean: served %s, err %v; want the Clean record and no refusal", status, got.ContentHash, err)
		}
	}
}

// A not-analysed record that DID report a finding claims it, and still
// conflicts with a Clean record on the same snapshot.
func TestToolchainConflict_ANotAnalysedFindingStillClaims(t *testing.T) {
	t.Parallel()
	found := notAnalysed(tcRecord(t, "sha256:found", "go1.27.1", snapNew, true, time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)), domain.StatusScanFailed)
	clean := tcRecord(t, "sha256:clean", "go1.27.2", snapNew, false, time.Date(2026, 10, 11, 11, 0, 0, 0, time.UTC))
	_, err := domain.Compose([]domain.VulnerabilityRecord{found, clean})
	var c domain.ToolchainConflict
	if !errors.As(err, &c) {
		t.Errorf("Compose = %v, want a ToolchainConflict", err)
	}
}

// outcome is what a composition says, reduced to something comparable across
// orderings: the served hash, or the conflict's values and hashes.
func outcome(t *testing.T, recs []domain.VulnerabilityRecord) string {
	t.Helper()
	got, err := domain.Compose(recs)
	var c domain.ToolchainConflict
	switch {
	case errors.As(err, &c):
		return "conflict " + c.Error()
	case err != nil:
		t.Fatalf("Compose: %v", err)
	}
	return "served " + got.ContentHash
}

func permutations(recs []domain.VulnerabilityRecord) [][]domain.VulnerabilityRecord {
	if len(recs) <= 1 {
		return [][]domain.VulnerabilityRecord{append([]domain.VulnerabilityRecord(nil), recs...)}
	}
	var out [][]domain.VulnerabilityRecord
	for i := range recs {
		rest := append(append([]domain.VulnerabilityRecord(nil), recs[:i]...), recs[i+1:]...)
		for _, p := range permutations(rest) {
			out = append(out, append([]domain.VulnerabilityRecord{recs[i]}, p...))
		}
	}
	return out
}

// The order guard: every ordering of the same records gives the same answer.
// The first set is the zenbpm shape, where one toolchain holds a Clean and an
// Affected record on different snapshots; picking each toolchain's first row
// made the answer depend on which came back first.
func TestToolchainConflict_AnswerDoesNotDependOnRowOrder(t *testing.T) {
	t.Parallel()
	at := func(d int) time.Time { return time.Date(2026, 10, d, 12, 0, 0, 0, time.UTC) }
	sets := map[string][]domain.VulnerabilityRecord{
		"no conflict": {
			tcRecord(t, "sha256:a", "go1.26.5", snapOld, false, at(1)),
			tcRecord(t, "sha256:b", "go1.27.2", snapOld, false, at(2)),
			tcRecord(t, "sha256:c", "go1.27.2", snapNew, true, at(11)),
			tcRecord(t, "sha256:d", "go1.27.2", snapNew, true, at(10)),
			tcRecord(t, "sha256:e", "go1.26.5", snapOld, false, at(3)),
		},
		"no claim": {
			notAnalysed(tcRecord(t, "sha256:a", "go1.27.1", snapNew, false, at(11)), domain.StatusScanFailed),
			tcRecord(t, "sha256:b", "go1.27.2", snapNew, false, at(10)),
			notAnalysed(tcRecord(t, "sha256:c", "go1.26.5", snapNew, false, at(9)), domain.StatusUnscannable),
			tcRecord(t, "sha256:d", "go1.27.2", snapOld, false, at(2)),
			tcRecord(t, "sha256:e", "go1.27.2", snapNew, false, at(8)),
		},
		"claimed finding": {
			notAnalysed(tcRecord(t, "sha256:a", "go1.27.1", snapNew, true, at(11)), domain.StatusScanFailed),
			tcRecord(t, "sha256:b", "go1.27.2", snapNew, false, at(10)),
			notAnalysed(tcRecord(t, "sha256:c", "go1.26.5", snapNew, false, at(9)), domain.StatusUnscannable),
			tcRecord(t, "sha256:d", "go1.27.2", snapOld, false, at(2)),
			tcRecord(t, "sha256:e", "go1.27.1", snapNew, true, at(8)),
		},
		"conflict": {
			tcRecord(t, "sha256:a", "go1.26.5", snapNew, false, at(10)),
			tcRecord(t, "sha256:b", "go1.27.2", snapNew, true, at(11)),
			tcRecord(t, "sha256:c", "go1.27.2", snapOld, false, at(2)),
			tcRecord(t, "sha256:d", "go1.26.5", snapNew, false, at(11)),
			tcRecord(t, "sha256:e", "go1.26.5", snapOld, true, at(1)),
		},
	}
	for name, recs := range sets {
		want := outcome(t, recs)
		for _, p := range permutations(recs) {
			if got := outcome(t, p); got != want {
				t.Fatalf("%s: order changed the answer:\n got  %s\n want %s", name, got, want)
			}
		}
		wantConflict := name == "conflict" || name == "claimed finding"
		if wantConflict != (len(want) > 8 && want[:8] == "conflict") {
			t.Errorf("%s: outcome %q", name, want)
		}
	}
}

// One database version retrieved twice is one advisory set: a re-download, and
// the same instant stored at whole-second precision. Two toolchains that
// disagree across those retrievals still conflict.
func TestToolchainConflict_TwoRetrievalsOfOneVersionAreOneSnapshot(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 10, 11, 11, 57, 16, 349792969, time.UTC)
	for name, other := range map[string]time.Time{
		"re-download":      at.Add(26 * time.Hour),
		"second precision": at.Truncate(time.Second),
	} {
		a := tcRecord(t, "sha256:a", "go1.26.5", vulntest.MustSealOver("vuln.go.dev", "2026-10-08T22:31:09Z", at, []byte("db")), false,
			time.Date(2026, 10, 11, 11, 0, 0, 0, time.UTC))
		b := tcRecord(t, "sha256:b", "go1.27.2", vulntest.MustSealOver("vuln.go.dev", "2026-10-08T22:31:09Z", other, []byte("db")), true,
			time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC))
		_, err := domain.Compose([]domain.VulnerabilityRecord{a, b})
		var c domain.ToolchainConflict
		if !errors.As(err, &c) {
			t.Errorf("%s: Compose = %v, want a ToolchainConflict", name, err)
		}
	}
}

// One version label over two different databases is two advisory sets: the
// content hashes say so, and their verdicts are not compared. A snapshot that
// carries no hash is matched on source and version alone.
func TestToolchainConflict_DifferentDatabaseHashesAreTwoSnapshots(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 10, 11, 11, 57, 16, 0, time.UTC)
	a := tcRecord(t, "sha256:a", "go1.26.5", vulntest.MustSealOver("vuln.go.dev", "2026-10-08T22:31:09Z", at, []byte("db1")), false,
		time.Date(2026, 10, 11, 11, 0, 0, 0, time.UTC))
	b := tcRecord(t, "sha256:b", "go1.27.2", vulntest.MustSealOver("vuln.go.dev", "2026-10-08T22:31:09Z", at, []byte("db2")), true,
		time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC))
	if _, err := domain.Compose([]domain.VulnerabilityRecord{a, b}); err != nil {
		t.Errorf("two databases under one version label conflicted: %v", err)
	}
	a.DatabaseSnapshot = vulntest.MustNewAt("vuln.go.dev", "2026-10-08T22:31:09Z", at.Add(time.Hour))
	if _, err := domain.Compose([]domain.VulnerabilityRecord{a, b}); err == nil {
		t.Error("an unhashed snapshot of the same version did not conflict")
	}
	a.DatabaseSnapshot = vulntest.MustSealOver("osv.dev", "2026-10-08T22:31:09Z", at, []byte("db2"))
	if _, err := domain.Compose([]domain.VulnerabilityRecord{a, b}); err != nil {
		t.Errorf("two sources under one version label conflicted: %v", err)
	}
}
