package domain_test

import (
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// checksumBypass is the motivating advisory: a malicious module proxy bypassing
// the checksum database in cmd/go, backported to two branches — fixed 1.25.10 on
// the 1.25 line and 1.26.3 on the 1.26 line. Its two-interval range is exactly
// the shape a single "fixed" field cannot express, which is why the judgment
// reads the advisory record rather than the index's collapsed fix.
func checksumBypass() domain.ToolchainAdvisory {
	return domain.ToolchainAdvisory{
		ID:      "GO-2026-4984",
		Summary: "Malicious module proxy can bypass checksum database in cmd/go",
		Ranges: []domain.ToolchainRange{
			{Introduced: "0", Fixed: "1.25.10"},
			{Introduced: "1.26.0-0", Fixed: "1.26.3"},
		},
	}
}

func liveSet(advs ...domain.ToolchainAdvisory) domain.ToolchainAdvisorySet {
	return domain.ToolchainAdvisorySet{KeyPresent: true, Advisories: advs}
}

func snapshot(t *testing.T) domain.DatabaseSnapshot {
	t.Helper()
	return vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z")
}

// TestJudgeToolchain_AnOlderToolchainIsReportedAffected is the headline: a build
// performed by a toolchain below the advisory's fix for its own branch weakens
// the verification anchors every fetch record claims, and nothing in the module
// evidence says so — no project imports cmd/go, so no reachability analysis of
// scanned code can ever reach it.
func TestJudgeToolchain_AnOlderToolchainIsReportedAffected(t *testing.T) {
	j := domain.JudgeToolchain("go1.26.2", snapshot(t), liveSet(checksumBypass()))

	if j.Status != domain.ToolchainAffected {
		t.Fatalf("status = %q, want %q for a toolchain below the fix on its own branch", j.Status, domain.ToolchainAffected)
	}
	if len(j.Covering) != 1 || j.Covering[0].ID != "GO-2026-4984" {
		t.Fatalf("covering = %+v, want the advisory named", j.Covering)
	}
	// The fix reported is the one for the branch this toolchain is on. The
	// advisory's other fix, 1.25.10, is a move backwards from go1.26.2 into a
	// toolchain the same advisory still covers.
	if got := j.Covering[0].FixedFor("go1.26.2"); got != "1.26.3" {
		t.Errorf("FixedFor(go1.26.2) = %q, want the fix on the 1.26 branch", got)
	}
	if got := j.Covering[0].FixedFor("go1.25.9"); got != "1.25.10" {
		t.Errorf("FixedFor(go1.25.9) = %q, want the fix on the 1.25 branch", got)
	}
	if j.Snapshot.Version() != "2026-07-27T20:14:16Z" {
		t.Errorf("the judgment does not name the snapshot it was made against: %+v", j.Snapshot)
	}
}

// TestJudgeToolchain_APatchedToolchainIsClear pins the other half of the
// backport shape. 1.25.10 is fixed on its own branch even though the advisory's
// highest fix is 1.26.3, so a per-branch reading must clear it — the collapsed
// index fix alone would report it affected.
func TestJudgeToolchain_APatchedToolchainIsClear(t *testing.T) {
	for _, version := range []string{"go1.25.10", "go1.25.12", "go1.26.3", "go1.26.5"} {
		j := domain.JudgeToolchain(version, snapshot(t), liveSet(checksumBypass()))
		if j.Status != domain.ToolchainClear {
			t.Errorf("%s: status = %q, want %q (covering %+v)", version, j.Status, domain.ToolchainClear, j.Covering)
		}
		if j.Judged != 1 {
			t.Errorf("%s: judged = %d, want the count of advisories the clear rests on", version, j.Judged)
		}
	}
}

// TestJudgeToolchain_AnUnfixedAdvisoryCoversEveryLaterVersion: a range with no
// fixed event runs to infinity, and the newest toolchain in the world is still
// inside it.
func TestJudgeToolchain_AnUnfixedAdvisoryCoversEveryLaterVersion(t *testing.T) {
	adv := domain.ToolchainAdvisory{ID: "GO-2026-9999", Ranges: []domain.ToolchainRange{{Introduced: "1.26.0-0"}}}
	j := domain.JudgeToolchain("go1.26.5", snapshot(t), liveSet(adv))
	if j.Status != domain.ToolchainAffected {
		t.Fatalf("status = %q, want %q for an open-ended range", j.Status, domain.ToolchainAffected)
	}
	if got := j.Covering[0].FixedFor("go1.26.5"); got != "" {
		t.Errorf("FixedFor = %q, want empty: no fix has been published", got)
	}
}

// TestJudgeToolchain_AWithdrawnAdvisoryDoesNotReportAffected ranks a retraction
// the way the module findings axis already ranks one: it is not affected, and it
// is not clear either. Collapsing it to clear would delete the fact that an
// advisory matched at all.
func TestJudgeToolchain_AWithdrawnAdvisoryDoesNotReportAffected(t *testing.T) {
	retracted := checksumBypass()
	retracted.WithdrawnAt = time.Date(2026, 4, 8, 0, 0, 0, 0, time.UTC)

	j := domain.JudgeToolchain("go1.26.2", snapshot(t), liveSet(retracted))

	if j.Status != domain.ToolchainWithdrawn {
		t.Fatalf("status = %q, want %q", j.Status, domain.ToolchainWithdrawn)
	}
	if len(j.Covering) != 0 {
		t.Errorf("covering = %+v, want empty: a retracted advisory is not a live finding", j.Covering)
	}
	if len(j.WithdrawnCovering) != 1 {
		t.Fatalf("withdrawn covering = %+v, want the retraction reported", j.WithdrawnCovering)
	}
}

// One advisory that still stands decides the axis, exactly as it does for a
// module record: reporting Withdrawn because most matches were retracted would
// bury a live one.
func TestJudgeToolchain_OneLiveAdvisoryOutranksARetractedOne(t *testing.T) {
	retracted := checksumBypass()
	retracted.ID = "GO-2026-4900"
	retracted.WithdrawnAt = time.Date(2026, 4, 8, 0, 0, 0, 0, time.UTC)

	j := domain.JudgeToolchain("go1.26.2", snapshot(t), liveSet(retracted, checksumBypass()))

	if j.Status != domain.ToolchainAffected {
		t.Fatalf("status = %q, want %q", j.Status, domain.ToolchainAffected)
	}
	if len(j.Covering) != 1 || len(j.WithdrawnCovering) != 1 {
		t.Errorf("covering = %+v / withdrawn = %+v, want each in its own list", j.Covering, j.WithdrawnCovering)
	}
}

// TestJudgeToolchain_ASnapshotWithoutTheToolchainKeyIsUnjudged: a database
// generation that never listed the key cannot answer the question, and the
// difference between "asked and nothing covered it" and "could not be asked" is
// the whole point of carrying KeyPresent separately.
func TestJudgeToolchain_ASnapshotWithoutTheToolchainKeyIsUnjudged(t *testing.T) {
	j := domain.JudgeToolchain("go1.26.5", snapshot(t), domain.ToolchainAdvisorySet{})

	if j.Status != domain.ToolchainUnjudged {
		t.Fatalf("status = %q, want %q", j.Status, domain.ToolchainUnjudged)
	}
	if j.Reason != domain.ToolchainReasonNoKey {
		t.Errorf("reason = %q, want %q", j.Reason, domain.ToolchainReasonNoKey)
	}
}

// The other two missing inputs each name themselves, because each has a
// different remedy: re-walk, or store a database at all.
func TestJudgeToolchain_MissingInputsNameThemselves(t *testing.T) {
	noVersion := domain.JudgeToolchain("", snapshot(t), liveSet(checksumBypass()))
	if noVersion.Status != domain.ToolchainUnjudged || noVersion.Reason != domain.ToolchainReasonNoVersion {
		t.Errorf("no version: status %q reason %q", noVersion.Status, noVersion.Reason)
	}

	noSnapshot := domain.JudgeToolchain("go1.26.5", domain.DatabaseSnapshot{}, liveSet(checksumBypass()))
	if noSnapshot.Status != domain.ToolchainUnjudged || noSnapshot.Reason != domain.ToolchainReasonNoSnapshot {
		t.Errorf("no snapshot: status %q reason %q", noSnapshot.Status, noSnapshot.Reason)
	}
}

// A version outside the semantic-version grammar is reported unjudged rather
// than assumed affected. The module scan's conservative rule — an unparseable
// version stays in the finding — protects a known hit from being dropped; here
// there is no hit to protect, and the same rule would invent one against a
// toolchain nothing was measured about.
func TestJudgeToolchain_AnIncomparableVersionIsUnjudgedNotAssumedAffected(t *testing.T) {
	for _, version := range []string{"go1.27rc1", "devel +abc1234"} {
		j := domain.JudgeToolchain(version, snapshot(t), liveSet(checksumBypass()))
		if j.Status != domain.ToolchainUnjudged {
			t.Errorf("%s: status = %q, want %q", version, j.Status, domain.ToolchainUnjudged)
		}
		if j.Reason != domain.ToolchainReasonUncomparable {
			t.Errorf("%s: reason = %q, want %q", version, j.Reason, domain.ToolchainReasonUncomparable)
		}
	}
}

// The database states its ranges bare and `go env GOVERSION` reports a "go"
// prefix; both forms name the same toolchain and must judge alike.
func TestJudgeToolchain_ReadsBothVersionForms(t *testing.T) {
	prefixed := domain.JudgeToolchain("go1.26.2", snapshot(t), liveSet(checksumBypass()))
	bare := domain.JudgeToolchain("1.26.2", snapshot(t), liveSet(checksumBypass()))
	if prefixed.Status != bare.Status {
		t.Errorf("go1.26.2 judged %q but 1.26.2 judged %q", prefixed.Status, bare.Status)
	}
}

// An advisory whose bounds are not versions cannot state coverage, and a
// judgment must not manufacture it from an unreadable range. The id stays in
// the snapshot's list — it is simply not evidence about this version.
func TestJudgeToolchain_AnUnreadableRangeCoversNothing(t *testing.T) {
	garbage := domain.ToolchainAdvisory{ID: "GO-2026-0002", Ranges: []domain.ToolchainRange{
		{Introduced: "not-a-version", Fixed: "1.99.0"},
		{Introduced: "0", Fixed: "also-not-a-version"},
	}}
	j := domain.JudgeToolchain("go1.26.5", snapshot(t), liveSet(garbage))
	if j.Status != domain.ToolchainClear {
		t.Errorf("status = %q, want %q: an unreadable range states nothing", j.Status, domain.ToolchainClear)
	}
	if got := garbage.FixedFor("go1.26.5"); got != "" {
		t.Errorf("FixedFor = %q, want empty when no range covers the version", got)
	}
	if got := garbage.FixedFor("go1.27rc1"); got != "" {
		t.Errorf("FixedFor = %q, want empty for a version that cannot be compared", got)
	}
}

// Matched advisories are reported in a stable order, so two readings of one
// judgment name them alike and a report can be diffed against another.
func TestJudgeToolchain_CoveringAdvisoriesAreOrderedByID(t *testing.T) {
	later := checksumBypass()
	earlier := checksumBypass()
	earlier.ID = "GO-2026-4001"

	j := domain.JudgeToolchain("go1.26.2", snapshot(t), liveSet(later, earlier))
	if len(j.Covering) != 2 {
		t.Fatalf("covering = %+v, want both", j.Covering)
	}
	if j.Covering[0].ID != "GO-2026-4001" || j.Covering[1].ID != "GO-2026-4984" {
		t.Errorf("covering order = %s, %s; want them sorted by id", j.Covering[0].ID, j.Covering[1].ID)
	}
}

// A version string that is nothing but the prefix names no toolchain, and is
// reported as one that could not be compared rather than crashing a comparison.
func TestJudgeToolchain_ABarePrefixIsNotAVersion(t *testing.T) {
	j := domain.JudgeToolchain("go", snapshot(t), liveSet(checksumBypass()))
	if j.Status != domain.ToolchainUnjudged || j.Reason != domain.ToolchainReasonUncomparable {
		t.Errorf("status %q reason %q, want an uncomparable version", j.Status, j.Reason)
	}
}
