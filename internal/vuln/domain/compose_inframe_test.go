package domain_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	"code.eitanity.com/kanonarion/internal/vuln/domain"
)

func projectFrame() domain.Rooting {
	return domain.TargetRootedAt(coordinatetest.MustNew("example.com/app", "local"))
}

// The refusal names the walk of the newest disagreeing record and the --gomod
// pin, and no re-scan: a re-scan appends a record and leaves the other standing.
func TestToolchainConflict_NamesThePinsAndNoRescan(t *testing.T) {
	t.Parallel()
	older, newer := disagreeingPair(t, projectFrame())
	older.WalkID, newer.WalkID = "01OLDWALK", "01NEWWALK"
	newer.ScannedAt = older.ScannedAt.Add(time.Hour)

	// Either order: the newest record decides, not the position.
	for _, recs := range [][]domain.VulnerabilityRecord{{older, newer}, {newer, older}} {
		_, err := domain.Compose(recs)
		var conflict domain.ToolchainConflict
		if !errors.As(err, &conflict) {
			t.Fatalf("Compose = %v, want a ToolchainConflict", err)
		}
		if conflict.NewestWalkID != "01NEWWALK" {
			t.Errorf("NewestWalkID = %q, want the newest record's walk", conflict.NewestWalkID)
		}
		msg := conflict.Error()
		coord := older.Coordinate.String()
		for _, want := range []string{
			"kanonarion vuln-show " + coord + " --walk-id 01NEWWALK",
			"kanonarion vuln-show " + coord + " --gomod ./go.mod",
			"kanonarion vuln-show " + coord + " --history",
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("refusal does not name %q:\n%s", want, msg)
			}
		}
		if strings.Contains(msg, "vuln-scan-rescan") {
			t.Errorf("refusal still offers a re-scan:\n%s", msg)
		}
	}
}

// A newest record naming no walk offers no --walk-id line rather than a
// placeholder; the --gomod pin still stands.
func TestToolchainConflict_NoWalkNoWalkIDLine(t *testing.T) {
	t.Parallel()
	c := domain.ToolchainConflict{
		Coordinate: coordinatetest.MustNew("example.com/dep", "v1.0.0"),
		Values:     []string{"go1.26.5", "go1.27.2"},
	}
	msg := c.Error()
	if strings.Contains(msg, "--walk-id") {
		t.Errorf("refusal names --walk-id with no walk to name:\n%s", msg)
	}
	if !strings.Contains(msg, "--gomod ./go.mod") {
		t.Errorf("refusal does not name --gomod:\n%s", msg)
	}
}

func isolatedRec(t *testing.T, reachable bool) domain.VulnerabilityRecord {
	t.Helper()
	r := sampleRecord(t)
	r.Rooting = domain.RootingIsolated
	r.ContentHash = "sha256:iso"
	r.Findings = []domain.VulnerabilityFinding{{ID: "GO-2026-0001",
		Reachable: &domain.ReachabilityResult{IsReachable: reachable}}}
	return r
}

// inFrameFixture is the candidate set the ComposeInFrame tests choose from.
type inFrameFixture struct {
	frame                    domain.Rooting
	own, other, iso          domain.VulnerabilityRecord
	isoA, isoB               domain.VulnerabilityRecord
	conflictOld, conflictNew domain.VulnerabilityRecord
}

func newInFrameFixture(t *testing.T) inFrameFixture {
	t.Helper()
	f := inFrameFixture{frame: projectFrame()}
	f.own = sampleRecord(t)
	f.own.Rooting, f.own.ContentHash = f.frame, "sha256:own"
	f.other = sampleRecord(t)
	f.other.Rooting = domain.TargetRootedAt(coordinatetest.MustNew("example.com/other", "local"))
	f.iso = isolatedRec(t, false)
	f.isoA, f.isoB = isolatedRec(t, false), isolatedRec(t, true)
	f.isoA.Toolchain, f.isoB.Toolchain, f.isoB.ContentHash = "go1.26.5", "go1.27.2", "sha256:iso2"
	f.conflictOld, f.conflictNew = disagreeingPair(t, f.frame)
	return f
}

func TestComposeInFrame_EmptyIsAnAbsence(t *testing.T) {
	t.Parallel()
	if _, _, _, found, err := domain.ComposeInFrame(nil, projectFrame()); found || err != nil {
		t.Errorf("found=%v err=%v, want an absence", found, err)
	}
}

func TestComposeInFrame_TheFrameAnswersWithTheIsolatedAside(t *testing.T) {
	t.Parallel()
	f := newInFrameFixture(t)
	rec, aside, hasAside, found, err := domain.ComposeInFrame([]domain.VulnerabilityRecord{f.own, f.iso, f.other}, f.frame)
	if err != nil || !found || rec.ContentHash != f.own.ContentHash || !hasAside || aside.ContentHash != f.iso.ContentHash {
		t.Errorf("rec=%s aside=%s hasAside=%v found=%v err=%v", rec.ContentHash, aside.ContentHash, hasAside, found, err)
	}
}

func TestComposeInFrame_IsolatedAnswersWhenTheFrameHoldsNone(t *testing.T) {
	t.Parallel()
	f := newInFrameFixture(t)
	rec, _, hasAside, found, err := domain.ComposeInFrame([]domain.VulnerabilityRecord{f.iso, f.other}, f.frame)
	if err != nil || !found || rec.ContentHash != f.iso.ContentHash || hasAside {
		t.Errorf("rec=%s hasAside=%v found=%v err=%v", rec.ContentHash, hasAside, found, err)
	}
}

func TestComposeInFrame_AnotherConsumerNeverAnswers(t *testing.T) {
	t.Parallel()
	f := newInFrameFixture(t)
	if _, _, _, found, err := domain.ComposeInFrame([]domain.VulnerabilityRecord{f.other}, f.frame); found || err != nil {
		t.Errorf("found=%v err=%v, want an absence", found, err)
	}
}

func TestComposeInFrame_IsolatedFrameHasNoAside(t *testing.T) {
	t.Parallel()
	f := newInFrameFixture(t)
	rec, _, hasAside, found, err := domain.ComposeInFrame([]domain.VulnerabilityRecord{f.iso}, domain.RootingIsolated)
	if err != nil || !found || rec.ContentHash != f.iso.ContentHash || hasAside {
		t.Errorf("rec=%s hasAside=%v found=%v err=%v", rec.ContentHash, hasAside, found, err)
	}
}

func TestComposeInFrame_ConflictsThatWouldAnswerAreReturned(t *testing.T) {
	t.Parallel()
	f := newInFrameFixture(t)
	for _, recs := range [][]domain.VulnerabilityRecord{{f.conflictOld, f.conflictNew}, {f.isoA, f.isoB}} {
		_, _, _, found, err := domain.ComposeInFrame(recs, f.frame)
		var c domain.ToolchainConflict
		if found || !errors.As(err, &c) {
			t.Errorf("found=%v err=%v, want the conflict", found, err)
		}
	}
}

func TestComposeInFrame_ADisputedAsideIsDropped(t *testing.T) {
	t.Parallel()
	f := newInFrameFixture(t)
	rec, _, hasAside, found, err := domain.ComposeInFrame([]domain.VulnerabilityRecord{f.own, f.isoA, f.isoB}, f.frame)
	if err != nil || !found || rec.ContentHash != f.own.ContentHash || hasAside {
		t.Errorf("rec=%s hasAside=%v found=%v err=%v", rec.ContentHash, hasAside, found, err)
	}
}
