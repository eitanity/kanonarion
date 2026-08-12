package store_test

import (
	"testing"
	"time"

	localdomain "github.com/eitanity/kanonarion/internal/local/domain"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// The local context does not depend on the vulnerability context, so the rungs
// the local probe reports are spelled out in its own domain rather than
// imported. Two spellings of one ladder is exactly how a ladder drifts, and this
// package is the one place that sees both — the loader here is the seam the
// stored rung crosses on its way into a probe answer.
//
// So the spellings are pinned here. A consumer comparing a probe's negative with
// a stored query's must be comparing words from one vocabulary; if these ever
// diverge, the two surfaces are publishing rungs that only look like each
// other.
func TestProbeRungsSpellTheLadder(t *testing.T) {
	for _, tc := range []struct {
		name  string
		local string
		want  vulndomain.ReachabilitySoundness
	}{
		{"not stated", localdomain.ProbeSoundnessNotStated, vulndomain.SoundnessNotStated},
		{"unconfirmed", localdomain.ProbeSoundnessUnconfirmed, vulndomain.SoundnessUnconfirmed},
	} {
		if tc.local != string(tc.want) {
			t.Errorf("%s: the local probe spells it %q, the ladder spells it %q", tc.name, tc.local, tc.want)
		}
	}
}

// TestProbeAbsenceIsNotConfirmed pins the judgement behind the rung a
// symbol-table absence earns, not just its spelling.
//
// Confirmed means a search ran over a call graph built with function bodies and
// found no path. The probe builds no call graph at all: it reads the linker's
// output and observes that a name is not in it, which is the same class of
// evidence as a binary-mode analyser's symbol table — and NegativeSoundness
// classifies that unconfirmed. Promoting the probe to confirmed would make the
// word mean two different searches.
func TestProbeAbsenceIsNotConfirmed(t *testing.T) {
	if localdomain.ProbeSoundnessUnconfirmed == string(vulndomain.SoundnessConfirmed) {
		t.Fatal("a symbol-table absence reports itself as a search that ran over a built call graph")
	}
	if vulndomain.ReachabilitySoundness(localdomain.ProbeSoundnessUnconfirmed).IsConfirmed() {
		t.Error("a symbol-table absence passes the confirmed-negative gate")
	}
}

// TestLoadFindings_CarriesTheRungAcrossTheSeam pins where the rung is derived.
//
// This loader is the last place that holds the whole stored finding — the
// analyser that produced the verdict and the fidelity it saw at. Below it the
// port carries a bool and some strings, so a probe that derived the rung later
// would be deriving it from nothing. The rung is therefore computed here and
// travels with the verdict.
func TestLoadFindings_CarriesTheRungAcrossTheSeam(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	isolated := vulndomain.RootingIsolated
	neg := reachableFinding("GO-2026-0001", false, isolated)
	neg.Reachable.DerivedBy.Fidelity = "source"
	pos := reachableFinding("GO-2026-0002", true, isolated)

	s := &fakeVulnStore{records: map[string][]vulndomain.VulnerabilityRecord{
		"example.com/dep": {record(coord, recordSpec{
			rooting:   isolated,
			scannedAt: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
			findings:  []vulndomain.VulnerabilityFinding{neg, pos},
		})},
	}}

	got := loadOne(t, s, coord).Findings[coord]
	if len(got) != 2 {
		t.Fatalf("seeded %d finding(s), want 2", len(got))
	}
	byID := map[string]int{}
	for i, f := range got {
		byID[f.ID] = i
	}
	negative := got[byID["GO-2026-0001"]]
	if negative.ReachableSoundness != string(vulndomain.SoundnessInferred) {
		t.Errorf("negative crossed the seam with soundness %q, want inferred", negative.ReachableSoundness)
	}
	if negative.ReachableSoundnessReason == "" {
		t.Error("negative crossed the seam with a rung and no basis behind it")
	}
	positive := got[byID["GO-2026-0002"]]
	if positive.ReachableSoundness != localdomain.ProbeSoundnessNotStated {
		t.Errorf("positive crossed the seam with soundness %q, want none", positive.ReachableSoundness)
	}
}
