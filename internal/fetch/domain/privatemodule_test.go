package domain_test

import (
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

// TestPrivateModuleVCSLeg_IsDatedCacheableAndNeverEvidence: the withheld git
// leg is this record's own moment, keeps the record cacheable, and counts as
// no cross-verification evidence.
func TestPrivateModuleVCSLeg_IsDatedCacheableAndNeverEvidence(t *testing.T) {
	r := fetchtest.Record(t, fetchtest.Status(domain2.VerifiedByGoSum), fetchtest.VCSCheck(domain2.LegPrivateModule, ""))
	legs := domain2.RecordLegs(r)
	if len(legs) != 1 || legs[0].Provenance != domain2.LegPrivateModule || legs[0].EstablishedAt == "" {
		t.Fatalf("legs = %+v, want one dated private-module VCS leg", legs)
	}
	if !domain2.RecordIsCacheable(r) {
		t.Error("a private-module record is not cacheable; it is a settled answer about the module")
	}
	if got := domain2.VCSEvidenceOf(legs, true); got != domain2.VCSNever {
		t.Errorf("VCSEvidenceOf = %v, want VCSNever", got)
	}
}

// TestComposeKeepsEstablishedLegOverPrivateModule: a later private-route run
// establishes nothing, so it must not displace a git leg the ledger holds.
func TestComposeKeepsEstablishedLegOverPrivateModule(t *testing.T) {
	earlier := fetchtest.Record(t,
		fetchtest.Status(domain2.Verified),
		fetchtest.SumDBCheck(domain2.LegRechecked, ""),
		fetchtest.VCSCheck(domain2.LegRechecked, ""),
		fetchtest.FetchedAt(sampleRecord().FetchedAt))
	later := fetchtest.Record(t,
		fetchtest.Status(domain2.VerifiedByGoSum),
		fetchtest.VCSCheck(domain2.LegPrivateModule, ""),
		fetchtest.FetchedAt(sampleRecord().FetchedAt.Add(24*time.Hour)))

	c, err := domain2.Compose([]domain2.FactRecord{earlier, later})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got := domain2.VCSEvidenceOf(c.Legs, true); got != domain2.VCSRechecked {
		t.Errorf("composed VCS evidence = %v, want VCSRechecked", got)
	}
}

// TestNotFetchedRemedy_PrivateModuleNamesTheProjectRoute: with the rule
// installed, a private module's remedy is the fetch against the project's
// go.mod; every other module keeps the plain fetch.
func TestNotFetchedRemedy_PrivateModuleNamesTheProjectRoute(t *testing.T) {
	domain2.SetPrivateModuleRule(func(path string) bool { return path == "corp.example.com/a" })
	t.Cleanup(func() { domain2.SetPrivateModuleRule(nil) })
	if got, want := domain2.NotFetchedRemedy(coordinatetest.MustNew("corp.example.com/a", "v1.0.0")),
		"run 'kanonarion fetch corp.example.com/a@v1.0.0 --gomod <path to the project's go.mod>' from the project "+
			"that requires it (a private module is verified against its go.sum)"; got != want {
		t.Errorf("remedy = %q, want %q", got, want)
	}
	if got := domain2.NotFetchedRemedy(coordinatetest.MustNew("example.org/pub", "v1.0.0")); got != "run 'kanonarion fetch example.org/pub@v1.0.0' first" {
		t.Errorf("public remedy = %q", got)
	}
	domain2.SetPrivateModuleRule(nil)
	if got := domain2.NotFetchedRemedy(coordinatetest.MustNew("corp.example.com/a", "v1.0.0")); got != "run 'kanonarion fetch corp.example.com/a@v1.0.0' first" {
		t.Errorf("with no rule, remedy = %q", got)
	}
}
