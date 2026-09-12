package application_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// gitNotInstalled is what a VCSClient returns on a host with no git binary. It
// wraps ports.ErrVCSToolMissing exactly as the gitexec adapter does, which is
// the contract the fetch pipeline matches on.
func gitNotInstalled() error {
	return fmt.Errorf("%w: git not found in PATH", ports.ErrVCSToolMissing)
}

// TestVCSToolMissingRecordIsReVerifiedNotServedFromCache is the regression guard.
// Before it, a host with no git recorded VerifiedBySumDBOnly for every module it
// fetched and the cache served that answer on every later run, so a property of
// one machine became a permanent property of the module and only --force undid
// it.
func TestVCSToolMissingRecordIsReVerifiedNotServedFromCache(t *testing.T) {
	vcs := &fakeVCS{resolveErr: gitNotInstalled(), checkoutErr: gitNotInstalled()}
	uc := newUseCaseWithSumDB(newProxyWithOrigin(), vcs, newFakeBlob(), newFakeFacts(),
		availableSumDB(fetchtest.H1("fakehash==")))

	first, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	if got := first.Record.VCSCheck; got != string(domain2.LegUnavailable) {
		t.Fatalf("VCSCheck = %q, want %q: the host fault is recorded as a fact about the module",
			got, domain2.LegUnavailable)
	}
	if domain2.RecordIsCacheable(first.Record.FactRecord) {
		t.Error("a record whose git leg could not run is cacheable, so the downgrade is permanent")
	}

	// Still no git: the record is re-verified rather than served, and says the
	// same thing again.
	second, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if second.FromCache {
		t.Fatal("the record was served from cache: a host fault is a permanent finding again")
	}

	// git is installed. An ordinary run — no --force — must re-establish the leg.
	vcs.resolveErr, vcs.checkoutErr = nil, nil
	third, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("third Execute: %v", err)
	}
	if third.FromCache {
		t.Fatal("the run on a host with git served the old record instead of re-verifying")
	}
	if got := third.Record.VCSCheck; got != string(domain2.LegRechecked) {
		t.Errorf("VCSCheck = %q, want %q: the check ran and its result was not recorded", got, domain2.LegRechecked)
	}
	if !domain2.RecordIsCacheable(third.Record.FactRecord) {
		t.Fatal("the re-established record is still not cacheable, so every future run re-fetches")
	}

	fourth, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("fourth Execute: %v", err)
	}
	if !fourth.FromCache {
		t.Error("caching stayed disabled for the coordinate after the leg was re-established")
	}
}

// TestVCSCheckRanAndDisagreedStaysCacheable is the control for a real finding:
// the checkout succeeded and reproduced a different tree. That is an answer
// about the module, so the status stands and the record is served as before.
func TestVCSCheckRanAndDisagreedStaysCacheable(t *testing.T) {
	// checkoutErr nil → the checkout lands in an empty directory whose hash
	// cannot match the proxy zip, which is the mismatch path.
	uc := newUseCaseWithSumDB(newProxyWithOrigin(), &fakeVCS{}, newFakeBlob(), newFakeFacts(),
		availableSumDB(fetchtest.H1("fakehash==")))

	first, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	if got := first.Record.VerificationStatus; got != string(domain2.VerifiedBySumDBOnly) {
		t.Errorf("VerificationStatus = %q, want %q", got, domain2.VerifiedBySumDBOnly)
	}
	if got := first.Record.VCSCheck; got != string(domain2.LegRechecked) {
		t.Errorf("VCSCheck = %q, want %q: a check that ran was recorded as one that could not", got, domain2.LegRechecked)
	}
	if !domain2.RecordIsCacheable(first.Record.FactRecord) {
		t.Fatal("a mismatch finding is not cacheable: real findings now cost a re-fetch every run")
	}
	second, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if !second.FromCache {
		t.Error("the mismatch record was re-fetched rather than served")
	}
}

// TestModuleWithNoVCSAnchorStaysCacheable is the control for the vanity hosts —
// a module path no forge URL can be inferred from. Nothing was attempted, there
// is no host fault, and the record is served exactly as before.
func TestModuleWithNoVCSAnchorStaysCacheable(t *testing.T) {
	// A single-segment path: no forge URL can be inferred, so git is never asked.
	coord := coordinatetest.MustNew("example.com", "v1.0.0")
	vcs := &fakeVCS{resolveErr: errors.New("git must not be asked for a module with no inferable URL")}
	uc := newUseCaseWithSumDB(&fakeProxy{}, vcs, newFakeBlob(), newFakeFacts(),
		availableSumDB(fetchtest.H1("fakehash==")))

	first, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	if got := first.Record.VerificationStatus; got != string(domain2.VerifiedBySumDBOnly) {
		t.Errorf("VerificationStatus = %q, want %q", got, domain2.VerifiedBySumDBOnly)
	}
	if got := first.Record.VCSCheck; got == string(domain2.LegUnavailable) {
		t.Error("a module with no VCS anchor was recorded as a host fault")
	}
	if !domain2.RecordIsCacheable(first.Record.FactRecord) {
		t.Fatal("a module with no VCS anchor is no longer cacheable")
	}
	second, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if !second.FromCache {
		t.Error("the record was re-fetched rather than served")
	}
}

// TestSkipVCSVerifyRecordsAnAbsentLegEvenWithoutGit is the control for the
// operator's own choice. --skip-vcs-verify asks for no VCS leg; that request is
// answered the same way whether or not the host happens to have git, and the
// record stays cacheable so the flag does not disable caching.
func TestSkipVCSVerifyRecordsAnAbsentLegEvenWithoutGit(t *testing.T) {
	vcs := &fakeVCS{resolveErr: gitNotInstalled(), checkoutErr: gitNotInstalled()}
	uc := newUseCaseWithSumDB(&fakeProxy{}, vcs, newFakeBlob(), newFakeFacts(),
		availableSumDB(fetchtest.H1("fakehash==")))

	first, err := uc.Execute(context.Background(), application.FetchRequest{
		Coordinate: testCoord, SkipVCSVerify: true,
	})
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	if got := first.Record.VCSCheck; got != string(domain2.LegAbsent) {
		t.Errorf("VCSCheck = %q, want the absent leg the operator asked for", got)
	}
	if !domain2.RecordIsCacheable(first.Record.FactRecord) {
		t.Fatal("--skip-vcs-verify made the record un-cacheable, so the flag now costs a re-fetch every run")
	}
	second, err := uc.Execute(context.Background(), application.FetchRequest{
		Coordinate: testCoord, SkipVCSVerify: true,
	})
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if !second.FromCache {
		t.Error("a --skip-vcs-verify record was re-fetched rather than served")
	}
}
