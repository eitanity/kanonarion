package application_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	"code.eitanity.com/kanonarion/internal/fetch/application"
	domain2 "code.eitanity.com/kanonarion/internal/fetch/domain"
	"code.eitanity.com/kanonarion/internal/fetch/fetchtest"
	"code.eitanity.com/kanonarion/internal/fetch/ports"
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

// remoteTimedOut is what the gitexec adapter returns when a fetch exceeds its
// bound: the ports sentinel, with the bound named in the message.
func remoteTimedOut() error {
	return fmt.Errorf("git fetch --depth=1 --end-of-options origin aaaa exceeded the 2m0s fetch bound: %w",
		ports.ErrVCSRemoteTimeout)
}

// A cross-check whose remote did not answer within the bound could not run. It
// is recorded like a host with no git — unavailable, no binding, not cacheable —
// so the next ordinary fetch checks again instead of serving the stall back.
func TestVCSRemoteTimeoutRecordIsReVerifiedNotServedFromCache(t *testing.T) {
	vcs := &fakeVCS{checkoutErr: remoteTimedOut()}
	uc := newUseCaseWithSumDB(newProxyWithOrigin(), vcs, newFakeBlob(), newFakeFacts(),
		availableSumDB(fetchtest.H1("fakehash==")))

	first, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	if got := first.Record.VCSCheck; got != string(domain2.LegUnavailable) {
		t.Fatalf("VCSCheck = %q, want %q: a timeout was stored as a check that ran", got, domain2.LegUnavailable)
	}
	if got := first.Record.VCSURLBinding; got != "" {
		t.Errorf("VCSURLBinding = %q on a leg that timed out, want empty", got)
	}
	if got := first.Record.VerificationStatus; got != string(domain2.VerifiedBySumDBOnly) {
		t.Errorf("VerificationStatus = %q, want %q", got, domain2.VerifiedBySumDBOnly)
	}
	if !strings.Contains(first.Record.VerificationDetail, "exceeded the 2m0s fetch bound") {
		t.Errorf("detail %q does not name the fetch bound", first.Record.VerificationDetail)
	}
	if domain2.RecordIsCacheable(first.Record.FactRecord) {
		t.Fatal("a record whose git leg timed out is cacheable, so the stall is permanent")
	}

	// The remote answers now. An ordinary run — no --force — re-runs the check.
	vcs.checkoutErr = nil
	second, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if second.FromCache {
		t.Fatal("the timed-out record was served from cache instead of re-verified")
	}
	if vcs.checkouts != 2 {
		t.Errorf("CheckoutToDir ran %d time(s), want 2: the cross-check was not re-run", vcs.checkouts)
	}
	if got := second.Record.VCSCheck; got != string(domain2.LegRechecked) {
		t.Errorf("VCSCheck = %q, want %q", got, domain2.LegRechecked)
	}
}

// A tag resolution whose remote did not answer within the bound could not run
// either, and is recorded exactly as a timed-out fetch is.
func TestVCSResolveTimeoutRecordIsReVerifiedNotServedFromCache(t *testing.T) {
	coord := coordinatetest.MustNew("github.com/pkg/errors", "v0.9.1")
	vcs := &fakeVCS{resolveErr: fmt.Errorf(
		"ls-remote https://github.com/pkg/errors refs/tags/v0.9.1: git ls-remote --exit-code exceeded the 2m0s fetch bound: %w",
		ports.ErrVCSRemoteTimeout)}
	uc := newUseCaseWithSumDB(&fakeProxy{}, vcs, newFakeBlob(), newFakeFacts(),
		availableSumDB(fetchtest.H1("fakehash==")))

	first, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	if got := first.Record.VCSCheck; got != string(domain2.LegUnavailable) {
		t.Fatalf("VCSCheck = %q, want %q: a timed-out ls-remote was stored as a check that ran", got, domain2.LegUnavailable)
	}
	if got := first.Record.VCSURLBinding; got != "" {
		t.Errorf("VCSURLBinding = %q on a leg that timed out, want empty", got)
	}
	if got := first.Record.VerificationStatus; got != string(domain2.VerifiedBySumDBOnly) {
		t.Errorf("VerificationStatus = %q, want %q", got, domain2.VerifiedBySumDBOnly)
	}
	if !strings.Contains(first.Record.VerificationDetail, "exceeded the 2m0s fetch bound") {
		t.Errorf("detail %q does not name the fetch bound", first.Record.VerificationDetail)
	}
	if domain2.RecordIsCacheable(first.Record.FactRecord) {
		t.Fatal("a record whose tag resolution timed out is cacheable")
	}
	if vcs.checkouts != 0 {
		t.Errorf("CheckoutToDir ran %d time(s) after resolution timed out, want 0", vcs.checkouts)
	}

	vcs.resolveErr = nil
	second, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if second.FromCache {
		t.Fatal("the timed-out record was served from cache instead of re-verified")
	}
	if vcs.resolves != 2 || vcs.checkouts != 1 {
		t.Errorf("ResolveTag ran %d, CheckoutToDir %d time(s); want 2 and 1: the leg was not re-run", vcs.resolves, vcs.checkouts)
	}
	if got := second.Record.VCSCheck; got != string(domain2.LegRechecked) {
		t.Errorf("VCSCheck = %q, want %q", got, domain2.LegRechecked)
	}
}

// preFixTimeoutDetail is the detail of a road-test record written before a
// timed-out leg was recorded as unavailable.
const preFixTimeoutDetail = "checkout: git fetch: exit status 128: fatal: Unable to create '/var/tmp/kanonarion-verify-2016628119/.git/shallow.lock': File exists.\n\n" +
	"Another git process seems to be running in this repository, e.g.\nan editor opened by 'git commit'. Please make sure all processes\n" +
	"are terminated then try again. If it still fails, a git process\nmay have crashed in this repository earlier:\nremove the file manually to continue.\n" +
	" (after: git fetch --depth=1 --end-of-options origin 0016334f314179e3bb1d63ac7a5dbcb2ee7b3ee1 exceeded the 2m0s fetch bound: signal: killed: )"

// A record stored before the fix says its leg was rechecked although the fetch
// timed out. An ordinary fetch re-checks it and writes the new measurement
// beside it; the same record without the phrase is served from cache, which is
// what makes the first half a measurement rather than a cache miss.
func TestPreFixTimedOutRecordIsReVerifiedNotServedFromCache(t *testing.T) {
	for _, tc := range []struct {
		name      string
		detail    string
		wantCache bool
	}{
		{"timed out before the fix", preFixTimeoutDetail, false},
		{"control: ordinary rechecked record", "proxy hash h1:a= does not match git checkout hash h1:b=", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blobs, facts := newFakeBlob(), newFakeFacts()
			seeded := fetchtest.Record(t,
				fetchtest.Coordinate(testCoord),
				fetchtest.ModuleHash(fetchtest.H1("seed==")),
				fetchtest.GoModHash(fetchtest.H1("seedmod==")),
				fetchtest.Status(domain2.VerifiedBySumDBOnly),
				fetchtest.Detail(tc.detail),
				fetchtest.VCSCheck(domain2.LegRechecked, ""),
				fetchtest.FetchedAt(fixedTime),
				fetchtest.PipelineVersion("test-0.1.0"),
			)
			for _, id := range []ports.BlobIdentity{fetchtest.ZipIdentity(t, seeded), fetchtest.GoModIdentity(t, seeded)} {
				if err := blobs.Put(context.Background(), id, strings.NewReader("seeded")); err != nil {
					t.Fatalf("seed blob: %v", err)
				}
			}
			if err := facts.PutFetchRecord(context.Background(), mustSealRecord(t, seeded)); err != nil {
				t.Fatalf("seed record: %v", err)
			}
			vcs := &fakeVCS{}
			uc := newUseCaseWithSumDB(newProxyWithOrigin(), vcs, blobs, facts, availableSumDB(fetchtest.H1("fakehash==")))

			res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if res.FromCache != tc.wantCache {
				t.Fatalf("FromCache = %v, want %v", res.FromCache, tc.wantCache)
			}
			if !tc.wantCache && vcs.checkouts != 1 {
				t.Errorf("CheckoutToDir ran %d time(s), want 1: the cross-check was not re-run", vcs.checkouts)
			}
		})
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
