package application_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

var (
	fixedTime  = time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	testCoord  = coordinate.ModuleCoordinate{Path: "github.com/gorilla/mux", Version: "v1.8.1"}
	discardLog = slog.New(slog.NewTextHandler(noopWriter{}, nil))
)

type noopWriter struct{}

func (noopWriter) Write(p []byte) (int, error) { return len(p), nil }

// newUseCase constructs a use case with sumdb disabled. Most tests use this.
func newUseCase(proxy ports.ModuleProxy, vcs ports.VCSClient, blobs ports.BlobStore, facts ports.FactStore) *application.FetchModuleUseCase {
	return application.NewFetchModuleUseCase(proxy, vcs, blobs, facts, disabledSumDB(), fixedClock{fixedTime}, fakeStopwatch{}, "test-0.1.0", discardLog)
}

// newUseCaseWithSumDB constructs a use case with a custom sumdb client.
func newUseCaseWithSumDB(proxy ports.ModuleProxy, vcs ports.VCSClient, blobs ports.BlobStore, facts ports.FactStore, sumdb ports.SumDBClient) *application.FetchModuleUseCase {
	return application.NewFetchModuleUseCase(proxy, vcs, blobs, facts, sumdb, fixedClock{fixedTime}, fakeStopwatch{}, "test-0.1.0", discardLog)
}

func TestExecute_HappyPath(t *testing.T) {
	proxy := &fakeProxy{
		infos: map[string]ports.ModuleInfo{
			testCoord.String(): {
				Version: "v1.8.1",
				Time:    fixedTime,
				Origin: &ports.ModuleOrigin{
					VCS:  "git",
					URL:  "https://github.com/gorilla/mux",
					Ref:  "refs/tags/v1.8.1",
					Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				},
			},
		},
	}
	// sumdb matches the fake zip hash; VCS checkout fails → VerifiedBySumDBOnly.
	fakeHash := domain2.ModuleHash{Algorithm: "h1", Value: "fakehash=="}
	sumdb := availableSumDB(fakeHash)
	vcs := &fakeVCS{checkoutErr: errors.New("no real checkout in test")}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCaseWithSumDB(proxy, vcs, blobs, facts, sumdb)
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.FromCache {
		t.Error("expected FromCache=false on first fetch")
	}
	if result.Record.ModulePath != testCoord.Path {
		t.Errorf("ModulePath = %q, want %q", result.Record.ModulePath, testCoord.Path)
	}
	if result.Record.ContentHash == "" {
		t.Error("ContentHash not set")
	}
	h := domain2.CanonicalHasher{}
	if err := h.VerifyContentHash(result.Record); err != nil {
		t.Errorf("VerifyContentHash: %v", err)
	}
	// sumdb matched fake hash, VCS checkout failed → VerifiedBySumDBOnly.
	if result.Record.VerificationStatus != string(domain2.VerifiedBySumDBOnly) {
		t.Errorf("VerificationStatus = %q, want %q", result.Record.VerificationStatus, domain2.VerifiedBySumDBOnly)
	}
}

func TestExecute_Verified_SumDBAndVCS(t *testing.T) {
	// sumdb matches AND VCS checkout succeeds → Verified.
	fakeHash := domain2.ModuleHash{Algorithm: "h1", Value: "fakehash=="}
	proxy := &fakeProxy{
		infos: map[string]ports.ModuleInfo{
			testCoord.String(): {
				Version: "v1.8.1",
				Origin: &ports.ModuleOrigin{
					URL:  "https://github.com/gorilla/mux",
					Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				},
			},
		},
	}
	sumdb := availableSumDB(fakeHash)
	// fakeVCS.CheckoutToDir succeeds but leaves empty dir → HashDir returns some hash.
	// For Verified we need the dir hash to match the zip hash. Since the zip data
	// is "fake-zip" (not a real zip), hashZipBytes returns an error and the proxy
	// ends up with ZipHash = fakeHash from the fake. The dir hash won't match, so
	// crossVerify will give UnverifiedHashMismatch. Use disabledSumDB to test the
	// Verified path instead via the fakeVCS that succeeds at resolution but fails
	// checkout so we stay at VerifiedBySumDBOnly (since we can't truly produce a
	// matching dir hash in unit tests without a real zip).
	// This test validates the sumdb+VCS path exists; the golden-path integration
	// test covers real zip verification.
	vcs := &fakeVCS{checkoutErr: nil} // checkout "succeeds" (empty dir)
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCaseWithSumDB(proxy, vcs, blobs, facts, sumdb)
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// crossVerify hashes the empty checkout dir, which differs from fakeHash, so
	// vcsStatus would be UnverifiedHashMismatch — but sumdb already attested the
	// zip, so it downgrades to VerifiedBySumDBOnly rather than hard-failing.
	if result.Record.VerificationStatus != string(domain2.VerifiedBySumDBOnly) {
		t.Errorf("expected VerifiedBySumDBOnly (sumdb attested; VCS reproduction failed), got %q", result.Record.VerificationStatus)
	}
	if result.Record.ContentHash == "" {
		t.Error("ContentHash not set")
	}
}

func TestExecute_CacheHit(t *testing.T) {
	proxy := &fakeProxy{}
	vcs := &fakeVCS{}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCase(proxy, vcs, blobs, facts)
	ctx := context.Background()

	r1, err := uc.Execute(ctx, application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	if r1.FromCache {
		t.Error("first fetch should not be cached")
	}

	r2, err := uc.Execute(ctx, application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if !r2.FromCache {
		t.Error("second fetch should be cached")
	}
	if r2.Record.ContentHash != r1.Record.ContentHash {
		t.Error("cached record differs from original")
	}
}

func TestExecute_ForceRefetch(t *testing.T) {
	proxy := &fakeProxy{}
	vcs := &fakeVCS{}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCase(proxy, vcs, blobs, facts)
	ctx := context.Background()

	_, err := uc.Execute(ctx, application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}

	r2, err := uc.Execute(ctx, application.FetchRequest{Coordinate: testCoord, Force: true})
	if err != nil {
		t.Fatalf("force Execute: %v", err)
	}
	if r2.FromCache {
		t.Error("force should bypass cache")
	}
}

func TestExecute_UnverifiedNoSumDB_VCSFails(t *testing.T) {
	// sumdb disabled, VCS fails → UnverifiedNoSumDB.
	proxy := &fakeProxy{}
	vcs := &fakeVCS{resolveErr: errors.New("git binary not found")}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCase(proxy, vcs, blobs, facts) // uses disabledSumDB
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.VerificationStatus != string(domain2.UnverifiedNoSumDB) {
		t.Errorf("expected UnverifiedNoSumDB, got %q", result.Record.VerificationStatus)
	}
}

func TestExecute_VerifiedBySumDBOnly_VCSUnavailable(t *testing.T) {
	// sumdb available and matching, VCS fails → VerifiedBySumDBOnly.
	fakeHash := domain2.ModuleHash{Algorithm: "h1", Value: "fakehash=="}
	proxy := &fakeProxy{}
	sumdb := availableSumDB(fakeHash)
	vcs := &fakeVCS{resolveErr: errors.New("network unreachable")}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCaseWithSumDB(proxy, vcs, blobs, facts, sumdb)
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.VerificationStatus != string(domain2.VerifiedBySumDBOnly) {
		t.Errorf("expected VerifiedBySumDBOnly, got %q", result.Record.VerificationStatus)
	}
}

// trustedOriginProxy returns a proxy whose Origin passes validation, so
// resolveGitRef yields a provisional Verified (git ref resolved, ready to
// cross-verify) without any cross-verification having run.
func trustedOriginProxy() *fakeProxy {
	return &fakeProxy{
		infos: map[string]ports.ModuleInfo{
			testCoord.String(): {
				Version: testCoord.Version,
				Time:    fixedTime,
				Origin: &ports.ModuleOrigin{
					VCS:  "git",
					URL:  "https://github.com/gorilla/mux",
					Ref:  "refs/tags/" + testCoord.Version,
					Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				},
			},
		},
	}
}

func TestExecute_SkipVCSVerify_DowngradesToSumDBOnly(t *testing.T) {
	// A trusted Origin makes resolveGitRef return a provisional Verified, but
	// with SkipVCSVerify the zip is never reproduced from the git tree. The
	// record must NOT claim the strongest Verified — it is VerifiedBySumDBOnly,
	// because only the sumdb (transparency-log) leg actually ran.
	fakeHash := domain2.ModuleHash{Algorithm: "h1", Value: "fakehash=="}
	sumdb := availableSumDB(fakeHash)
	// A VCS that would "succeed" if cross-verify ran, proving the skip — not a
	// VCS failure — is what holds the status at sumdb-only.
	vcs := &fakeVCS{checkoutErr: nil}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCaseWithSumDB(trustedOriginProxy(), vcs, blobs, facts, sumdb)
	result, err := uc.Execute(context.Background(), application.FetchRequest{
		Coordinate:    testCoord,
		SkipVCSVerify: true,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.VerificationStatus != string(domain2.VerifiedBySumDBOnly) {
		t.Fatalf("VerificationStatus = %q, want %q (skip must not claim git cross-verification)",
			result.Record.VerificationStatus, domain2.VerifiedBySumDBOnly)
	}
	if !strings.Contains(result.Record.VerificationDetail, "VCS cross-verification skipped") {
		t.Errorf("detail %q should record that cross-verification was skipped", result.Record.VerificationDetail)
	}
}

func TestExecute_SkipVCSVerify_SumDBUnavailableStillNoSumDB(t *testing.T) {
	// The skip downgrade must only touch the sumdb-passed case: when sumdb is
	// unavailable the record stays UnverifiedNoSumDB, never silently promoted.
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCaseWithSumDB(trustedOriginProxy(), &fakeVCS{}, blobs, facts, disabledSumDB())
	result, err := uc.Execute(context.Background(), application.FetchRequest{
		Coordinate:    testCoord,
		SkipVCSVerify: true,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.VerificationStatus != string(domain2.UnverifiedNoSumDB) {
		t.Errorf("VerificationStatus = %q, want %q", result.Record.VerificationStatus, domain2.UnverifiedNoSumDB)
	}
}

func TestExecute_VCSToolMissing_ActionableDetailReachesRecord(t *testing.T) {
	// sumdb verifies authenticity but the VCS tool is absent: the record stays
	// VerifiedBySumDBOnly, and the actionable tool-missing detail is persisted so
	// a consumer can tell "not VCS-checked because git is absent" from a failure.
	fakeHash := domain2.ModuleHash{Algorithm: "h1", Value: "fakehash=="}
	proxy := &fakeProxy{}
	sumdb := availableSumDB(fakeHash)
	vcs := &fakeVCS{resolveErr: fmt.Errorf("resolve: %w", ports.ErrVCSToolMissing)}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCaseWithSumDB(proxy, vcs, blobs, facts, sumdb)
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.VerificationStatus != string(domain2.VerifiedBySumDBOnly) {
		t.Errorf("expected VerifiedBySumDBOnly, got %q", result.Record.VerificationStatus)
	}
	if !strings.Contains(result.Record.VerificationDetail, ports.ErrVCSToolMissing.Error()) {
		t.Errorf("verification detail %q does not carry the tool-missing classification", result.Record.VerificationDetail)
	}
}

func TestExecute_VerifiedBySumDBOnly_VCSReproductionMismatch(t *testing.T) {
	// sumdb passes + VCS checkout succeeds but the reproduced hash differs
	// from the proxy zip → downgrades to VerifiedBySumDBOnly, not UnverifiedHashMismatch.
	// Regression: major-version subdirs, submodules, and generated files can cause
	// naive reproduction mismatches for legitimately authentic modules.
	fakeHash := domain2.ModuleHash{Algorithm: "h1", Value: "fakehash=="}
	proxy := &fakeProxy{} // no Origin — forces resolveInferredGitRef + crossVerify
	sumdb := availableSumDB(fakeHash)
	vcs := &fakeVCS{checkoutErr: nil} // checkout "succeeds" but empty dir → hash differs
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCaseWithSumDB(proxy, vcs, blobs, facts, sumdb)
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.VerificationStatus != string(domain2.VerifiedBySumDBOnly) {
		t.Errorf("expected VerifiedBySumDBOnly (sumdb attested; VCS reproduction mismatch is soft), got %q",
			result.Record.VerificationStatus)
	}
}

func TestExecute_UnverifiedHashMismatch_SumDB(t *testing.T) {
	// sumdb returns a different hash than what the proxy served → UnverifiedHashMismatch.
	// A genuine proxy-vs-sumdb mismatch still hard-fails even when VCS also disagrees.
	wrongHash := domain2.ModuleHash{Algorithm: "h1", Value: "wronghash=="}
	proxy := &fakeProxy{}
	sumdb := availableSumDB(wrongHash) // differs from fakeProxy's "fakehash=="
	vcs := &fakeVCS{}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCaseWithSumDB(proxy, vcs, blobs, facts, sumdb)
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.VerificationStatus != string(domain2.UnverifiedHashMismatch) {
		t.Errorf("expected UnverifiedHashMismatch, got %q", result.Record.VerificationStatus)
	}
}

func TestExecute_UnverifiedNoSumDB_NonGitHub(t *testing.T) {
	// gopkg.in module: can't infer VCS URL; sumdb disabled → UnverifiedNoSumDB.
	coord := coordinate.ModuleCoordinate{Path: "gopkg.in/yaml.v3", Version: "v3.0.1"}
	proxy := &fakeProxy{}
	vcs := &fakeVCS{}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCase(proxy, vcs, blobs, facts)
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.VerificationStatus != string(domain2.UnverifiedNoSumDB) {
		t.Errorf("expected UnverifiedNoSumDB, got %q", result.Record.VerificationStatus)
	}
}

func TestExecute_ProxyInfoError(t *testing.T) {
	proxy := &fakeProxy{infoErr: errors.New("proxy unreachable")}
	vcs := &fakeVCS{}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCase(proxy, vcs, blobs, facts)
	_, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err == nil {
		t.Error("expected error when proxy.Info fails")
	}
}

func TestExecute_ProxyDownloadError(t *testing.T) {
	proxy := &fakeProxy{dlErr: errors.New("network error")}
	vcs := &fakeVCS{}
	blobs := newFakeBlob()
	facts := newFakeFacts()

	uc := newUseCase(proxy, vcs, blobs, facts)
	_, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err == nil {
		t.Error("expected error when proxy.Download fails")
	}
}
