package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// fakeZipHash and fakeGoModHash mirror the hashes fakeProxy.Download computes
// for the default fake download, so a project go.sum fake can be made to agree
// or disagree with the fetched bytes deterministically.
var (
	fakeZipHash   = domain2.ModuleHash{Algorithm: "h1", Value: "fakehash=="}
	fakeGoModHash = domain2.ModuleHash{Algorithm: "h1", Value: "fakegomodhash=="}
)

// projectGoSum builds a use case whose network sumdb is disabled but whose
// walk-root go.sum verifier returns res for every coordinate (KN-404).
func projectGoSum(t *testing.T, res ports.SumDBResult) (*application.FetchModuleUseCase, *fakeFacts) {
	t.Helper()
	proxy := &fakeProxy{}
	vcs := &fakeVCS{checkoutErr: errors.New("no checkout in test")}
	facts := newFakeFacts()
	uc := newUseCaseWithSumDB(proxy, vcs, newFakeBlob(), facts, disabledSumDB()).
		WithProjectGoSum(&fakeSumDB{result: res})
	return uc, facts
}

// A matching local go.sum entry, with the network checksum DB unavailable,
// elevates the outcome to VerifiedByGoSum rather than UnverifiedNoSumDB.
func TestExecute_ProjectGoSum_MatchElevatesToVerifiedByGoSum(t *testing.T) {
	uc, _ := projectGoSum(t, ports.SumDBResult{Available: true, ZipHash: fakeZipHash})

	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.VerificationStatus != string(domain2.VerifiedByGoSum) {
		t.Errorf("VerificationStatus = %q, want %q", result.Record.VerificationStatus, domain2.VerifiedByGoSum)
	}
}

// A present-but-mismatched zip entry is tamper-evidence: Execute fails hard with
// ErrGoSumVerification and persists no record.
func TestExecute_ProjectGoSum_ZipMismatchHardFails(t *testing.T) {
	wrong := domain2.ModuleHash{Algorithm: "h1", Value: "tamperedhash=="}
	uc, facts := projectGoSum(t, ports.SumDBResult{Available: true, ZipHash: wrong})

	_, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if !errors.Is(err, application.ErrGoSumVerification) {
		t.Fatalf("Execute err = %v, want ErrGoSumVerification", err)
	}
	if _, ok, _ := facts.GetFetchRecord(context.Background(), testCoord, "test-0.1.0"); ok {
		t.Error("a record was persisted for a go.sum tamper; want none")
	}
}

// The go.mod hash is also cross-checked when go.sum records one: a matching zip
// but mismatched go.mod still fails hard.
func TestExecute_ProjectGoSum_GoModMismatchHardFails(t *testing.T) {
	wrongGoMod := domain2.ModuleHash{Algorithm: "h1", Value: "tamperedgomod=="}
	uc, _ := projectGoSum(t, ports.SumDBResult{Available: true, ZipHash: fakeZipHash, GoModHash: wrongGoMod})

	_, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if !errors.Is(err, application.ErrGoSumVerification) {
		t.Fatalf("Execute err = %v, want ErrGoSumVerification", err)
	}
}

// A matching go.mod entry passes (no false mismatch when go.sum records /go.mod).
func TestExecute_ProjectGoSum_GoModMatchPasses(t *testing.T) {
	uc, _ := projectGoSum(t, ports.SumDBResult{Available: true, ZipHash: fakeZipHash, GoModHash: fakeGoModHash})

	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.VerificationStatus != string(domain2.VerifiedByGoSum) {
		t.Errorf("VerificationStatus = %q, want %q", result.Record.VerificationStatus, domain2.VerifiedByGoSum)
	}
}

// A module absent from go.sum is not a hard failure on the normal path: it falls
// through to network sumdb verification (here disabled → UnverifiedNoSumDB).
func TestExecute_ProjectGoSum_AbsentFallsThrough(t *testing.T) {
	uc, _ := projectGoSum(t, ports.SumDBResult{Available: false, Reason: "not in go.sum"})

	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.VerificationStatus != string(domain2.UnverifiedNoSumDB) {
		t.Errorf("VerificationStatus = %q, want %q (fall-through to network sumdb)",
			result.Record.VerificationStatus, domain2.UnverifiedNoSumDB)
	}
}

// go.sum complements, never downgrades, the network path: when the network
// checksum DB verifies the zip, the stronger VerifiedBySumDBOnly stands even
// though the local go.sum also agreed.
func TestExecute_ProjectGoSum_NetworkSumDBRemainsPrimary(t *testing.T) {
	proxy := &fakeProxy{}
	vcs := &fakeVCS{checkoutErr: errors.New("no checkout in test")}
	uc := newUseCaseWithSumDB(proxy, vcs, newFakeBlob(), newFakeFacts(), availableSumDB(fakeZipHash)).
		WithProjectGoSum(&fakeSumDB{result: ports.SumDBResult{Available: true, ZipHash: fakeZipHash}})

	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.VerificationStatus != string(domain2.VerifiedBySumDBOnly) {
		t.Errorf("VerificationStatus = %q, want %q", result.Record.VerificationStatus, domain2.VerifiedBySumDBOnly)
	}
}
