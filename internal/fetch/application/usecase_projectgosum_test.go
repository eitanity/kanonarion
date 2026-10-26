package application_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/fetch/application"
	domain2 "code.eitanity.com/kanonarion/internal/fetch/domain"
	"code.eitanity.com/kanonarion/internal/fetch/fetchtest"
	"code.eitanity.com/kanonarion/internal/fetch/ports"
)

// fakeZipHash and fakeGoModHash mirror the hashes fakeProxy.Download computes
// for the default fake download, so a project go.sum fake can be made to agree
// or disagree with the fetched bytes deterministically.
var (
	fakeZipHash   = fetchtest.H1("fakehash==")
	fakeGoModHash = fetchtest.H1("fakegomodhash==")
)

// projectGoSum builds a use case whose network sumdb is disabled but whose
// walk-root go.sum verifier returns res for every coordinate.
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
	wrong := fetchtest.H1("tamperedhash==")
	uc, facts := projectGoSum(t, ports.SumDBResult{Available: true, ZipHash: wrong})

	_, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if !errors.Is(err, application.ErrGoSumVerification) {
		t.Fatalf("Execute err = %v, want ErrGoSumVerification", err)
	}
	if _, ok, rerr := facts.GetFetchRecord(context.Background(), testCoord, "test-0.1.0"); rerr != nil || ok {
		t.Errorf("a record was persisted for a go.sum tamper; want none (read error: %v)", rerr)
	}
}

// The go.mod hash is also cross-checked when go.sum records one: a matching zip
// but mismatched go.mod still fails hard.
func TestExecute_ProjectGoSum_GoModMismatchHardFails(t *testing.T) {
	wrongGoMod := fetchtest.H1("tamperedgomod==")
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

// A go.sum entry on a line whose hash does not parse is never read as absent:
// both the full and the go.mod-only fetch fail hard naming the line, rather
// than falling through to the network checksum database.
func TestExecute_ProjectGoSum_AnUnreadableEntryFailsHardNamingTheLine(t *testing.T) {
	unreadable := ports.SumDBResult{
		Available:      false,
		Reason:         `malformed go.sum line 3: invalid module hash "garbage"`,
		Unavailability: ports.SumDBUnavailabilityFailure,
		Err:            errors.New(`malformed go.sum line 3: invalid module hash "garbage"`),
	}
	for name, goModOnly := range map[string]bool{"full fetch": false, "go.mod-only fetch": true} {
		t.Run(name, func(t *testing.T) {
			uc, facts := projectGoSum(t, unreadable)
			_, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord, GoModOnly: goModOnly})
			if !errors.Is(err, application.ErrGoSumVerification) || !strings.Contains(err.Error(), "malformed go.sum line 3") {
				t.Fatalf("Execute err = %v, want ErrGoSumVerification naming the line", err)
			}
			if _, ok, rerr := facts.GetFetchRecord(context.Background(), testCoord, "test-0.1.0"); rerr != nil || ok {
				t.Errorf("a record was persisted over an unreadable go.sum entry; want none (read error: %v)", rerr)
			}
		})
	}
}
