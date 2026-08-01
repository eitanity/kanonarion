package application_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// The measured shape: a project replaces an upstream module with a first-party
// fork, and go.sum records the checksum under the FORK — the only coordinate
// the toolchain ever writes.
var (
	forkCoord     = coordinatetest.MustNew("github.com/cortezaproject/gval", "v1.2.4")
	upstreamCoord = coordinatetest.MustNew("github.com/PaesslerAG/gval", "v1.2.1")
)

// keyedSumDB answers only for the coordinates it holds, so a test can pin which
// SPELLING of a replaced module the lookup used rather than inferring it.
type keyedSumDB struct {
	entries map[coordinate.ModuleCoordinate]ports.SumDBResult
}

func (k *keyedSumDB) Lookup(_ context.Context, c coordinate.ModuleCoordinate) ports.SumDBResult {
	if res, ok := k.entries[c]; ok {
		return res
	}
	return ports.SumDBResult{
		Available:      false,
		Reason:         "no go.sum entry for " + c.String(),
		Unavailability: ports.SumDBUnavailabilityPolicy,
	}
}

// replacedGoSum builds a use case whose network sumdb is disabled and whose
// walk-root go.sum holds exactly the supplied entries.
func replacedGoSum(t *testing.T, entries map[coordinate.ModuleCoordinate]ports.SumDBResult) (*application.FetchModuleUseCase, *fakeFacts) {
	t.Helper()
	facts := newFakeFacts()
	uc := newUseCaseWithSumDB(&fakeProxy{}, &fakeVCS{checkoutErr: errors.New("no checkout in test")},
		newFakeBlob(), facts, disabledSumDB()).
		WithProjectGoSum(&keyedSumDB{entries: entries})
	return uc, facts
}

// A module replaced by another module verifies against the TARGET's go.sum
// entry. go.sum carries nothing under the upstream coordinate — the toolchain
// records the module it selects, at the path it selects it at — so a lookup
// keyed on the original would find nothing to check the fork against.
func TestExecute_ReplacedModule_VerifiesAgainstTheReplaceTargetEntry(t *testing.T) {
	uc, _ := replacedGoSum(t, map[coordinate.ModuleCoordinate]ports.SumDBResult{
		forkCoord: {Available: true, ZipHash: fakeZipHash},
	})

	result, err := uc.Execute(context.Background(), application.FetchRequest{
		Coordinate: forkCoord, OriginalCoordinate: upstreamCoord,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.VerificationStatus != string(domain2.VerifiedByGoSum) {
		t.Errorf("VerificationStatus = %q, want %q", result.Record.VerificationStatus, domain2.VerifiedByGoSum)
	}
}

// The report names the coordinate the anchor was found under, and the one the
// project requires the module as. Without both, a reader of a verified fork
// cannot tell which spelling was checked — which is exactly the doubt the
// verification exists to remove.
func TestExecute_ReplacedModule_ReportNamesTheAnchoringCoordinate(t *testing.T) {
	uc, _ := replacedGoSum(t, map[coordinate.ModuleCoordinate]ports.SumDBResult{
		forkCoord: {Available: true, ZipHash: fakeZipHash},
	})

	result, err := uc.Execute(context.Background(), application.FetchRequest{
		Coordinate: forkCoord, OriginalCoordinate: upstreamCoord,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	detail := result.Record.VerificationDetail
	for _, want := range []string{forkCoord.String(), "required as " + upstreamCoord.String()} {
		if !strings.Contains(detail, want) {
			t.Errorf("verification detail %q does not name %q", detail, want)
		}
	}
}

// A replaced module whose TARGET entry is absent from go.sum is a hard stop
// naming both coordinates, not a silent fall-through. A replacement always has
// an entry when go.sum describes this build; its absence means the file being
// consulted does not, and reporting the module as fetched anyway would put it
// outside the only anchor an air-gapped run has.
func TestExecute_ReplacedModule_TargetAbsentFromGoSumIsAHardStop(t *testing.T) {
	uc, facts := replacedGoSum(t, map[coordinate.ModuleCoordinate]ports.SumDBResult{
		// go.sum holds ONLY the upstream coordinate — the spelling the
		// toolchain never writes for a replaced module.
		upstreamCoord: {Available: true, ZipHash: fakeZipHash},
	})

	_, err := uc.Execute(context.Background(), application.FetchRequest{
		Coordinate: forkCoord, OriginalCoordinate: upstreamCoord,
	})
	if !errors.Is(err, application.ErrGoSumVerification) {
		t.Fatalf("Execute err = %v, want ErrGoSumVerification", err)
	}
	for _, want := range []string{forkCoord.String(), upstreamCoord.String()} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err, want)
		}
	}
	if _, ok, _ := facts.GetFetchRecord(context.Background(), forkCoord, "test-0.1.0"); ok {
		t.Error("a record was persisted for a fork with no go.sum anchor; want none")
	}
}

// An unreplaced module is unaffected: go.sum legitimately omits transitively
// cached entries, so absence still falls through to network verification rather
// than becoming a refusal.
func TestExecute_UnreplacedModule_AbsentFromGoSumStillFallsThrough(t *testing.T) {
	uc, facts := replacedGoSum(t, nil)

	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.VerificationStatus == string(domain2.VerifiedByGoSum) {
		t.Error("an absent go.sum entry was reported as a go.sum verification")
	}
	if _, ok, _ := facts.GetFetchRecord(context.Background(), testCoord, "test-0.1.0"); !ok {
		t.Error("no record persisted for an unreplaced module absent from go.sum")
	}
}

// A replacement that names the same coordinate as the requirement is not a
// replacement at all, and must not inherit the refusal.
func TestExecute_SelfReplacement_IsNotTreatedAsReplaced(t *testing.T) {
	uc, _ := replacedGoSum(t, nil)

	if _, err := uc.Execute(context.Background(), application.FetchRequest{
		Coordinate: testCoord, OriginalCoordinate: testCoord,
	}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
}
