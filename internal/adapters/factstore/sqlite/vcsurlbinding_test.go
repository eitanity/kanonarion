package sqlite_test

import (
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

// TestVCSURLBindingRoundTripsThroughTheStore guards the column added with the
// field. Dropped from the INSERT or the SELECT, the record would come back
// claiming no binding — and because the read path re-verifies the content hash
// and fails closed, a field written but not read back does not merely lose the
// attribution, it makes every new record unreadable.
func TestVCSURLBindingRoundTripsThroughTheStore(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	for _, binding := range []domain2.VCSURLBinding{
		domain2.VCSURLBindingCoordinateDerived,
		domain2.VCSURLBindingProxyNamed,
	} {
		r := sampleRecord(t, "github.com/foo/"+string(binding), "v1.0.0", "0.4.0",
			fetchtest.VCSURLBinding(binding))
		if err := s.PutFetchRecord(ctx, mustSeal(t, r)); err != nil {
			t.Fatalf("Put(%s): %v", binding, err)
		}
		got, ok, err := s.GetFetchRecord(ctx,
			coordinatetest.MustNew(r.ModulePath, r.ModuleVersion), r.PipelineVersion)
		if err != nil || !ok {
			t.Fatalf("Get(%s): ok=%v err=%v", binding, ok, err)
		}
		if got.VCSURLBinding != string(binding) {
			t.Errorf("VCSURLBinding = %q, want %q", got.VCSURLBinding, binding)
		}
	}
}

// TestPreBindingRecordStillReadsBack is the migration guard at the storage
// layer. A record persisted before the column existed defaults to the empty
// string, which must survive the round trip and keep verifying its content hash.
// The column's DEFAULT ” is what makes that true for rows already on disk.
func TestPreBindingRecordStillReadsBack(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	r := sampleRecord(t, "github.com/foo/legacy-binding", "v1.0.0", "0.4.0")
	if r.VCSURLBinding != "" {
		t.Fatalf("fixture is not a pre-binding record: binding = %q", r.VCSURLBinding)
	}
	if err := s.PutFetchRecord(ctx, mustSeal(t, r)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok, err := s.GetFetchRecord(ctx,
		coordinatetest.MustNew(r.ModulePath, r.ModuleVersion), r.PipelineVersion)
	if err != nil || !ok {
		t.Fatalf("a record without a URL binding failed to read back: ok=%v err=%v", ok, err)
	}
	if got.VCSURLBinding != "" {
		t.Errorf("VCSURLBinding = %q, want empty", got.VCSURLBinding)
	}
}

// TestBindingIsNotInventedForAnOldRecord pins the decision not to guess. A
// pre-binding record carries a git_url and a module path, so a binding could be
// derived from them on read — and must not be. The function that derives a clone
// URL from a module path is live code, so a sealed record's meaning would move
// whenever it is edited, and a git_url is recorded even where no cross-verify
// ran, so the guess would attribute a binding to a leg that never happened.
func TestBindingIsNotInventedForAnOldRecord(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	// A module path from which inferRepoURL would derive exactly this git_url.
	r := sampleRecord(t, "github.com/foo/bar", "v1.0.0", "0.4.0",
		fetchtest.GitReference(domain2.GitReference{URL: "https://github.com/foo/bar"}))
	if err := s.PutFetchRecord(ctx, mustSeal(t, r)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok, err := s.GetFetchRecord(ctx,
		coordinatetest.MustNew(r.ModulePath, r.ModuleVersion), r.PipelineVersion)
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if got.VCSURLBinding != "" {
		t.Errorf("VCSURLBinding = %q: a binding was derived from git_url on read rather than being read "+
			"from the record, which would make a sealed record's meaning move under it", got.VCSURLBinding)
	}
}
