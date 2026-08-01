package application_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	application2 "github.com/eitanity/kanonarion/internal/walk/application"
	domain3 "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// replaceRecordingFetcher records the pre-replace identity each fetch was given,
// so a test can measure that the walk hands the fetch both coordinates rather
// than inferring it from the resulting record.
type replaceRecordingFetcher struct {
	inner walkports.ModuleFetcher
	mu    sync.Mutex
	// originals maps the coordinate fetched to the coordinate it was fetched as
	// a replacement for. A zero value means the walk claimed no replacement.
	originals map[coordinate.ModuleCoordinate]coordinate.ModuleCoordinate
}

func newReplaceRecordingFetcher(inner walkports.ModuleFetcher) *replaceRecordingFetcher {
	return &replaceRecordingFetcher{
		inner:     inner,
		originals: map[coordinate.ModuleCoordinate]coordinate.ModuleCoordinate{},
	}
}

func (f *replaceRecordingFetcher) EnsureFetched(ctx context.Context, c coordinate.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	return f.EnsureFetchedReplacing(ctx, c, coordinate.ModuleCoordinate{})
}

func (f *replaceRecordingFetcher) EnsureFetchedReplacing(ctx context.Context, c, original coordinate.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	f.mu.Lock()
	f.originals[c] = original
	f.mu.Unlock()
	res, err := f.inner.EnsureFetchedReplacing(ctx, c, original)
	if err != nil {
		return res, fmt.Errorf("inner fetcher: %w", err)
	}
	return res, nil
}

func (f *replaceRecordingFetcher) originalFor(c coordinate.ModuleCoordinate) (coordinate.ModuleCoordinate, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.originals[c]
	return o, ok
}

// TestResolveProject_ReplacedModuleIsFetchedWithBothIdentities is the seam
// between the walk and go.sum verification: a fork is fetched at the
// REPLACEMENT coordinate — the one go.sum records — while the fetch is also
// told the coordinate the project requires it under, so the verification can
// name both. Without the second identity the fetch cannot refuse, or report,
// anything about a replacement.
func TestResolveProject_ReplacedModuleIsFetchedWithBothIdentities(t *testing.T) {
	blobs := newFakeBlobStore()
	inner := newFakeFetcher()
	inner.add(t, "example.com/fork", "v1.2.4", "module example.com/fork\ngo 1.21\n", blobs)
	rec := newReplaceRecordingFetcher(inner)

	resolver := application2.NewGraphResolver(
		newXmodParser(), rec, blobs,
		fixedClock{fixedNow}, "",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)

	mainGoMod := []byte(`module example.com/project

go 1.21

require example.com/upstream v1.2.1

replace example.com/upstream => example.com/fork v1.2.4
`)
	target := coord("example.com/project", coordinate.LocalVersion)
	if _, err := resolver.ResolveProject(t.Context(), target, mainGoMod, "", domain3.StageDepth{MaxDepth: 0, FollowReplace: true, FollowIndirect: true}, nil, false, false); err != nil {
		t.Fatalf("ResolveProject: %v", err)
	}

	forkCoord := coord("example.com/fork", "v1.2.4")
	original, ok := rec.originalFor(forkCoord)
	if !ok {
		t.Fatalf("the fork was never fetched; fetches: %+v", rec.originals)
	}
	if want := coord("example.com/upstream", "v1.2.1"); original != want {
		t.Errorf("fork fetched as a replacement for %v, want %v", original, want)
	}
}

// An unreplaced module carries no second identity: claiming one would make
// every module look replaced and turn a legitimately absent go.sum entry into a
// refusal.
func TestResolveProject_UnreplacedModuleCarriesNoOriginal(t *testing.T) {
	blobs := newFakeBlobStore()
	inner := newFakeFetcher()
	inner.add(t, "example.com/dep", "v1.0.0", "module example.com/dep\ngo 1.21\n", blobs)
	rec := newReplaceRecordingFetcher(inner)

	resolver := application2.NewGraphResolver(
		newXmodParser(), rec, blobs,
		fixedClock{fixedNow}, "",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)

	mainGoMod := []byte("module example.com/project\n\ngo 1.21\n\nrequire example.com/dep v1.0.0\n")
	target := coord("example.com/project", coordinate.LocalVersion)
	if _, err := resolver.ResolveProject(t.Context(), target, mainGoMod, "", domain3.StageDepth{MaxDepth: 0, FollowReplace: true, FollowIndirect: true}, nil, false, false); err != nil {
		t.Fatalf("ResolveProject: %v", err)
	}

	original, ok := rec.originalFor(coord("example.com/dep", "v1.0.0"))
	if !ok {
		t.Fatalf("the dependency was never fetched; fetches: %+v", rec.originals)
	}
	if original != (coordinate.ModuleCoordinate{}) {
		t.Errorf("an unreplaced module was fetched as a replacement for %v", original)
	}
}
