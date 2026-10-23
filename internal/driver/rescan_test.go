package driver

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	staleapp "github.com/eitanity/kanonarion/internal/staleness/application"
	stalenessdomain "github.com/eitanity/kanonarion/internal/staleness/domain"
	staleports "github.com/eitanity/kanonarion/internal/staleness/ports"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

type fakeRescan struct {
	got vulnapp.RescanRequest
	err error
}

func (f *fakeRescan) Rescan(_ context.Context, req vulnapp.RescanRequest) (vulndomain.WalkScanRun, error) {
	f.got = req
	return vulndomain.WalkScanRun{ID: "rescan"}, f.err
}

func TestRescan_AsksTheRescanWhatTheRequestNames(t *testing.T) {
	snap, err := vulndomain.NewDatabaseSnapshot("osv", "v1", time.Unix(1, 0).UTC(), "sha256:"+strings.Repeat("0", 64))
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	f := &fakeRescan{}
	run, err := NewRescanUseCase(f).Run(t.Context(), RescanRequest{
		WalkID: "w", Snapshot: &snap, Reachability: true, Operator: "op",
		Progress: func(coordinate.ModuleCoordinate, vulndomain.VulnerabilityRecord, int, int) { calls++ },
	})
	if err != nil || run.ID != "rescan" {
		t.Fatalf("Run = %+v, %v", run, err)
	}
	if f.got.WalkID != "w" || f.got.Snapshot != &snap || !f.got.EnableReachability || f.got.Operator != "op" || f.got.Progress == nil {
		t.Errorf("rescan asked %+v", f.got)
	}
	f.got.Progress(coordinate.ModuleCoordinate{}, vulndomain.VulnerabilityRecord{}, 1, 1)
	if calls != 1 {
		t.Error("the progress callback did not reach the rescan")
	}
}

// The error is the re-scan's own, so the CLI can still match the frame refusal.
func TestRescan_ReturnsTheRescansErrorUnwrapped(t *testing.T) {
	refusal := &vulnapp.FrameNotReproducibleError{WalkID: "w"}
	_, err := NewRescanUseCase(&fakeRescan{err: refusal}).Run(t.Context(), RescanRequest{WalkID: "w"})
	if err != refusal { //nolint:errorlint // identity is the claim
		t.Errorf("err = %v, want the rescan's own error", err)
	}
}

type fakeLatest struct{ asked int }

func (f *fakeLatest) LatestInfo(_ context.Context, path string) (staleports.LatestInfo, error) {
	f.asked++
	if path != "example.com/mod" {
		return staleports.LatestInfo{}, staleports.ErrPathAbsent
	}
	return staleports.LatestInfo{Version: "v1.4.0"}, nil
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

func TestStalenessResolver_ResolvesThroughTheWrappedResolver(t *testing.T) {
	up := &fakeLatest{}
	r := NewStalenessResolver(staleapp.NewResolver(up, nil, fixedClock{}, time.Hour, false))
	ans, err := r.Resolve(t.Context(), "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := stalenessdomain.Record{ModulePath: "example.com/mod", LatestVersion: "v1.4.0", LookedUpAt: fixedClock{}.Now()}
	if ans.ModulePath != want.ModulePath || ans.LatestVersion != want.LatestVersion || !ans.LookedUpAt.Equal(want.LookedUpAt) || !ans.NewerMajor.Probed {
		t.Errorf("answer = %+v", ans)
	}
	if _, err := r.Resolve(t.Context(), "example.com/gone", ""); !errors.Is(err, staleports.ErrPathAbsent) {
		t.Errorf("an absent path = %v, want ErrPathAbsent", err)
	}
}
