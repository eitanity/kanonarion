package driver

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	extractapp "code.eitanity.com/kanonarion/internal/extract/application"
	vulnapp "code.eitanity.com/kanonarion/internal/vuln/application"
	vulndomain "code.eitanity.com/kanonarion/internal/vuln/domain"
	walkapp "code.eitanity.com/kanonarion/internal/walk/application"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// fakeScanner records what the scan stage asked of it.
type fakeScanner struct {
	refresh    vulnapp.SnapshotRefresh
	refreshErr error
	refreshed  int

	prior    vulndomain.WalkScanRun
	reusable bool
	reuseErr error
	reuseDir string
	served   []string
	serveErr error
	scanned  []vulnapp.ScanWalkParams
	run      vulndomain.WalkScanRun
	scanErr  error
}

func (f *fakeScanner) RefreshSnapshot(context.Context, string) (vulnapp.SnapshotRefresh, error) {
	f.refreshed++
	return f.refresh, f.refreshErr
}

func (f *fakeScanner) ReusableRun(_ context.Context, _, projectDir string) (vulndomain.WalkScanRun, bool, error) {
	f.reuseDir = projectDir
	return f.prior, f.reusable, f.reuseErr
}

func (f *fakeScanner) ServeReusableRun(run vulndomain.WalkScanRun, surface string) error {
	f.served = append(f.served, run.ID+"@"+surface)
	return f.serveErr
}

func (f *fakeScanner) Scan(_ context.Context, p vulnapp.ScanWalkParams) (vulndomain.WalkScanRun, error) {
	f.scanned = append(f.scanned, p)
	return f.run, f.scanErr
}

var defaultStageSet = []string{"license", "interface", "callgraph", "example"}

func coordinateFixture() (*fakeWalk, *fakeExtract, *fakeScanner) {
	w := &fakeWalk{rec: walkdomain.WalkRecord{ID: "walk-1", OverallStatus: walkdomain.WalkSucceeded}}
	x := &fakeExtract{}
	x.run.ID = "run-x"
	s := &fakeScanner{run: vulndomain.WalkScanRun{ID: "scan-1"}}
	return w, x, s
}

func TestCoordinateAnalysis_RunsTheThreeStagesInspectRuns(t *testing.T) {
	w, x, s := coordinateFixture()
	uc := NewCoordinateAnalysisUseCase(w, x, s, defaultStageSet, nil)
	coord := coordinatetest.MustNew("example.com/mod", "v1.2.3")

	res, err := uc.Run(t.Context(), CoordinateAnalysisRequest{
		Coordinate: coord, Force: true, Reachability: true, FreshAdvisories: true, Operator: "op",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	wantWalk := walkapp.WalkRequest{Target: coord, Force: true, Scope: walkdomain.WalkScopeCode, Depth: walkdomain.WalkDepthFull}
	if !reflect.DeepEqual(w.gotReq, wantWalk) {
		t.Errorf("walk request = %+v, want %+v", w.gotReq, wantWalk)
	}
	wantExtract := extractapp.ExtractRequest{WalkID: "walk-1", Stages: defaultStageSet, Force: true}
	if !reflect.DeepEqual(x.gotReq, wantExtract) {
		t.Errorf("extract request = %+v, want %+v", x.gotReq, wantExtract)
	}
	if s.refreshed != 1 || len(s.scanned) != 1 {
		t.Fatalf("refreshed %d, scanned %d; want 1 and 1", s.refreshed, len(s.scanned))
	}
	want := vulnapp.ScanWalkParams{WalkID: "walk-1", Force: true, EnableReachability: true, CallGraphWorkers: 1, Operator: "op"}
	if got := s.scanned[0]; !reflect.DeepEqual(got, want) {
		t.Errorf("scan params = %+v, want %+v", got, want)
	}
	if res.Walk.ID != "walk-1" || res.Extraction.ID != "run-x" || res.Scan.ID != "scan-1" || res.ScanReused {
		t.Errorf("result = %+v", res)
	}
}

func TestCoordinateAnalysis_ServesAStoredRunUnderInspect(t *testing.T) {
	w, x, s := coordinateFixture()
	s.reusable, s.prior = true, vulndomain.WalkScanRun{ID: "stored"}
	res, err := NewCoordinateAnalysisUseCase(w, x, s, defaultStageSet, nil).Run(t.Context(),
		CoordinateAnalysisRequest{Coordinate: coordinatetest.MustNew("example.com/mod", "v1.2.3"), Stages: []string{"license"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.ScanReused || res.Scan.ID != "stored" || len(s.scanned) != 0 || s.refreshed != 0 {
		t.Errorf("result %+v, scanned %d, refreshed %d", res, len(s.scanned), s.refreshed)
	}
	if !reflect.DeepEqual(s.served, []string{"stored@" + vulnapp.ServeSurfaceInspect}) {
		t.Errorf("served = %v", s.served)
	}
	if !reflect.DeepEqual(x.gotReq.Stages, []string{"license"}) {
		t.Errorf("stages = %v, want the requested subset", x.gotReq.Stages)
	}
}

func TestCoordinateAnalysis_RefusesWhatItCannotAnalyse(t *testing.T) {
	local, err := coordinate.NewLocalCoordinate("example.com/proj")
	if err != nil {
		t.Fatal(err)
	}
	private := func(path string) bool { return strings.HasPrefix(path, "corp.example/") }
	for name, tc := range map[string]struct {
		coord coordinate.ModuleCoordinate
		want  string
	}{
		"zero":    {coordinate.ModuleCoordinate{}, "no module coordinate"},
		"local":   {local, "local working tree"},
		"private": {coordinatetest.MustNew("corp.example/m", "v1.0.0"), "GOPRIVATE/GONOPROXY"},
	} {
		t.Run(name, func(t *testing.T) {
			w, x, s := coordinateFixture()
			_, err := NewCoordinateAnalysisUseCase(w, x, s, defaultStageSet, private).Run(t.Context(), CoordinateAnalysisRequest{Coordinate: tc.coord})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Run = %v, want an error naming %q", err, tc.want)
			}
			if w.gotReq.Target.Path() != "" {
				t.Error("a refused coordinate was walked")
			}
		})
	}
}

func TestCoordinateAnalysis_StopsWhereInspectStops(t *testing.T) {
	boom := errors.New("boom")
	coord := coordinatetest.MustNew("example.com/mod", "v1.2.3")
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for name, tc := range map[string]struct {
		ctx     context.Context
		arrange func(*fakeWalk, *fakeExtract, *fakeScanner)
		want    string
		scanned bool
	}{
		"walk error":     {t.Context(), func(w *fakeWalk, _ *fakeExtract, _ *fakeScanner) { w.err = boom }, "walk: boom", false},
		"walk failed":    {t.Context(), func(w *fakeWalk, _ *fakeExtract, _ *fakeScanner) { w.rec.OverallStatus = walkdomain.WalkFailed }, "walk: walk walk-1 failed", false},
		"walk cancelled": {t.Context(), func(w *fakeWalk, _ *fakeExtract, _ *fakeScanner) { w.rec.OverallStatus = walkdomain.WalkCancelled }, "walk: walk walk-1 cancelled", false},
		"extract error":  {t.Context(), func(_ *fakeWalk, x *fakeExtract, _ *fakeScanner) { x.err = boom }, "extract: boom", false},
		"interrupted":    {cancelled, func(*fakeWalk, *fakeExtract, *fakeScanner) {}, "extract: context canceled", false},
		"scan error":     {t.Context(), func(_ *fakeWalk, _ *fakeExtract, s *fakeScanner) { s.scanErr = boom }, "vuln-scan: boom", true},
	} {
		t.Run(name, func(t *testing.T) {
			w, x, s := coordinateFixture()
			tc.arrange(w, x, s)
			_, err := NewCoordinateAnalysisUseCase(w, x, s, defaultStageSet, nil).Run(tc.ctx, CoordinateAnalysisRequest{Coordinate: coord})
			if err == nil || err.Error() != tc.want && !strings.HasPrefix(err.Error(), tc.want) {
				t.Errorf("Run = %v, want %q", err, tc.want)
			}
			if got := len(s.scanned) > 0; got != tc.scanned {
				t.Errorf("scanned = %v, want %v", got, tc.scanned)
			}
		})
	}
}

func TestCoordinateAnalysis_APartialWalkIsAnalysed(t *testing.T) {
	w, x, s := coordinateFixture()
	w.rec.OverallStatus = walkdomain.WalkPartial
	if _, err := NewCoordinateAnalysisUseCase(w, x, s, defaultStageSet, nil).Run(t.Context(),
		CoordinateAnalysisRequest{Coordinate: coordinatetest.MustNew("example.com/mod", "v1.2.3")}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(s.scanned) != 1 {
		t.Errorf("a partial walk was not scanned")
	}
}
