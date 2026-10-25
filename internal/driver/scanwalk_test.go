package driver

import (
	"errors"
	"reflect"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

func TestScanWalk_HooksSeeEachDecision(t *testing.T) {
	boom := errors.New("boom")
	for name, tc := range map[string]struct {
		req     WalkScan
		arrange func(*fakeScanner, *ScanHooks)
		want    string
		reused  bool
		scanned int
	}{
		"refresh hook ends the stage": {WalkScan{Fresh: true}, func(_ *fakeScanner, h *ScanHooks) {
			h.Refreshed = func(vulnapp.SnapshotRefresh, error) error { return boom }
		}, "boom", false, 0},
		"refresh failure is told then returned": {WalkScan{Fresh: true}, func(s *fakeScanner, h *ScanHooks) {
			s.refreshErr = boom
			h.Refreshed = func(_ vulnapp.SnapshotRefresh, err error) error {
				if !errors.Is(err, boom) {
					t.Errorf("Refreshed told %v", err)
				}
				return nil
			}
		}, "refreshing the advisory database: boom", false, 0},
		"reuse check fails": {WalkScan{}, func(s *fakeScanner, _ *ScanHooks) { s.reuseErr = boom }, "checking for a reusable scan run: boom", false, 0},
		"witness fails":     {WalkScan{}, func(s *fakeScanner, _ *ScanHooks) { s.reusable, s.serveErr = true, boom }, "witnessing the served scan run: boom", false, 0},
		"serve hook replaces the witness": {WalkScan{}, func(s *fakeScanner, h *ScanHooks) {
			s.reusable = true
			h.Serve = func(vulndomain.WalkScanRun) error { return boom }
		}, "boom", true, 0},
		"force measures past a stored run": {WalkScan{Force: true}, func(s *fakeScanner, h *ScanHooks) {
			s.reusable = true
			h.Scanning = func() {}
		}, "", false, 1},
	} {
		t.Run(name, func(t *testing.T) {
			s := &fakeScanner{}
			var h ScanHooks
			tc.arrange(s, &h)
			_, reused, err := ScanWalk(t.Context(), s, tc.req, h)
			if got := errString(err); got != tc.want {
				t.Errorf("err = %q, want %q", got, tc.want)
			}
			if reused != tc.reused || len(s.scanned) != tc.scanned {
				t.Errorf("reused %v scanned %d, want %v and %d", reused, len(s.scanned), tc.reused, tc.scanned)
			}
			if tc.reused && len(s.served) != 0 {
				t.Error("a Serve hook did not replace the stage's own witnessing")
			}
		})
	}
}

func TestScanWalk_PassesEveryChoiceToTheScan(t *testing.T) {
	s := &fakeScanner{run: vulndomain.WalkScanRun{ID: "r"}}
	progress := func(coordinate.ModuleCoordinate, vulndomain.VulnerabilityRecord, int, int) {}
	var told bool
	run, reused, err := ScanWalk(t.Context(), s, WalkScan{
		WalkID: "w", Fresh: true, Reachability: true, CallGraphWorkers: 3, BinaryModePrePass: true,
		Operator: "op", ProjectDir: "/p", NoVendor: true, Surface: "audit", Progress: progress,
	}, ScanHooks{Scanning: func() { told = true }})
	if err != nil || reused || run.ID != "r" || !told {
		t.Fatalf("ScanWalk = %+v %v %v, told %v", run, reused, err, told)
	}
	got := s.scanned[0]
	if got.Progress == nil {
		t.Error("progress callback dropped")
	}
	got.Progress = nil
	want := vulnapp.ScanWalkParams{WalkID: "w", EnableReachability: true, CallGraphWorkers: 3, BinaryModePrePass: true,
		Operator: "op", ProjectDir: "/p", NoVendor: true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("params = %+v, want %+v", got, want)
	}
	if s.reuseDir != "/p" {
		t.Errorf("reuse asked about %q, want the project directory", s.reuseDir)
	}
}

func TestScanFailedError_UnwrapsToTheScansOwnFailure(t *testing.T) {
	boom := errors.New("boom")
	_, _, err := ScanWalk(t.Context(), &fakeScanner{scanErr: boom}, WalkScan{Force: true}, ScanHooks{})
	var sf *ScanFailedError
	if !errors.As(err, &sf) || !errors.Is(err, boom) || err.Error() != "boom" {
		t.Errorf("err = %v, want a ScanFailedError over boom", err)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
