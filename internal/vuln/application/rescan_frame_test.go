package application_test

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// recordingClosureReader answers "not vendored" for every tree and remembers
// which go.mod it was asked about. The path it saw is the proof that the frame
// reached the delegated scan: the reader is consulted only for a run that has a
// project directory to analyse.
type recordingClosureReader struct {
	mu   sync.Mutex
	seen []string
}

func (r *recordingClosureReader) VendoredClosure(_ context.Context, goModPath string) (ports.VendoredClosure, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, goModPath)
	return ports.VendoredClosure{}, nil
}

func (r *recordingClosureReader) paths() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

// projectWalk builds a walk rooted at a local project, carrying the directory it
// was taken from — the provenance a re-scan needs to reproduce the frame.
func projectWalk(t *testing.T, dir string) (walkdomain.WalkRecord, *fakeWalkStore) {
	t.Helper()
	root := coordinatetest.MustNew("example.com/app", coordinate.LocalVersion)
	dep := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
	walk := walkdomain.WalkRecord{
		ID:     "walk-frame-1",
		Target: root,
		Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{
			{Coordinate: root},
			{Coordinate: dep},
		}},
		ProjectDir: dir,
	}
	ws := newFakeWalkStore()
	if err := ws.PutWalk(t.Context(), walk); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}
	return walk, ws
}

func frameRescanner(t *testing.T, ws *fakeWalkStore, db *fakeDatabase) *application.RescanWalkUseCase {
	t.Helper()
	clk := fixedClock{t: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)}
	vulnStore := newFakeVulnStore()
	moduleUC := application.NewScanModuleUseCase(
		newFakeFacts(), newFakeBlob(), vulnStore, ws, &fakeScanner{}, db, nil, clk, "v1", slog.Default(),
	)
	return application.NewRescanWalkUseCase(ws, vulnStore, moduleUC, nil, clk, "v1", slog.Default())
}

// A re-scan of a project-rooted walk with nothing wired to reach the project's
// tree used to re-derive every module in isolation and say nothing about it. The
// operator asked for the same evidence against a newer database; they were
// handed an answer to a different question, and the isolated verdict then
// outranked the consumer's route on the read.
func TestRescan_RefusesWhenItCannotReachTheProjectTree(t *testing.T) {
	dir := t.TempDir()
	_, ws := projectWalk(t, dir)
	db := &fakeDatabase{snapshot: vulntest.MustNew("test", "v2")}

	// No closure reader wired.
	_, err := frameRescanner(t, ws, db).Rescan(t.Context(), application.RescanRequest{WalkID: "walk-frame-1", EnableReachability: true})
	if err == nil {
		t.Fatal("want a refusal, got a completed re-scan under another frame")
	}
	var frame *application.FrameNotReproducibleError
	if !errors.As(err, &frame) {
		t.Fatalf("want FrameNotReproducibleError, got %T: %v", err, err)
	}
	if frame.ProjectDir != dir {
		t.Errorf("refusal names project dir %q, want %q", frame.ProjectDir, dir)
	}
	for _, want := range []string{"would change its analysis frame", "in isolation", "a different question"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal missing %q:\n%s", want, err.Error())
		}
	}
	// The refusal comes before any work: a snapshot fetched for a run that will
	// not happen is a network round trip charged for nothing.
	if n := db.snapshotCalls.Load(); n != 0 {
		t.Errorf("the re-scan fetched a snapshot before refusing (%d calls)", n)
	}
}

// A directory the walk names but this machine does not hold is the same refusal
// with the reason that applies: the checkout is elsewhere. Degrading to the
// fetched artefacts is what the scan path does when asked to scan; a re-scan is
// asked to reproduce a frame, and there is nothing narrower to answer with.
func TestRescan_RefusesWhenTheRecordedDirectoryIsGone(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "moved-away")
	_, ws := projectWalk(t, missing)
	db := &fakeDatabase{snapshot: vulntest.MustNew("test", "v2")}

	uc := frameRescanner(t, ws, db).WithVendoredClosure(&recordingClosureReader{})
	_, err := uc.Rescan(t.Context(), application.RescanRequest{WalkID: "walk-frame-1"})
	var frame *application.FrameNotReproducibleError
	if !errors.As(err, &frame) {
		t.Fatalf("want FrameNotReproducibleError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "not readable from here") {
		t.Errorf("refusal does not name the reason:\n%s", err.Error())
	}
}

// With the wiring in place the re-scan reproduces the frame: the delegated scan
// is handed the walk's own project directory, which is what makes it
// project-rooted rather than a pool of isolated per-module analyses.
func TestRescan_PreservesTheProjectRootedFrame(t *testing.T) {
	dir := t.TempDir()
	_, ws := projectWalk(t, dir)
	db := &fakeDatabase{snapshot: vulntest.MustNew("test", "v2")}
	reader := &recordingClosureReader{}

	uc := frameRescanner(t, ws, db).WithVendoredClosure(reader)
	if _, err := uc.Rescan(t.Context(), application.RescanRequest{WalkID: "walk-frame-1"}); err != nil {
		t.Fatalf("Rescan: %v", err)
	}

	want := filepath.Join(dir, "go.mod")
	seen := reader.paths()
	found := false
	for _, p := range seen {
		if p == want {
			found = true
		}
	}
	if !found {
		t.Errorf("the delegated scan was never pointed at the walk's project tree: asked about %v, want %s", seen, want)
	}
}

// A walk of a published coordinate has no project tree to reproduce: the
// delegated scan roots at the target module itself from the walk alone. It must
// not be dragged into the refusal, which would make every coordinate re-scan
// depend on wiring it has no use for.
func TestRescan_CoordinateWalkNeedsNoProjectFrame(t *testing.T) {
	target := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
	walk, ws, _, _ := makeWalkWithModules(t, target)
	walk.Target = target
	if err := ws.PutWalk(t.Context(), walk); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}
	db := &fakeDatabase{snapshot: vulntest.MustNew("test", "v2")}

	if _, err := frameRescanner(t, ws, db).Rescan(t.Context(), application.RescanRequest{WalkID: walk.ID}); err != nil {
		t.Fatalf("Rescan of a coordinate walk refused: %v", err)
	}
}

// -- the frame the WALK does not record -------------------------------------

// frameRescannerWithStore is frameRescanner with the vulnerability store handed
// back, so a test can seed the run whose frame the re-scan must consult.
func frameRescannerWithStore(t *testing.T, ws *fakeWalkStore, db *fakeDatabase) (*application.RescanWalkUseCase, *fakeVulnStore) {
	t.Helper()
	clk := fixedClock{t: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)}
	vulnStore := newFakeVulnStore()
	moduleUC := application.NewScanModuleUseCase(
		newFakeFacts(), newFakeBlob(), vulnStore, ws, &fakeScanner{}, db, nil, clk, "v1", slog.Default(),
	)
	return application.NewRescanWalkUseCase(ws, vulnStore, moduleUC, nil, clk, "v1", slog.Default()), vulnStore
}

// seedRunWithRooting stores one scan run for walkID whose records were produced
// in the given frame.
func seedRunWithRooting(t *testing.T, store *fakeVulnStore, walkID string, rooting domain.Rooting) {
	t.Helper()
	snap := vulntest.MustNew("test", "v1")
	rec, err := domain.VulnerabilityRecordHasher{}.SetContentHash(domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coordinatetest.MustNew("github.com/foo/bar", "v1.0.0"),
		WalkID:           walkID,
		OverallStatus:    domain.StatusClean,
		DatabaseSnapshot: snap,
		ScannedAt:        time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC),
		PipelineVersion:  "v1",
		Rooting:          rooting,
	})
	if err != nil {
		t.Fatalf("sealing prior-run record: %v", err)
	}
	run := domain.WalkScanRun{ID: "run-prior", WalkID: walkID, Snapshot: snap, PipelineVersion: "v1"}
	if perr := store.PutWalkScanRun(t.Context(), run); perr != nil {
		t.Fatalf("PutWalkScanRun: %v", perr)
	}
	store.SetRunRecords(run.ID, []domain.VulnerabilityRecord{rec})
}

// A walk that records no project directory was read as proof that no frame was
// at stake, and the re-scan degraded to isolated with nothing but a log line.
// The directory is provenance the walk hash deliberately excludes and a scan can
// be handed one directly, so the walk cannot settle the question — the run being
// re-scanned can, and it says the analysis was rooted at the project.
func TestRescan_RefusesWhenTheWalkNamesNoTreeButThePriorRunWasProjectRooted(t *testing.T) {
	root := coordinatetest.MustNew("example.com/app", coordinate.LocalVersion)
	walk := walkdomain.WalkRecord{
		ID:     "walk-frame-2",
		Target: root,
		Graph:  walkdomain.Graph{Nodes: []walkdomain.GraphNode{{Coordinate: root}}},
		// No ProjectDir.
	}
	ws := newFakeWalkStore()
	if err := ws.PutWalk(t.Context(), walk); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}
	db := &fakeDatabase{snapshot: vulntest.MustNew("test", "v2")}
	uc, store := frameRescannerWithStore(t, ws, db)
	seedRunWithRooting(t, store, walk.ID, domain.TargetRootedAt(root))

	_, err := uc.Rescan(t.Context(), application.RescanRequest{WalkID: walk.ID, EnableReachability: true})
	if err == nil {
		t.Fatal("want a refusal, got a completed re-scan under another frame")
	}
	var frame *application.FrameNotReproducibleError
	if !errors.As(err, &frame) {
		t.Fatalf("want FrameNotReproducibleError, got %T: %v", err, err)
	}
	if frame.ProjectDir != "" {
		t.Errorf("refusal invents a project dir %q; the walk records none", frame.ProjectDir)
	}
	for _, want := range []string{
		"the walk records no project directory, but the run being re-scanned recorded a project-rooted analysis frame",
		"in isolation",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal missing %q:\n%s", want, err.Error())
		}
	}
	// The refusal is settled before any network work, like every other frame refusal.
	if n := db.snapshotCalls.Load(); n != 0 {
		t.Errorf("the re-scan fetched a snapshot before refusing (%d calls)", n)
	}
}

// The same walk whose prior run WAS isolated has no frame to reproduce, so the
// re-scan proceeds. Refusing here would make every module-pool walk unscannable.
func TestRescan_ProceedsWhenNeitherTheWalkNorThePriorRunIsProjectRooted(t *testing.T) {
	root := coordinatetest.MustNew("example.com/app", coordinate.LocalVersion)
	walk := walkdomain.WalkRecord{
		ID:     "walk-frame-3",
		Target: root,
		Graph:  walkdomain.Graph{Nodes: []walkdomain.GraphNode{{Coordinate: root}}},
	}
	ws := newFakeWalkStore()
	if err := ws.PutWalk(t.Context(), walk); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}
	db := &fakeDatabase{snapshot: vulntest.MustNew("test", "v2")}
	uc, store := frameRescannerWithStore(t, ws, db)
	seedRunWithRooting(t, store, walk.ID, domain.RootingIsolated)

	if _, err := uc.Rescan(t.Context(), application.RescanRequest{WalkID: walk.ID}); err != nil {
		t.Fatalf("Rescan refused a walk with no frame to reproduce: %v", err)
	}
}

// A walk with no prior run at all has nothing to reproduce either, and must not
// be refused on a read that found nothing.
func TestRescan_ProceedsWhenTheWalkHasNoPriorRun(t *testing.T) {
	root := coordinatetest.MustNew("example.com/app", coordinate.LocalVersion)
	walk := walkdomain.WalkRecord{
		ID:     "walk-frame-4",
		Target: root,
		Graph:  walkdomain.Graph{Nodes: []walkdomain.GraphNode{{Coordinate: root}}},
	}
	ws := newFakeWalkStore()
	if err := ws.PutWalk(t.Context(), walk); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}
	db := &fakeDatabase{snapshot: vulntest.MustNew("test", "v2")}
	uc, _ := frameRescannerWithStore(t, ws, db)

	if _, err := uc.Rescan(t.Context(), application.RescanRequest{WalkID: walk.ID}); err != nil {
		t.Fatalf("Rescan refused a walk with no prior run: %v", err)
	}
}

// A ledger that cannot be read is a fault, not a frame. Answering "isolated is
// fine" because the runs could not be listed is how the refusal turns into the
// silent frame change it exists to prevent, so the read failure is raised.
func TestRescan_ReadFaultSettlingTheFrameIsRaisedNotReadAsNoFrame(t *testing.T) {
	root := coordinatetest.MustNew("example.com/app", coordinate.LocalVersion)
	walk := walkdomain.WalkRecord{
		ID:     "walk-frame-5",
		Target: root,
		Graph:  walkdomain.Graph{Nodes: []walkdomain.GraphNode{{Coordinate: root}}},
	}

	for _, tc := range []struct {
		name string
		seed func(*fakeVulnStore)
		want string
	}{
		{
			name: "the runs cannot be listed",
			seed: func(s *fakeVulnStore) { s.errOnListRuns = errors.New("runs table unreadable") },
			want: "to settle its analysis frame: runs table unreadable",
		},
		{
			name: "the run's records cannot be listed",
			seed: func(s *fakeVulnStore) { s.errOnListRecords = errors.New("record unreadable") },
			want: "to settle its analysis frame: record unreadable",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ws := newFakeWalkStore()
			if err := ws.PutWalk(t.Context(), walk); err != nil {
				t.Fatalf("PutWalk: %v", err)
			}
			db := &fakeDatabase{snapshot: vulntest.MustNew("test", "v2")}
			uc, store := frameRescannerWithStore(t, ws, db)
			seedRunWithRooting(t, store, walk.ID, domain.TargetRootedAt(root))
			tc.seed(store)

			_, err := uc.Rescan(t.Context(), application.RescanRequest{WalkID: walk.ID})
			if err == nil {
				t.Fatal("a read fault was read as 'no frame to reproduce'")
			}
			var frame *application.FrameNotReproducibleError
			if errors.As(err, &frame) {
				t.Errorf("a read fault was reported as a frame refusal: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error missing %q:\n%v", tc.want, err)
			}
		})
	}
}
