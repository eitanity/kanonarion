package application_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// divergenceDep is the one dependency the fixtures below compare on. The walk
// resolves it at walkedVersion; the manifest is rewritten per test.
const (
	divergenceDep = "github.com/golang-jwt/jwt/v4"
	walkedVersion = "v4.5.1"
)

// divergenceFixture wires the reuse question around a project walk: a local
// target, one resolved dependency, and a working tree on disk whose manifest the
// test controls. It returns the use case, the directory, and the run that is
// servable while the tree agrees.
//
// projectDirOnWalk decides which spelling of the command is under test. Recorded
// on the walk, the caller passes no directory and the reuse decision has to
// adopt the walk's own — the `vuln-scan <walk-id>` form the defect was reported
// against. Left off, the caller names the tree itself.
func divergenceFixture(t *testing.T, projectDirOnWalk bool) (*application.ScanWalkUseCase, string, domain.WalkScanRun) {
	t.Helper()

	uc, store, walks := reuseFixtureWithWalks(t, "v1")
	dir := t.TempDir()

	root := coordinatetest.MustNew("example.com/app", coordinate.LocalVersion)
	dep := coordinatetest.MustNew(divergenceDep, walkedVersion)
	walk := walkdomain.WalkRecord{
		ID:     reuseWalkID,
		Target: root,
		Graph: walkdomain.Graph{
			Target: root,
			Nodes: []walkdomain.GraphNode{
				{Coordinate: root, ResolutionSource: walkdomain.ResolutionLocalMainModule},
				{Coordinate: dep, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS},
			},
		},
	}
	if projectDirOnWalk {
		walk.ProjectDir = dir
	}
	if err := walks.PutWalk(context.Background(), walk); err != nil {
		t.Fatalf("seeding the project walk: %v", err)
	}

	snap := vulntest.MustNew("vuln.go.dev", "2026-07-27T16:28:49Z")
	seedSnapshot(t, store, snap)
	run := seedRun(t, store, "vscan-1", reuseWalkID, snap, "v1", domain.CoverageComplete)
	return uc, dir, run
}

// writeManifest puts a go.mod in dir requiring divergenceDep at version.
func writeManifest(t *testing.T, dir, version string) {
	t.Helper()
	body := fmt.Sprintf("module example.com/app\n\ngo 1.24\n\nrequire %s %s\n", divergenceDep, version)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(body), 0o600); err != nil {
		t.Fatalf("writing the project manifest: %v", err)
	}
}

// askedDir is the directory the caller names, which is empty when the walk
// carries its own.
func askedDir(dir string, projectDirOnWalk bool) string {
	if projectDirOnWalk {
		return ""
	}
	return dir
}

// TestReusableRun_ADivergedProjectDirectoryIsRefusedWhateverTheCacheHolds is the
// property: what a diverged directory is told must not depend on whether a
// stored run happens to be servable.
//
// The same servable run is in the store throughout. While the tree requires what
// the walk resolved it is served; the moment the tree moves off it, it is not —
// so the command reaches the same metadata-only degradation it reaches when no
// stored run exists at all. Both directions are exercised, because the direction
// that matters is the one nobody reproduces: a tree that has moved ONTO a
// vulnerable version would otherwise be handed a stored "clean" answer about the
// version it left.
func TestReusableRun_ADivergedProjectDirectoryIsRefusedWhateverTheCacheHolds(t *testing.T) {
	for _, tc := range []struct {
		name     string
		required string
	}{
		{"the tree moved to a later version", "v4.5.2"},
		{"the tree moved back to an earlier version", "v4.5.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, spelling := range []struct {
				name             string
				projectDirOnWalk bool
			}{
				{"the caller names the tree", false},
				{"the walk remembers the tree", true},
			} {
				t.Run(spelling.name, func(t *testing.T) {
					uc, dir, want := divergenceFixture(t, spelling.projectDirOnWalk)
					asked := askedDir(dir, spelling.projectDirOnWalk)

					// Control: while the tree agrees, this run is servable. Without it a
					// refusal below would prove nothing about the divergence.
					writeManifest(t, dir, walkedVersion)
					got, ok, err := uc.ReusableRun(context.Background(), reuseWalkID, asked)
					if err != nil || !ok {
						t.Fatalf("control: ReusableRun = (%v, %v), want the stored run served", ok, err)
					}
					if got.ID != want.ID {
						t.Fatalf("control: served run = %s, want %s", got.ID, want.ID)
					}

					writeManifest(t, dir, tc.required)
					run, ok, err := uc.ReusableRun(context.Background(), reuseWalkID, asked)
					if err != nil {
						t.Fatalf("ReusableRun: %v", err)
					}
					if ok {
						t.Fatalf("served stored run %q for a directory that no longer requires the versions the walk resolved: "+
							"the answer would depend on the cache holding it", run.ID)
					}
				})
			}
		})
	}
}

// TestReusableRun_ServesAnAgreeingProjectDirectory is the saving this must not
// cost. An unchanged checkout still reuses, which is what keeps a warm audit
// sub-second.
func TestReusableRun_ServesAnAgreeingProjectDirectory(t *testing.T) {
	uc, dir, want := divergenceFixture(t, true)
	writeManifest(t, dir, walkedVersion)

	got, ok, err := uc.ReusableRun(context.Background(), reuseWalkID, "")
	if err != nil {
		t.Fatalf("ReusableRun: %v", err)
	}
	if !ok || got.ID != want.ID {
		t.Fatalf("ReusableRun = (%s, %v), want the stored run %s served", got.ID, ok, want.ID)
	}
}

// TestReusableRun_ServesAWalkThatNamesNoProjectDirectory keeps the check to the
// walks it can speak about. A coordinate-keyed walk has no working tree, so
// there is nothing to compare and nothing to refuse.
func TestReusableRun_ServesAWalkThatNamesNoProjectDirectory(t *testing.T) {
	uc, store, walks := reuseFixtureWithWalks(t, "v1")
	target := coordinatetest.MustNew(divergenceDep, walkedVersion)
	if err := walks.PutWalk(context.Background(), walkdomain.WalkRecord{
		ID:     reuseWalkID,
		Target: target,
		Graph: walkdomain.Graph{
			Target: target,
			Nodes:  []walkdomain.GraphNode{{Coordinate: target, ResolutionSource: walkdomain.ResolutionMVS}},
		},
	}); err != nil {
		t.Fatalf("seeding the coordinate walk: %v", err)
	}
	snap := vulntest.MustNew("vuln.go.dev", "2026-07-27T16:28:49Z")
	seedSnapshot(t, store, snap)
	want := seedRun(t, store, "vscan-1", reuseWalkID, snap, "v1", domain.CoverageComplete)

	got, ok, err := uc.ReusableRun(context.Background(), reuseWalkID, "")
	if err != nil {
		t.Fatalf("ReusableRun: %v", err)
	}
	if !ok || got.ID != want.ID {
		t.Fatalf("ReusableRun = (%s, %v), want the stored run %s served", got.ID, ok, want.ID)
	}
}

// TestReusableRun_ServesAWalkWhoseProjectDirectoryIsGone pins the degradation
// the scan itself takes. A checkout that has moved cannot be compared and cannot
// be analysed either; refusing the stored run would buy a re-scan that reaches
// the same place with less evidence.
func TestReusableRun_ServesAWalkWhoseProjectDirectoryIsGone(t *testing.T) {
	uc, dir, want := divergenceFixture(t, true)
	writeManifest(t, dir, walkedVersion)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("removing the project directory: %v", err)
	}

	got, ok, err := uc.ReusableRun(context.Background(), reuseWalkID, "")
	if err != nil {
		t.Fatalf("ReusableRun: %v", err)
	}
	if !ok || got.ID != want.ID {
		t.Fatalf("ReusableRun = (%s, %v), want the stored run %s served", got.ID, ok, want.ID)
	}
}

// TestReusableRun_ServesADirectoryItCannotCompare keeps an unreadable manifest
// from being read as a verdict. A directory holding no go.mod establishes
// nothing about the build either way, and the scan already treats that as
// "could not check" rather than as drift.
func TestReusableRun_ServesADirectoryItCannotCompare(t *testing.T) {
	uc, _, want := divergenceFixture(t, true)

	got, ok, err := uc.ReusableRun(context.Background(), reuseWalkID, "")
	if err != nil {
		t.Fatalf("ReusableRun: %v", err)
	}
	if !ok || got.ID != want.ID {
		t.Fatalf("ReusableRun = (%s, %v), want the stored run %s served", got.ID, ok, want.ID)
	}
}
