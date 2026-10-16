package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
	localdomain "github.com/eitanity/kanonarion/internal/local/domain"
	vulnsqlite "github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
	walksqlite "github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

const (
	seedOldWalkID = "01JS0NGARD0000000000000SO1"
	seedNewWalkID = "01JS0NGARD0000000000000SN1"
	seedOldRunID  = "01JS0NGARD0000000000000SR1"
	seedNewRunID  = "01JS0NGARD0000000000000SR2"
	// seedOldToolchain is the Go the older walk was taken under, before the
	// upgrade. It is never this host's, so the two walks name two toolchains.
	seedOldToolchain = "go1.20.1"
)

// seedWalkSpec is one project walk of the fixture tree, with the scan run that
// wrote its one vulnerability record.
type seedWalkSpec struct {
	walkID, runID string
	toolchain     string
	at            time.Time
	snapshotV     string
	// snapAt is when the snapshot was retrieved; zero means at.
	snapAt    time.Time
	status    vulndomain.VulnerabilityStatus
	findingID string
	// noRun leaves the scan run out, as a scan that was interrupted or aborted
	// before it completed leaves its records and no run.
	noRun bool
	// pipeline is the record's pipeline version; empty means this build's.
	pipeline string
}

// twoWalkStore builds the store after a Go upgrade: an older walk of the tree
// under one toolchain and a newer one under this host's, each with a record of
// the same dependency in the tree's own frame, and the two records disagree.
// With sameToolchain both walks state this host's toolchain: the control. With
// noWalks the walk records are left out, so the probe falls back to the
// frame-wide seed it took before a walk anchored it.
func twoWalkStore(t *testing.T, sameToolchain, noWalks bool) (storeRoot, treeDir string) {
	t.Helper()
	storeRoot, treeDir, host := upgradeStoreHost(t)
	old := seedOldToolchain
	if sameToolchain {
		old = host.toolchain
	}
	specs := []seedWalkSpec{
		{walkID: seedOldWalkID, runID: seedOldRunID, toolchain: old, at: jsonDocAt,
			snapshotV: "v2026-03-01", status: vulndomain.StatusClean},
		{walkID: seedNewWalkID, runID: seedNewRunID, toolchain: host.toolchain, at: jsonDocAt.Add(48 * time.Hour),
			snapshotV: "v2026-03-03", status: vulndomain.StatusAffected, findingID: jsonDocFindingID},
	}
	seedWalkStore(t, storeRoot, treeDir, host, specs, noWalks)
	return storeRoot, treeDir
}

// seedWalkStore writes each spec's project walk (unless noWalks), record and
// scan run into a fresh store at storeRoot.
func seedWalkStore(t *testing.T, storeRoot, treeDir string, host walkBuildEnv, specs []seedWalkSpec, noWalks bool) {
	t.Helper()
	ctx := context.Background()
	db, err := sqlitestore.Open(filepath.Join(storeRoot, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening the fixture store: %v", err)
	}
	defer func() { _ = db.Close() }()
	if aerr := sqlitestore.Apply(db, allMigrations()); aerr != nil {
		t.Fatalf("migrating the fixture store: %v", aerr)
	}
	root, err := coordinate.NewLocalCoordinate(jsonDocRootPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range specs {
		if !noWalks {
			seedProjectWalk(t, ctx, db, root, host, treeDir, s)
		}
		seedWalkVulnRecord(t, ctx, db, root, s)
	}
}

// upgradeStoreHost is the host's build environment for a fixture tree, skipping
// the test when this host's toolchain cannot be probed.
func upgradeStoreHost(t *testing.T) (storeRoot, treeDir string, host walkBuildEnv) {
	t.Helper()
	storeRoot, treeDir = t.TempDir(), t.TempDir()
	writeJSONDocPopulatedTree(t, treeDir)
	host = currentWalkBuildEnv(context.Background(), "", treeDir, nil)
	if host.toolchain == "" {
		t.Skip("this host's Go toolchain could not be probed")
	}
	return storeRoot, treeDir, host
}

func seedProjectWalk(t *testing.T, ctx context.Context, db sqlitestore.DB, root coordinate.ModuleCoordinate,
	host walkBuildEnv, treeDir string, s seedWalkSpec,
) {
	t.Helper()
	graph := walkdomain.Graph{
		Target: root,
		Nodes: []walkdomain.GraphNode{
			{Coordinate: root, ResolutionSource: walkdomain.ResolutionLocalMainModule},
			{Coordinate: jsonDocDep, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS},
		},
		Edges:           []walkdomain.GraphEdge{{From: root, To: jsonDocDep, ConstraintVersion: jsonDocDep.Version()}},
		BuildEnv:        walkdomain.BuildEnv{GOOS: host.platform.GOOS, GOARCH: host.platform.GOARCH, GoVersion: s.toolchain},
		ResolvedAt:      s.at,
		PipelineVersion: walkapp.PipelineVersion,
	}
	graph.Sort()
	outcome := walkdomain.WalkOutcome{
		Target: root,
		Graph:  graph,
		PerNodeResults: map[coordinate.ModuleCoordinate]walkdomain.NodeResult{
			root:       {Coordinate: root, Status: walkdomain.NodeSucceeded},
			jsonDocDep: {Coordinate: jsonDocDep, Status: walkdomain.NodeSucceeded},
		},
		StartedAt:     s.at,
		CompletedAt:   s.at.Add(time.Second),
		OverallStatus: walkdomain.WalkSucceeded,
	}
	rec := walkdomain.NewWalkRecord(s.walkID, "guard", walkapp.PipelineVersion,
		walkdomain.WalkScopeCode, walkdomain.WalkDepthFull, outcome, walkdomain.DefaultDepthPolicy(), "")
	rec.ProjectDir = treeDir
	rec, err := walkdomain.WalkRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("sealing walk %s: %v", s.walkID, err)
	}
	if err := walksqlite.New(db).PutWalk(ctx, rec); err != nil {
		t.Fatalf("seeding walk %s: %v", s.walkID, err)
	}
}

func seedWalkVulnRecord(t *testing.T, ctx context.Context, db sqlitestore.DB, root coordinate.ModuleCoordinate, s seedWalkSpec) {
	t.Helper()
	store := vulnsqlite.New(db)
	snapAt := s.snapAt
	if snapAt.IsZero() {
		snapAt = s.at
	}
	snapshot := vulntest.MustNewAt(jsonDocSnapSource, s.snapshotV, snapAt)
	if err := store.PutDatabaseSnapshot(ctx, snapshot, strings.NewReader("advisory snapshot "+s.snapshotV)); err != nil {
		t.Fatalf("seeding snapshot %s: %v", s.snapshotV, err)
	}
	record := vulndomain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       jsonDocDep,
		WalkID:           s.walkID,
		OverallStatus:    s.status,
		DatabaseSnapshot: snapshot,
		ScannedAt:        s.at,
		PipelineVersion:  pipelineOr(s.pipeline),
		Rooting:          frameOf(root),
		Toolchain:        gotoolchain.Version(s.toolchain),
	}
	if s.findingID != "" {
		record.Findings = []vulndomain.VulnerabilityFinding{{
			ID: s.findingID, Summary: "a seeded finding", AffectedRange: "< v1.3.0", FixedIn: "v1.3.0",
		}}
	}
	record, err := vulndomain.VulnerabilityRecordHasher{}.SetContentHash(record)
	if err != nil {
		t.Fatalf("sealing the record of %s: %v", s.walkID, err)
	}
	if perr := store.PutVulnerabilityRecord(ctx, record); perr != nil {
		t.Fatalf("seeding the record of %s: %v", s.walkID, perr)
	}
	status := vulndomain.WalkStatusAllClean
	if s.status == vulndomain.StatusAffected {
		status = vulndomain.WalkStatusAffected
	}
	run := vulndomain.WalkScanRun{
		ID: s.runID, WalkID: s.walkID, Snapshot: snapshot,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{jsonDocDep: record.ContentHash},
		StartedAt:        s.at, CompletedAt: s.at.Add(time.Second),
		OverallStatus: status, Operator: "guard", PipelineVersion: pipelineOr(s.pipeline),
	}
	if s.noRun {
		return
	}
	if run, err = (vulndomain.WalkScanRunHasher{}).SetContentHash(run); err != nil {
		t.Fatal(err)
	}
	if err := store.PutWalkScanRun(ctx, run); err != nil {
		t.Fatalf("seeding the run of %s: %v", s.walkID, err)
	}
}

// After a Go upgrade the store holds the tree's older walk under the old
// toolchain beside the newer walk under this one. The probe seeds from the
// newest project walk alone and names it, where composing every walk of the
// frame refused on a conflict no re-scan could clear.
func TestLocalReachability_SeedsFromTheNewestProjectWalk(t *testing.T) {
	fixtureRoot, treeDir := twoWalkStore(t, false, false)

	stdout, stderr, err := runAside("reachability", "--local", treeDir, "--store-root", fixtureRoot)
	if err != nil {
		t.Fatalf("exit %d: %v\n%s", ExitCodeForError(err), err, stderr)
	}
	if !strings.Contains(stdout, `seed:      seed restricted to stored records scanned by walk "`+seedNewWalkID+`"`) {
		t.Errorf("the seed line does not name the newest walk:\n%s", stdout)
	}
	if strings.Contains(stdout, seedOldWalkID) {
		t.Errorf("the older walk's records reached the answer:\n%s", stdout)
	}
	if !strings.Contains(stdout, jsonDocFindingID) {
		t.Errorf("the newest walk's finding is not in the answer:\n%s", stdout)
	}
}

// Unanchored vuln-show over the same store answers: the two records were
// measured against two advisory snapshots, so their difference is not the
// toolchain's, and the newer snapshot is served. Both pins answer too.
func TestVulnShow_TwoToolchainsOnTwoSnapshotsAnswer(t *testing.T) {
	fixtureRoot, treeDir := twoWalkStore(t, false, false)

	stdout, stderr, err := runAside("vuln-show", jsonDocDepCoord, "--store-root", fixtureRoot)
	if err != nil {
		t.Fatalf("exit %d: %v\n%s", ExitCodeForError(err), err, stderr)
	}
	if !strings.Contains(stdout, jsonDocDepCoord+" — Affected") || !strings.Contains(stdout, seedNewWalkID) {
		t.Errorf("not served the newer snapshot's record:\n%s", stdout)
	}
	for _, pin := range [][]string{{"--walk-id", seedNewWalkID}, {"--gomod", filepath.Join(treeDir, "go.mod")}} {
		args := append([]string{"vuln-show", jsonDocDepCoord, "--store-root", fixtureRoot}, pin...)
		if _, perr, err := runAside(args...); err != nil {
			t.Errorf("%v: exit %d: %v\n%s", pin, ExitCodeForError(err), err, perr)
		}
	}
}

// Two toolchains that disagree on ONE snapshot are a conflict. The refusal
// names the pins that resolve it and no re-scan, which appends a record and
// leaves the other standing.
func TestVulnShow_ToolchainConflictNamesThePinsNotARescan(t *testing.T) {
	root := t.TempDir()
	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening the fixture store: %v", err)
	}
	if aerr := sqlitestore.Apply(db, allMigrations()); aerr != nil {
		t.Fatalf("migrating the fixture store: %v", aerr)
	}
	ctx := context.Background()
	at := jsonDocAt
	// An isolated scan under the old Go and a scan rooted at the module itself
	// under the new one, against the same snapshot: two frames, so both write.
	seedWalkVulnRecord(t, ctx, db, coordinate.ModuleCoordinate{}, seedWalkSpec{
		walkID: seedOldWalkID, runID: seedOldRunID, toolchain: seedOldToolchain, at: at,
		snapshotV: "v2026-03-01", status: vulndomain.StatusClean})
	seedWalkVulnRecord(t, ctx, db, jsonDocDep, seedWalkSpec{
		walkID: seedNewWalkID, runID: seedNewRunID, toolchain: "go1.27.2", at: at.Add(time.Hour),
		snapshotV: "v2026-03-01", snapAt: at, status: vulndomain.StatusAffected, findingID: jsonDocFindingID})
	_ = db.Close()

	stdout, stderr, err := runAside("vuln-show", jsonDocDepCoord, "--store-root", root)
	if err == nil {
		t.Fatalf("two toolchains disagreeing on one snapshot answered\n%s\n%s", stdout, stderr)
	}
	msg := err.Error()
	for _, want := range []string{
		"two Go toolchains scanned it",
		"kanonarion vuln-show " + jsonDocDepCoord + " --walk-id " + seedNewWalkID,
		"kanonarion vuln-show " + jsonDocDepCoord + " --gomod ./go.mod",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal does not name %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "vuln-scan-rescan") {
		t.Errorf("refusal still offers a re-scan:\n%s", msg)
	}
}

// The control: walks under one toolchain compose without conflict, and the
// anchored seed serves exactly what the frame-wide seed serves over the same
// records. Only the seed line, which names the walk, and the clock differ.
func TestLocalReachability_OneToolchainServesTheSameAnswer(t *testing.T) {
	anchoredStore, anchoredTree := twoWalkStore(t, true, false)
	frameStore, frameTree := twoWalkStore(t, true, true)

	anchored, stderr, err := runAside("reachability", "--local", anchoredTree, "--store-root", anchoredStore)
	if err != nil {
		t.Fatalf("anchored: exit %d: %v\n%s", ExitCodeForError(err), err, stderr)
	}
	frameWide, stderr, err := runAside("reachability", "--local", frameTree, "--store-root", frameStore)
	if err != nil {
		t.Fatalf("frame-wide: exit %d: %v\n%s", ExitCodeForError(err), err, stderr)
	}
	if !strings.Contains(anchored, `scanned by walk "`+seedNewWalkID+`"`) {
		t.Errorf("the anchored seed does not name the newest walk:\n%s", anchored)
	}
	normalise := func(out, tree string) string {
		lines := strings.Split(strings.ReplaceAll(out, tree, "<tree>"), "\n")
		kept := lines[:0]
		for _, l := range lines {
			if strings.HasPrefix(l, "  seed:") || strings.HasPrefix(l, "  snapshot:") {
				continue
			}
			kept = append(kept, l)
		}
		return strings.Join(kept, "\n")
	}
	if a, f := normalise(anchored, anchoredTree), normalise(frameWide, frameTree); a != f {
		t.Errorf("one toolchain, two answers.\nanchored:\n%s\nframe-wide:\n%s", a, f)
	}
}

// A tree with no go.mod at its root names no project walk, so the probe keeps
// the frame-wide seed rather than guessing a manifest.
func TestLocalSeedAnchor_NoGoModKeepsTheFrameWideSeed(t *testing.T) {
	if _, ok, err := localSeedAnchor(context.Background(), nil, nil, t.TempDir()); ok || err != nil {
		t.Errorf("ok=%v err=%v, want no anchor and no error", ok, err)
	}
}

// frameOf is the frame a fixture record is measured in: rooted at root, or the
// isolated frame when root is zero.
func frameOf(root coordinate.ModuleCoordinate) vulndomain.Rooting {
	if root.IsZero() {
		return vulndomain.RootingIsolated
	}
	return vulndomain.TargetRootedAt(root)
}

// pipelineOr is v, or this build's vulnerability pipeline version when v is empty.
func pipelineOr(v string) string {
	if v == "" {
		return vulnapp.PipelineVersion
	}
	return v
}

// A Go upgrade whose first scan stopped short: the newer walk holds a record
// and no scan run. The probe seeds from the older walk, whose scan completed,
// names the newer one, and says how to complete it.
func TestLocalReachability_AnIncompleteScanSeedsFromTheLastCompletedWalk(t *testing.T) {
	fixtureRoot, treeDir, host := upgradeStoreHost(t)
	seedWalkStore(t, fixtureRoot, treeDir, host, []seedWalkSpec{
		{walkID: seedOldWalkID, runID: seedOldRunID, toolchain: seedOldToolchain, at: jsonDocAt,
			snapshotV: "v2026-03-01", status: vulndomain.StatusAffected, findingID: jsonDocFindingID},
		{walkID: seedNewWalkID, runID: seedNewRunID, toolchain: host.toolchain, at: jsonDocAt.Add(48 * time.Hour),
			snapshotV: "v2026-03-03", status: vulndomain.StatusClean, noRun: true},
	}, false)

	stdout, stderr, err := runAside("reachability", "--local", treeDir, "--store-root", fixtureRoot)
	if err != nil {
		t.Fatalf("exit %d: %v\n%s", ExitCodeForError(err), err, stderr)
	}
	for _, want := range []string{
		`seed:      walk "` + seedNewWalkID + `"'s vuln-scan did not complete; kanonarion vuln-scan --gomod ./go.mod`,
		`seeded from walk "` + seedOldWalkID + `"`,
		"1 covered, 1 with findings",
		jsonDocFindingID,
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the probe does not say %q:\n%s", want, stdout)
		}
	}
}

// No walk of the tree has a completed scan: every uncovered line says so, the
// remedy completes the scan, and nothing covered exits 4.
func TestLocalReachability_NoCompletedScanSaysSoOnEveryLine(t *testing.T) {
	fixtureRoot, treeDir, host := upgradeStoreHost(t)
	seedWalkStore(t, fixtureRoot, treeDir, host, []seedWalkSpec{
		{walkID: seedOldWalkID, runID: seedOldRunID, toolchain: seedOldToolchain, at: jsonDocAt,
			snapshotV: "v2026-03-01", status: vulndomain.StatusClean, noRun: true},
		{walkID: seedNewWalkID, runID: seedNewRunID, toolchain: host.toolchain, at: jsonDocAt.Add(48 * time.Hour),
			snapshotV: "v2026-03-03", status: vulndomain.StatusClean, noRun: true},
	}, false)

	stdout, _, err := runAside("reachability", "--local", treeDir, "--store-root", fixtureRoot)
	if code := ExitCodeForError(err); code != ExitNotFound {
		t.Fatalf("exit %d (%v), want %d: nothing is covered\n%s", code, err, ExitNotFound, stdout)
	}
	if !strings.Contains(stdout, jsonDocDepCoord+" — "+localdomain.UncoveredScanIncomplete) {
		t.Errorf("the uncovered line does not say the scan did not complete:\n%s", stdout)
	}
	if strings.Contains(stdout, localdomain.UncoveredNotInSeedWalk) || strings.Contains(stdout, localdomain.UncoveredNoStoredRecord) {
		t.Errorf("an uncovered line says the walk holds no record:\n%s", stdout)
	}
	if !strings.Contains(stdout, "to widen the answer: "+remedyCompleteScan().String()) {
		t.Errorf("the remedy does not complete the scan:\n%s", stdout)
	}
	if !strings.Contains(stdout, `scanned by walk "`+seedNewWalkID+`"`) {
		t.Errorf("the seed line does not name the newest walk:\n%s", stdout)
	}
}

// After a pipeline bump every record of the build is superseded: the lead says
// so, the closing line says nothing is covered, and the exit is 4 in text and
// in JSON. The JSON document is still printed in full.
func TestLocalReachability_AllSupersededCoversNothingAndExits4(t *testing.T) {
	fixtureRoot, treeDir, host := upgradeStoreHost(t)
	seedWalkStore(t, fixtureRoot, treeDir, host, []seedWalkSpec{
		{walkID: seedNewWalkID, runID: seedNewRunID, toolchain: host.toolchain, at: jsonDocAt,
			snapshotV: "v2026-03-03", status: vulndomain.StatusClean, pipeline: "v1"},
	}, false)

	stdout, _, err := runAside("reachability", "--local", treeDir, "--store-root", fixtureRoot)
	if code := ExitCodeForError(err); code != ExitNotFound {
		t.Fatalf("exit %d (%v), want %d\n%s", code, err, ExitNotFound, stdout)
	}
	for _, want := range []string{
		localdomain.UncoveredSupersededPipeline,
		"to widen the answer: These modules hold records only from superseded scan logic",
		"\n" + noModuleCoveredLine + "\n",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the probe does not say %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "no affected modules") || strings.Contains(stdout, "carry no stored record") {
		t.Errorf("the probe reads as a clean answer about modules it did not cover:\n%s", stdout)
	}

	stdout, _, err = runAside("reachability", "--local", treeDir, "--store-root", fixtureRoot, "--json")
	if code := ExitCodeForError(err); code != ExitNotFound {
		t.Fatalf("--json: exit %d (%v), want %d", code, err, ExitNotFound)
	}
	if !strings.Contains(stdout, `"covered_modules": 0`) {
		t.Errorf("--json does not print the coverage:\n%s", stdout)
	}
}

// A Go upgrade on one advisory snapshot: the two walks' records disagree, which
// an unpinned read refuses. The second scan's write completes, and every read
// that names the build answers from the new walk's record alone.
func TestLocalReachability_AGoUpgradeOnOneSnapshotAnswersFromTheNewWalk(t *testing.T) {
	fixtureRoot, treeDir, host := upgradeStoreHost(t)
	seedWalkStore(t, fixtureRoot, treeDir, host, []seedWalkSpec{
		{walkID: seedOldWalkID, runID: seedOldRunID, toolchain: seedOldToolchain, at: jsonDocAt,
			snapshotV: "v2026-03-01", status: vulndomain.StatusClean},
		{walkID: seedNewWalkID, runID: seedNewRunID, toolchain: host.toolchain, at: jsonDocAt.Add(48 * time.Hour),
			snapshotV: "v2026-03-01", snapAt: jsonDocAt, status: vulndomain.StatusAffected, findingID: jsonDocFindingID},
	}, false)

	stdout, stderr, err := runAside("reachability", "--local", treeDir, "--store-root", fixtureRoot)
	if err != nil {
		t.Fatalf("reachability --local: exit %d: %v\n%s", ExitCodeForError(err), err, stderr)
	}
	if !strings.Contains(stdout, `scanned by walk "`+seedNewWalkID+`"`) || !strings.Contains(stdout, "1 covered, 1 with findings") {
		t.Errorf("the probe does not cover the build from the new walk:\n%s", stdout)
	}
	if _, _, unpinned := runAside("vuln-show", jsonDocDepCoord, "--store-root", fixtureRoot); unpinned == nil ||
		!strings.Contains(unpinned.Error(), "two Go toolchains scanned it") {
		t.Errorf("the unpinned read did not refuse on the two toolchains: %v", unpinned)
	}
	stdout, stderr, err = runAside("vuln-show", jsonDocDepCoord, "--gomod", filepath.Join(treeDir, "go.mod"), "--store-root", fixtureRoot)
	if err != nil || !strings.Contains(stdout, jsonDocFindingID) {
		t.Errorf("vuln-show --gomod: err %v\n%s%s", err, stdout, stderr)
	}
	stdout, _, err = runAside("vuln-by-id", jsonDocFindingID, "--store-root", fixtureRoot)
	if err != nil || !strings.Contains(stdout, jsonDocDepCoord) {
		t.Errorf("vuln-by-id does not name the new toolchain's affected record: err %v\n%s", err, stdout)
	}
	for _, pin := range [][]string{{"--gomod", filepath.Join(treeDir, "go.mod")}, {"--walk-id", seedNewWalkID}} {
		args := append([]string{"context", "--json", "--store-root", fixtureRoot}, pin...)
		stdout, stderr, err = runAside(args...)
		if err != nil || strings.Contains(stdout, `"read_error"`) || !strings.Contains(stdout, jsonDocFindingID) {
			t.Errorf("context %v does not answer from the new walk's record: err %v\n%s%s", pin, err, stdout, stderr)
		}
	}
}

// After the same upgrade, a by-id read of a walk lists only the generation that
// walk's run named, and only when it carries the advisory.
func TestVulnByID_AGoUpgradeListsOnlyTheWalksOwnGeneration(t *testing.T) {
	fixtureRoot, treeDir, host := upgradeStoreHost(t)
	seedWalkStore(t, fixtureRoot, treeDir, host, []seedWalkSpec{
		{walkID: seedOldWalkID, runID: seedOldRunID, toolchain: seedOldToolchain, at: jsonDocAt,
			snapshotV: "v2026-03-01", status: vulndomain.StatusClean},
		{walkID: seedNewWalkID, runID: seedNewRunID, toolchain: host.toolchain, at: jsonDocAt.Add(48 * time.Hour),
			snapshotV: "v2026-03-01", snapAt: jsonDocAt, status: vulndomain.StatusAffected, findingID: jsonDocFindingID},
	}, false)

	// The older walk's record lacks the advisory, so a by-id read of that walk
	// lists nothing, in text and in JSON; the newer walk's read lists its record.
	stdout, _, err := runAside("vuln-by-id", jsonDocFindingID, "--walk-id", seedOldWalkID, "--store-root", fixtureRoot)
	if err != nil || !strings.Contains(stdout, "no modules in walk "+seedOldWalkID+" affected by "+jsonDocFindingID) {
		t.Errorf("vuln-by-id on the older walk lists a record that lacks the advisory: err %v\n%s", err, stdout)
	}
	stdout, _, err = runAside("vuln-by-id", jsonDocFindingID, "--walk-id", seedOldWalkID, "--json", "--store-root", fixtureRoot)
	if err != nil || strings.TrimSpace(stdout) != "[]" {
		t.Errorf("vuln-by-id --json on the older walk = err %v\n%s, want []", err, stdout)
	}
	stdout, _, err = runAside("vuln-by-id", jsonDocFindingID, "--walk-id", seedNewWalkID, "--json", "--store-root", fixtureRoot)
	if err != nil || !strings.Contains(stdout, seedNewWalkID) || strings.Contains(stdout, seedOldWalkID) {
		t.Errorf("vuln-by-id --json on the newer walk does not list its own record alone: err %v\n%s", err, stdout)
	}
}
