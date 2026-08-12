package store_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/local/adapters/vulnfindings/store"
	"github.com/eitanity/kanonarion/internal/local/ports"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
)

// probedTree is the module path of the working tree under probe in these tests.
// Another consumer's records are written against otherConsumer, which is the
// shared-store situation the frame filter exists for.
const (
	probedTree    = "example.com/app"
	otherConsumer = "example.com/other"
)

// fakeVulnStore is an in-memory implementation of vulnports.VulnerabilityStore.
// Only ListVulnerabilityRecordsForModule is implemented; all other methods
// panic.
//
// It holds every generation per coordinate rather than one composed record,
// because the frame filter under test is exactly the choice among them: a fake
// that pre-composed would answer the question the adapter is supposed to ask.
type fakeVulnStore struct {
	records map[string][]vulndomain.VulnerabilityRecord // keyed by coord.Path
	// generations is the store census, keyed by coord.Path, seeded independently
	// of records: the case it reproduces is a coordinate held only at a pipeline
	// version the reads do not return.
	generations map[string][]vulnports.VulnerabilityRecordGeneration
	err         error
}

func (s *fakeVulnStore) ListVulnerabilityRecordGenerationsForModule(_ context.Context, coord coordinate.ModuleCoordinate) ([]vulnports.VulnerabilityRecordGeneration, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.generations[coord.Path()], nil
}

func (s *fakeVulnStore) ListVulnerabilityRecordsForModule(_ context.Context, coord coordinate.ModuleCoordinate, _ string) ([]vulndomain.VulnerabilityRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.records[coord.Path()], nil
}

// Unused methods — panic so test failures are obvious if they're accidentally called.
func (s *fakeVulnStore) PutVulnerabilityRecord(_ context.Context, _ vulndomain.VulnerabilityRecord) error {
	panic("unexpected call: PutVulnerabilityRecord")
}
func (s *fakeVulnStore) GetVulnerabilityRecord(_ context.Context, _ coordinate.ModuleCoordinate, _ string, _ vulndomain.DatabaseSnapshot) (vulndomain.VulnerabilityRecord, bool, error) {
	panic("unexpected call: GetVulnerabilityRecord")
}
func (s *fakeVulnStore) GetLatestVulnerabilityRecord(_ context.Context, _ coordinate.ModuleCoordinate, _ string) (vulndomain.VulnerabilityRecord, bool, error) {
	panic("unexpected call: GetLatestVulnerabilityRecord")
}
func (s *fakeVulnStore) ListVulnerabilityRecordsForModuleInWalk(_ context.Context, _ coordinate.ModuleCoordinate, _ string, _ string) ([]vulndomain.VulnerabilityRecord, error) {
	panic("unexpected call: ListVulnerabilityRecordsForModuleInWalk")
}
func (s *fakeVulnStore) PutWalkScanRun(_ context.Context, _ vulndomain.WalkScanRun) error {
	panic("unexpected call: PutWalkScanRun")
}
func (s *fakeVulnStore) GetWalkScanRun(_ context.Context, _ string) (vulndomain.WalkScanRun, bool, error) {
	panic("unexpected call: GetWalkScanRun")
}
func (s *fakeVulnStore) ListWalkScanRuns(_ context.Context, _ string) ([]vulndomain.WalkScanRun, error) {
	panic("unexpected call: ListWalkScanRuns")
}
func (s *fakeVulnStore) ListAllWalkScanRuns(_ context.Context) ([]vulndomain.WalkScanRun, error) {
	panic("unexpected call: ListAllWalkScanRuns")
}
func (s *fakeVulnStore) PutDatabaseSnapshot(_ context.Context, _ vulndomain.DatabaseSnapshot, _ io.Reader) error {
	panic("unexpected call: PutDatabaseSnapshot")
}
func (s *fakeVulnStore) GetDatabaseSnapshot(_ context.Context, _ vulndomain.DatabaseSnapshot) (io.ReadCloser, error) {
	panic("unexpected call: GetDatabaseSnapshot")
}
func (s *fakeVulnStore) GetLatestDatabaseSnapshot(_ context.Context) (vulndomain.DatabaseSnapshot, bool, error) {
	panic("unexpected call: GetLatestDatabaseSnapshot")
}
func (s *fakeVulnStore) ListDatabaseSnapshots(_ context.Context) ([]vulndomain.DatabaseSnapshot, error) {
	panic("unexpected call: ListDatabaseSnapshots")
}
func (s *fakeVulnStore) ListVulnerabilityRecordsByFindingID(_ context.Context, _, _ string) ([]vulndomain.VulnerabilityRecord, error) {
	panic("unexpected call: ListVulnerabilityRecordsByFindingID")
}
func (s *fakeVulnStore) ListVulnerabilityRecords(_ context.Context, _ string) ([]vulndomain.VulnerabilityRecord, error) {
	panic("unexpected call: ListVulnerabilityRecords")
}

var _ vulnports.VulnerabilityStore = (*fakeVulnStore)(nil)

// -- helpers --

func mustCoord(t *testing.T, path, ver string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, ver)
	if err != nil {
		t.Fatalf("NewModuleCoordinate(%q, %q): %v", path, ver, err)
	}
	return c
}

// rootedAt is the frame of a walk rooted at a project working tree, which is
// what a consumer's scans of a dependency are recorded in.
func rootedAt(t *testing.T, path string) vulndomain.Rooting {
	t.Helper()
	c, err := coordinate.NewLocalCoordinate(path)
	if err != nil {
		t.Fatalf("NewLocalCoordinate(%q): %v", path, err)
	}
	return vulndomain.TargetRootedAt(c)
}

// recordSpec is the minimum a seeding test needs to state about one stored
// generation: the frame it was measured in, and the finding it carries.
type recordSpec struct {
	rooting   vulndomain.Rooting
	findings  []vulndomain.VulnerabilityFinding
	scannedAt time.Time
}

func record(coord coordinate.ModuleCoordinate, spec recordSpec) vulndomain.VulnerabilityRecord {
	return vulndomain.VulnerabilityRecord{
		Coordinate: coord,
		Rooting:    spec.rooting,
		Findings:   spec.findings,
		ScannedAt:  spec.scannedAt,
	}
}

// reachableFinding is a finding whose reachability verdict was settled by the
// stored scan — the value the seed carries across, and the one that must not
// come from another build.
func reachableFinding(id string, reachable bool, rooting vulndomain.Rooting) vulndomain.VulnerabilityFinding {
	return vulndomain.VulnerabilityFinding{
		ID:      id,
		Summary: id + " summary",
		Reachable: &vulndomain.ReachabilityResult{
			IsReachable: reachable,
			DerivedBy: vulndomain.ReachabilityDerivation{
				Analyser: vulndomain.AnalyserGovulncheck,
				Rooting:  rooting,
			},
		},
	}
}

func loadOne(t *testing.T, s *fakeVulnStore, coord coordinate.ModuleCoordinate) ports.FindingSet {
	t.Helper()
	adapter := store.New(s, "v1")
	set, err := adapter.LoadFindings(context.Background(), []coordinate.ModuleCoordinate{coord}, probedTree)
	if err != nil {
		t.Fatalf("LoadFindings: %v", err)
	}
	return set
}

// -- frame anchoring --

// TestLoadFindings_AnotherConsumersRecordDoesNotSeed is the headline: a shared
// store holds another project's target-rooted record and an isolated one, and
// the probe of THIS tree must be seeded from the isolated record alone.
func TestLoadFindings_AnotherConsumersRecordDoesNotSeed(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	other := rootedAt(t, otherConsumer)
	s := &fakeVulnStore{records: map[string][]vulndomain.VulnerabilityRecord{
		"example.com/dep": {
			record(coord, recordSpec{
				rooting:   other,
				scannedAt: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
				findings:  []vulndomain.VulnerabilityFinding{reachableFinding("GO-2026-0001", true, other)},
			}),
			record(coord, recordSpec{
				rooting:   vulndomain.RootingIsolated,
				scannedAt: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
				findings: []vulndomain.VulnerabilityFinding{
					reachableFinding("GO-2026-0001", false, vulndomain.RootingIsolated),
				},
			}),
		},
	}}

	set := loadOne(t, s, coord)
	findings := set.Findings[coord]
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].Reachable == nil {
		t.Fatal("Reachable = nil, want the isolated frame's verdict")
	}
	if *findings[0].Reachable {
		t.Error("seeded Reachable = true — that is the OTHER consumer's build's verdict; " +
			"the isolated record said not reachable")
	}
	if !strings.Contains(findings[0].ReachableBasis, string(vulndomain.RootingIsolated)) {
		t.Errorf("ReachableBasis = %q, want it to name the isolated frame", findings[0].ReachableBasis)
	}
}

// TestLoadFindings_OwnFrameSeeds: the tree's own target-rooted record is the
// one that seeds, over an isolated record that would otherwise be preferred.
func TestLoadFindings_OwnFrameSeeds(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	own := rootedAt(t, probedTree)
	s := &fakeVulnStore{records: map[string][]vulndomain.VulnerabilityRecord{
		"example.com/dep": {
			record(coord, recordSpec{
				rooting:   vulndomain.RootingIsolated,
				scannedAt: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
				findings: []vulndomain.VulnerabilityFinding{
					reachableFinding("GO-2026-0001", false, vulndomain.RootingIsolated),
				},
			}),
			record(coord, recordSpec{
				rooting:   own,
				scannedAt: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
				findings:  []vulndomain.VulnerabilityFinding{reachableFinding("GO-2026-0001", true, own)},
			}),
		},
	}}

	set := loadOne(t, s, coord)
	findings := set.Findings[coord]
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].Reachable == nil || !*findings[0].Reachable {
		t.Errorf("Reachable = %v, want the tree's own frame's true", findings[0].Reachable)
	}
	if !strings.Contains(findings[0].ReachableBasis, probedTree) {
		t.Errorf("ReachableBasis = %q, want it to name this tree's frame", findings[0].ReachableBasis)
	}
}

// TestLoadFindings_OwnFrameMatchesOnPathNotVersion: a walk of this tree records
// its root as a coordinate with a version the tree's go.mod cannot state, so
// the anchor compares module paths.
func TestLoadFindings_OwnFrameMatchesOnPathNotVersion(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	tagged, err := coordinate.NewModuleCoordinate(probedTree, "v1.2.3")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	own := vulndomain.TargetRootedAt(tagged)
	s := &fakeVulnStore{records: map[string][]vulndomain.VulnerabilityRecord{
		"example.com/dep": {
			record(coord, recordSpec{
				rooting:   own,
				scannedAt: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
				findings:  []vulndomain.VulnerabilityFinding{reachableFinding("GO-2026-0001", true, own)},
			}),
		},
	}}

	set := loadOne(t, s, coord)
	if len(set.Findings[coord]) != 1 {
		t.Fatalf("findings = %d, want 1 — a walk-assigned root version must not hide the tree's own frame",
			len(set.Findings[coord]))
	}
}

// TestLoadFindings_NoAcceptableRecordSeedsNothing: only another consumer's
// records exist, so the probe seeds nothing for the coordinate — and does not
// report it as scanned, because this build was not the one measured.
func TestLoadFindings_NoAcceptableRecordSeedsNothing(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	other := rootedAt(t, otherConsumer)
	s := &fakeVulnStore{records: map[string][]vulndomain.VulnerabilityRecord{
		"example.com/dep": {
			record(coord, recordSpec{
				rooting:   other,
				scannedAt: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
				findings:  []vulndomain.VulnerabilityFinding{reachableFinding("GO-2026-0001", true, other)},
			}),
		},
	}}

	set := loadOne(t, s, coord)
	if len(set.Findings) != 0 {
		t.Errorf("findings = %d, want 0", len(set.Findings))
	}
	if _, ok := set.Scanned[coord]; ok {
		t.Error("coord reported as scanned — no record measures THIS build, so it is uncovered")
	}
	if _, ok := set.OtherFrameOnly[coord]; !ok {
		t.Error("coord not reported as held in another frame — that absence is not the same as never scanned")
	}
}

// TestLoadFindings_FramelessRecordsStillSeed: a store written before the frame
// was recorded still seeds, on the same narrow terms composition uses — nothing
// in the group states a frame.
func TestLoadFindings_FramelessRecordsStillSeed(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	s := &fakeVulnStore{records: map[string][]vulndomain.VulnerabilityRecord{
		"example.com/dep": {
			record(coord, recordSpec{
				scannedAt: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
				findings:  []vulndomain.VulnerabilityFinding{{ID: "GO-2026-0001", Summary: "s"}},
			}),
		},
	}}

	set := loadOne(t, s, coord)
	if len(set.Findings[coord]) != 1 {
		t.Fatalf("findings = %d, want 1", len(set.Findings[coord]))
	}
}

// TestLoadFindings_StatesItsRestriction: the seed's restriction is reported, so
// the answer says what it was drawn from.
func TestLoadFindings_StatesItsRestriction(t *testing.T) {
	s := &fakeVulnStore{records: map[string][]vulndomain.VulnerabilityRecord{}}
	adapter := store.New(s, "v1")
	set, err := adapter.LoadFindings(context.Background(), nil, probedTree)
	if err != nil {
		t.Fatalf("LoadFindings: %v", err)
	}
	if !strings.Contains(set.Restriction, probedTree) {
		t.Errorf("Restriction = %q, want it to name the probed tree", set.Restriction)
	}
	if !strings.Contains(set.Restriction, "isolated") {
		t.Errorf("Restriction = %q, want it to name the isolated fallback", set.Restriction)
	}

	set, err = adapter.LoadFindings(context.Background(), nil, "")
	if err != nil {
		t.Fatalf("LoadFindings: %v", err)
	}
	if !strings.Contains(set.Restriction, "no module path") {
		t.Errorf("Restriction = %q, want it to say the tree declares no module path", set.Restriction)
	}
}

// -- mapping --

func TestLoadFindings_MapsFields(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	s := &fakeVulnStore{
		records: map[string][]vulndomain.VulnerabilityRecord{
			"example.com/dep": {record(coord, recordSpec{
				rooting: vulndomain.RootingIsolated,
				findings: []vulndomain.VulnerabilityFinding{
					{
						ID:                     "GHSA-0001",
						Aliases:                []string{"CVE-2024-0001"},
						Summary:                "A test vulnerability",
						AffectedSymbols:        []string{"VulnFunc", "(*VulnType).Method"},
						AdvisoryNamesNoSymbols: true,
					},
				},
			})},
		},
	}

	set := loadOne(t, s, coord)
	findings, ok := set.Findings[coord]
	if !ok {
		t.Fatal("coord not present in result")
	}
	if len(findings) != 1 {
		t.Fatalf("findings count = %d, want 1", len(findings))
	}
	f := findings[0]
	if f.ID != "GHSA-0001" {
		t.Errorf("ID = %q, want GHSA-0001", f.ID)
	}
	if len(f.Aliases) != 1 || f.Aliases[0] != "CVE-2024-0001" {
		t.Errorf("Aliases = %v", f.Aliases)
	}
	if f.Summary != "A test vulnerability" {
		t.Errorf("Summary = %q", f.Summary)
	}
	if len(f.AffectedSymbols) != 2 {
		t.Errorf("AffectedSymbols = %v, want 2 entries", f.AffectedSymbols)
	}
	if !f.AdvisoryNamesNoSymbols {
		t.Error("AdvisoryNamesNoSymbols = false, want true")
	}
	if f.ReachableBasis != "" {
		t.Errorf("ReachableBasis = %q, want empty for a finding with no stored verdict", f.ReachableBasis)
	}
}

func TestLoadFindings_OmitsCoordWithNoRecord(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	s := &fakeVulnStore{records: map[string][]vulndomain.VulnerabilityRecord{}} // no records

	set := loadOne(t, s, coord)
	if len(set.Findings) != 0 {
		t.Errorf("result len = %d, want 0 (coord with no record should be omitted)", len(set.Findings))
	}
	if len(set.Scanned) != 0 {
		t.Errorf("scanned len = %d, want 0", len(set.Scanned))
	}
}

func TestLoadFindings_ScannedWithEmptyFindings(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	s := &fakeVulnStore{
		records: map[string][]vulndomain.VulnerabilityRecord{
			"example.com/dep": {record(coord, recordSpec{rooting: vulndomain.RootingIsolated})},
		},
	}

	set := loadOne(t, s, coord)
	if len(set.Findings) != 0 {
		t.Errorf("result len = %d, want 0 (coord with no findings should be omitted)", len(set.Findings))
	}
	if _, ok := set.Scanned[coord]; !ok {
		t.Error("coord missing from Scanned — a clean record is coverage, not absence")
	}
}

func TestLoadFindings_MultipleCoords(t *testing.T) {
	coordA := mustCoord(t, "example.com/a", "v1.0.0")
	coordB := mustCoord(t, "example.com/b", "v2.0.0")
	coordC := mustCoord(t, "example.com/c", "v3.0.0") // no record
	s := &fakeVulnStore{
		records: map[string][]vulndomain.VulnerabilityRecord{
			"example.com/a": {record(coordA, recordSpec{
				rooting:  vulndomain.RootingIsolated,
				findings: []vulndomain.VulnerabilityFinding{{ID: "GHSA-A", Summary: "vuln A"}},
			})},
			"example.com/b": {record(coordB, recordSpec{
				rooting:  vulndomain.RootingIsolated,
				findings: []vulndomain.VulnerabilityFinding{{ID: "GHSA-B", Summary: "vuln B"}},
			})},
		},
	}
	adapter := store.New(s, "v1")

	result, err := adapter.LoadFindings(context.Background(),
		[]coordinate.ModuleCoordinate{coordA, coordB, coordC}, probedTree)
	if err != nil {
		t.Fatalf("LoadFindings: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Errorf("result len = %d, want 2", len(result.Findings))
	}
	if _, ok := result.Findings[coordA]; !ok {
		t.Error("coordA not in result")
	}
	if _, ok := result.Findings[coordB]; !ok {
		t.Error("coordB not in result")
	}
	if _, ok := result.Findings[coordC]; ok {
		t.Error("coordC should not be in result (no record)")
	}
}

func TestLoadFindings_StoreError_Propagates(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	storeErr := errors.New("database unavailable")
	s := &fakeVulnStore{err: storeErr}
	adapter := store.New(s, "v1")

	_, err := adapter.LoadFindings(context.Background(), []coordinate.ModuleCoordinate{coord}, probedTree)
	if !errors.Is(err, storeErr) {
		t.Errorf("error = %v, want wrapping %v", err, storeErr)
	}
}

func TestLoadFindings_EmptyCoords(t *testing.T) {
	s := &fakeVulnStore{records: map[string][]vulndomain.VulnerabilityRecord{}}
	adapter := store.New(s, "v1")

	result, err := adapter.LoadFindings(context.Background(), nil, probedTree)
	if err != nil {
		t.Fatalf("LoadFindings: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("result len = %d, want 0", len(result.Findings))
	}
}

// Compile-time check that adapter satisfies the port interface.
var _ ports.VulnFindingLoader = (*store.VulnStoreAdapter)(nil)

func (s *fakeVulnStore) GetVulnerabilityRecordAt(_ context.Context, _ coordinate.ModuleCoordinate, _ string, _ vulndomain.DatabaseSnapshot, _ vulndomain.Rooting) (vulndomain.VulnerabilityRecord, bool, error) {
	panic("unexpected call: GetVulnerabilityRecordAt")
}

func (s *fakeVulnStore) HasVulnerabilityRecord(_ context.Context, _ coordinate.ModuleCoordinate, _ string, _ vulndomain.DatabaseSnapshot, _ string) (bool, error) {
	panic("unexpected call: HasVulnerabilityRecord")
}

// -- superseded generations --

// A coordinate the store holds only at a pipeline version this loader does not
// read is not an unscanned dependency. The keyed read returns nothing for it,
// exactly as it does for a module nobody has ever looked at, and the coverage
// block used to call both "never vuln-scanned".
func TestLoadFindings_SupersededOnlyIsNotAnUnscannedCoordinate(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	s := &fakeVulnStore{
		// No records at the version the adapter reads: the bump left them behind.
		records: map[string][]vulndomain.VulnerabilityRecord{},
		generations: map[string][]vulnports.VulnerabilityRecordGeneration{
			coord.Path(): {{PipelineVersion: "v0", Records: 16, Findings: 252}},
		},
	}

	set := loadOne(t, s, coord)

	if _, ok := set.Scanned[coord]; ok {
		t.Error("a superseded record must not count as scanned for this build")
	}
	if _, ok := set.SupersededOnly[coord]; !ok {
		t.Errorf("coordinate not recorded as superseded-only: %+v", set.SupersededOnly)
	}
}

// The control: a coordinate the store holds nothing for at any generation stays
// in the plain uncovered bucket.
func TestLoadFindings_NeverScannedIsNotSupersededOnly(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	s := &fakeVulnStore{records: map[string][]vulndomain.VulnerabilityRecord{}}

	set := loadOne(t, s, coord)

	if _, ok := set.SupersededOnly[coord]; ok {
		t.Error("a coordinate the store has never held was reported as superseded")
	}
}
