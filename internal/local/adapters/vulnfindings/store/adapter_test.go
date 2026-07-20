package store_test

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/local/adapters/vulnfindings/store"
	"github.com/eitanity/kanonarion/internal/local/ports"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
)

// fakeVulnStore is an in-memory implementation of vulnports.VulnerabilityStore.
// Only GetLatestVulnerabilityRecord is implemented; all other methods panic.
type fakeVulnStore struct {
	records map[string]vulndomain.VulnerabilityRecord // keyed by coord.Path
	err     error
}

func (s *fakeVulnStore) GetLatestVulnerabilityRecord(_ context.Context, coord coordinate.ModuleCoordinate, _ string) (vulndomain.VulnerabilityRecord, bool, error) {
	if s.err != nil {
		return vulndomain.VulnerabilityRecord{}, false, s.err
	}
	r, ok := s.records[coord.Path]
	return r, ok, nil
}

// Unused methods — panic so test failures are obvious if they're accidentally called.
func (s *fakeVulnStore) PutVulnerabilityRecord(_ context.Context, _ vulndomain.VulnerabilityRecord) error {
	panic("unexpected call: PutVulnerabilityRecord")
}
func (s *fakeVulnStore) GetVulnerabilityRecord(_ context.Context, _ coordinate.ModuleCoordinate, _ string, _ vulndomain.DatabaseSnapshot) (vulndomain.VulnerabilityRecord, bool, error) {
	panic("unexpected call: GetVulnerabilityRecord")
}
func (s *fakeVulnStore) GetLatestVulnerabilityRecordForWalk(_ context.Context, _ coordinate.ModuleCoordinate, _ string, _ string) (vulndomain.VulnerabilityRecord, bool, error) {
	panic("unexpected call: GetLatestVulnerabilityRecordForWalk")
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
func (s *fakeVulnStore) ListVulnerabilityRecordsByFindingID(_ context.Context, _ string) ([]vulndomain.VulnerabilityRecord, error) {
	panic("unexpected call: ListVulnerabilityRecordsByFindingID")
}
func (s *fakeVulnStore) ListVulnerabilityRecords(_ context.Context, _ string) ([]vulndomain.VulnerabilityRecord, error) {
	panic("unexpected call: ListVulnerabilityRecords")
}
func (s *fakeVulnStore) ListVulnerabilityRecordsForModule(_ context.Context, _ coordinate.ModuleCoordinate, _ string) ([]vulndomain.VulnerabilityRecord, error) {
	panic("unexpected call: ListVulnerabilityRecordsForModule")
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

// -- tests --

func TestLoadFindings_MapsFields(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	s := &fakeVulnStore{
		records: map[string]vulndomain.VulnerabilityRecord{
			"example.com/dep": {
				Coordinate: coord,
				Findings: []vulndomain.VulnerabilityFinding{
					{
						ID:              "GHSA-0001",
						Aliases:         []string{"CVE-2024-0001"},
						Summary:         "A test vulnerability",
						AffectedSymbols: []string{"VulnFunc", "(*VulnType).Method"},
					},
				},
			},
		},
	}
	adapter := store.New(s, "v1")

	result, err := adapter.LoadFindings(context.Background(), []coordinate.ModuleCoordinate{coord})
	if err != nil {
		t.Fatalf("LoadFindings: %v", err)
	}
	findings, ok := result[coord]
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
}

func TestLoadFindings_OmitsCoordWithNoRecord(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	s := &fakeVulnStore{records: map[string]vulndomain.VulnerabilityRecord{}} // no records
	adapter := store.New(s, "v1")

	result, err := adapter.LoadFindings(context.Background(), []coordinate.ModuleCoordinate{coord})
	if err != nil {
		t.Fatalf("LoadFindings: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("result len = %d, want 0 (coord with no record should be omitted)", len(result))
	}
}

func TestLoadFindings_OmitsCoordWithEmptyFindings(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	s := &fakeVulnStore{
		records: map[string]vulndomain.VulnerabilityRecord{
			"example.com/dep": {Coordinate: coord, Findings: nil},
		},
	}
	adapter := store.New(s, "v1")

	result, err := adapter.LoadFindings(context.Background(), []coordinate.ModuleCoordinate{coord})
	if err != nil {
		t.Fatalf("LoadFindings: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("result len = %d, want 0 (coord with no findings should be omitted)", len(result))
	}
}

func TestLoadFindings_MultipleCoords(t *testing.T) {
	coordA := mustCoord(t, "example.com/a", "v1.0.0")
	coordB := mustCoord(t, "example.com/b", "v2.0.0")
	coordC := mustCoord(t, "example.com/c", "v3.0.0") // no record
	s := &fakeVulnStore{
		records: map[string]vulndomain.VulnerabilityRecord{
			"example.com/a": {
				Coordinate: coordA,
				Findings:   []vulndomain.VulnerabilityFinding{{ID: "GHSA-A", Summary: "vuln A"}},
			},
			"example.com/b": {
				Coordinate: coordB,
				Findings:   []vulndomain.VulnerabilityFinding{{ID: "GHSA-B", Summary: "vuln B"}},
			},
		},
	}
	adapter := store.New(s, "v1")

	result, err := adapter.LoadFindings(context.Background(), []coordinate.ModuleCoordinate{coordA, coordB, coordC})
	if err != nil {
		t.Fatalf("LoadFindings: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("result len = %d, want 2", len(result))
	}
	if _, ok := result[coordA]; !ok {
		t.Error("coordA not in result")
	}
	if _, ok := result[coordB]; !ok {
		t.Error("coordB not in result")
	}
	if _, ok := result[coordC]; ok {
		t.Error("coordC should not be in result (no record)")
	}
}

func TestLoadFindings_StoreError_Propagates(t *testing.T) {
	coord := mustCoord(t, "example.com/dep", "v1.0.0")
	storeErr := errors.New("database unavailable")
	s := &fakeVulnStore{err: storeErr}
	adapter := store.New(s, "v1")

	_, err := adapter.LoadFindings(context.Background(), []coordinate.ModuleCoordinate{coord})
	if !errors.Is(err, storeErr) {
		t.Errorf("error = %v, want wrapping %v", err, storeErr)
	}
}

func TestLoadFindings_EmptyCoords(t *testing.T) {
	s := &fakeVulnStore{records: map[string]vulndomain.VulnerabilityRecord{}}
	adapter := store.New(s, "v1")

	result, err := adapter.LoadFindings(context.Background(), nil)
	if err != nil {
		t.Fatalf("LoadFindings: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("result len = %d, want 0", len(result))
	}
}

// Compile-time check that adapter satisfies the port interface.
var _ ports.VulnFindingLoader = (*store.VulnStoreAdapter)(nil)
