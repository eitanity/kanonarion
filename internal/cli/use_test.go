package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
)

// TestCopyToModCache_PipelineVersionBinding pins the contract that
// copyToModCache looks up the fact record under the caller-supplied
// pipeline version. A regression here resurfaces the silent
// "fact record not found" failure for walks whose fetch records live
// under a non-default PV (e.g. after a PV bump).
func TestCopyToModCache_PipelineVersionBinding(t *testing.T) {
	c, err := coordinate.NewModuleCoordinate("example.com/m", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	const storedPV = "9.9.9"

	facts := newPVFakeFacts()
	_ = facts.PutFetchRecord(context.Background(), fetchdomain.FactRecord{
		ModulePath:      c.Path,
		ModuleVersion:   c.Version,
		PipelineVersion: storedPV,
		ContentLocation: "fake:zip",
	})
	blobs := newPVFakeBlobs() // Get always errors — we only care about the lookup
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Matching PV: lookup succeeds, code proceeds past GetFetchRecord and
	// fails at the next step (blob fetch / mkdir). Any error string other
	// than "fact record not found" proves the lookup matched.
	err = copyToModCache(context.Background(), c, facts, blobs, t.TempDir(), storedPV, logger)
	if err == nil {
		t.Fatal("expected an error after the fact lookup (no real blob)")
	}
	if strings.Contains(err.Error(), "fact record not found") {
		t.Fatalf("matching PV should have found the record, got: %v", err)
	}

	// Wrong PV: must surface "fact record not found", proving the argument
	// is honoured rather than a compile-time constant.
	err = copyToModCache(context.Background(), c, facts, blobs, t.TempDir(), "0.0.0", logger)
	if err == nil || !strings.Contains(err.Error(), "fact record not found") {
		t.Fatalf("wrong PV should have returned 'fact record not found', got: %v", err)
	}
}

// pvFakeFacts is a minimal in-memory FactStore for the PV-binding test.
type pvFakeFacts struct {
	mu      sync.Mutex
	records map[string]fetchdomain.FactRecord
}

func newPVFakeFacts() *pvFakeFacts {
	return &pvFakeFacts{records: make(map[string]fetchdomain.FactRecord)}
}

func (f *pvFakeFacts) PutFetchRecord(_ context.Context, r fetchdomain.FactRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[r.ModulePath+"@"+r.ModuleVersion+"#"+r.PipelineVersion] = r
	return nil
}

func (f *pvFakeFacts) GetFetchRecord(_ context.Context, coord coordinate.ModuleCoordinate, pv string) (fetchdomain.FactRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.records[coord.Path+"@"+coord.Version+"#"+pv]
	return r, ok, nil
}

// pvFakeBlobs satisfies BlobStore but never returns content; copyToModCache
// only reaches Get after a successful fact lookup, and the binding test only
// needs to distinguish lookup-miss from lookup-hit.
type pvFakeBlobs struct{}

func newPVFakeBlobs() *pvFakeBlobs { return &pvFakeBlobs{} }

func (pvFakeBlobs) Put(_ context.Context, _ io.Reader) (fetchports.BlobHandle, error) {
	return "", errors.New("not implemented")
}

func (pvFakeBlobs) Get(_ context.Context, h fetchports.BlobHandle) (io.ReadCloser, error) {
	return nil, fmt.Errorf("blob not found: %s", h)
}

func (pvFakeBlobs) GetPath(_ context.Context, h fetchports.BlobHandle) (string, error) {
	return "", fmt.Errorf("blob not found: %s", h)
}

func (pvFakeBlobs) Exists(_ context.Context, _ fetchports.BlobHandle) (bool, error) {
	return false, nil
}
