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
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
)

// This test used to pin the opposite contract: that copyToModCache looked the
// record up under a caller-supplied pipeline version, which the command dug out of
// the walk's per-node FetchRecord and, failing that, guessed from a compile-time
// constant. That workaround is what the version-keyed read forced, and it left the
// silent "fact record not found" it was written to avoid for any walk whose
// records predated the per-node field.
//
// What it pins now is that no pipeline version is supplied at all, and the record
// is found under a version no caller names.
func TestCopyToModCache_FindsARecordUnderAnyPipelineVersion(t *testing.T) {
	c, err := coordinate.NewModuleCoordinate("example.com/m", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	const storedPV = "9.9.9"

	facts := newPVFakeFacts()
	_ = facts.PutFetchRecord(context.Background(), fetchtest.Sealed(t, fetchtest.Coordinate(c), fetchtest.PipelineVersion(storedPV), fetchtest.Content("fake:zip")))
	blobs := newPVFakeBlobs() // Get always errors — we only care about the lookup
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// The lookup succeeds and the copy proceeds to fail at the next step (blob
	// fetch), so any error other than "fact record not found" proves the record
	// was found without its pipeline version being named.
	err = copyToModCache(context.Background(), c, facts, blobs, t.TempDir(), logger)
	if err == nil {
		t.Fatal("expected an error after the fact lookup (no real blob)")
	}
	if strings.Contains(err.Error(), "fact record not found") {
		t.Fatalf("the record is held at pipeline %s and must be found without the caller naming it, got: %v", storedPV, err)
	}

	// A coordinate the ledger holds nothing about is still absent.
	other, err := coordinate.NewModuleCoordinate("example.com/absent", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	err = copyToModCache(context.Background(), other, facts, blobs, t.TempDir(), logger)
	if err == nil || !strings.Contains(err.Error(), "fact record not found") {
		t.Fatalf("an unmeasured coordinate should have returned 'fact record not found', got: %v", err)
	}
}

// pvFakeFacts is a minimal in-memory FactStore for the lookup test.
type pvFakeFacts struct {
	mu      sync.Mutex
	records map[string]fetchdomain.FactRecord
}

func newPVFakeFacts() *pvFakeFacts {
	return &pvFakeFacts{records: make(map[string]fetchdomain.FactRecord)}
}

func (f *pvFakeFacts) PutFetchRecord(_ context.Context, sealed fetchdomain.SealedRecord) error {
	if sealed.IsZero() {
		return fetchdomain.ErrUnsealedRecord
	}
	r := sealed.Record()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[r.ModulePath+"@"+r.ModuleVersion+"#"+r.PipelineVersion] = r
	return nil
}

func (f *pvFakeFacts) GetFetchRecord(_ context.Context, coord coordinate.ModuleCoordinate, pv string) (fetchdomain.CompositeRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.records[coord.Path()+"@"+coord.Version()+"#"+pv]
	if !ok {
		return fetchdomain.CompositeRecord{}, false, nil
	}
	c, cerr := fetchdomain.Compose([]fetchdomain.FactRecord{r})
	if cerr != nil {
		return fetchdomain.CompositeRecord{}, false, cerr //nolint:wrapcheck // test fake
	}
	return c, true, nil
}

// ComposeFetchRecord answers the coordinate-only composed read, satisfying the
// optional fetchports.FactRecordComposer capability the way the sqlite store does.
func (f *pvFakeFacts) ComposeFetchRecord(_ context.Context, coord coordinate.ModuleCoordinate) (fetchdomain.CompositeRecord, bool, error) {
	if coord.IsZero() {
		return fetchdomain.CompositeRecord{}, false, coordinate.ErrZeroCoordinate
	}
	f.mu.Lock()
	held := make([]fetchdomain.FactRecord, 0, len(f.records))
	for _, r := range f.records {
		held = append(held, r)
	}
	f.mu.Unlock()
	//nolint:wrapcheck // test fake; the helper already names the coordinate
	return fetchtest.ComposeCoordinate(coord, held)
}

// pvFakeBlobs satisfies BlobStore but never returns content; copyToModCache
// only reaches Get after a successful fact lookup, and the binding test only
// needs to distinguish lookup-miss from lookup-hit.
type pvFakeBlobs struct{}

func newPVFakeBlobs() *pvFakeBlobs { return &pvFakeBlobs{} }

func (pvFakeBlobs) Put(_ context.Context, identity fetchports.BlobIdentity, _ io.Reader) error {
	return errors.New("not implemented")
}

func (pvFakeBlobs) Get(_ context.Context, identity fetchports.BlobIdentity) (io.ReadCloser, error) {
	return nil, fmt.Errorf("blob not found: %s", identity)
}

func (pvFakeBlobs) GetPath(_ context.Context, identity fetchports.BlobIdentity) (string, error) {
	return "", fmt.Errorf("blob not found: %s", identity)
}

func (pvFakeBlobs) Exists(_ context.Context, identity fetchports.BlobIdentity) (bool, error) {
	return false, nil
}
