package application_test

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/coordinate"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// fakeAudit implements ports.AuditSink in memory, capturing every event so a
// test can assert what the read/serve verification path recorded. Set err to
// exercise the assurance-log failure path.
type fakeAudit struct {
	mu     sync.Mutex
	events []audit.Event
	err    error
}

func newFakeAudit() *fakeAudit { return &fakeAudit{} }

func (a *fakeAudit) RecordEvent(e audit.Event) error {
	if a.err != nil {
		return a.err
	}
	a.mu.Lock()
	a.events = append(a.events, e)
	a.mu.Unlock()
	return nil
}

// only returns the single captured event, failing the test if the count differs.
func (a *fakeAudit) only(t testingT) audit.Event {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.events) != 1 {
		t.Fatalf("want exactly one audit event, got %d: %+v", len(a.events), a.events)
	}
	return a.events[0]
}

// testingT is the slice of *testing.T that fakeAudit.only depends on, kept
// minimal so the helper does not import testing into a non-_test symbol.
type testingT interface {
	Helper()
	Fatalf(string, ...any)
}

// fakeProxy implements ports.ModuleProxy in memory.
type fakeProxy struct {
	mu           sync.Mutex
	infos        map[string]ports.ModuleInfo
	downloads    map[string]fakeDownload
	infoErr      error
	dlErr        error
	zipDownloads int // count of full Download (zip) calls
}

type fakeDownload struct {
	zipData   string
	goModData string
	zipHash   domain2.ModuleHash
	goModHash domain2.ModuleHash
}

func (f *fakeProxy) Info(_ context.Context, coord coordinate.ModuleCoordinate) (ports.ModuleInfo, error) {
	if f.infoErr != nil {
		return ports.ModuleInfo{}, f.infoErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	info, ok := f.infos[coord.String()]
	if !ok {
		info = ports.ModuleInfo{Version: coord.Version(), Time: time.Now()}
	}
	return info, nil
}

//goland:noinspection GrazieInspectionRunner
func (f *fakeProxy) Download(_ context.Context, coord coordinate.ModuleCoordinate) (ports.ModuleDownload, error) {
	if f.dlErr != nil {
		return ports.ModuleDownload{}, f.dlErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.zipDownloads++
	dl, ok := f.downloads[coord.String()]
	if !ok {
		dl = fakeDownload{
			zipData:   "fake-zip",
			goModData: "module " + coord.Path(),
			zipHash:   fetchtest.H1("fakehash=="),
			goModHash: fetchtest.H1("fakegomodhash=="),
		}
	}
	return ports.ModuleDownload{
		Zip:       io.NopCloser(strings.NewReader(dl.zipData)),
		GoMod:     io.NopCloser(strings.NewReader(dl.goModData)),
		ZipHash:   dl.zipHash,
		GoModHash: dl.goModHash,
	}, nil
}

func (f *fakeProxy) DownloadGoMod(_ context.Context, coord coordinate.ModuleCoordinate) (ports.GoModDownload, error) {
	if f.dlErr != nil {
		return ports.GoModDownload{}, f.dlErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	dl, ok := f.downloads[coord.String()]
	if !ok {
		dl = fakeDownload{
			goModData: "module " + coord.Path(),
			goModHash: fetchtest.H1("fakegomodhash=="),
		}
	}
	return ports.GoModDownload{
		GoMod:     io.NopCloser(strings.NewReader(dl.goModData)),
		GoModHash: dl.goModHash,
	}, nil
}

// fakeVCS implements ports.VCSClient in memory.
type fakeVCS struct {
	commits     map[string]string // "url|ref" → commit
	resolveErr  error
	checkoutErr error
}

func (f *fakeVCS) ResolveTag(_ context.Context, url, ref string) (string, error) {
	if f.resolveErr != nil {
		return "", f.resolveErr
	}
	key := url + "|" + ref
	if c, ok := f.commits[key]; ok {
		return c, nil
	}
	return strings.Repeat("a", 40), nil
}

func (f *fakeVCS) CheckoutToDir(_ context.Context, _, _, dir string) error {
	return f.checkoutErr
}

// fakeBlob implements ports.BlobStore in memory.
type fakeBlob struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newFakeBlob() *fakeBlob { return &fakeBlob{data: make(map[string][]byte)} }

func (f *fakeBlob) Put(_ context.Context, identity ports.BlobIdentity, content io.Reader) error {
	b, err := io.ReadAll(content)
	if err != nil {
		return fmt.Errorf("reading content: %w", err)
	}
	f.mu.Lock()
	f.data[identity.String()] = b
	f.mu.Unlock()
	return nil
}

func (f *fakeBlob) Get(_ context.Context, identity ports.BlobIdentity) (io.ReadCloser, error) {
	f.mu.Lock()
	b := f.data[identity.String()]
	f.mu.Unlock()
	return io.NopCloser(strings.NewReader(string(b))), nil
}

func (f *fakeBlob) Exists(_ context.Context, identity ports.BlobIdentity) (bool, error) {
	f.mu.Lock()
	_, ok := f.data[identity.String()]
	f.mu.Unlock()
	return ok, nil
}

func (f *fakeBlob) GetPath(_ context.Context, identity ports.BlobIdentity) (string, error) {
	f.mu.Lock()
	_, ok := f.data[identity.String()]
	f.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("blob not found: %s", identity)
	}
	return "/fake/path/" + identity.String(), nil
}

// fakeFacts implements ports.FactStore in memory.
type fakeFacts struct {
	mu      sync.Mutex
	records map[string]domain2.FactRecord
}

func newFakeFacts() *fakeFacts { return &fakeFacts{records: make(map[string]domain2.FactRecord)} }

func (f *fakeFacts) PutFetchRecord(_ context.Context, sealed domain2.SealedRecord) error {
	if sealed.IsZero() {
		return domain2.ErrUnsealedRecord
	}
	r := sealed.Record()
	key := r.ModulePath + "@" + r.ModuleVersion + "#" + r.PipelineVersion
	f.mu.Lock()
	f.records[key] = r
	f.mu.Unlock()
	return nil
}

func (f *fakeFacts) GetFetchRecord(_ context.Context, coord coordinate.ModuleCoordinate, pv string) (domain2.CompositeRecord, bool, error) {
	key := coord.Path() + "@" + coord.Version() + "#" + pv
	f.mu.Lock()
	r, ok := f.records[key]
	f.mu.Unlock()
	if !ok {
		return domain2.CompositeRecord{}, false, nil
	}
	c, cerr := domain2.Compose([]domain2.FactRecord{r})
	if cerr != nil {
		return domain2.CompositeRecord{}, false, cerr //nolint:wrapcheck // test fake
	}
	return c, true, nil
}

// fixedClock implements ports.Clock with a fixed time.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// fakeStopwatch implements ports.Stopwatch deterministically: every lap reports d.
type fakeStopwatch struct{ d time.Duration }

func (s fakeStopwatch) Start() ports.Lap { return fakeLap(s) }

type fakeLap struct{ d time.Duration }

func (l fakeLap) Elapsed() time.Duration { return l.d }

// fakeSumDB implements ports.SumDBClient with a configurable result.
type fakeSumDB struct {
	result ports.SumDBResult
}

func (f *fakeSumDB) Lookup(_ context.Context, _ coordinate.ModuleCoordinate) ports.SumDBResult {
	return f.result
}

// disabledSumDB returns a fakeSumDB that reports sumdb as unavailable.
func disabledSumDB() *fakeSumDB {
	return &fakeSumDB{result: ports.SumDBResult{Available: false, Reason: "disabled in tests"}}
}

// availableSumDB returns a fakeSumDB that reports the given zip hash as verified.
func availableSumDB(zipHash domain2.ModuleHash) *fakeSumDB {
	return &fakeSumDB{result: ports.SumDBResult{Available: true, ZipHash: zipHash}}
}

// mustSealRecord wraps a record in the SealedRecord the store accepts for
// writing. The store takes only sealed records, so a test that seeds one goes
// through here rather than reaching past the guard the ledger depends on.
func mustSealRecord(t *testing.T, r domain2.FactRecord) domain2.SealedRecord {
	t.Helper()
	sealed, err := domain2.Rehydrate(r)
	if err != nil {
		t.Fatalf("sealing record: %v", err)
	}
	return sealed
}

// seedRaw writes a record straight into the fake's map, past PutFetchRecord.
//
// It exists for the tests whose subject is a record that is ALREADY bad in the
// store. Such a record cannot be sealed — Rehydrate refuses it, which is exactly
// the guard those tests rely on elsewhere — so seeding it through the port is
// impossible by construction. Reaching past the port here is what lets the read
// side still be tested against the state an operator or a corrupted file can
// produce.
func (f *fakeFacts) seedRaw(r domain2.FactRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.records == nil {
		f.records = map[string]domain2.FactRecord{}
	}
	f.records[r.ModulePath+"@"+r.ModuleVersion+"#"+r.PipelineVersion] = r
}

// ListFetchRecords satisfies the optional ports.FactRecordLister capability, so
// the write path can find earlier measurements of an artefact and inherit the
// validation legs they established. A fake without it would make the pipeline
// inherit nothing, which is honest degradation but not what the tests that
// exercise inheritance are about.
func (f *fakeFacts) ListFetchRecords(_ context.Context, coord coordinate.ModuleCoordinate, pv string) ([]domain2.FactRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []domain2.FactRecord
	if r, ok := f.records[coord.Path()+"@"+coord.Version()+"#"+pv]; ok {
		out = append(out, r)
	}
	return out, nil
}
