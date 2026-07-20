package application_test

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/coordinate"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
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
	mu        sync.Mutex
	infos     map[string]ports.ModuleInfo
	downloads map[string]fakeDownload
	infoErr   error
	dlErr     error
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
		info = ports.ModuleInfo{Version: coord.Version, Time: time.Now()}
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
	dl, ok := f.downloads[coord.String()]
	if !ok {
		dl = fakeDownload{
			zipData:   "fake-zip",
			goModData: "module " + coord.Path,
			zipHash:   domain2.ModuleHash{Algorithm: "h1", Value: "fakehash=="},
			goModHash: domain2.ModuleHash{Algorithm: "h1", Value: "fakegomodhash=="},
		}
	}
	return ports.ModuleDownload{
		Zip:       io.NopCloser(strings.NewReader(dl.zipData)),
		GoMod:     io.NopCloser(strings.NewReader(dl.goModData)),
		ZipHash:   dl.zipHash,
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
	data map[ports.BlobHandle][]byte
}

func newFakeBlob() *fakeBlob { return &fakeBlob{data: make(map[ports.BlobHandle][]byte)} }

func (f *fakeBlob) Put(_ context.Context, content io.Reader) (ports.BlobHandle, error) {
	b, err := io.ReadAll(content)
	if err != nil {
		return "", fmt.Errorf("reading content: %w", err)
	}
	h := ports.BlobHandle("fake:" + string(b))
	f.mu.Lock()
	f.data[h] = b
	f.mu.Unlock()
	return h, nil
}

func (f *fakeBlob) Get(_ context.Context, h ports.BlobHandle) (io.ReadCloser, error) {
	f.mu.Lock()
	b := f.data[h]
	f.mu.Unlock()
	return io.NopCloser(strings.NewReader(string(b))), nil
}

func (f *fakeBlob) Exists(_ context.Context, h ports.BlobHandle) (bool, error) {
	f.mu.Lock()
	_, ok := f.data[h]
	f.mu.Unlock()
	return ok, nil
}

func (f *fakeBlob) GetPath(_ context.Context, h ports.BlobHandle) (string, error) {
	f.mu.Lock()
	_, ok := f.data[h]
	f.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("blob not found: %s", h)
	}
	return "/fake/path/" + string(h), nil
}

// fakeFacts implements ports.FactStore in memory.
type fakeFacts struct {
	mu      sync.Mutex
	records map[string]domain2.FactRecord
}

func newFakeFacts() *fakeFacts { return &fakeFacts{records: make(map[string]domain2.FactRecord)} }

func (f *fakeFacts) PutFetchRecord(_ context.Context, r domain2.FactRecord) error {
	key := r.ModulePath + "@" + r.ModuleVersion + "#" + r.PipelineVersion
	f.mu.Lock()
	f.records[key] = r
	f.mu.Unlock()
	return nil
}

func (f *fakeFacts) GetFetchRecord(_ context.Context, coord coordinate.ModuleCoordinate, pv string) (domain2.FactRecord, bool, error) {
	key := coord.Path + "@" + coord.Version + "#" + pv
	f.mu.Lock()
	r, ok := f.records[key]
	f.mu.Unlock()
	return r, ok, nil
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
