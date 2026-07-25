package application_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
)

var errBlobNotFound = errors.New("blob not found")

type fakeClock struct{ t time.Time }

func (c fakeClock) Now() time.Time { return c.t }

// fakeStopwatch is a deterministic ports.Stopwatch: every lap reports d.
type fakeStopwatch struct{ d time.Duration }

func (s fakeStopwatch) Start() fetchports.Lap { return fakeLap(s) }

type fakeLap struct{ d time.Duration }

func (l fakeLap) Elapsed() time.Duration { return l.d }

type fakeFactStore struct {
	records map[factKey]domain2.FactRecord
}

type factKey struct{ path, version, pipeline string }

func (s *fakeFactStore) PutFetchRecord(_ context.Context, sealed domain2.SealedRecord) error {
	r := sealed.Record()
	if s.records == nil {
		s.records = make(map[factKey]domain2.FactRecord)
	}
	s.records[factKey{r.ModulePath, r.ModuleVersion, r.PipelineVersion}] = r
	return nil
}

func (s *fakeFactStore) GetFetchRecord(_ context.Context, coord coordinate.ModuleCoordinate, pv string) (domain2.CompositeRecord, bool, error) {
	if s.records == nil {
		return domain2.CompositeRecord{}, false, nil
	}
	r, ok := s.records[factKey{coord.Path, coord.Version, pv}]
	if !ok {
		return domain2.CompositeRecord{}, false, nil
	}
	c, err := domain2.Compose([]domain2.FactRecord{r})
	if err != nil {
		return domain2.CompositeRecord{}, false, err //nolint:wrapcheck // test fake
	}
	return c, true, nil
}

type fakeBlobStore struct {
	blobs map[string][]byte
}

func (s *fakeBlobStore) Put(_ context.Context, identity fetchports.BlobIdentity, r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("reading blob: %w", err)
	}
	if s.blobs == nil {
		s.blobs = make(map[string][]byte)
	}
	s.blobs[identity.String()] = data
	return nil
}

func (s *fakeBlobStore) Get(_ context.Context, identity fetchports.BlobIdentity) (io.ReadCloser, error) {
	if s.blobs == nil {
		return nil, errBlobNotFound
	}
	data, ok := s.blobs[identity.String()]
	if !ok {
		return nil, errBlobNotFound
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (s *fakeBlobStore) Exists(_ context.Context, identity fetchports.BlobIdentity) (bool, error) {
	if s.blobs == nil {
		return false, nil
	}
	_, ok := s.blobs[identity.String()]
	return ok, nil
}

func (s *fakeBlobStore) GetPath(_ context.Context, identity fetchports.BlobIdentity) (string, error) {
	if s.blobs == nil {
		return "", errBlobNotFound
	}
	_, ok := s.blobs[identity.String()]
	if !ok {
		return "", errBlobNotFound
	}
	// For testing, we might need real files if the analyser actually reads them.
	// But in these unit tests, many things are mocked.
	// We'll return a fake path for now.
	return "/fake/path/" + identity.String(), nil
}

type fakeCallGraphStore struct {
	records map[cgKey]domain.CallGraphRecord
	putErr  error
	getErr  error
}

type cgKey struct{ path, version, pipeline string }

func (s *fakeCallGraphStore) PutCallGraphRecord(_ context.Context, r domain.CallGraphRecord) error {
	if s.putErr != nil {
		return s.putErr
	}
	if s.records == nil {
		s.records = make(map[cgKey]domain.CallGraphRecord)
	}
	s.records[cgKey{r.Coordinate.Path, r.Coordinate.Version, r.PipelineVersion}] = r
	return nil
}

func (s *fakeCallGraphStore) GetCallGraphRecord(_ context.Context, coord coordinate.ModuleCoordinate, pv string) (domain.CallGraphRecord, bool, error) {
	if s.getErr != nil {
		return domain.CallGraphRecord{}, false, s.getErr
	}
	if s.records == nil {
		return domain.CallGraphRecord{}, false, nil
	}
	r, ok := s.records[cgKey{coord.Path, coord.Version, pv}]
	return r, ok, nil
}

func (s *fakeCallGraphStore) ListCallGraphRecords(_ context.Context, _ ports.CallGraphFilter) ([]ports.CallGraphSummary, error) {
	return nil, nil
}

func (s *fakeCallGraphStore) FindCallers(_ context.Context, _ string, _ string) ([]ports.CallEdgeRef, error) {
	return nil, nil
}

func (s *fakeCallGraphStore) FindCallees(_ context.Context, _ string, _ string) ([]ports.CallEdgeRef, error) {
	return nil, nil
}

type fakeAnalyser struct {
	record  domain.CallGraphRecord
	err     error
	lastDir string
	calls   int
}

func (f *fakeAnalyser) AnalyserMetadata() ports.AnalyserMetadata {
	return ports.AnalyserMetadata{Algorithm: domain.AlgorithmCHA, Version: "test"}
}

func (f *fakeAnalyser) Analyse(_ context.Context, _ string, coord coordinate.ModuleCoordinate) (domain.CallGraphRecord, error) {
	if f.err != nil {
		return domain.CallGraphRecord{}, f.err
	}
	r := f.record
	r.Coordinate = coord
	return r, nil
}

// AnalyseDir lets fakeAnalyser double as a ports.LocalCallGraphAnalyser.
// dir is recorded so tests can assert it was forwarded.
func (f *fakeAnalyser) AnalyseDir(_ context.Context, dir string, coord coordinate.ModuleCoordinate) (domain.CallGraphRecord, error) {
	f.lastDir = dir
	f.calls++
	if f.err != nil {
		return domain.CallGraphRecord{}, f.err
	}
	r := f.record
	r.Coordinate = coord
	return r, nil
}

// Compile-time interface checks.
var _ fetchports.FactStore = (*fakeFactStore)(nil)
var _ fetchports.BlobStore = (*fakeBlobStore)(nil)
var _ ports.CallGraphStore = (*fakeCallGraphStore)(nil)
var _ ports.CallGraphAnalyser = (*fakeAnalyser)(nil)
var _ ports.LocalCallGraphAnalyser = (*fakeAnalyser)(nil)
