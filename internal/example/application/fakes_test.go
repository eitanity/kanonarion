package application_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/example/domain"
	"github.com/eitanity/kanonarion/internal/example/ports"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
)

var errBlobNotFound = errors.New("blob not found")

// fakeClock returns a fixed time.
type fakeClock struct{ t time.Time }

func (c fakeClock) Now() time.Time { return c.t }

// fakeStopwatch is a deterministic ports.Stopwatch: every lap reports d.
type fakeStopwatch struct{ d time.Duration }

func (s fakeStopwatch) Start() fetchports.Lap { return fakeLap(s) }

type fakeLap struct{ d time.Duration }

func (l fakeLap) Elapsed() time.Duration { return l.d }

// fakeFactStore holds fetch records keyed by (path, version, pipeline_version).
type fakeFactStore struct {
	records map[factKey]domain2.FactRecord
}

type factKey struct{ path, version, pipeline string }

func (s *fakeFactStore) PutFetchRecord(_ context.Context, sealed domain2.SealedRecord) error {
	if sealed.IsZero() {
		return domain2.ErrUnsealedRecord
	}
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
	r, ok := s.records[factKey{coord.Path(), coord.Version(), pv}]
	if !ok {
		return domain2.CompositeRecord{}, false, nil
	}
	c, err := domain2.Compose([]domain2.FactRecord{r})
	if err != nil {
		return domain2.CompositeRecord{}, false, err //nolint:wrapcheck // test fake
	}
	return c, true, nil
}

// fakeBlobStore holds blobs keyed by handle.
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
	return "/fake/path/" + identity.String(), nil
}

// fakeExampleStore holds example records keyed by (path, version, pipeline_version).
type fakeExampleStore struct {
	records map[exampleKey]domain.ExampleRecord
}

type exampleKey struct{ path, version, pipeline string }

func (s *fakeExampleStore) PutExampleRecord(_ context.Context, r domain.ExampleRecord) error {
	if s.records == nil {
		s.records = make(map[exampleKey]domain.ExampleRecord)
	}
	s.records[exampleKey{r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion}] = r
	return nil
}

func (s *fakeExampleStore) GetExampleRecord(_ context.Context, coord coordinate.ModuleCoordinate, pv string) (domain.ExampleRecord, bool, error) {
	if s.records == nil {
		return domain.ExampleRecord{}, false, nil
	}
	r, ok := s.records[exampleKey{coord.Path(), coord.Version(), pv}]
	return r, ok, nil
}

func (s *fakeExampleStore) ListExampleRecords(_ context.Context, _ ports.ExampleFilter) ([]ports.ExampleSummary, error) {
	return nil, nil
}

func (s *fakeExampleStore) FindBySymbol(_ context.Context, _ string, _ string, _ coordinate.ModuleSet) ([]ports.ExampleRef, error) {
	return nil, nil
}

func (s *fakeExampleStore) FindBySymbolInModule(_ context.Context, _ coordinate.ModuleCoordinate, _ string, _ string) ([]ports.ExampleRef, error) {
	return nil, nil
}

// Ensure fakes satisfy their interfaces at compile time.
var _ fetchports.FactStore = (*fakeFactStore)(nil)
var _ fetchports.BlobStore = (*fakeBlobStore)(nil)
var _ ports.ExampleStore = (*fakeExampleStore)(nil)
