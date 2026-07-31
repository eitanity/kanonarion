package application_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/iface/domain"
	"github.com/eitanity/kanonarion/internal/iface/ports"
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

// ComposeFetchRecord answers the coordinate-only composed read, satisfying the
// optional fetchports.FactRecordComposer capability. It folds every record filed
// for the coordinate whatever pipeline version wrote it, exactly as the sqlite
// store does — a fake that consulted one pipeline version here would let a test
// go green on a read production answers differently.
func (s *fakeFactStore) ComposeFetchRecord(_ context.Context, coord coordinate.ModuleCoordinate) (domain2.CompositeRecord, bool, error) {
	if coord.IsZero() {
		return domain2.CompositeRecord{}, false, coordinate.ErrZeroCoordinate
	}
	held := make([]domain2.FactRecord, 0, len(s.records))
	for _, r := range s.records {
		held = append(held, r)
	}
	//nolint:wrapcheck // test fake; the helper already names the coordinate
	return fetchtest.ComposeCoordinate(coord, held)
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

// fakeInterfaceStore holds interface records keyed by (path, version, pipeline).
type fakeInterfaceStore struct {
	records map[ifaceKey]domain.InterfaceRecord
	putErr  error
}

type ifaceKey struct{ path, version, pipeline string }

func (s *fakeInterfaceStore) PutInterfaceRecord(_ context.Context, r domain.InterfaceRecord) error {
	if s.putErr != nil {
		return s.putErr
	}
	if s.records == nil {
		s.records = make(map[ifaceKey]domain.InterfaceRecord)
	}
	s.records[ifaceKey{r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion}] = r
	return nil
}

func (s *fakeInterfaceStore) GetInterfaceRecord(_ context.Context, coord coordinate.ModuleCoordinate, pv string) (domain.InterfaceRecord, bool, error) {
	if s.records == nil {
		return domain.InterfaceRecord{}, false, nil
	}
	r, ok := s.records[ifaceKey{coord.Path(), coord.Version(), pv}]
	return r, ok, nil
}

func (s *fakeInterfaceStore) ListInterfaceRecords(_ context.Context, _ ports.InterfaceFilter) ([]ports.InterfaceSummary, error) {
	return nil, nil
}

func (s *fakeInterfaceStore) FindSymbol(_ context.Context, _ string, _ string, _ coordinate.ModuleSet) ([]ports.SymbolRef, error) {
	return nil, nil
}

// fakeExtractor returns a fixed InterfaceRecord.
type fakeExtractor struct {
	record domain.InterfaceRecord
	err    error
}

func (f *fakeExtractor) Extract(_ context.Context, _ fs.FS, coord coordinate.ModuleCoordinate) (domain.InterfaceRecord, error) {
	if f.err != nil {
		return domain.InterfaceRecord{}, f.err
	}
	r := f.record
	r.Coordinate = coord
	return r, nil
}

// Compile-time interface checks.
var _ fetchports.FactStore = (*fakeFactStore)(nil)
var _ fetchports.BlobStore = (*fakeBlobStore)(nil)
var _ ports.InterfaceStore = (*fakeInterfaceStore)(nil)
var _ ports.InterfaceExtractor = (*fakeExtractor)(nil)
