package application_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/license/domain"
	"github.com/eitanity/kanonarion/internal/license/ports"
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

func (s *fakeFactStore) PutFetchRecord(_ context.Context, r domain2.FactRecord) error {
	if s.records == nil {
		s.records = make(map[factKey]domain2.FactRecord)
	}
	s.records[factKey{r.ModulePath, r.ModuleVersion, r.PipelineVersion}] = r
	return nil
}

func (s *fakeFactStore) GetFetchRecord(_ context.Context, coord coordinate.ModuleCoordinate, pv string) (domain2.FactRecord, bool, error) {
	if s.records == nil {
		return domain2.FactRecord{}, false, nil
	}
	r, ok := s.records[factKey{coord.Path, coord.Version, pv}]
	return r, ok, nil
}

// fakeBlobStore holds blobs keyed by handle.
type fakeBlobStore struct {
	blobs map[fetchports.BlobHandle][]byte
}

func (s *fakeBlobStore) Put(_ context.Context, r io.Reader) (fetchports.BlobHandle, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("reading blob content: %w", err)
	}
	h := fetchports.BlobHandle("blob:" + string(data[:min(8, len(data))]))
	if s.blobs == nil {
		s.blobs = make(map[fetchports.BlobHandle][]byte)
	}
	s.blobs[h] = data
	return h, nil
}

func (s *fakeBlobStore) Get(_ context.Context, h fetchports.BlobHandle) (io.ReadCloser, error) {
	if s.blobs == nil {
		return nil, errBlobNotFound
	}
	data, ok := s.blobs[h]
	if !ok {
		return nil, errBlobNotFound
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (s *fakeBlobStore) Exists(_ context.Context, h fetchports.BlobHandle) (bool, error) {
	if s.blobs == nil {
		return false, nil
	}
	_, ok := s.blobs[h]
	return ok, nil
}

func (s *fakeBlobStore) GetPath(_ context.Context, h fetchports.BlobHandle) (string, error) {
	if s.blobs == nil {
		return "", errBlobNotFound
	}
	_, ok := s.blobs[h]
	if !ok {
		return "", errBlobNotFound
	}
	return "/fake/path/" + string(h), nil
}

// fakeLicenceStore holds license records.
type fakeLicenseStore struct {
	records map[licenseKey]domain.LicenseRecord
}

type licenseKey struct{ path, version, pipeline string }

func (s *fakeLicenseStore) PutLicenseRecord(_ context.Context, r domain.LicenseRecord) error {
	if s.records == nil {
		s.records = make(map[licenseKey]domain.LicenseRecord)
	}
	s.records[licenseKey{r.Coordinate.Path, r.Coordinate.Version, r.PipelineVersion}] = r
	return nil
}

func (s *fakeLicenseStore) GetLicenseRecord(_ context.Context, coord coordinate.ModuleCoordinate, pv string) (domain.LicenseRecord, bool, error) {
	if s.records == nil {
		return domain.LicenseRecord{}, false, nil
	}
	r, ok := s.records[licenseKey{coord.Path, coord.Version, pv}]
	return r, ok, nil
}

func (s *fakeLicenseStore) ListLicenseRecords(_ context.Context, _ ports.LicenseFilter) ([]ports.LicenseSummary, error) {
	return nil, nil
}

// fakeDetector returns a fixed match for every call.
type fakeDetector struct {
	match ports.LicenseMatch
	meta  ports.DetectorMetadata
}

func (d *fakeDetector) Detect(_ context.Context, _ []byte) (ports.LicenseMatch, error) {
	return d.match, nil
}

func (d *fakeDetector) DetectorMetadata() ports.DetectorMetadata {
	return d.meta
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
