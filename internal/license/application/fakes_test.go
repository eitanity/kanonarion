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
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
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

// fakeLicenceStore holds license records.
type fakeLicenseStore struct {
	records map[licenseKey]domain.LicenseRecord
	// puts is every record written, in order. The map above keeps one record per
	// coordinate, so it cannot say how many generations a run appended — which is
	// the whole question when a local tree is re-read.
	puts []domain.LicenseRecord
	// getErr makes the read leg fail, which is the only way to reach a caller's
	// store-failure branch: a fake that can only be empty proves absence
	// handling and nothing else.
	getErr error
}

type licenseKey struct{ path, version, pipeline string }

func (s *fakeLicenseStore) PutLicenseRecord(_ context.Context, r domain.LicenseRecord) error {
	if s.records == nil {
		s.records = make(map[licenseKey]domain.LicenseRecord)
	}
	s.records[licenseKey{r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion}] = r
	s.puts = append(s.puts, r)
	return nil
}

// IdenticalGeneration lets fakeLicenseStore answer the after-the-fact read: does
// the ledger already hold this measurement?
//
// It reads the append log rather than the records map, because the map keeps one
// record per coordinate and the question is about every generation the ledger
// holds. The rule is the domain's, so a test cannot go green on a laxer one than
// the sqlite store applies. Newest first, matching the store.
func (s *fakeLicenseStore) IdenticalGeneration(_ context.Context, rec domain.LicenseRecord) (domain.LicenseRecord, bool, error) {
	if s.getErr != nil {
		return domain.LicenseRecord{}, false, s.getErr
	}
	if !domain.NamesAnalysedContent(rec) {
		return domain.LicenseRecord{}, false, nil
	}
	for i := len(s.puts) - 1; i >= 0; i-- {
		held := s.puts[i]
		if held.Coordinate != rec.Coordinate || held.PipelineVersion != rec.PipelineVersion {
			continue
		}
		same, err := domain.SameMeasurement(rec, held)
		if err != nil {
			return domain.LicenseRecord{}, false, err //nolint:wrapcheck // test fake
		}
		if same {
			return held, true, nil
		}
	}
	return domain.LicenseRecord{}, false, nil
}

func (s *fakeLicenseStore) GetLicenseRecord(_ context.Context, coord coordinate.ModuleCoordinate, pv string) (domain.LicenseRecord, bool, error) {
	if s.getErr != nil {
		return domain.LicenseRecord{}, false, s.getErr
	}
	if s.records == nil {
		return domain.LicenseRecord{}, false, nil
	}
	r, ok := s.records[licenseKey{coord.Path(), coord.Version(), pv}]
	return r, ok, nil
}

func (s *fakeLicenseStore) ListLicenseRecords(_ context.Context, _ ports.LicenseFilter) ([]ports.LicenseSummary, error) {
	return nil, nil
}

// fakeDetector returns a fixed match for every call.
type fakeDetector struct {
	match ports.LicenseMatch
	meta  ports.DetectorMetadata
	// calls counts detections, so a test can tell a served answer from a
	// measured one without inspecting what was served.
	calls int
}

func (d *fakeDetector) Detect(_ context.Context, _ []byte) (ports.LicenseMatch, error) {
	d.calls++
	return d.match, nil
}

func (d *fakeDetector) DetectorMetadata() ports.DetectorMetadata {
	return d.meta
}

// Ensure the fake offers the optional capability the use case looks for; a fake
// that silently did not would make every reuse test pass by never asking.
var _ ports.IdenticalGenerationReader = (*fakeLicenseStore)(nil)
