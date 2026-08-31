package application_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/native/domain"
	"github.com/eitanity/kanonarion/internal/native/ports"
)

var errBlobNotFound = errors.New("blob not found")

type fakeClock struct{ t time.Time }

func (c fakeClock) Now() time.Time { return c.t }

type fakeStopwatch struct{}

func (fakeStopwatch) Start() fetchports.Lap { return fakeLap{} }

type fakeLap struct{}

func (fakeLap) Elapsed() time.Duration { return 0 }

// fakeFactStore holds fetch measurements the way the real ledger does: keyed by
// coordinate, composed on read.
type fakeFactStore struct {
	records []fetchdomain.FactRecord
}

func (s *fakeFactStore) PutFetchRecord(_ context.Context, sealed fetchdomain.SealedRecord) error {
	if sealed.IsZero() {
		return fetchdomain.ErrUnsealedRecord
	}
	s.records = append(s.records, sealed.Record())
	return nil
}

func (s *fakeFactStore) GetFetchRecord(_ context.Context, coord coordinate.ModuleCoordinate, pv string) (fetchdomain.CompositeRecord, bool, error) {
	held := make([]fetchdomain.FactRecord, 0, len(s.records))
	for _, r := range s.records {
		if r.Coordinate() == coord && r.PipelineVersion == pv {
			held = append(held, r)
		}
	}
	if len(held) == 0 {
		return fetchdomain.CompositeRecord{}, false, nil
	}
	c, err := fetchdomain.Compose(held)
	if err != nil {
		return fetchdomain.CompositeRecord{}, false, err //nolint:wrapcheck // test fake
	}
	return c, true, nil
}

func (s *fakeFactStore) ComposeFetchRecord(_ context.Context, coord coordinate.ModuleCoordinate) (fetchdomain.CompositeRecord, bool, error) {
	if coord.IsZero() {
		return fetchdomain.CompositeRecord{}, false, coordinate.ErrZeroCoordinate
	}
	//nolint:wrapcheck // test fake; the helper already names the coordinate
	return fetchtest.ComposeCoordinate(coord, s.records)
}

func (s *fakeFactStore) ListFetchRecords(_ context.Context, coord coordinate.ModuleCoordinate, pv string) ([]fetchdomain.FactRecord, error) {
	var out []fetchdomain.FactRecord
	for _, r := range s.records {
		if r.Coordinate() == coord && r.PipelineVersion == pv {
			out = append(out, r)
		}
	}
	return out, nil
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
		s.blobs = map[string][]byte{}
	}
	s.blobs[identity.String()] = data
	return nil
}

func (s *fakeBlobStore) Get(_ context.Context, identity fetchports.BlobIdentity) (io.ReadCloser, error) {
	data, ok := s.blobs[identity.String()]
	if !ok {
		return nil, errBlobNotFound
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (s *fakeBlobStore) Exists(_ context.Context, identity fetchports.BlobIdentity) (bool, error) {
	_, ok := s.blobs[identity.String()]
	return ok, nil
}

// fakeNativeStore counts writes as well as holding them, so a test can tell a
// served record from a re-measured one.
type fakeNativeStore struct {
	records map[coordinate.ModuleCoordinate]domain.Record
	puts    int
	getErr  error
}

func (s *fakeNativeStore) PutNativeRecord(_ context.Context, rec domain.Record) error {
	if rec.Coordinate.IsZero() {
		return coordinate.ErrZeroCoordinate
	}
	if s.records == nil {
		s.records = map[coordinate.ModuleCoordinate]domain.Record{}
	}
	s.records[rec.Coordinate] = rec
	s.puts++
	return nil
}

func (s *fakeNativeStore) GetNativeRecord(_ context.Context, coord coordinate.ModuleCoordinate) (domain.Record, bool, error) {
	if s.getErr != nil {
		return domain.Record{}, false, s.getErr
	}
	rec, ok := s.records[coord]
	return rec, ok, nil
}

// failingSourceReader stands in for a Go file whose header cannot be parsed.
type failingSourceReader struct{ err error }

func (r failingSourceReader) ImportPaths(string, []byte) ([]string, error) { return nil, r.err }
func (r failingSourceReader) CgoPreamble(string, []byte) (string, error)   { return "", r.err }

// failingPreambleReader answers imports but not the preamble, so a preamble
// that cannot be read is not silently taken as "links nothing".
type failingPreambleReader struct {
	inner ports.GoSourceReader
	err   error
}

func (r failingPreambleReader) ImportPaths(name string, src []byte) ([]string, error) {
	return r.inner.ImportPaths(name, src) //nolint:wrapcheck // test fake
}
func (r failingPreambleReader) CgoPreamble(string, []byte) (string, error) { return "", r.err }

// bytesReader wraps fixture bytes for the blob port's Put.
func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// buildZip renders files into a module zip, keying every entry under the
// standard "<path>@<version>/" prefix a module zip carries.
func buildZip(t *testing.T, coord coordinate.ModuleCoordinate, files map[string]string) []byte {
	t.Helper()
	return buildZipWithPrefix(t, coord.Path()+"@"+coord.Version()+"/", files)
}

func buildZipWithPrefix(t *testing.T, prefix string, files map[string]string) []byte {
	t.Helper()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	for _, name := range names {
		w, err := zw.Create(prefix + name)
		if err != nil {
			t.Fatalf("creating zip entry %s: %v", name, err)
		}
		if _, err := w.Write([]byte(files[name])); err != nil {
			t.Fatalf("writing zip entry %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing zip: %v", err)
	}
	return buf.Bytes()
}
