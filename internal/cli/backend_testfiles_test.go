package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
	fetchsqlite "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/audit"
	cgsqlite "github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/composition/storage"
	sqlitestorage "github.com/eitanity/kanonarion/internal/composition/storage/sqlite"
	"github.com/eitanity/kanonarion/internal/coordinate"
	dirsqlite "github.com/eitanity/kanonarion/internal/directive/adapters/store/sqlite"
	exsqlite "github.com/eitanity/kanonarion/internal/example/adapters/store/sqlite"
	extstore "github.com/eitanity/kanonarion/internal/extract/adapters/store/sqlite"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fipssqlite "github.com/eitanity/kanonarion/internal/fips/adapters/store/sqlite"
	gdsqlite "github.com/eitanity/kanonarion/internal/godebug/adapters/store/sqlite"
	ifacesqlite "github.com/eitanity/kanonarion/internal/iface/adapters/store/sqlite"
	licsqlite "github.com/eitanity/kanonarion/internal/license/adapters/store/sqlite"
	nativesqlite "github.com/eitanity/kanonarion/internal/native/adapters/store/sqlite"
	sbomstore "github.com/eitanity/kanonarion/internal/sbom/adapters/store/sqlite"
	stalesqlite "github.com/eitanity/kanonarion/internal/staleness/adapters/store/sqlite"
	stdlibsqlite "github.com/eitanity/kanonarion/internal/stdlib/adapters/store/sqlite"
	vensqlite "github.com/eitanity/kanonarion/internal/vendortree/adapters/store/sqlite"
	vulnsqlite "github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	walksqlite "github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
)

// The testfiles backend keeps everything under the directory its config.yaml
// section names, so a callgraph child (this test binary re-run) sees the same
// state, and nothing lands under the store root. The audit events and the
// attestations it receives are JSON files the acceptance test reads; the
// record stores reuse the SQLite adapters over records.db in that directory.
const testFilesBackendName = "testfiles"

// testFilesSettings is the backend's config.yaml section.
type testFilesSettings struct {
	Dir string `yaml:"dir"`
}

func testFilesBackend() storage.Backend {
	return storage.Backend{
		Name:     testFilesBackendName,
		Section:  testFilesBackendName,
		Defaults: testFilesSettings{},
		Open:     openTestFiles,
	}
}

// Events and attestations are JSON files, one per kind.
const (
	testFilesEvents       = "events.jsonl"
	testFilesAttestations = "attestations.json"
	testFilesRecords      = "records.db"
)

func openTestFiles(_ context.Context, req storage.Request) (*storage.Storage, error) {
	var settings testFilesSettings
	if err := yaml.Unmarshal(req.Section, &settings); err != nil {
		return nil, fmt.Errorf("testfiles section: %w", err)
	}
	if settings.Dir == "" {
		return nil, errors.New("testfiles section: dir is required")
	}
	records := filepath.Join(settings.Dir, testFilesRecords)
	if req.Intent == storage.IntentInspect {
		if _, err := os.Stat(records); err != nil {
			return nil, &storage.NotFoundError{Location: settings.Dir}
		}
	}
	if err := os.MkdirAll(settings.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("testfiles dir: %w", err)
	}
	db, err := sqlitestore.Open(records, sqlitestorage.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		return nil, fmt.Errorf("testfiles records: %w", err)
	}
	sink := &jsonEventSink{path: filepath.Join(settings.Dir, testFilesEvents)}
	facts := fetchsqlite.New(db)
	walks, callGraphs := walksqlite.New(db), cgsqlite.New(db)
	licences, examples, extractions, stdlib := licsqlite.New(db), exsqlite.New(db), extstore.New(db), stdlibsqlite.New(db)
	facts.ReportSetAside(req.SetAside)
	walks.ReportSetAside(req.SetAside)
	callGraphs.ReportSetAside(req.SetAside)
	licences.ReportSetAside(req.SetAside)
	examples.ReportSetAside(req.SetAside)
	extractions.ReportSetAside(req.SetAside)
	stdlib.ReportSetAside(req.SetAside)
	return &storage.Storage{
		Facts:             auditedFacts{Store: facts, sink: sink},
		Attestations:      &jsonAttestations{path: filepath.Join(settings.Dir, testFilesAttestations)},
		Audit:             sink,
		Blobs:             localfs.New(settings.Dir),
		Walks:             walks,
		WalkPresence:      walks,
		Licenses:          licences,
		Interfaces:        ifacesqlite.New(db),
		CallGraphs:        callGraphs,
		CallGraphOutcomes: callGraphs,
		Examples:          examples,
		Extractions:       extractions,
		Vulnerabilities:   vulnsqlite.New(db),
		SBOMs:             sbomstore.New(db),
		Directives:        dirsqlite.New(db),
		GoDebug:           gdsqlite.New(db),
		Vendor:            vensqlite.New(db),
		FIPS:              fipssqlite.New(db),
		Stdlib:            stdlib,
		Staleness:         stalesqlite.New(db),
		Native:            nativesqlite.New(db),
		Close:             db.Close,
	}, nil
}

// auditedFacts records a fact write in the backend's own event file, as the
// SQLite backend's auditing store does in audit.jsonl.
type auditedFacts struct {
	*fetchsqlite.Store
	sink *jsonEventSink
}

func (f auditedFacts) PutFetchRecord(ctx context.Context, sealed fetchdomain.SealedRecord) error {
	if err := f.Store.PutFetchRecord(ctx, sealed); err != nil {
		return err //nolint:wrapcheck // test backend
	}
	return f.sink.RecordEvent(audit.Event{Type: audit.EventFactRecordWritten, Payload: map[string]any{
		"module": sealed.Record().ModulePath,
	}})
}

// jsonEventSink appends one JSON line per event.
type jsonEventSink struct {
	mu   sync.Mutex
	path string
}

func (s *jsonEventSink) RecordEvent(e audit.Event) error {
	if err := e.Validate(); err != nil {
		return fmt.Errorf("invalid audit event: %w", err)
	}
	line, err := json.Marshal(struct {
		EventType audit.EventType `json:"event_type"`
		Payload   map[string]any  `json:"payload,omitempty"`
	}{e.Type, e.Payload})
	if err != nil {
		return fmt.Errorf("marshalling event: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- test directory
	if err != nil {
		return fmt.Errorf("opening events: %w", err)
	}
	_, werr := f.Write(append(line, '\n'))
	return errors.Join(werr, f.Close())
}

// jsonAttestation is one stored attestation; the coordinate is kept as its
// string because ModuleCoordinate has no JSON form.
type jsonAttestation struct {
	Coordinate       string    `json:"coordinate"`
	PipelineVersion  string    `json:"pipeline_version"`
	SubjectKind      string    `json:"subject_kind"`
	SubjectAlgorithm string    `json:"subject_algorithm"`
	SubjectDigest    string    `json:"subject_digest"`
	Bundle           []byte    `json:"bundle"`
	SignedAt         time.Time `json:"signed_at"`
}

// jsonAttestations keeps every attestation in one JSON array, re-read on each
// call so a child process's writes are seen.
type jsonAttestations struct {
	mu   sync.Mutex
	path string
}

func (a *jsonAttestations) load() ([]jsonAttestation, error) {
	data, err := os.ReadFile(a.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading attestations: %w", err)
	}
	var out []jsonAttestation
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decoding attestations: %w", err)
	}
	return out, nil
}

func (a *jsonAttestations) PutAttestation(_ context.Context, r fetchdomain.AttestationRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	all, err := a.load()
	if err != nil {
		return err
	}
	rec := jsonAttestation{
		Coordinate: r.Coordinate.String(), PipelineVersion: r.PipelineVersion,
		SubjectKind: string(r.SubjectKind), SubjectAlgorithm: r.SubjectAlgorithm, SubjectDigest: r.SubjectDigest,
		Bundle: r.Bundle, SignedAt: r.SignedAt,
	}
	replaced := false
	for i, have := range all {
		if have.Coordinate == rec.Coordinate && have.PipelineVersion == rec.PipelineVersion &&
			have.SubjectKind == rec.SubjectKind && have.SubjectDigest == rec.SubjectDigest {
			all[i], replaced = rec, true
		}
	}
	if !replaced {
		all = append(all, rec)
	}
	data, err := json.Marshal(all)
	if err != nil {
		return fmt.Errorf("encoding attestations: %w", err)
	}
	return os.WriteFile(a.path, data, 0o600) //nolint:wrapcheck // test backend
}

func (a *jsonAttestations) ListAttestations(_ context.Context, coord coordinate.ModuleCoordinate, pv string) ([]fetchdomain.AttestationRecord, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	all, err := a.load()
	if err != nil {
		return nil, err
	}
	var out []fetchdomain.AttestationRecord
	for _, r := range all {
		if r.Coordinate != coord.String() || r.PipelineVersion != pv {
			continue
		}
		out = append(out, fetchdomain.AttestationRecord{
			Coordinate: coord, PipelineVersion: pv, SubjectKind: fetchdomain.SubjectKind(r.SubjectKind),
			SubjectAlgorithm: r.SubjectAlgorithm, SubjectDigest: r.SubjectDigest, Bundle: r.Bundle, SignedAt: r.SignedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SubjectKind != out[j].SubjectKind {
			return out[i].SubjectKind < out[j].SubjectKind
		}
		return out[i].SubjectDigest < out[j].SubjectDigest
	})
	return out, nil
}

// eventTypeCounts tallies a JSONL event file by event_type; an absent file is
// an empty tally.
func eventTypeCounts(path string) (map[string]int, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if os.IsNotExist(err) {
		return map[string]int{}, nil
	}
	if err != nil {
		return nil, err //nolint:wrapcheck // test helper
	}
	counts := map[string]int{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e struct {
			EventType string `json:"event_type"`
		}
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("decoding %q: %w", sc.Text(), err)
		}
		counts[e.EventType]++
	}
	return counts, sc.Err() //nolint:wrapcheck // test helper
}
