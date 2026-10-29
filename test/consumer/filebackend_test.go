package consumer_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"code.eitanity.com/kanonarion/pkg/kanonarion"
)

// filesBackend keeps the stores a fetch, a call-graph child and the
// call-graph queries use as JSON files under <store root>/files, so a parent
// and its child share them across processes with no SQLite involved. Every
// other store is a stub the flow never calls.
func filesBackend() kanonarion.Backend {
	return kanonarion.Backend{
		Name: "files",
		Open: func(_ context.Context, req kanonarion.StorageRequest) (*kanonarion.Storage, error) {
			fs := fileStore{dir: filepath.Join(req.StoreRoot, "files")}
			return &kanonarion.Storage{
				Facts: fileFacts{fs}, Attestations: noAttestations{}, Audit: noAudit{}, Blobs: fileBlobs{fs},
				Walks: noWalks{}, WalkPresence: stubPresence{}, Licenses: stubLicences{}, Interfaces: stubInterfaces{},
				CallGraphs: fileCallGraphs{fs}, CallGraphOutcomes: fileCallGraphs{fs}, Examples: stubExamples{},
				Extractions: stubExtractions{}, Vulnerabilities: stubVulns{}, SBOMs: stubSBOMs{},
				Directives: stubDirectives{}, GoDebug: stubGoDebug{}, Vendor: stubVendor{}, FIPS: stubFIPS{},
				Stdlib: stubStdlib{}, Staleness: stubStaleness{}, Native: stubNative{},
			}, nil
		},
	}
}

// fileStore is one directory per kind, one file per key.
type fileStore struct{ dir string }

func (f fileStore) path(kind, key string) string {
	return filepath.Join(f.dir, kind, url.PathEscape(key))
}

func (f fileStore) put(kind, key string, data []byte) error {
	p := f.path(kind, key)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err //nolint:wrapcheck // test backend
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err //nolint:wrapcheck // test backend
	}
	return os.Rename(tmp, p) //nolint:wrapcheck // test backend
}

func (f fileStore) get(kind, key string) ([]byte, bool, error) {
	data, err := os.ReadFile(f.path(kind, key))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return data, err == nil, err //nolint:wrapcheck // test backend
}

// all returns every value of kind whose key starts with prefix.
func (f fileStore) all(kind, prefix string) ([][]byte, error) {
	entries, err := os.ReadDir(filepath.Join(f.dir, kind))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err //nolint:wrapcheck // test backend
	}
	var out [][]byte
	for _, e := range entries {
		key, uerr := url.PathUnescape(e.Name())
		if uerr != nil || strings.HasSuffix(e.Name(), ".tmp") || !strings.HasPrefix(key, prefix) {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(f.dir, kind, e.Name()))
		if rerr != nil {
			return nil, rerr //nolint:wrapcheck // test backend
		}
		out = append(out, data)
	}
	return out, nil
}

type fileFacts struct{ fs fileStore }

func (s fileFacts) PutFetchRecord(_ context.Context, sealed kanonarion.SealedRecord) error {
	rec := sealed.Record()
	data, err := json.Marshal(rec)
	if err != nil {
		return err //nolint:wrapcheck // test backend
	}
	return s.fs.put("facts", factKey(rec.Coordinate(), rec.PipelineVersion), data)
}

func (s fileFacts) GetFetchRecord(_ context.Context, coord kanonarion.ModuleCoordinate, pipelineVersion string) (kanonarion.CompositeRecord, bool, error) {
	data, ok, err := s.fs.get("facts", factKey(coord, pipelineVersion))
	if !ok || err != nil {
		return kanonarion.CompositeRecord{}, false, err
	}
	var rec kanonarion.FactRecord
	if uerr := json.Unmarshal(data, &rec); uerr != nil {
		return kanonarion.CompositeRecord{}, false, uerr //nolint:wrapcheck // test backend
	}
	composed, err := kanonarion.ComposeFetchRecords([]kanonarion.FactRecord{rec})
	return composed, err == nil, err //nolint:wrapcheck // test backend
}

// ComposeFetchRecord composes every measurement of coord, at any pipeline:
// the read an extraction stage asks a fact store for.
func (s fileFacts) ComposeFetchRecord(_ context.Context, coord kanonarion.ModuleCoordinate) (kanonarion.CompositeRecord, bool, error) {
	all, err := s.fs.all("facts", factKey(coord, ""))
	if err != nil || len(all) == 0 {
		return kanonarion.CompositeRecord{}, false, err
	}
	recs := make([]kanonarion.FactRecord, 0, len(all))
	for _, data := range all {
		var rec kanonarion.FactRecord
		if uerr := json.Unmarshal(data, &rec); uerr != nil {
			return kanonarion.CompositeRecord{}, false, uerr //nolint:wrapcheck // test backend
		}
		recs = append(recs, rec)
	}
	composed, err := kanonarion.ComposeFetchRecords(recs)
	return composed, err == nil, err //nolint:wrapcheck // test backend
}

// The file backend's fact store offers the read Storage requires of it.
var _ kanonarion.FactRecordComposer = fileFacts{}

type fileBlobs struct{ fs fileStore }

func (s fileBlobs) Put(_ context.Context, identity kanonarion.BlobIdentity, content io.Reader) error {
	data, err := io.ReadAll(content)
	if err != nil {
		return err //nolint:wrapcheck // test backend
	}
	return s.fs.put("blobs", identity.String(), data)
}

func (s fileBlobs) Get(_ context.Context, identity kanonarion.BlobIdentity) (io.ReadCloser, error) {
	data, ok, err := s.fs.get("blobs", identity.String())
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("blob not found")
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (s fileBlobs) Exists(_ context.Context, identity kanonarion.BlobIdentity) (bool, error) {
	_, ok, err := s.fs.get("blobs", identity.String())
	return ok, err
}

// fileCallGraphs appends every record and serves the newest at a coordinate.
type fileCallGraphs struct{ fs fileStore }

func graphKey(coord kanonarion.ModuleCoordinate, pipelineVersion string) string {
	return coord.String() + "#" + pipelineVersion + "#"
}

func (s fileCallGraphs) PutCallGraphRecord(_ context.Context, rec kanonarion.CallGraphRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err //nolint:wrapcheck // test backend
	}
	return s.fs.put("callgraphs", graphKey(rec.Coordinate, rec.PipelineVersion)+rec.ContentHash, data)
}

// newest is the newest record at each coordinate whose key starts with prefix.
func (s fileCallGraphs) newest(prefix string) ([]kanonarion.CallGraphRecord, error) {
	all, err := s.fs.all("callgraphs", prefix)
	if err != nil {
		return nil, err
	}
	byKey := map[string]kanonarion.CallGraphRecord{}
	for _, data := range all {
		var rec kanonarion.CallGraphRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return nil, err //nolint:wrapcheck // test backend
		}
		k := graphKey(rec.Coordinate, rec.PipelineVersion)
		if old, ok := byKey[k]; !ok || rec.ExtractedAt.After(old.ExtractedAt) {
			byKey[k] = rec
		}
	}
	out := make([]kanonarion.CallGraphRecord, 0, len(byKey))
	for _, rec := range byKey {
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Coordinate.String() < out[j].Coordinate.String() })
	return out, nil
}

func (s fileCallGraphs) GetCallGraphRecord(_ context.Context, coord kanonarion.ModuleCoordinate, pipelineVersion string) (kanonarion.CallGraphRecord, bool, error) {
	recs, err := s.newest(graphKey(coord, pipelineVersion))
	if err != nil || len(recs) == 0 {
		return kanonarion.CallGraphRecord{}, false, err
	}
	return recs[0], true, nil
}

func (s fileCallGraphs) LatestCallGraphOutcome(ctx context.Context, coord kanonarion.ModuleCoordinate, pipelineVersion string) (kanonarion.CallGraphOutcome, bool, error) {
	rec, ok, err := s.GetCallGraphRecord(ctx, coord, pipelineVersion)
	if !ok || err != nil {
		return kanonarion.CallGraphOutcome{}, false, err
	}
	return kanonarion.CallGraphOutcome{
		ContentHash: rec.ContentHash, OverallStatus: rec.OverallStatus, FailureCause: rec.FailureCause,
		FailureDetail: rec.FailureDetail, NodeCount: rec.NodeCount, EdgeCount: rec.EdgeCount, ExtractedAt: rec.ExtractedAt,
	}, true, nil
}

func (s fileCallGraphs) ListCallGraphRecords(_ context.Context, filter kanonarion.CallGraphFilter) ([]kanonarion.CallGraphSummary, error) {
	recs, err := s.newest("")
	if err != nil {
		return nil, err
	}
	var out []kanonarion.CallGraphSummary
	for _, r := range recs {
		if (filter.PipelineVersion != "" && r.PipelineVersion != filter.PipelineVersion) ||
			(filter.ModulePath != "" && r.Coordinate.Path() != filter.ModulePath) {
			continue
		}
		out = append(out, kanonarion.CallGraphSummary{
			ModulePath: r.Coordinate.Path(), ModuleVersion: r.Coordinate.Version(), PipelineVersion: r.PipelineVersion,
			Algorithm: r.Algorithm, OverallStatus: r.OverallStatus, Completeness: r.Completeness,
			AnalysisSource: r.AnalysisSource, NodeCount: r.NodeCount, EdgeCount: r.EdgeCount,
			ExtractedAt: r.ExtractedAt, ContentHash: r.ContentHash,
		})
	}
	return out, nil
}

// edges answers FindCallers (to) and FindCallees (!to) off the newest records.
func (s fileCallGraphs) edges(symbolID, pipelineVersion string, scope kanonarion.ModuleSet, opts kanonarion.EdgeQueryOptions, to bool) ([]kanonarion.CallEdgeRef, error) {
	recs, err := s.newest("")
	if err != nil {
		return nil, err
	}
	var out []kanonarion.CallEdgeRef
	for _, r := range recs {
		if r.PipelineVersion != pipelineVersion || (scope.IsRestricted() && !scope.ContainsPathVersion(r.Coordinate.Path(), r.Coordinate.Version())) {
			continue
		}
		test := map[string]bool{}
		for _, n := range r.Nodes {
			test[n.ID] = n.IsTest
		}
		for _, e := range r.Edges {
			if (to && e.ToID != symbolID) || (!to && e.FromID != symbolID) {
				continue
			}
			isTest := test[e.FromID] || test[e.ToID]
			if isTest && opts.ExcludeTests {
				continue
			}
			out = append(out, kanonarion.CallEdgeRef{
				ModulePath: r.Coordinate.Path(), ModuleVersion: r.Coordinate.Version(), PipelineVersion: r.PipelineVersion,
				FromID: e.FromID, ToID: e.ToID, Confidence: e.Confidence, IsTest: isTest, Kind: e.Kind,
			})
		}
	}
	return out, nil
}

func (s fileCallGraphs) FindCallers(_ context.Context, symbolID, pipelineVersion string, scope kanonarion.ModuleSet, opts kanonarion.EdgeQueryOptions) ([]kanonarion.CallEdgeRef, error) {
	return s.edges(symbolID, pipelineVersion, scope, opts, true)
}

func (s fileCallGraphs) FindCallees(_ context.Context, symbolID, pipelineVersion string, scope kanonarion.ModuleSet, opts kanonarion.EdgeQueryOptions) ([]kanonarion.CallEdgeRef, error) {
	return s.edges(symbolID, pipelineVersion, scope, opts, false)
}

type noAttestations struct{}

func (noAttestations) PutAttestation(context.Context, kanonarion.AttestationRecord) error { return nil }

func (noAttestations) ListAttestations(context.Context, kanonarion.ModuleCoordinate, string) ([]kanonarion.AttestationRecord, error) {
	return nil, nil
}

type noAudit struct{}

func (noAudit) RecordEvent(kanonarion.AuditEvent) error { return nil }

// noWalks holds no walk, so a child that looks for a build list finds none.
type noWalks struct{ kanonarion.WalkStore }

func (noWalks) ListWalks(context.Context, kanonarion.WalkFilter) ([]kanonarion.WalkSummary, error) {
	return nil, nil
}

func (noWalks) GetWalk(context.Context, string) (kanonarion.WalkRecord, error) {
	return kanonarion.WalkRecord{}, errors.New("no walk is stored")
}
