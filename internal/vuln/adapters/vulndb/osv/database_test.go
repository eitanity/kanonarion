package osv_test

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/vulndb/osv"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// gzipJSON compresses JSON bytes with gzip.
func gzipJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(raw); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// zipEntry is a single file written into a fake vulndb.zip. stored selects the
// uncompressed Store method, used to build incompressible padding so the served
// body crosses byte-based progress thresholds.
type zipEntry struct {
	name    string
	content []byte
	stored  bool
}

// buildVulnDBZip assembles an in-memory zip from the given entries, matching the
// govulncheck file:// layout the bulk endpoint serves.
func buildVulnDBZip(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		method := zip.Deflate
		if e.stored {
			method = zip.Store
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: method})
		if err != nil {
			t.Fatalf("create zip entry %s: %v", e.name, err)
		}
		if _, err := w.Write(e.content); err != nil {
			t.Fatalf("write zip entry %s: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

// defaultVulnDBZip returns a minimal but layout-complete vulndb.zip.
func defaultVulnDBZip(t *testing.T) []byte {
	t.Helper()
	return buildVulnDBZip(t, []zipEntry{
		{name: "index/db.json", content: []byte(`{"modified":"2024-01-01T00:00:00Z"}`)},
		{name: "index/modules.json", content: []byte(`[{"path":"github.com/foo/bar","vulns":[{"id":"GO-2024-0001"}]}]`)},
		{name: "ID/GO-2024-0001.json", content: []byte(`{"id":"GO-2024-0001","summary":"test vulnerability"}`)},
	})
}

// buildFakeServer returns an httptest.Server that serves a minimal vuln.go.dev
// API: the bulk /vulndb.zip endpoint plus the gzip indexes CheckVulnerable uses.
// It records how many times /vulndb.zip was requested.
func buildFakeServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()

	var zipHits atomic.Int64
	zipBody := defaultVulnDBZip(t)

	mux := http.NewServeMux()

	mux.HandleFunc("/vulndb.zip", func(w http.ResponseWriter, _ *http.Request) {
		zipHits.Add(1)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(zipBody)))
		_, _ = w.Write(zipBody)
	})

	// index/modules.json.gz — consumed by CheckVulnerable's lazy load.
	mux.HandleFunc("/index/modules.json.gz", func(w http.ResponseWriter, _ *http.Request) {
		modules := []map[string]any{
			{"path": "github.com/foo/bar", "vulns": []map[string]string{{"id": "GO-2024-0001"}}},
		}
		_, _ = w.Write(gzipJSON(t, modules))
	})

	return httptest.NewServer(mux), &zipHits
}

// clientRewritingTo returns an http.Client whose transport rewrites the
// hardcoded vuln.go.dev host to the test server.
func clientRewritingTo(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	return &http.Client{
		Transport: &rewriteTransport{target: srv.URL},
	}
}

type rewriteTransport struct{ target string }

func (rt *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.URL.Scheme = "http"
	cloned.URL.Host = strings.TrimPrefix(rt.target, "http://")
	resp, err := http.DefaultTransport.RoundTrip(cloned)
	if err != nil {
		return nil, fmt.Errorf("round trip: %w", err)
	}
	return resp, nil
}

func TestSnapshot_ReturnsBulkZipWithLayout(t *testing.T) {
	srv, _ := buildFakeServer(t)
	defer srv.Close()

	db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{})
	snap, rc, err := db.Snapshot(t.Context())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	defer func() { _ = rc.Close() }()

	if snap.Source != "vuln.go.dev" {
		t.Errorf("snapshot source: got %q, want vuln.go.dev", snap.Source)
	}
	// Version comes from index/db.json's modified field inside the zip.
	if snap.Version != "2024-01-01T00:00:00Z" {
		t.Errorf("snapshot version: got %q, want 2024-01-01T00:00:00Z", snap.Version)
	}

	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading snapshot: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("opening zip: %v", err)
	}
	names := make(map[string]bool)
	for _, f := range zr.File {
		names[f.Name] = true
	}
	for _, want := range []string{"index/db.json", "index/modules.json", "ID/GO-2024-0001.json"} {
		if !names[want] {
			t.Errorf("zip missing expected file: %s", want)
		}
	}
}

// TestSnapshot_IssuesSingleRequest is the acceptance guard: a fresh snapshot
// fetch must hit vuln.go.dev O(1) times, not once per entry.
func TestSnapshot_IssuesSingleRequest(t *testing.T) {
	srv, zipHits := buildFakeServer(t)
	defer srv.Close()

	db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{})
	_, rc, err := db.Snapshot(t.Context())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	_ = rc.Close()

	if got := zipHits.Load(); got != 1 {
		t.Errorf("expected exactly 1 request to /vulndb.zip, got %d", got)
	}
}

func TestGetSnapshot_DelegatesToStore(t *testing.T) {
	store := &fakeVulnStore{content: "snapshot-content"}
	db := osv.New(nil, store)

	snap := domain.DatabaseSnapshot{Source: "govulndb", Version: "v2024-01-01"}
	rc, err := db.GetSnapshot(t.Context(), snap)
	if err != nil {
		t.Fatalf("GetSnapshot: %v", err)
	}
	defer func() { _ = rc.Close() }()

	got, _ := io.ReadAll(rc)
	if string(got) != "snapshot-content" {
		t.Errorf("content: got %q, want %q", string(got), "snapshot-content")
	}
}

func TestSnapshot_ServerError_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{})
	_, _, err := db.Snapshot(t.Context())
	if err == nil {
		t.Fatal("expected error on server 500, got nil")
	}
}

func TestSnapshot_RateLimited_ReturnsRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{})
	_, _, err := db.Snapshot(t.Context())
	if err == nil {
		t.Fatal("expected error on HTTP 429, got nil")
	}
	if !strings.Contains(err.Error(), "429") || !strings.Contains(err.Error(), "120") {
		t.Errorf("error should surface 429 and Retry-After: %v", err)
	}
}

// TestSnapshot_FailsClosedOnLayout asserts the validator rejects every archive
// that is not a complete govulncheck file:// layout, so a malformed bulk
// response can never be persisted as a usable snapshot.
func TestSnapshot_FailsClosedOnLayout(t *testing.T) {
	good := []zipEntry{
		{name: "index/db.json", content: []byte(`{"modified":"2024-01-01T00:00:00Z"}`)},
		{name: "index/modules.json", content: []byte(`[]`)},
		{name: "ID/GO-2024-0001.json", content: []byte(`{"id":"GO-2024-0001"}`)},
	}

	cases := []struct {
		name string
		body []byte
	}{
		{"not a zip", []byte("this is not a zip archive")},
		{"missing db.json", buildVulnDBZip(t, []zipEntry{good[1], good[2]})},
		{"missing modules.json", buildVulnDBZip(t, []zipEntry{good[0], good[2]})},
		{"missing ID entries", buildVulnDBZip(t, []zipEntry{good[0], good[1]})},
		{"empty modified", buildVulnDBZip(t, []zipEntry{
			{name: "index/db.json", content: []byte(`{"modified":""}`)},
			good[1], good[2],
		})},
		{"malformed db.json", buildVulnDBZip(t, []zipEntry{
			{name: "index/db.json", content: []byte(`{not json`)},
			good[1], good[2],
		})},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(body)
			}))
			defer srv.Close()

			db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{})
			_, _, err := db.Snapshot(t.Context())
			if err == nil {
				t.Fatalf("expected fail-closed error for %s, got nil", tc.name)
			}
		})
	}
}

// fakeVulnStore is a minimal ports.VulnerabilityStore for testing the OSV adapter.
type fakeVulnStore struct {
	content string
}

func (f *fakeVulnStore) PutVulnerabilityRecord(_ context.Context, _ domain.VulnerabilityRecord) error {
	return nil
}
func (f *fakeVulnStore) GetVulnerabilityRecord(_ context.Context, _ fetchdomain.ModuleCoordinate, _ string, _ domain.DatabaseSnapshot) (domain.VulnerabilityRecord, bool, error) {
	return domain.VulnerabilityRecord{}, false, nil
}
func (f *fakeVulnStore) PutWalkScanRun(_ context.Context, _ domain.WalkScanRun) error { return nil }
func (f *fakeVulnStore) GetWalkScanRun(_ context.Context, _ string) (domain.WalkScanRun, bool, error) {
	return domain.WalkScanRun{}, false, nil
}
func (f *fakeVulnStore) ListWalkScanRuns(_ context.Context, _ string) ([]domain.WalkScanRun, error) {
	return nil, nil
}
func (f *fakeVulnStore) ListAllWalkScanRuns(_ context.Context) ([]domain.WalkScanRun, error) {
	return nil, nil
}
func (f *fakeVulnStore) PutDatabaseSnapshot(_ context.Context, _ domain.DatabaseSnapshot, _ io.Reader) error {
	return nil
}
func (f *fakeVulnStore) GetDatabaseSnapshot(_ context.Context, _ domain.DatabaseSnapshot) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(f.content)), nil
}
func (f *fakeVulnStore) GetLatestDatabaseSnapshot(_ context.Context) (domain.DatabaseSnapshot, bool, error) {
	return domain.DatabaseSnapshot{}, false, nil
}
func (f *fakeVulnStore) ListDatabaseSnapshots(_ context.Context) ([]domain.DatabaseSnapshot, error) {
	return nil, nil
}
func (f *fakeVulnStore) ListVulnerabilityRecordsByFindingID(_ context.Context, _ string) ([]domain.VulnerabilityRecord, error) {
	return nil, nil
}
func (f *fakeVulnStore) ListVulnerabilityRecords(_ context.Context, _ string) ([]domain.VulnerabilityRecord, error) {
	return nil, nil
}
func (f *fakeVulnStore) GetLatestVulnerabilityRecord(_ context.Context, _ fetchdomain.ModuleCoordinate, _ string) (domain.VulnerabilityRecord, bool, error) {
	return domain.VulnerabilityRecord{}, false, nil
}
func (f *fakeVulnStore) GetLatestVulnerabilityRecordForWalk(_ context.Context, _ fetchdomain.ModuleCoordinate, _ string, _ string) (domain.VulnerabilityRecord, bool, error) {
	return domain.VulnerabilityRecord{}, false, nil
}
func (f *fakeVulnStore) ListVulnerabilityRecordsForModule(_ context.Context, _ fetchdomain.ModuleCoordinate, _ string) ([]domain.VulnerabilityRecord, error) {
	return nil, nil
}

func TestCheckVulnerable_LazilyLoadsIndex(t *testing.T) {
	srv, _ := buildFakeServer(t)
	defer srv.Close()

	db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{})
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	vulns, err := db.CheckVulnerable(t.Context(), []fetchdomain.ModuleCoordinate{coord})
	if err != nil {
		t.Fatalf("CheckVulnerable: %v", err)
	}

	if len(vulns) != 1 {
		t.Errorf("expected 1 vulnerable module, got %d", len(vulns))
	}
	if ids, ok := vulns[coord]; !ok || ids[0] != "GO-2024-0001" {
		t.Errorf("expected GO-2024-0001, got %v", ids)
	}
}

func TestCheckVulnerable_VersionRangeFiltering(t *testing.T) {
	// Serve a modules index with two entries:
	// github.com/foo/bar: fixed at 2.0.0 (GO-2024-0001)
	// github.com/foo/baz: no fixed version (GO-2024-0002)
	mux := http.NewServeMux()
	mux.HandleFunc("/index/modules.json.gz", func(w http.ResponseWriter, _ *http.Request) {
		modules := []map[string]any{
			{"path": "github.com/foo/bar", "vulns": []map[string]any{
				{"id": "GO-2024-0001", "fixed": "2.0.0"},
			}},
			{"path": "github.com/foo/baz", "vulns": []map[string]any{
				{"id": "GO-2024-0002"},
			}},
		}
		_, _ = w.Write(gzipJSON(t, modules))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{})
	ctx := t.Context()

	cases := []struct {
		path    string
		version string
		wantIDs []string // nil means no match expected
	}{
		{"github.com/foo/bar", "v1.0.0", []string{"GO-2024-0001"}},  // before fix
		{"github.com/foo/bar", "v2.0.0", nil},                       // at fix
		{"github.com/foo/bar", "v3.0.0", nil},                       // past fix
		{"github.com/foo/baz", "v1.0.0", []string{"GO-2024-0002"}},  // no fix ever
		{"github.com/foo/baz", "v99.0.0", []string{"GO-2024-0002"}}, // still no fix
		{"github.com/other/pkg", "v1.0.0", nil},                     // not in index
	}

	for _, tc := range cases {
		coord := fetchdomain.ModuleCoordinate{Path: tc.path, Version: tc.version}
		vulns, err := db.CheckVulnerable(ctx, []fetchdomain.ModuleCoordinate{coord})
		if err != nil {
			t.Fatalf("%s@%s: CheckVulnerable: %v", tc.path, tc.version, err)
		}
		ids := vulns[coord]
		if len(ids) != len(tc.wantIDs) {
			t.Errorf("%s@%s: got vuln IDs %v, want %v", tc.path, tc.version, ids, tc.wantIDs)
			continue
		}
		for i, want := range tc.wantIDs {
			if ids[i] != want {
				t.Errorf("%s@%s: got ID %q at [%d], want %q", tc.path, tc.version, ids[i], i, want)
			}
		}
	}
}

// buildLargeZipServer serves a layout-complete vulndb.zip whose body exceeds
// sizeBytes (via an incompressible, Store-method padding entry), with an
// explicit Content-Length so byte-based progress can be asserted.
func buildLargeZipServer(t *testing.T, sizeBytes int) *httptest.Server {
	t.Helper()
	padding := make([]byte, sizeBytes)
	if _, err := rand.Read(padding); err != nil {
		t.Fatalf("rand: %v", err)
	}
	body := buildVulnDBZip(t, []zipEntry{
		{name: "index/db.json", content: []byte(`{"modified":"2024-01-01T00:00:00Z"}`)},
		{name: "index/modules.json", content: []byte(`[]`)},
		{name: "ID/GO-2024-0001.json", content: []byte(`{"id":"GO-2024-0001"}`)},
		{name: "ID/GO-2024-9999.json", content: padding, stored: true},
	})
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		_, _ = w.Write(body)
	}))
}

// TestSnapshot_LogsByteProgress guards the bulk download against regressing
// into a silent multi-megabyte network operation: the read loop must emit a
// start line carrying content_length, periodic byte-progress lines, and a
// completion line.
func TestSnapshot_LogsByteProgress(t *testing.T) {
	// 2 MiB body comfortably crosses the 512 KiB progress interval several times.
	srv := buildLargeZipServer(t, 2*1024*1024)
	defer srv.Close()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{}).WithLogger(logger)
	_, rc, err := db.Snapshot(t.Context())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	defer func() { _ = rc.Close() }()

	logs := logBuf.String()
	for _, want := range []string{
		"downloading",
		"content_length=",
		"download progress",
		"downloaded_bytes=",
		"download complete",
		"zip_bytes=",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("snapshot logs missing %q; logs:\n%s", want, logs)
		}
	}
}

// advisoryMux serves a modules index plus per-advisory ID/<id>.json records,
// modelling the subset of vuln.go.dev that LookupFindings consumes.
func advisoryMux(t *testing.T, modules []map[string]any, advisories map[string]string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/index/modules.json.gz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(gzipJSON(t, modules))
	})
	for id, body := range advisories {
		mux.HandleFunc("/ID/"+id+".json", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, body)
		})
	}
	return mux
}

// TestLookupFindings_EnrichesFromAdvisory is the road-test exemplar: a
// metadata-path lookup for an unpatched advisory must surface the summary,
// affected range, the explicit "no fix" state, and the at-risk symbol.
func TestLookupFindings_EnrichesFromAdvisory(t *testing.T) {
	advisory := `{
		"id": "GO-2025-3884",
		"summary": "CSRF bypass in gorilla/csrf",
		"aliases": ["CVE-2025-1234"],
		"published": "2025-06-01T00:00:00Z",
		"modified": "2025-06-02T00:00:00Z",
		"affected": [{
			"package": {"ecosystem": "Go", "name": "github.com/gorilla/csrf"},
			"ranges": [{"type": "SEMVER", "events": [{"introduced": "1.7.3"}]}],
			"ecosystem_specific": {"imports": [{"path": "github.com/gorilla/csrf", "symbols": ["TrustedOrigins"]}]}
		}]
	}`
	mux := advisoryMux(t,
		[]map[string]any{{"path": "github.com/gorilla/csrf", "vulns": []map[string]any{{"id": "GO-2025-3884"}}}},
		map[string]string{"GO-2025-3884": advisory},
	)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{})
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/gorilla/csrf", Version: "v1.7.3"}

	findings, err := db.LookupFindings(t.Context(), coord)
	if err != nil {
		t.Fatalf("LookupFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ID != "GO-2025-3884" {
		t.Errorf("ID = %q", f.ID)
	}
	if f.Summary != "CSRF bypass in gorilla/csrf" {
		t.Errorf("Summary = %q", f.Summary)
	}
	if f.AffectedRange != ">= v1.7.3" {
		t.Errorf("AffectedRange = %q, want %q", f.AffectedRange, ">= v1.7.3")
	}
	if f.FixedIn != "" {
		t.Errorf("FixedIn = %q, want empty (no fix exists)", f.FixedIn)
	}
	if len(f.AffectedSymbols) != 1 || f.AffectedSymbols[0] != "TrustedOrigins" {
		t.Errorf("AffectedSymbols = %v, want [TrustedOrigins]", f.AffectedSymbols)
	}
	if f.FixDisplay() != "no fix available" {
		t.Errorf("FixDisplay() = %q", f.FixDisplay())
	}
}

// TestLookupFindings_PatchedAdvisory checks an advisory with a real fix surfaces
// its fixed version and a bounded affected range.
func TestLookupFindings_PatchedAdvisory(t *testing.T) {
	advisory := `{
		"id": "GO-2024-0042",
		"summary": "patched issue",
		"affected": [{
			"package": {"ecosystem": "Go", "name": "github.com/foo/bar"},
			"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]}],
			"ecosystem_specific": {"imports": [{"path": "github.com/foo/bar", "symbols": ["Vuln", "AlsoVuln"]}]}
		}]
	}`
	mux := advisoryMux(t,
		[]map[string]any{{"path": "github.com/foo/bar", "vulns": []map[string]any{{"id": "GO-2024-0042", "fixed": "1.2.0"}}}},
		map[string]string{"GO-2024-0042": advisory},
	)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{})
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	findings, err := db.LookupFindings(t.Context(), coord)
	if err != nil {
		t.Fatalf("LookupFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.FixedIn != "v1.2.0" {
		t.Errorf("FixedIn = %q, want v1.2.0", f.FixedIn)
	}
	if f.AffectedRange != "< v1.2.0" {
		t.Errorf("AffectedRange = %q, want %q", f.AffectedRange, "< v1.2.0")
	}
	// Symbols are sorted deterministically.
	if len(f.AffectedSymbols) != 2 || f.AffectedSymbols[0] != "AlsoVuln" || f.AffectedSymbols[1] != "Vuln" {
		t.Errorf("AffectedSymbols = %v, want [AlsoVuln Vuln]", f.AffectedSymbols)
	}
}

// TestLookupFindings_DegradesOnAdvisoryFetchFailure verifies a finding survives
// as a bare ID + known fixed version when its advisory cannot be fetched, rather
// than vanishing (the module is still known-affected).
func TestLookupFindings_DegradesOnAdvisoryFetchFailure(t *testing.T) {
	mux := advisoryMux(t,
		[]map[string]any{{"path": "github.com/foo/bar", "vulns": []map[string]any{{"id": "GO-2024-0042", "fixed": "1.2.0"}}}},
		nil, // no advisory handler -> 404 on ID fetch
	)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{})
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	findings, err := db.LookupFindings(t.Context(), coord)
	if err != nil {
		t.Fatalf("LookupFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 degraded finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ID != "GO-2024-0042" || f.FixedIn != "v1.2.0" {
		t.Errorf("degraded finding = %+v, want ID GO-2024-0042 / FixedIn v1.2.0", f)
	}
	if f.Summary != "" || f.AffectedRange != "" {
		t.Errorf("expected unenriched finding, got summary=%q range=%q", f.Summary, f.AffectedRange)
	}
}

// TestLookupFindings_PatchedVersionNotAffected confirms a version at or past the
// fix yields no findings.
func TestLookupFindings_PatchedVersionNotAffected(t *testing.T) {
	mux := advisoryMux(t,
		[]map[string]any{{"path": "github.com/foo/bar", "vulns": []map[string]any{{"id": "GO-2024-0042", "fixed": "1.2.0"}}}},
		nil,
	)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{})
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v2.0.0"}

	findings, err := db.LookupFindings(t.Context(), coord)
	if err != nil {
		t.Fatalf("LookupFindings: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for patched version, got %d", len(findings))
	}
}

// TestLookupFindings_IndexFetchFailure surfaces an error when the modules index
// cannot be loaded (the lazy ensureIndex load fails).
func TestLookupFindings_IndexFetchFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{})
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	if _, err := db.LookupFindings(t.Context(), coord); err == nil {
		t.Fatal("expected error when modules index fetch fails, got nil")
	}
}

// TestLookupFindings_PreVPrefixedVersions confirms advisory ranges already
// carrying a leading 'v' are not double-prefixed.
func TestLookupFindings_PreVPrefixedVersions(t *testing.T) {
	advisory := `{
		"id": "GO-2024-0099",
		"summary": "prefixed",
		"affected": [{
			"package": {"ecosystem": "Go", "name": "github.com/foo/bar"},
			"ranges": [{"type": "SEMVER", "events": [{"introduced": "v1.0.0"}, {"fixed": "v1.5.0"}]}]
		}]
	}`
	mux := advisoryMux(t,
		[]map[string]any{{"path": "github.com/foo/bar", "vulns": []map[string]any{{"id": "GO-2024-0099", "fixed": "v1.5.0"}}}},
		map[string]string{"GO-2024-0099": advisory},
	)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{})
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.2.0"}

	findings, err := db.LookupFindings(t.Context(), coord)
	if err != nil {
		t.Fatalf("LookupFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.FixedIn != "v1.5.0" {
		t.Errorf("FixedIn = %q, want v1.5.0 (no double v)", f.FixedIn)
	}
	if f.AffectedRange != ">= v1.0.0, < v1.5.0" {
		t.Errorf("AffectedRange = %q, want %q", f.AffectedRange, ">= v1.0.0, < v1.5.0")
	}
}

// TestLookupFindings_MultiRangeBackport is the multi-range backport regression: an advisory
// with per-branch backports lists multiple introduced/fixed pairs, but
// index/modules.json collapses them to the single highest fixed. A
// coordinate-only match against that collapsed fixed over-reports a version
// patched on an older branch. LookupFindings must instead evaluate the full
// affected[].ranges event list, so only versions truly inside an affected
// interval are flagged. Mirrors GO-2026-5856 (stdlib): the 1.26 branch is fixed
// at 1.26.5 even though the highest fix is 1.27.0-rc.2.
func TestLookupFindings_MultiRangeBackport(t *testing.T) {
	// Three affected intervals: [0, 1.25.12), [1.26.0-0, 1.26.5),
	// [1.27.0-0, 1.27.0-rc.2). modules.json collapses to the highest fix.
	advisory := `{
		"id": "GO-2026-5856",
		"summary": "stdlib multi-branch backport",
		"affected": [{
			"package": {"ecosystem": "Go", "name": "stdlib"},
			"ranges": [{"type": "SEMVER", "events": [
				{"introduced": "0"}, {"fixed": "1.25.12"},
				{"introduced": "1.26.0-0"}, {"fixed": "1.26.5"},
				{"introduced": "1.27.0-0"}, {"fixed": "1.27.0-rc.2"}
			]}],
			"ecosystem_specific": {"imports": [{"path": "crypto/tls", "symbols": ["Conn.Handshake"]}]}
		}]
	}`
	mux := advisoryMux(t,
		[]map[string]any{{"path": "stdlib", "vulns": []map[string]any{{"id": "GO-2026-5856", "fixed": "1.27.0-rc.2"}}}},
		map[string]string{"GO-2026-5856": advisory},
	)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{})

	cases := []struct {
		version  string
		affected bool
	}{
		{"v1.24.0", true},       // base branch, before first fix
		{"v1.25.11", true},      // base branch, one below first fix
		{"v1.25.12", false},     // base branch fixed
		{"v1.25.13", false},     // above base fix, below 1.26 introduced
		{"v1.26.4", true},       // 1.26 branch, unpatched
		{"v1.26.5", false},      // 1.26 branch fixed (the ticket case)
		{"v1.26.6", false},      // above 1.26 fix, below 1.27 introduced
		{"v1.27.0-rc.1", true},  // 1.27 branch, unpatched pre-release
		{"v1.27.0-rc.2", false}, // 1.27 branch fixed
		{"v1.27.0", false},      // final release, past all fixes
	}
	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			coord := fetchdomain.ModuleCoordinate{Path: "stdlib", Version: tc.version}
			findings, err := db.LookupFindings(t.Context(), coord)
			if err != nil {
				t.Fatalf("LookupFindings: %v", err)
			}
			got := len(findings) > 0
			if got != tc.affected {
				t.Fatalf("version %s: affected = %v, want %v (findings=%d)", tc.version, got, tc.affected, len(findings))
			}
			if tc.affected && findings[0].ID != "GO-2026-5856" {
				t.Errorf("version %s: finding ID = %q, want GO-2026-5856", tc.version, findings[0].ID)
			}
		})
	}
}

// TestLookupFindings_MultiRangeConservativeOnPackageMismatch confirms the
// full-range refinement never drops a coarse-index hit it cannot evaluate: when
// no affected block names the module path, the finding is kept rather than
// silently cleared.
func TestLookupFindings_MultiRangeConservativeOnPackageMismatch(t *testing.T) {
	// The advisory's affected block names a different package than the coordinate,
	// so the range check has nothing to evaluate against and must stay conservative.
	advisory := `{
		"id": "GO-2026-4970",
		"summary": "mismatched package block",
		"affected": [{
			"package": {"ecosystem": "Go", "name": "some/other/module"},
			"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]
		}]
	}`
	mux := advisoryMux(t,
		[]map[string]any{{"path": "github.com/foo/bar", "vulns": []map[string]any{{"id": "GO-2026-4970", "fixed": "2.0.0"}}}},
		map[string]string{"GO-2026-4970": advisory},
	)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{})
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.5.0"}

	findings, err := db.LookupFindings(t.Context(), coord)
	if err != nil {
		t.Fatalf("LookupFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 conservatively-kept finding, got %d", len(findings))
	}
}

// TestLookupFindings_ConservativeWhenUnrefinable exercises the two remaining
// conservative branches of the full-range check: an affected block whose ranges
// are not version-comparable SEMVER, and a coordinate whose version cannot be
// parsed. In both cases the coarse-index hit must be kept, never cleared.
func TestLookupFindings_ConservativeWhenUnrefinable(t *testing.T) {
	cases := []struct {
		name    string
		version string
		ranges  string
	}{
		{
			name:    "non-semver range",
			version: "v1.0.0",
			ranges:  `[{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc123"}]}]`,
		},
		{
			name:    "unparseable version",
			version: "not-a-version",
			ranges:  `[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			advisory := fmt.Sprintf(`{
				"id": "GO-2026-0001",
				"summary": "unrefinable",
				"affected": [{
					"package": {"ecosystem": "Go", "name": "github.com/foo/bar"},
					"ranges": %s
				}]
			}`, tc.ranges)
			// Empty fixed in the index => the coarse pre-filter treats every version
			// as affected, so the request reaches the full-range refinement.
			mux := advisoryMux(t,
				[]map[string]any{{"path": "github.com/foo/bar", "vulns": []map[string]any{{"id": "GO-2026-0001"}}}},
				map[string]string{"GO-2026-0001": advisory},
			)
			srv := httptest.NewServer(mux)
			defer srv.Close()

			db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{})
			coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: tc.version}

			findings, err := db.LookupFindings(t.Context(), coord)
			if err != nil {
				t.Fatalf("LookupFindings: %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("expected 1 conservatively-kept finding, got %d", len(findings))
			}
		})
	}
}
