package osv_test

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"code.eitanity.com/kanonarion/internal/adapters/goenv"
	"code.eitanity.com/kanonarion/internal/vuln/adapters/vulndb/osv"
	"code.eitanity.com/kanonarion/internal/vuln/domain"
)

// mirrorZip is a layout-complete vulndb.zip whose advisory is stored
// uncompressed, so a test can flip one byte of it and know which entry broke.
func mirrorZip(t *testing.T) []byte {
	t.Helper()
	return buildVulnDBZip(t, []zipEntry{
		{name: "index/db.json", content: []byte(`{"modified":"2024-01-01T00:00:00Z"}`)},
		{name: "index/modules.json", content: []byte(`[{"path":"github.com/foo/bar","vulns":[{"id":"GO-2024-0001"}]}]`)},
		{name: "ID/GO-2024-0001.json", content: []byte(`{"id":"GO-2024-0001","summary":"mirror advisory body"}`), stored: true},
	})
}

// mirror serves vuln.go.dev's three files over HTTPS under a path prefix, the
// way an organisation's server would, and records every path it was asked for.
type mirror struct {
	srv  *httptest.Server
	mu   sync.Mutex
	hits []string
}

func newMirror(t *testing.T, zipBody []byte, status int) *mirror {
	t.Helper()
	m := &mirror{}
	m.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.hits = append(m.hits, r.URL.Path)
		m.mu.Unlock()
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		switch r.URL.Path {
		case "/go/vulndb.zip":
			_, _ = w.Write(zipBody) //nolint:errcheck // a failed write is seen by the client under test
		case "/go/index/db.json":
			_, _ = w.Write([]byte(`{"modified":"2024-01-01T00:00:00Z"}`)) //nolint:errcheck // as above
		case "/go/index/modules.json.gz":
			_, _ = w.Write(gzipJSON(t, []map[string]any{{"path": "github.com/foo/bar", "vulns": []map[string]string{{"id": "GO-2024-0001"}}}})) //nolint:errcheck // as above
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mirror) base() string { return m.srv.URL + "/go" }

func (m *mirror) requested() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.hits...)
}

// A mirror's archive is the same database: the snapshot keeps vuln.go.dev as
// its source, version and content hash, and records the mirror as its origin.
// The same bytes served as vuln.go.dev record no origin.
func TestSnapshot_FromAMirrorKeepsTheIdentityAndRecordsTheOrigin(t *testing.T) {
	permitted(t)
	body := mirrorZip(t)
	m := newMirror(t, body, http.StatusOK)

	var logs bytes.Buffer
	got, rc, err := osv.New(m.srv.Client(), &fakeVulnStore{}, testClock).WithBase(m.base()).
		WithLogger(slog.New(slog.NewTextHandler(&logs, nil))).Snapshot(t.Context())
	if err != nil {
		t.Fatalf("Snapshot from the mirror: %v", err)
	}
	_ = rc.Close()
	if !strings.Contains(logs.String(), "source="+m.base()) {
		t.Errorf("the download log does not name the mirror:\n%s", logs.String())
	}

	srv, _ := buildFakeServerServing(t, body)
	want, rc2, err := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{}, testClock).Snapshot(t.Context())
	if err != nil {
		t.Fatalf("Snapshot from vuln.go.dev: %v", err)
	}
	_ = rc2.Close()

	if got.Source() != "vuln.go.dev" || got.Source() != want.Source() || got.Version() != want.Version() ||
		got.ContentHash() != want.ContentHash() || got.ContentHash() != domain.HashSnapshotContent(body) {
		t.Errorf("mirror snapshot %s, vuln.go.dev snapshot %s: want the same source, version and hash", got, want)
	}
	if got.Origin() != m.base() || want.Origin() != "" {
		t.Errorf("origins: mirror %q (want %q), vuln.go.dev %q (want empty)", got.Origin(), m.base(), want.Origin())
	}
	if hits := m.requested(); len(hits) != 1 || hits[0] != "/go/vulndb.zip" {
		t.Errorf("mirror requests = %v, want [/go/vulndb.zip]", hits)
	}
}

// --fresh reads the two indexes from the mirror too.
func TestLatestVersionAndIndex_ReadTheMirror(t *testing.T) {
	permitted(t)
	m := newMirror(t, mirrorZip(t), http.StatusOK)
	db := osv.New(m.srv.Client(), &fakeVulnStore{}, testClock).WithBase(m.base())

	version, err := db.LatestVersion(t.Context())
	if err != nil || version != "2024-01-01T00:00:00Z" {
		t.Fatalf("LatestVersion = %q, %v", version, err)
	}
	index, err := db.PublishedAdvisoryIndex(t.Context())
	if err != nil || len(index["github.com/foo/bar"]) != 1 {
		t.Fatalf("PublishedAdvisoryIndex = %v, %v", index, err)
	}
	if hits := m.requested(); strings.Join(hits, " ") != "/go/index/db.json /go/index/modules.json.gz" {
		t.Errorf("mirror requests = %v", hits)
	}
}

// A mirror's archive goes through every check vuln.go.dev's does: a corrupted
// entry, a truncated body and an HTTP error are each refused, naming the mirror.
func TestSnapshot_ABrokenMirrorIsRefused(t *testing.T) {
	permitted(t)
	good := mirrorZip(t)
	corrupt := bytes.Clone(good)
	at := bytes.Index(corrupt, []byte("mirror advisory body"))
	if at < 0 {
		t.Fatal("the stored advisory body is not in the archive")
	}
	corrupt[at] ^= 0xff

	cases := []struct {
		name   string
		body   []byte
		status int
		want   string
	}{
		{"corrupted entry", corrupt, http.StatusOK, "checksum"},
		{"truncated body", good[:len(good)/2], http.StatusOK, "validate vulndb.zip from"},
		{"not found", nil, http.StatusNotFound, "404"},
		{"rate limited", nil, http.StatusTooManyRequests, "rate limited by https://"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMirror(t, tc.body, tc.status)
			_, rc, err := osv.New(m.srv.Client(), &fakeVulnStore{}, testClock).WithBase(m.base()).Snapshot(t.Context())
			if err == nil {
				_ = rc.Close()
				t.Fatal("a broken mirror archive was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// GOPROXY=off forbids the advisory download from a mirror as it does from
// vuln.go.dev: nothing reaches the mirror.
func TestSnapshot_AMirrorIsRefusedUnderAirGap(t *testing.T) {
	airGapped(t)
	m := newMirror(t, mirrorZip(t), http.StatusOK)
	_, _, err := osv.New(m.srv.Client(), &fakeVulnStore{}, testClock).WithBase(m.base()).Snapshot(t.Context())
	if !errors.Is(err, goenv.ErrNetworkForbidden) {
		t.Fatalf("err = %v, want the no-network refusal", err)
	}
	if hits := m.requested(); len(hits) != 0 {
		t.Errorf("the mirror was asked for %v under GOPROXY=off", hits)
	}
}

// buildFakeServerServing serves body as vuln.go.dev's /vulndb.zip.
func buildFakeServerServing(t *testing.T, body []byte) (*httptest.Server, *[]string) {
	t.Helper()
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		_, _ = w.Write(body) //nolint:errcheck // a failed write is seen by the client under test
	}))
	t.Cleanup(srv.Close)
	return srv, &paths
}
