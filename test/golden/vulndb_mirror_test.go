package golden_test

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/cli"
	vulnsqlite "github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/pkg/kanonarion"
)

// vulnMirror serves the fixture advisory database in vuln.go.dev's layout over
// HTTPS, the way an organisation's internal server would.
type vulnMirror struct {
	srv  *httptest.Server
	zip  []byte
	mu   sync.Mutex
	hits []string
}

func newVulnMirror(t *testing.T, zipBody []byte, status int) *vulnMirror {
	t.Helper()
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	if _, err := w.Write([]byte(`[{"path":"example.com/mod","vulns":[{"id":"` + auditAdvisoryID + `","modified":"` + auditSnapshotVersion + `","fixed":"1.3.0"}]}]`)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	m := &vulnMirror{zip: zipBody}
	m.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.hits = append(m.hits, r.URL.Path)
		m.mu.Unlock()
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		var body []byte
		switch r.URL.Path {
		case "/vulndb/vulndb.zip":
			body = m.zip
		case "/vulndb/index/db.json":
			body = []byte(`{"modified":"` + auditSnapshotVersion + `"}`)
		case "/vulndb/index/modules.json.gz":
			body = gz.Bytes()
		default:
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body) //nolint:errcheck // a failed write is seen by the client under test
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *vulnMirror) base() string { return m.srv.URL + "/vulndb" }

func (m *vulnMirror) requested() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.hits...)
}

// onlyTheMirror makes the mirror the one host this process can reach: its
// certificate is trusted and every other host is refused before a socket is
// opened, so a request for vuln.go.dev fails rather than leaving the machine.
// It returns the hosts that were refused.
func onlyTheMirror(t *testing.T, m *vulnMirror) *[]string {
	t.Helper()
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatal("http.DefaultTransport is not an *http.Transport")
	}
	pool := x509.NewCertPool()
	pool.AddCert(m.srv.Certificate())
	mirrorHost := m.srv.Listener.Addr().String()
	var mu sync.Mutex
	var refused []string
	oldTLS, oldProxy := tr.TLSClientConfig, tr.Proxy
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	tr.Proxy = func(r *http.Request) (*url.URL, error) {
		if r.URL.Host == mirrorHost {
			return nil, nil
		}
		mu.Lock()
		refused = append(refused, r.URL.Host)
		mu.Unlock()
		return nil, errors.New("unreachable in this test: only the mirror is")
	}
	t.Cleanup(func() {
		tr.TLSClientConfig, tr.Proxy = oldTLS, oldProxy
		tr.CloseIdleConnections()
	})
	return &refused
}

// mirrorStore is a fixture store holding no advisory snapshot, whose
// config.yaml names the mirror.
func mirrorStore(t *testing.T, fx *auditFixture, m *vulnMirror) string {
	t.Helper()
	store := fx.newStore(t)
	execStore(t, store, `DELETE FROM vulnerability_snapshots`)
	if err := os.WriteFile(filepath.Join(store, "config.yaml"),
		[]byte("version: \"3\"\nvulndb:\n  url: "+m.base()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return store
}

// storedSnapshots reads source, version, hash and origin of every stored
// snapshot.
func storedSnapshots(t *testing.T, store string) [][4]string {
	t.Helper()
	db, err := sqlitestore.Open(filepath.Join(store, "mirror.db"), nil, sqlitestore.IntentRead)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.DB().Query(`SELECT source, version, content_hash, origin FROM vulnerability_snapshots`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out [][4]string
	for rows.Next() {
		var r [4]string
		if err := rows.Scan(&r[0], &r[1], &r[2], &r[3]); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// runMirrored runs one command against store with the fixture's offline module
// environment, except that GOPROXY is not `off`: off forbids the advisory
// download too. A file:// proxy that does not exist keeps modules offline.
func runMirrored(t *testing.T, fx *auditFixture, store string, args ...string) (stdout, stderr string, exit int) {
	t.Helper()
	for k, v := range fx.env() {
		t.Setenv(k, v)
	}
	t.Setenv("GOPROXY", "file://"+filepath.Join(t.TempDir(), "no-proxy"))
	t.Setenv("KANONARION_STORE", store)
	var out, errBuf bytes.Buffer
	err := cli.Run(args, &out, &errBuf)
	if err != nil {
		errBuf.WriteString(err.Error())
	}
	return out.String(), errBuf.String(), cli.ExitCodeForError(err)
}

// mirroredWalk is a walked fixture project on a store whose config names a
// mirror, with every host but the mirror unreachable. want is the snapshot a
// download from the mirror must record: vuln.go.dev at the database's own
// version, the hash of the bytes served, and the mirror as origin.
func mirroredWalk(t *testing.T) (fx *auditFixture, m *vulnMirror, store string, want [4]string) {
	t.Helper()
	fx = buildAuditFixture(t)
	t.Chdir(fx.project)
	blob := auditVulnDB(t)
	m = newVulnMirror(t, blob, http.StatusOK)
	refused := onlyTheMirror(t, m)
	t.Cleanup(func() {
		for _, host := range *refused {
			if strings.Contains(host, "vuln.go.dev") {
				t.Errorf("a request for %s was made", host)
			}
		}
	})
	store = mirrorStore(t, fx, m)
	if _, stderr, code := runMirrored(t, fx, store, "walk", "--gomod", fx.gomod(), "--from-modcache", "--no-progress"); code != cli.ExitOK {
		t.Fatalf("walk exit %d:\n%s", code, stderr)
	}
	return fx, m, store, [4]string{"vuln.go.dev", auditSnapshotVersion, domain.HashSnapshotContent(blob), m.base()}
}

// With vulndb.url naming the mirror and vuln.go.dev unreachable, vuln-scan and
// vuln-scan --fresh succeed, and the run and the stored snapshot record the
// mirror as their origin.
func TestVulnScan_FromAConfiguredMirror(t *testing.T) {
	fx, m, store, want := mirroredWalk(t)

	stdout, stderr, code := runMirrored(t, fx, store, "vuln-scan", "--gomod", fx.gomod(), "--json", "--no-progress")
	if code > cli.ExitPartial {
		t.Fatalf("vuln-scan exit %d:\n%s", code, stderr)
	}
	if !strings.Contains(stdout, `"origin": "`+m.base()+`"`) {
		t.Errorf("vuln-scan --json does not name the mirror:\n%s", stdout)
	}
	if got := storedSnapshots(t, store); len(got) != 1 || got[0] != want {
		t.Errorf("stored snapshots = %v, want [%v]", got, want)
	}
	if hits := m.requested(); strings.Join(hits, " ") != "/vulndb/vulndb.zip" {
		t.Errorf("mirror requests after vuln-scan = %v", hits)
	}

	_, stderr, code = runMirrored(t, fx, store, "vuln-scan", "--gomod", fx.gomod(), "--fresh", "--no-progress")
	if code > cli.ExitPartial {
		t.Fatalf("vuln-scan --fresh exit %d:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "checked vuln.go.dev (mirror "+m.base()+") and found it unchanged") {
		t.Errorf("--fresh does not say it checked the mirror:\n%s", stderr)
	}
	if hits := m.requested(); len(hits) != 2 || hits[1] != "/vulndb/index/db.json" {
		t.Errorf("mirror requests after --fresh = %v", hits)
	}

	stdout, stderr, _ = runMirrored(t, fx, store, "vuln-snapshot-show", "vuln.go.dev", auditSnapshotVersion)
	if !strings.Contains(stdout, "Origin:       "+m.base()) {
		t.Errorf("vuln-snapshot-show does not name the origin:\n%s%s", stdout, stderr)
	}
}

// The public driver reads the store's config.yaml as the CLI does: its re-scan
// downloads from the mirror and records the origin on the run.
func TestDriverRescan_FromAConfiguredMirror(t *testing.T) {
	_, m, store, want := mirroredWalk(t)
	var walkID string
	db, err := sqlitestore.Open(filepath.Join(store, "mirror.db"), nil, sqlitestore.IntentRead)
	if err != nil {
		t.Fatal(err)
	}
	qerr := db.DB().QueryRow(`SELECT id FROM walks LIMIT 1`).Scan(&walkID)
	_ = db.Close()
	if qerr != nil {
		t.Fatal(qerr)
	}
	drv, cleanup, err := kanonarion.OpenDriver(store)
	if err != nil {
		t.Fatalf("OpenDriver: %v", err)
	}
	run, err := drv.Rescan.Run(t.Context(), kanonarion.RescanRequest{WalkID: walkID, Operator: "test"})
	if cerr := cleanup(); cerr != nil {
		t.Error(cerr)
	}
	if err != nil {
		t.Fatalf("driver Rescan: %v", err)
	}
	if got := [4]string{run.Snapshot.Source(), run.Snapshot.Version(), run.Snapshot.ContentHash(), run.Snapshot.Origin()}; got != want {
		t.Errorf("driver run snapshot = %v, want %v", got, want)
	}
	if got := storedSnapshots(t, store); len(got) != 1 || got[0] != want {
		t.Errorf("stored snapshots = %v, want [%v]", got, want)
	}
	if hits := m.requested(); strings.Join(hits, " ") != "/vulndb/vulndb.zip" {
		t.Errorf("mirror requests = %v", hits)
	}
}

// A mirror serving a corrupted, a truncated or no archive is refused, and no
// snapshot is recorded. GOPROXY=off still forbids the download from a mirror.
func TestVulnScan_ABrokenOrForbiddenMirrorRecordsNothing(t *testing.T) {
	fx := buildAuditFixture(t)
	t.Chdir(fx.project)
	blob := auditVulnDB(t)
	corrupt := bytes.Clone(blob)
	at := bytes.Index(corrupt, []byte("example vulnerability"))
	if at < 0 {
		t.Fatal("the advisory body is not stored uncompressed in the fixture archive")
	}
	corrupt[at] ^= 0xff

	for _, tc := range []struct {
		name    string
		body    []byte
		status  int
		goproxy string
		want    string
	}{
		{"corrupted", corrupt, http.StatusOK, "", "checksum"},
		{"truncated", blob[:len(blob)/2], http.StatusOK, "", "validate vulndb.zip from"},
		{"not found", nil, http.StatusNotFound, "", "404"},
		{"GOPROXY=off", blob, http.StatusOK, "off", "GOPROXY=off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newVulnMirror(t, tc.body, tc.status)
			onlyTheMirror(t, m)
			store := mirrorStore(t, fx, m)
			if _, stderr, code := runMirrored(t, fx, store, "walk", "--gomod", fx.gomod(), "--from-modcache", "--no-progress"); code != cli.ExitOK {
				t.Fatalf("walk exit %d:\n%s", code, stderr)
			}
			if tc.goproxy != "" {
				t.Setenv("GOPROXY", tc.goproxy)
			}
			for k, v := range fx.env() {
				if k != "GOPROXY" {
					t.Setenv(k, v)
				}
			}
			t.Setenv("KANONARION_STORE", store)
			var out, errBuf bytes.Buffer
			err := cli.Run([]string{"vuln-scan", "--gomod", fx.gomod(), "--no-progress"}, &out, &errBuf)
			if code := cli.ExitCodeForError(err); code == cli.ExitOK || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("vuln-scan exit %d, err %v; want a refusal containing %q", code, err, tc.want)
			}
			if got := storedSnapshots(t, store); len(got) != 0 {
				t.Errorf("a snapshot was recorded: %v", got)
			}
			if tc.goproxy == "off" && len(m.requested()) != 0 {
				t.Errorf("the mirror was asked for %v under GOPROXY=off", m.requested())
			}
		})
	}
}

// republished is the fixture database re-published under the same version
// with different bytes: one more advisory file beside the others.
func republished(t *testing.T, blob []byte) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		rc, oerr := f.Open()
		if oerr != nil {
			t.Fatal(oerr)
		}
		w, cerr := fixtureZipEntry(zw, f.Name)
		if cerr != nil {
			t.Fatal(cerr)
		}
		if _, cperr := io.Copy(w, io.LimitReader(rc, 1<<20)); cperr != nil {
			t.Fatal(cperr)
		}
		_ = rc.Close()
	}
	w, err := fixtureZipEntry(zw, "ID/GO-2026-0099.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(`{"id":"GO-2026-0099","modified":"` + auditSnapshotVersion + `"}`)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// scanRunsOldestFirst reads the store's scan runs in the order they ran.
func scanRunsOldestFirst(t *testing.T, store string) []domain.WalkScanRun {
	t.Helper()
	db, err := sqlitestore.Open(filepath.Join(store, "mirror.db"), nil, sqlitestore.IntentRead)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	runs, err := vulnsqlite.New(db).ListAllWalkScanRuns(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].StartedAt.Before(runs[j].StartedAt) })
	return runs
}

// storedSnapshotBytes reads the bytes the store serves for s, verified.
func storedSnapshotBytes(t *testing.T, store string, s domain.DatabaseSnapshot) ([]byte, error) {
	t.Helper()
	db, err := sqlitestore.Open(filepath.Join(store, "mirror.db"), nil, sqlitestore.IntentRead)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rc, err := vulnsqlite.New(db).GetDatabaseSnapshot(t.Context(), s)
	if err != nil {
		return nil, err //nolint:wrapcheck // compared by the caller
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return b, nil
}

// A re-scan that downloads different bytes under the version a stored run was
// judged against stores them beside the first: the earlier run's snapshot is
// still served and still verifies. Downloading the same bytes again writes
// nothing and records no event.
func TestVulnScanRescan_ARepublishedVersionDoesNotOverwrite(t *testing.T) {
	fx := buildAuditFixture(t)
	t.Chdir(fx.project)
	original := auditVulnDB(t)
	m := newVulnMirror(t, republished(t, original), http.StatusOK)
	onlyTheMirror(t, m)
	store := fx.newStore(t)
	if err := os.WriteFile(filepath.Join(store, "config.yaml"),
		[]byte("version: \"3\"\nvulndb:\n  url: "+m.base()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := runMirrored(t, fx, store, "walk", "--gomod", fx.gomod(), "--from-modcache", "--no-progress"); code != cli.ExitOK {
		t.Fatalf("walk exit %d:\n%s", code, stderr)
	}
	if _, stderr, code := runMirrored(t, fx, store, "vuln-scan", "--gomod", fx.gomod(), "--no-progress"); code > cli.ExitPartial {
		t.Fatalf("vuln-scan exit %d:\n%s", code, stderr)
	}
	runs := scanRunsOldestFirst(t, store)
	if len(runs) != 1 || runs[0].Snapshot.ContentHash() != domain.HashSnapshotContent(original) {
		t.Fatalf("the first run is not judged against the held snapshot: %v", runs)
	}
	for i := range 2 {
		if _, stderr, code := runMirrored(t, fx, store, "vuln-scan-rescan", runs[0].WalkID, "--no-progress"); code > cli.ExitPartial {
			t.Fatalf("rescan %d exit %d:\n%s", i, code, stderr)
		}
	}

	if got, err := storedSnapshotBytes(t, store, runs[0].Snapshot); err != nil || !bytes.Equal(got, original) {
		t.Errorf("the first run's snapshot after the re-scans: %d bytes, %v; want its own %d", len(got), err, len(original))
	}
	if rows := storedSnapshots(t, store); len(rows) != 2 {
		t.Errorf("snapshot rows = %v, want the original and the re-published one", rows)
	}
	if n := len(auditLinesOfType(t, store, "advisory_snapshot_recorded")); n != 1 {
		t.Errorf("advisory_snapshot_recorded events = %d, want 1: the second download held nothing new", n)
	}
	if hits := m.requested(); len(hits) != 2 {
		t.Errorf("mirror requests = %v, want two downloads", hits)
	}
	if _, stderr, code := runMirrored(t, fx, store, "vuln-scan-show", runs[0].ID); code != cli.ExitOK {
		t.Errorf("vuln-scan-show of the first run exit %d:\n%s", code, stderr)
	}
}

// auditLinesOfType counts the store's assurance-log lines of one event type.
func auditLinesOfType(t *testing.T, store, eventType string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(filepath.Join(store, "audit.jsonl")))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, `"event_type":"`+eventType+`"`) {
			out = append(out, line)
		}
	}
	return out
}
