package osv_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coordinatetest "github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/goenv"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/vulndb/osv"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// permitted declares the contract absent: a GOPROXY naming a real proxy, and no
// env file that could say otherwise. It is the control half of every assertion
// below — a guard that refused unconditionally would satisfy the refusal test
// and fail this one.
func permitted(t *testing.T) {
	t.Helper()
	t.Setenv("GOENV", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("GOPROXY", "https://proxy.example.com")
}

// airGapped declares the contract through Go's env file rather than the
// variable, so these tests also exercise the resolution the whole batch rests
// on: an operator who ran `go env -w GOPROXY=off` has forbidden the network.
func airGapped(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(path, []byte("GOPROXY=off\n"), 0o600); err != nil {
		t.Fatalf("writing env file: %v", err)
	}
	t.Setenv("GOENV", path)
	t.Setenv("GOPROXY", "")
}

// countingServer serves the two standalone endpoints the adapter reads and
// counts every request that arrives, so "refused before I/O" is a measurement
// rather than a claim about the box being offline.
func countingServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/index/db.json":
			_, _ = w.Write([]byte(`{"modified":"2026-01-01T00:00:00Z"}`))
		case "/vulndb.zip":
			_, _ = w.Write(defaultVulnDBZip(t))
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &hits
}

// TestLatestVersion_ControlReachesTheNetwork is the non-zero control: with the
// contract absent the version probe is made and the server sees it.
func TestLatestVersion_ControlReachesTheNetwork(t *testing.T) {
	permitted(t)
	srv, hits := countingServer(t)
	db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{})

	version, err := db.LatestVersion(context.Background())
	if err != nil {
		t.Fatalf("LatestVersion with the network permitted: %v", err)
	}
	if version != "2026-01-01T00:00:00Z" {
		t.Errorf("version = %q", version)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("request count = %d, want 1: the control must actually reach the server", got)
	}
}

// TestAdvisoryDownloads_RefusedUnderAirGap: every outbound read of the advisory
// database refuses before a socket is opened, and the request count stays at
// zero beside a server that would have answered.
func TestAdvisoryDownloads_RefusedUnderAirGap(t *testing.T) {
	airGapped(t)
	srv, hits := countingServer(t)
	db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{})
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"Snapshot", func() error { _, _, err := db.Snapshot(ctx); return err }},                          //nolint:wrapcheck // the sentinel identity is exactly what is asserted
		{"LatestVersion", func() error { _, err := db.LatestVersion(ctx); return err }},                   //nolint:wrapcheck // as above
		{"PublishedAdvisoryIndex", func() error { _, err := db.PublishedAdvisoryIndex(ctx); return err }}, //nolint:wrapcheck // as above
	} {
		err := tc.call()
		if err == nil {
			t.Fatalf("%s: no error; the environment declares no network", tc.name)
		}
		if !errors.Is(err, osv.ErrNetworkForbidden) {
			t.Errorf("%s: error %v does not carry ErrNetworkForbidden", tc.name, err)
		}
		if !errors.Is(err, goenv.ErrNetworkForbidden) {
			t.Errorf("%s: error %v does not carry the shared no-network fact", tc.name, err)
		}
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("request count = %d, want 0: the refusal must land before any I/O", got)
	}
}

// TestRefusal_NamesTheRemedy: a refusal that does not say what to run instead
// stops the operator rather than redirecting them.
func TestRefusal_NamesTheRemedy(t *testing.T) {
	airGapped(t)
	srv, _ := countingServer(t)
	db := osv.New(clientRewritingTo(t, srv), &fakeVulnStore{})

	_, _, err := db.Snapshot(context.Background())
	if err == nil {
		t.Fatal("expected a refusal")
	}
	for _, want := range []string{"--fresh", "--snapshot-source", "vuln-snapshot-list"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err, want)
		}
	}
}

// TestStoredSnapshot_StillAnswersUnderAirGap is the acceptance the ticket
// states: withdrawing the download must not withdraw the store. A snapshot
// already held is read, parsed and answered from with the contract in force.
func TestStoredSnapshot_StillAnswersUnderAirGap(t *testing.T) {
	airGapped(t)
	db := osv.New(nil, &fakeVulnStore{content: string(defaultVulnDBZip(t))})

	identity, err := domain.NewDatabaseSnapshot("vuln.go.dev", "2024-01-01T00:00:00Z", time.Now(), domain.HashSnapshotContent(defaultVulnDBZip(t)))
	if err != nil {
		t.Fatalf("building snapshot identity: %v", err)
	}
	index, err := db.SnapshotAdvisoryIndex(context.Background(), identity)
	if err != nil {
		t.Fatalf("reading the stored snapshot under GOPROXY=off: %v", err)
	}
	if len(index) == 0 {
		t.Error("stored snapshot answered with an empty index")
	}

	// The coordinate-match route is the same claim, and it did not hold: it read
	// the live service, so under GOPROXY=off it refused before any I/O and every
	// module in the scan recorded an advisory-match failure — while the store held
	// the advisory set the whole time. It reads the stored snapshot now, so an
	// air-gapped scan answers from the generation it names.
	findings, err := db.LookupFindings(context.Background(), coordinatetest.MustNew("github.com/foo/bar", "v1.0.0"), identity)
	if err != nil {
		t.Fatalf("matching a coordinate against the stored snapshot under GOPROXY=off: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "GO-2024-0001" {
		t.Errorf("findings = %+v, want the snapshot's own advisory", findings)
	}
}
