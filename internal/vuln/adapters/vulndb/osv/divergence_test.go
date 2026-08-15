package osv_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/vulndb/osv"
)

// divergenceWindow builds the situation this whole change exists for: a stored
// snapshot that does NOT list an advisory, and a live service that does.
//
// It returns a Database wired to both — the store holding the older generation,
// an HTTP client pointed at a server publishing the newer one — plus the count
// of requests that server received. The count is the measurement: a lookup that
// answers from the snapshot leaves it at zero, and one that reaches past the
// snapshot cannot.
func divergenceWindow(t *testing.T) (*osv.Database, *atomic.Int64) {
	t.Helper()

	const modulePath = "stdlib"
	const pinnedAdvisory = "GO-2026-1000"
	const advisoryPublishedSince = "GO-2026-6218"

	var hits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch {
		case r.URL.Path == "/index/modules.json.gz":
			_, _ = w.Write(gzipJSON(t, []map[string]any{{"path": modulePath, "vulns": []map[string]any{
				{"id": pinnedAdvisory, "fixed": "1.27.0-rc.3"},
				{"id": advisoryPublishedSince, "fixed": "1.27.0-rc.3"},
			}}}))
		case strings.HasPrefix(r.URL.Path, "/ID/"):
			// A fixed body: the server exists to be counted, not to be correct, and
			// echoing the requested path back into it would be reflecting a request
			// into a response for no gain.
			_, _ = io.WriteString(w, `{"id":"`+advisoryPublishedSince+`","summary":"published after the snapshot"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// The stored snapshot lists only the older advisory.
	store := &fakeVulnStore{content: string(advisorySnapshotZip(t,
		[]map[string]any{{"path": modulePath, "vulns": []map[string]any{{"id": pinnedAdvisory, "fixed": "1.27.0-rc.3"}}}},
		map[string]string{pinnedAdvisory: `{"id":"` + pinnedAdvisory + `","summary":"in the pinned generation"}`},
	))}

	return osv.New(clientRewritingTo(t, srv), store), &hits
}

// TestLookupFindings_DoesNotReportWhatTheSnapshotCannotProduce is the coordinate
// route's regression test.
//
// The advisory published since the snapshot is exactly the finding that used to
// arrive here, get merged into a record naming the snapshot, and be stamped
// not-reachable at high confidence on the strength of an analyser's silence
// about an advisory it was never given. The database this record names does not
// contain it, so it is not reported.
func TestLookupFindings_DoesNotReportWhatTheSnapshotCannotProduce(t *testing.T) {
	db, hits := divergenceWindow(t)
	coord := coordinatetest.MustNew("stdlib", "v1.26.5")

	findings, err := db.LookupFindings(t.Context(), coord, pinnedSnapshot(t))
	if err != nil {
		t.Fatalf("LookupFindings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly the one the pinned snapshot lists", findings)
	}
	if findings[0].ID != "GO-2026-1000" {
		t.Errorf("finding = %q, want GO-2026-1000: only the snapshot's own advisories may be reported", findings[0].ID)
	}
	if findings[0].Summary != "in the pinned generation" {
		t.Errorf("Summary = %q: the enrichment must come out of the snapshot too, not from the live record",
			findings[0].Summary)
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("the live database was requested %d times; a scan reads the database its record names, and nothing else", got)
	}
}

// TestCheckVulnerable_DoesNotSeeWhatTheSnapshotCannotProduce is the same guard on
// the cheap pre-check, which is the second caller of the same index. Its answer
// decides whether a module is analysed from source at all, so an advisory
// outside the pinned set must not be able to change that decision.
func TestCheckVulnerable_DoesNotSeeWhatTheSnapshotCannotProduce(t *testing.T) {
	db, hits := divergenceWindow(t)
	coord := coordinatetest.MustNew("stdlib", "v1.26.5")

	vulns, err := db.CheckVulnerable(t.Context(), []coordinate.ModuleCoordinate{coord}, pinnedSnapshot(t))
	if err != nil {
		t.Fatalf("CheckVulnerable: %v", err)
	}
	ids := vulns[coord]
	if len(ids) != 1 || ids[0] != "GO-2026-1000" {
		t.Errorf("ids = %v, want [GO-2026-1000]: only the pinned generation's advisories may be seen", ids)
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("the live database was requested %d times; the pre-check reads the pinned snapshot", got)
	}
}
