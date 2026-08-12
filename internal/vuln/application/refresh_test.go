package application_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// refreshFixture wires the smallest use case that can refresh the advisory
// database: the store it compares against and downloads into, the database that
// publishes a generation, and a walk whose module set the comparison is
// restricted to.
func refreshFixture(t testing.TB, db *fakeDatabase) (*application.ScanWalkUseCase, *fakeVulnStore) {
	t.Helper()
	vulnStore := newFakeVulnStore()
	walkStore := newFakeWalkStore()
	seedRefreshWalk(t, walkStore, "walk-1", "example.com/mod", coordinate.StdlibPath)
	moduleScanner := application.NewScanModuleUseCase(
		nil, nil, vulnStore, nil, nil, db, nil, nil, "v1", slog.Default(),
	)
	uc := application.NewScanWalkUseCase(
		walkStore, vulnStore, moduleScanner, nil, nil, "v1", slog.Default(),
	)
	return uc, vulnStore
}

// seedRefreshWalk stores a walk holding one node per path. The stdlib node is
// deliberately one of them: it is judged against the advisory database like any
// other module, so the comparison has to cover it.
func seedRefreshWalk(t testing.TB, store *fakeWalkStore, walkID string, paths ...string) {
	t.Helper()
	nodes := make([]walkdomain.GraphNode, 0, len(paths))
	for _, p := range paths {
		coord, err := coordinate.NewModuleCoordinate(p, "v1.0.0")
		if err != nil {
			t.Fatalf("coordinate for %s: %v", p, err)
		}
		nodes = append(nodes, walkdomain.GraphNode{Coordinate: coord})
	}
	rec := walkdomain.WalkRecord{ID: walkID, Graph: walkdomain.Graph{Nodes: nodes}}
	if err := store.PutWalk(context.Background(), rec); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}
}

// index is a shorthand for a module index naming one advisory per module.
func index(entries map[string]ports.AdvisoryIndexEntry) ports.AdvisoryIndex {
	out := make(ports.AdvisoryIndex, len(entries))
	for path, e := range entries {
		out[path] = []ports.AdvisoryIndexEntry{e}
	}
	return out
}

// TestRefreshSnapshot_UnchangedGenerationDownloadsNothing is the first check.
// The bulk database is a multi-megabyte transfer and the usual answer to "has it
// changed" is no; reading the published generation settles that in one small
// request, and nothing further is even asked.
func TestRefreshSnapshot_UnchangedGenerationDownloadsNothing(t *testing.T) {
	held := vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z")
	db := &fakeDatabase{snapshot: held, content: "{}"}
	uc, store := refreshFixture(t, db)
	seedSnapshot(t, store, held)

	got, err := uc.RefreshSnapshot(context.Background(), "walk-1")
	if err != nil {
		t.Fatalf("RefreshSnapshot: %v", err)
	}
	if n := db.snapshotCalls.Load(); n != 0 {
		t.Errorf("the database body was downloaded %d times for a generation already held", n)
	}
	if n := db.indexCalls.Load(); n != 0 {
		t.Errorf("the advisory index was read %d times for a generation that had not moved", n)
	}
	if n := db.latestVersionCalls.Load(); n != 1 {
		t.Errorf("published generation read %d times, want exactly 1", n)
	}
	if got.Outcome != application.RefreshUnchanged {
		t.Errorf("Outcome = %q, want %q", got.Outcome, application.RefreshUnchanged)
	}
	if got.Snapshot.Version() != held.Version() || got.PriorVersion != held.Version() {
		t.Errorf("refresh settled on %s (prior %s), want the stored %s",
			got.Snapshot.Version(), got.PriorVersion, held.Version())
	}
}

// TestRefreshSnapshot_AdvancedGenerationWithNoWalkRelevantChangeDownloadsNothing
// is the second check, and the larger saving. A new generation is published
// whenever any advisory anywhere moves; this walk is judged on the advisories
// listed for its own modules, and when those are identical the stored snapshot
// still answers.
func TestRefreshSnapshot_AdvancedGenerationWithNoWalkRelevantChangeDownloadsNothing(t *testing.T) {
	held := vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z")
	db := &fakeDatabase{
		snapshot:      vulntest.MustNew("vuln.go.dev", "2026-08-01T09:00:00Z"),
		content:       "{}",
		latestVersion: "2026-08-01T09:00:00Z",
		storedIndex: index(map[string]ports.AdvisoryIndexEntry{
			"example.com/mod":     {ID: "GO-2026-0001", Modified: "2026-01-01T00:00:00Z", Fixed: "1.2.0"},
			coordinate.StdlibPath: {ID: "GO-2026-0002", Modified: "2026-01-01T00:00:00Z", Fixed: "1.24.1"},
		}),
		// The published index moves for a module this walk does not hold.
		publishedIndex: index(map[string]ports.AdvisoryIndexEntry{
			"example.com/mod":     {ID: "GO-2026-0001", Modified: "2026-01-01T00:00:00Z", Fixed: "1.2.0"},
			coordinate.StdlibPath: {ID: "GO-2026-0002", Modified: "2026-01-01T00:00:00Z", Fixed: "1.24.1"},
			"example.com/other":   {ID: "GO-2026-9999", Modified: "2026-08-01T00:00:00Z", Fixed: "3.0.0"},
		}),
	}
	uc, store := refreshFixture(t, db)
	seedSnapshot(t, store, held)

	got, err := uc.RefreshSnapshot(context.Background(), "walk-1")
	if err != nil {
		t.Fatalf("RefreshSnapshot: %v", err)
	}
	if n := db.snapshotCalls.Load(); n != 0 {
		t.Errorf("the database body was downloaded %d times for a change no walk module is judged on", n)
	}
	if got.Outcome != application.RefreshIndexUnchanged {
		t.Errorf("Outcome = %q, want %q", got.Outcome, application.RefreshIndexUnchanged)
	}
	if got.Snapshot.Version() != held.Version() {
		t.Errorf("the stored snapshot was replaced: %s, want %s", got.Snapshot.Version(), held.Version())
	}
	if got.PublishedVersion != "2026-08-01T09:00:00Z" {
		t.Errorf("PublishedVersion = %q, want the advanced generation", got.PublishedVersion)
	}
	if got.ModulesCompared != 2 {
		t.Errorf("ModulesCompared = %d, want the walk's 2 modules", got.ModulesCompared)
	}
}

// TestRefreshSnapshot_AdvancedGenerationTouchingAWalkModuleDownloads: any delta
// on a module the walk holds is a change to the question this walk asks.
func TestRefreshSnapshot_AdvancedGenerationTouchingAWalkModuleDownloads(t *testing.T) {
	held := vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z")
	published := vulntest.MustNew("vuln.go.dev", "2026-08-01T09:00:00Z")
	db := &fakeDatabase{
		snapshot:      published,
		content:       "{}",
		latestVersion: published.Version(),
		storedIndex: index(map[string]ports.AdvisoryIndexEntry{
			"example.com/mod": {ID: "GO-2026-0001", Modified: "2026-01-01T00:00:00Z", Fixed: "1.2.0"},
		}),
		publishedIndex: index(map[string]ports.AdvisoryIndexEntry{
			"example.com/mod": {ID: "GO-2026-0001", Modified: "2026-01-01T00:00:00Z", Fixed: "1.3.0"},
		}),
	}
	uc, store := refreshFixture(t, db)
	seedSnapshot(t, store, held)

	got, err := uc.RefreshSnapshot(context.Background(), "walk-1")
	if err != nil {
		t.Fatalf("RefreshSnapshot: %v", err)
	}
	if n := db.snapshotCalls.Load(); n != 1 {
		t.Errorf("a changed remediation for a walk module downloaded the body %d times, want 1", n)
	}
	if got.Outcome != application.RefreshDownloaded {
		t.Errorf("Outcome = %q, want %q", got.Outcome, application.RefreshDownloaded)
	}
	if got.Snapshot.Version() != published.Version() {
		t.Errorf("refresh settled on %s, want the published %s", got.Snapshot.Version(), published.Version())
	}
	latest, ok, serr := store.GetLatestDatabaseSnapshot(context.Background())
	if serr != nil || !ok {
		t.Fatalf("stored latest snapshot after refresh: ok=%v err=%v", ok, serr)
	}
	if latest.Version() != published.Version() {
		t.Errorf("stored latest = %s, want the downloaded %s", latest.Version(), published.Version())
	}
}

// TestRefreshSnapshot_WithdrawnAdvisoryOnAWalkModuleDownloads: a withdrawal
// reaches the index as a change to the advisory's own modified stamp, so the
// comparison has to read that field and not only the identifiers.
func TestRefreshSnapshot_WithdrawnAdvisoryOnAWalkModuleDownloads(t *testing.T) {
	held := vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z")
	db := &fakeDatabase{
		snapshot:      vulntest.MustNew("vuln.go.dev", "2026-08-01T09:00:00Z"),
		content:       "{}",
		latestVersion: "2026-08-01T09:00:00Z",
		storedIndex: index(map[string]ports.AdvisoryIndexEntry{
			"example.com/mod": {ID: "GO-2026-0001", Modified: "2026-01-01T00:00:00Z", Fixed: "1.2.0"},
		}),
		publishedIndex: index(map[string]ports.AdvisoryIndexEntry{
			"example.com/mod": {ID: "GO-2026-0001", Modified: "2026-08-01T08:00:00Z", Fixed: "1.2.0"},
		}),
	}
	uc, store := refreshFixture(t, db)
	seedSnapshot(t, store, held)

	got, err := uc.RefreshSnapshot(context.Background(), "walk-1")
	if err != nil {
		t.Fatalf("RefreshSnapshot: %v", err)
	}
	if got.Outcome != application.RefreshDownloaded {
		t.Errorf("an advisory edited upstream did not re-download: Outcome = %q", got.Outcome)
	}
}

// TestRefreshSnapshot_UnreadableGenerationDownloadsAndSaysSo is the fail-closed
// rule at the first check. A refresh the operator asked for must not become a
// cache hit because the generation read failed — and the report must not let the
// fallback pass for a generation that genuinely moved.
func TestRefreshSnapshot_UnreadableGenerationDownloadsAndSaysSo(t *testing.T) {
	held := vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z")
	stampErr := errors.New("dial tcp: connection refused")
	db := &fakeDatabase{snapshot: held, content: "{}", latestVersionErr: stampErr}
	uc, store := refreshFixture(t, db)
	seedSnapshot(t, store, held)

	got, err := uc.RefreshSnapshot(context.Background(), "walk-1")
	if err != nil {
		t.Fatalf("RefreshSnapshot: %v", err)
	}
	if n := db.snapshotCalls.Load(); n != 1 {
		t.Errorf("an unreadable generation downloaded the body %d times, want 1", n)
	}
	if got.Outcome != application.RefreshDownloaded {
		t.Errorf("Outcome = %q, want %q", got.Outcome, application.RefreshDownloaded)
	}
	if !errors.Is(got.StampErr, stampErr) {
		t.Errorf("StampErr = %v, want the generation-read failure %v", got.StampErr, stampErr)
	}
}

// TestRefreshSnapshot_UnreadableIndexDownloadsAndSaysSo is the same rule at the
// second check: a comparison that could not be made is not a comparison that
// found nothing.
func TestRefreshSnapshot_UnreadableIndexDownloadsAndSaysSo(t *testing.T) {
	held := vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z")
	indexErr := errors.New("unexpected status fetching index: 503 Service Unavailable")
	db := &fakeDatabase{
		snapshot:      vulntest.MustNew("vuln.go.dev", "2026-08-01T09:00:00Z"),
		content:       "{}",
		latestVersion: "2026-08-01T09:00:00Z",
		indexErr:      indexErr,
	}
	uc, store := refreshFixture(t, db)
	seedSnapshot(t, store, held)

	got, err := uc.RefreshSnapshot(context.Background(), "walk-1")
	if err != nil {
		t.Fatalf("RefreshSnapshot: %v", err)
	}
	if n := db.snapshotCalls.Load(); n != 1 {
		t.Errorf("an unreadable index downloaded the body %d times, want 1", n)
	}
	if got.Outcome != application.RefreshDownloaded {
		t.Errorf("Outcome = %q, want %q", got.Outcome, application.RefreshDownloaded)
	}
	if got.IndexErr == nil || !errors.Is(got.IndexErr, indexErr) {
		t.Errorf("IndexErr = %v, want the index-read failure %v", got.IndexErr, indexErr)
	}
}

// TestRefreshSnapshot_UnknownWalkDownloads: with no module set to restrict the
// comparison to, there is no cheap answer, and guessing one would be a claim the
// run cannot support.
func TestRefreshSnapshot_UnknownWalkDownloads(t *testing.T) {
	held := vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z")
	db := &fakeDatabase{
		snapshot:      vulntest.MustNew("vuln.go.dev", "2026-08-01T09:00:00Z"),
		content:       "{}",
		latestVersion: "2026-08-01T09:00:00Z",
	}
	uc, store := refreshFixture(t, db)
	seedSnapshot(t, store, held)

	got, err := uc.RefreshSnapshot(context.Background(), "walk-absent")
	if err != nil {
		t.Fatalf("RefreshSnapshot: %v", err)
	}
	if got.Outcome != application.RefreshDownloaded {
		t.Errorf("Outcome = %q, want %q", got.Outcome, application.RefreshDownloaded)
	}
	if got.IndexErr == nil {
		t.Error("a walk that could not be loaded produced no stated reason for the download")
	}
}

// TestRefreshSnapshot_NoStoredSnapshotDownloads: with nothing to compare
// against, the body is the only thing that answers.
func TestRefreshSnapshot_NoStoredSnapshotDownloads(t *testing.T) {
	published := vulntest.MustNew("vuln.go.dev", "2026-08-01T09:00:00Z")
	db := &fakeDatabase{snapshot: published, content: "{}"}
	uc, _ := refreshFixture(t, db)

	got, err := uc.RefreshSnapshot(context.Background(), "walk-1")
	if err != nil {
		t.Fatalf("RefreshSnapshot: %v", err)
	}
	if n := db.latestVersionCalls.Load(); n != 0 {
		t.Errorf("the generation was read %d times with nothing to compare it against", n)
	}
	if !got.Downloaded() || got.PriorVersion != "" {
		t.Errorf("a first refresh must download and name no prior generation, got %+v", got)
	}
}

// TestRefreshSnapshot_UnchangedDatabaseLeavesTheStoredRunReusable is the
// behaviour the halves compose into: refreshing the database is not itself a
// reason to re-scan, and the run that answered against it still does — naming
// the generation it was really judged against.
func TestRefreshSnapshot_UnchangedDatabaseLeavesTheStoredRunReusable(t *testing.T) {
	held := vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z")
	db := &fakeDatabase{snapshot: held, content: "{}"}
	uc, store := refreshFixture(t, db)
	seedSnapshot(t, store, held)
	want := seedRun(t, store, "vscan-1", "walk-1", held, "v1", domain.CoverageComplete)

	if _, err := uc.RefreshSnapshot(context.Background(), "walk-1"); err != nil {
		t.Fatalf("RefreshSnapshot: %v", err)
	}
	got, ok, err := uc.ReusableRun(context.Background(), "walk-1", "")
	if err != nil {
		t.Fatalf("ReusableRun: %v", err)
	}
	if !ok {
		t.Fatal("a refresh that found the database unchanged left no run reusable")
	}
	if got.ID != want.ID {
		t.Errorf("reused run = %s, want %s", got.ID, want.ID)
	}
	if got.Snapshot.Version() != held.Version() {
		t.Errorf("the reused run names snapshot %s, want the one it was judged against, %s",
			got.Snapshot.Version(), held.Version())
	}
}

// TestRefreshSnapshot_IrrelevantlyAdvancedDatabaseLeavesTheStoredRunReusable is
// the same for the second check, and pins the part that is easy to get wrong:
// the reused run must still name the generation it was judged against, not the
// one the database now publishes.
func TestRefreshSnapshot_IrrelevantlyAdvancedDatabaseLeavesTheStoredRunReusable(t *testing.T) {
	held := vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z")
	db := &fakeDatabase{
		snapshot:      vulntest.MustNew("vuln.go.dev", "2026-08-01T09:00:00Z"),
		content:       "{}",
		latestVersion: "2026-08-01T09:00:00Z",
		storedIndex: index(map[string]ports.AdvisoryIndexEntry{
			"example.com/mod": {ID: "GO-2026-0001", Modified: "2026-01-01T00:00:00Z", Fixed: "1.2.0"},
		}),
	}
	uc, store := refreshFixture(t, db)
	seedSnapshot(t, store, held)
	want := seedRun(t, store, "vscan-1", "walk-1", held, "v1", domain.CoverageComplete)

	refresh, err := uc.RefreshSnapshot(context.Background(), "walk-1")
	if err != nil {
		t.Fatalf("RefreshSnapshot: %v", err)
	}
	if refresh.Outcome != application.RefreshIndexUnchanged {
		t.Fatalf("Outcome = %q, want %q", refresh.Outcome, application.RefreshIndexUnchanged)
	}
	got, ok, err := uc.ReusableRun(context.Background(), "walk-1", "")
	if err != nil {
		t.Fatalf("ReusableRun: %v", err)
	}
	if !ok {
		t.Fatal("a generation that changed nothing this walk is judged on forced a re-scan")
	}
	if got.ID != want.ID {
		t.Errorf("reused run = %s, want %s", got.ID, want.ID)
	}
	if got.Snapshot.Version() != held.Version() {
		t.Errorf("the reused run names snapshot %s, want the one it was judged against, %s",
			got.Snapshot.Version(), held.Version())
	}
}

// TestRefreshSnapshot_RelevantlyAdvancedDatabaseMakesTheStoredRunUnreusable is
// the converse, and the reason --fresh needs no reuse bypass of its own: the
// snapshot condition already refuses a run judged against a superseded database.
func TestRefreshSnapshot_RelevantlyAdvancedDatabaseMakesTheStoredRunUnreusable(t *testing.T) {
	held := vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z")
	published := vulntest.MustNew("vuln.go.dev", "2026-08-01T09:00:00Z")
	db := &fakeDatabase{
		snapshot:      published,
		content:       "{}",
		latestVersion: published.Version(),
		storedIndex: index(map[string]ports.AdvisoryIndexEntry{
			"example.com/mod": {ID: "GO-2026-0001", Modified: "2026-01-01T00:00:00Z", Fixed: "1.2.0"},
		}),
		publishedIndex: index(map[string]ports.AdvisoryIndexEntry{
			"example.com/mod": {ID: "GO-2026-0001", Modified: "2026-01-01T00:00:00Z", Fixed: ""},
		}),
	}
	uc, store := refreshFixture(t, db)
	seedSnapshot(t, store, held)
	seedRun(t, store, "vscan-1", "walk-1", held, "v1", domain.CoverageComplete)

	if _, err := uc.RefreshSnapshot(context.Background(), "walk-1"); err != nil {
		t.Fatalf("RefreshSnapshot: %v", err)
	}
	if _, ok, err := uc.ReusableRun(context.Background(), "walk-1", ""); err != nil {
		t.Fatalf("ReusableRun: %v", err)
	} else if ok {
		t.Error("a run judged against the superseded database was served after the refresh")
	}
}
