package composition_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	fetchsqlite "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	"github.com/eitanity/kanonarion/internal/composition"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/driver"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	licsqlite "github.com/eitanity/kanonarion/internal/license/adapters/store/sqlite"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// writeTree writes path -> content under a fresh directory and returns it.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	return root
}

// hasFunc reports whether coord's interface record declares a function name.
func hasFunc(ctx context.Context, t *testing.T, queries *composition.Queries, coord coordinate.ModuleCoordinate, name string) bool {
	t.Helper()
	rec, found, err := queries.Interface.GetInterfaceRecord(ctx, coord, ifaceapp.PipelineVersion)
	if err != nil || !found {
		t.Fatalf("GetInterfaceRecord(%s): found=%v err=%v", coord, found, err)
	}
	for _, p := range rec.Packages {
		for _, f := range p.Funcs {
			if f.Name == name {
				return true
			}
		}
	}
	return false
}

// The library driver analyses a go.work member and a local replacement, each
// under its own @local identity, with no request field asking for it; an edit
// to the replacement is in its record on the next run without Force.
func TestLocalWalkExtract_WorkspaceMembersAndReplacements(t *testing.T) {
	t.Setenv("GOWORK", "")
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOPROXY", "off")
	ws := writeTree(t, map[string]string{
		"go.work":   "go 1.22\n\nuse (\n\t./a\n\t./b\n)\n",
		"a/go.mod":  "module example.test/a\n\ngo 1.22\n\nrequire example.test/c v1.2.3\n\nreplace example.test/c v1.2.3 => ../c\n",
		"a/main.go": "package main\n\nimport (\n\t\"fmt\"\n\n\t\"example.test/b\"\n\t\"example.test/c\"\n)\n\nfunc main() { fmt.Println(b.B(), c.C()) }\n",
		"b/go.mod":  "module example.test/b\n\ngo 1.22\n",
		"b/b.go":    "package b\n\n// B is b.\nfunc B() string { return \"b\" }\n",
		"c/go.mod":  "module example.test/c\n\ngo 1.22\n",
		"c/c.go":    "package c\n\n// C is c.\nfunc C() string { return \"c\" }\n",
	})
	storeRoot := t.TempDir()
	drv, cleanup, err := composition.NewDriver(storeRoot)
	if err != nil {
		t.Fatalf("NewDriver: %v", err)
	}
	defer mustClose(t, cleanup)
	queries, qcleanup, err := composition.NewQueries(storeRoot)
	if err != nil {
		t.Fatalf("NewQueries: %v", err)
	}
	defer mustClose(t, qcleanup)

	ctx := context.Background()
	stages := []string{"license", "interface"}
	res, err := drv.LocalWalkExtract.Run(ctx, driver.LocalWalkExtractRequest{Dir: filepath.Join(ws, "a"), Stages: stages, AnalyseLocalRoot: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	root := coordinatetest.MustNew("example.test/a", coordinate.LocalVersion)
	member := coordinatetest.MustNew("example.test/b", coordinate.LocalVersion)
	replaced := coordinatetest.MustNew("example.test/c", coordinate.LocalVersion)
	sources := map[coordinate.ModuleCoordinate]walkdomain.ResolutionSource{}
	for _, n := range res.Walk.Graph.Nodes {
		sources[n.Coordinate] = n.ResolutionSource
	}
	for c, want := range map[coordinate.ModuleCoordinate]walkdomain.ResolutionSource{
		root:     walkdomain.ResolutionLocalAnalysed,
		member:   walkdomain.ResolutionLocalWorkspaceMember,
		replaced: walkdomain.ResolutionLocalReplace,
	} {
		if sources[c] != want {
			t.Errorf("%s source = %q, want %q (nodes %v)", c, sources[c], want, sources)
		}
		mod, ok := res.Extraction.PerModuleResults[c]
		if !ok {
			t.Errorf("no extraction result for %s", c)
			continue
		}
		for _, stage := range stages {
			if sr := mod.Stages[stage]; sr.Status.String() != "succeeded" {
				t.Errorf("%s %s = %s (%s), want succeeded", c, stage, sr.Status, sr.Error)
			}
		}
	}
	if !hasFunc(ctx, t, queries, member, "B") || !hasFunc(ctx, t, queries, replaced, "C") {
		t.Fatal("the member's or the replacement's own API is not in its record")
	}

	if err := os.WriteFile(filepath.Join(ws, "c", "c.go"), []byte("package c\n\n// C is c.\nfunc C() string { return \"c\" }\n\n// Added is new.\nfunc Added() int { return 1 }\n"), 0o600); err != nil {
		t.Fatalf("editing c.go: %v", err)
	}
	if _, err := drv.LocalWalkExtract.Run(ctx, driver.LocalWalkExtractRequest{Dir: filepath.Join(ws, "a"), Stages: []string{"interface"}}); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if !hasFunc(ctx, t, queries, replaced, "Added") {
		t.Error("the edit to the replacement is not in its record; a stale read was served")
	}
}

// A project that replaces a published module with a local directory files the
// directory under <path>@local: the published module's fetch record is
// byte-identical afterwards and is still what a read of its coordinate serves.
func TestLocalWalkExtract_LocalReplacementLeavesThePublishedRecordAlone(t *testing.T) {
	t.Setenv("GOPROXY", "off")
	storeRoot := t.TempDir()
	published := coordinatetest.MustNew("example.test/lib", "v1.6.0")

	before := seedPublishedRecord(t, storeRoot, published)

	proj := writeTree(t, map[string]string{
		"loc/go.mod":  "module example.test/loc\n\ngo 1.22\n\nrequire example.test/lib v1.6.0\n\nreplace example.test/lib v1.6.0 => ../fake\n",
		"loc/main.go": "package main\n\nimport \"example.test/lib\"\n\nfunc main() { _ = lib.FakeOnlyLocal() }\n",
		"fake/go.mod": "module example.test/lib\n",
		"fake/lib.go": "package lib\n\n// FakeOnlyLocal exists only in the local copy.\nfunc FakeOnlyLocal() string { return \"local\" }\n",
	})
	drv, cleanup, err := composition.NewDriver(storeRoot)
	if err != nil {
		t.Fatalf("NewDriver: %v", err)
	}
	defer mustClose(t, cleanup)
	if _, rerr := drv.LocalWalkExtract.Run(context.Background(), driver.LocalWalkExtractRequest{
		Dir: filepath.Join(proj, "loc"), Stages: []string{"interface"},
	}); rerr != nil {
		t.Fatalf("Run: %v", rerr)
	}
	queries, qcleanup, err := composition.NewQueries(storeRoot)
	if err != nil {
		t.Fatalf("NewQueries: %v", err)
	}
	defer mustClose(t, qcleanup)

	got, found, err := queries.Fetch.ComposeFetchRecord(context.Background(), published)
	if err != nil || !found || got.ContentHash != before.ContentHash || got.MeasurementCount != 1 {
		t.Errorf("published read = %s (%d measurements), found %v, err %v; want the seeded record alone",
			got.ContentHash, got.MeasurementCount, found, err)
	}
	local := coordinatetest.MustNew("example.test/lib", coordinate.LocalVersion)
	lr, found, err := queries.Fetch.ComposeFetchRecord(context.Background(), local)
	if err != nil || !found || lr.VerificationStatus != string(fetchdomain.LocalSource) {
		t.Errorf("local read = %+v, found %v, err %v; want the directory filed at %s", lr.VerificationStatus, found, err, local)
	}
	if !hasFunc(context.Background(), t, queries, local, "FakeOnlyLocal") {
		t.Errorf("%s does not carry the local copy's API", local)
	}
}

// seedPublishedRecord creates the store's schema and files one published
// measurement of coord, returning it as stored.
func seedPublishedRecord(t *testing.T, storeRoot string, coord coordinate.ModuleCoordinate) fetchdomain.FactRecord {
	t.Helper()
	_, cleanup, err := composition.NewDriver(storeRoot)
	if err != nil {
		t.Fatalf("NewDriver: %v", err)
	}
	mustClose(t, cleanup)
	facts, err := fetchsqlite.Open(filepath.Join(storeRoot, "mirror.db"))
	if err != nil {
		t.Fatalf("opening the fact store: %v", err)
	}
	defer func() {
		if cerr := facts.Close(); cerr != nil {
			t.Errorf("closing the fact store: %v", cerr)
		}
	}()
	seed := fetchtest.Sealed(t, fetchtest.Coordinate(coord), fetchtest.Status(fetchdomain.VerifiedByGoSum),
		fetchtest.ModuleHash(fetchtest.H1("published=")))
	if perr := facts.PutFetchRecord(context.Background(), seed); perr != nil {
		t.Fatalf("seeding: %v", perr)
	}
	rows, err := facts.ListFetchRecords(context.Background(), coord, seed.Record().PipelineVersion)
	if err != nil || len(rows) != 1 {
		t.Fatalf("seeded rows = %d, %v", len(rows), err)
	}
	return rows[0]
}

// A store written before local identity holds, under a published coordinate, a
// directory's fetch row and the licence record derived from it beside the
// published artefact's. Through the composition root the published coordinate
// reads the published licence, with no conflict; the directory's record stays.
func TestStorage_SupersededLocalGenerationIsLeftOutOfDerivedReads(t *testing.T) {
	ctx := context.Background()
	storeRoot := t.TempDir()
	published := coordinatetest.MustNew("example.test/uuid", "v1.6.0")
	seedPublishedRecord(t, storeRoot, published)

	facts, err := fetchsqlite.Open(filepath.Join(storeRoot, "mirror.db"))
	if err != nil {
		t.Fatalf("opening the fact store: %v", err)
	}
	localRow := fetchtest.Sealed(t, fetchtest.Coordinate(published), fetchtest.PipelineVersion("local-0.1.0"),
		fetchtest.Status(fetchdomain.LocalSource), fetchtest.ModuleHash(fetchtest.H1("directory=")))
	if perr := facts.PutFetchRecord(ctx, localRow); perr != nil {
		t.Fatalf("seeding the local row: %v", perr)
	}
	if cerr := facts.Close(); cerr != nil {
		t.Fatalf("closing the fact store: %v", cerr)
	}
	licences, err := licsqlite.Open(filepath.Join(storeRoot, "mirror.db"))
	if err != nil {
		t.Fatalf("opening the licence store: %v", err)
	}
	for _, r := range []struct{ spdx, artefact string }{{"", "directory="}, {"BSD-3-Clause", "published="}} {
		if perr := licences.PutLicenseRecord(ctx, licenceRecord(t, published, r.spdx, r.artefact)); perr != nil {
			t.Fatalf("seeding a licence record: %v", perr)
		}
	}
	if cerr := licences.Close(); cerr != nil {
		t.Fatalf("closing the licence store: %v", cerr)
	}

	queries, qcleanup, err := composition.NewQueries(storeRoot)
	if err != nil {
		t.Fatalf("NewQueries: %v", err)
	}
	defer mustClose(t, qcleanup)
	got, found, err := queries.License.GetLicenseRecord(ctx, published, licapp.PipelineVersion)
	if err != nil || !found || got.PrimarySPDX != "BSD-3-Clause" {
		t.Errorf("published licence = %q, found %v, err %v; want BSD-3-Clause with no conflict", got.PrimarySPDX, found, err)
	}
	history, err := queries.License.LicenseHistory(ctx, published, licapp.PipelineVersion)
	if err != nil || len(history) != 2 {
		t.Errorf("history = %d generations, %v; the ledger keeps both", len(history), err)
	}
}

// licenceRecord is a sealed licence record for coord derived from artefact.
func licenceRecord(t *testing.T, coord coordinate.ModuleCoordinate, spdx, artefact string) licdomain.LicenseRecord {
	t.Helper()
	status := licdomain.LicenseStatusDetected
	if spdx == "" {
		status = licdomain.LicenseStatusUnclassified
	}
	r := licdomain.LicenseRecord{
		SchemaVersion:     licdomain.LicenseSchemaVersion,
		Ecosystem:         fetchdomain.EcosystemGo,
		Coordinate:        coord,
		PrimarySPDX:       spdx,
		PrimaryConfidence: 0.95,
		OverallStatus:     status,
		ExtractedAt:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion:   licapp.PipelineVersion,
		ArtefactIdentity:  fetchtest.ZipArtefact(artefact).String(),
	}
	if spdx != "" {
		r.LicenseFiles = []licdomain.LicenseFileEntry{{Path: "LICENSE", SPDX: spdx, Confidence: 0.95, FileHash: "sha256:abc", FileSize: 1000}}
	}
	r, err := licdomain.LicenseRecordHasher{}.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return r
}
