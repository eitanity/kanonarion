package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/adapters/sqlitestore"
	"code.eitanity.com/kanonarion/internal/cli/testfakes"
	"code.eitanity.com/kanonarion/internal/coordinate"
	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
	"code.eitanity.com/kanonarion/internal/gotoolchain"
	licdomain "code.eitanity.com/kanonarion/internal/license/domain"
	vulnsqlite "code.eitanity.com/kanonarion/internal/vuln/adapters/store/sqlite"
	vulndomain "code.eitanity.com/kanonarion/internal/vuln/domain"
	"code.eitanity.com/kanonarion/internal/vuln/vulntest"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// disputeDroppedID is the advisory the second scan of the walk did not report.
const disputeDroppedID = "GO-2026-0002"

// disputeStore is one project walk scanned twice against one snapshot, under
// one toolchain and in one frame, the second scan dropping an advisory: the
// non-deterministic re-scan, written through the store's own write path.
func disputeStore(t *testing.T) (storeRoot, treeDir string, recs [2]vulndomain.VulnerabilityRecord) {
	t.Helper()
	return twoScanStore(t, "v2026-03-03", "v2026-03-03")
}

// retiredStore is the same two scans against two snapshots, the newer dropping
// the advisory: a retirement, which vuln-show serves.
func retiredStore(t *testing.T) (storeRoot, treeDir string, recs [2]vulndomain.VulnerabilityRecord) {
	t.Helper()
	return twoScanStore(t, "v2026-03-03", "v2026-03-10")
}

// twoScanStore writes one project walk and two scan runs of it, the first
// reporting two advisories under snapshot first and the second one of them
// under snapshot second.
func twoScanStore(t *testing.T, first, second string) (storeRoot, treeDir string, recs [2]vulndomain.VulnerabilityRecord) {
	t.Helper()
	storeRoot, treeDir, host := upgradeStoreHost(t)
	ctx := context.Background()
	db, err := sqlitestore.Open(filepath.Join(storeRoot, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening the fixture store: %v", err)
	}
	defer func() { _ = db.Close() }()
	if aerr := sqlitestore.Apply(db, allMigrations()); aerr != nil {
		t.Fatalf("migrating the fixture store: %v", aerr)
	}
	root, err := coordinate.NewLocalCoordinate(jsonDocRootPath)
	if err != nil {
		t.Fatal(err)
	}
	seedProjectWalk(t, ctx, db, root, host, treeDir, seedWalkSpec{walkID: seedNewWalkID, toolchain: host.toolchain, at: jsonDocAt})

	store := vulnsqlite.New(db)
	scans := []struct {
		runID, snapV string
		ids          []string
	}{
		{seedOldRunID, first, []string{jsonDocFindingID, disputeDroppedID}},
		{seedNewRunID, second, []string{jsonDocFindingID}},
	}
	for i, s := range scans {
		at := jsonDocAt.Add(time.Duration(i+1) * time.Hour)
		snapshot := vulntest.MustNewAt(jsonDocSnapSource, s.snapV, jsonDocAt.Add(time.Duration(i)*time.Minute))
		if perr := store.PutDatabaseSnapshot(ctx, snapshot, strings.NewReader("advisory snapshot "+s.snapV)); perr != nil {
			t.Fatalf("seeding the snapshot: %v", perr)
		}
		rec := vulndomain.VulnerabilityRecord{
			Ecosystem: fetchdomain.EcosystemGo, Coordinate: jsonDocDep, WalkID: seedNewWalkID,
			OverallStatus: vulndomain.StatusAffected, DatabaseSnapshot: snapshot, ScannedAt: at,
			PipelineVersion: pipelineOr(""), Rooting: frameOf(root), Toolchain: gotoolchain.Version(host.toolchain),
		}
		for _, id := range s.ids {
			rec.Findings = append(rec.Findings, vulndomain.VulnerabilityFinding{
				ID: id, Summary: "a seeded finding", AffectedRange: "< v1.3.0", FixedIn: "v1.3.0",
			})
		}
		if rec, err = (vulndomain.VulnerabilityRecordHasher{}).SetContentHash(rec); err != nil {
			t.Fatal(err)
		}
		if perr := store.PutVulnerabilityRecord(ctx, rec); perr != nil {
			t.Fatalf("appending scan %d: %v", i, perr)
		}
		run := vulndomain.WalkScanRun{
			ID: s.runID, WalkID: seedNewWalkID, Snapshot: snapshot,
			PerModuleResults: map[coordinate.ModuleCoordinate]string{jsonDocDep: rec.ContentHash},
			StartedAt:        at, CompletedAt: at.Add(time.Second),
			OverallStatus: vulndomain.WalkStatusAffected, Operator: "guard", PipelineVersion: pipelineOr(""),
		}
		if run, err = (vulndomain.WalkScanRunHasher{}).SetContentHash(run); err != nil {
			t.Fatal(err)
		}
		if perr := store.PutWalkScanRun(ctx, run); perr != nil {
			t.Fatalf("seeding run %d: %v", i, perr)
		}
		recs[i] = rec
	}
	return storeRoot, treeDir, recs
}

// Every composed read of a disputed coordinate exits 10 and names both records
// and the --history read; the by-advisory read reaches the module through the
// advisory the newer scan dropped, where it answered "no modules affected".
func TestVulnConflict_EveryComposedReadExits10(t *testing.T) {
	fixture, treeDir, recs := disputeStore(t)
	gomod := filepath.Join(treeDir, "go.mod")
	for _, args := range [][]string{
		{"vuln-show", jsonDocDepCoord},
		{"vuln-show", jsonDocDepCoord, "--json"},
		{"vuln-show", jsonDocDepCoord, "--walk-id", seedNewWalkID},
		{"vuln-show", jsonDocDepCoord, "--gomod", gomod},
		{"reachability", jsonDocDepCoord, "--vuln", disputeDroppedID},
		{"reachability", jsonDocDepCoord, "--vuln", disputeDroppedID, "--gomod", gomod},
		{"vuln-by-id", disputeDroppedID},
		{"vuln-by-id", jsonDocFindingID},
		{"vuln-by-id", disputeDroppedID, "--walk-id", seedNewWalkID},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout, stderr, err := runAside(append(args, "--store-root", fixture)...)
			if code := ExitCodeForError(err); code != ExitIntegrity {
				t.Fatalf("exit %d (%v), want %d\nstdout:\n%s\nstderr:\n%s", code, err, ExitIntegrity, stdout, stderr)
			}
			msg := err.Error()
			for _, want := range []string{
				"conflicting vulnerability records for " + jsonDocDepCoord,
				recs[0].ContentHash, recs[1].ContentHash,
				"kanonarion vuln-show " + jsonDocDepCoord + " --history",
			} {
				if !strings.Contains(msg, want) {
					t.Errorf("refusal does not name %q:\n%s", want, msg)
				}
			}
		})
	}
}

// --history is how a dispute is read: it lists both generations and exits 0.
func TestVulnConflict_HistoryListsBoth(t *testing.T) {
	fixture, _, recs := disputeStore(t)
	stdout, stderr, err := runAside("vuln-show", jsonDocDepCoord, "--history", "--json", "--store-root", fixture)
	if err != nil {
		t.Fatalf("exit %d: %v\n%s", ExitCodeForError(err), err, stderr)
	}
	for _, r := range recs {
		if !strings.Contains(stdout, r.ContentHash) {
			t.Errorf("history does not list %s:\n%s", r.ContentHash, stdout)
		}
	}
}

// context states the dispute as its vulnerability section's status rather than
// failing the document.
func TestVulnConflict_ContextSectionIsConflict(t *testing.T) {
	fixture, _, recs := disputeStore(t)
	stdout, stderr, err := runAside("context", jsonDocDepCoord, "--json", "--store-root", fixture)
	if ExitCodeForError(err) == ExitIntegrity {
		t.Fatalf("context failed the document on the dispute: %v\n%s", err, stderr)
	}
	var doc struct {
		Modules []struct {
			Vulnerabilities struct {
				Status string `json:"status"`
				Error  string `json:"error"`
			} `json:"vulnerabilities"`
		} `json:"modules"`
	}
	if jerr := json.Unmarshal([]byte(stdout), &doc); jerr != nil || len(doc.Modules) != 1 {
		t.Fatalf("decoding the document: %v\n%s", jerr, stdout)
	}
	v := doc.Modules[0].Vulnerabilities
	if v.Status != sectionStatusConflict {
		t.Fatalf("vulnerabilities.status = %q, want %q", v.Status, sectionStatusConflict)
	}
	for _, r := range recs {
		if !strings.Contains(v.Error, r.ContentHash) {
			t.Errorf("the section's statement does not name %s: %s", r.ContentHash, v.Error)
		}
	}

	for _, args := range [][]string{{"context", jsonDocDepCoord}, {"context", jsonDocDepCoord, "--full"}} {
		text, _, rerr := runAside(append(args, "--store-root", fixture)...)
		if ExitCodeForError(rerr) == ExitIntegrity {
			t.Errorf("%v failed the document on the dispute: %v", args, rerr)
		}
		if !strings.Contains(text, "conflicting vulnerability records for "+jsonDocDepCoord) || strings.Contains(text, "(failed:") {
			t.Errorf("%v does not state the dispute as such:\n%s", args, text)
		}
	}
}

// audit marks the row and exits 10 once the table is out.
func TestVulnConflict_AuditRowExits10(t *testing.T) {
	_, _, recs := disputeStore(t)
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecords(jsonDocDep, recs[0], recs[1])
	ctr := &Container{QueryFetch: unfetchedQueryFetch{}, QueryLicense: testfakes.NewFakeQueryLicense(), QueryVuln: uc}
	root, err := coordinate.NewLocalCoordinate(jsonDocRootPath)
	if err != nil {
		t.Fatal(err)
	}
	anchor := walkFrameAnchor(seedNewWalkID, root)
	row, err := buildAuditResult(t.Context(), walkdomain.GraphNode{Coordinate: jsonDocDep}, anchor,
		"production", licdomain.NewLicenseOverrideSet(nil), nil, ctr, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("buildAuditResult: %v", err)
	}
	if row.VulnStatus != auditRecordsConflict || !strings.Contains(row.VulnReason, recs[1].ContentHash) {
		t.Errorf("row = %q (%s), want it marked as conflicting", row.VulnStatus, row.VulnReason)
	}
	if code := ExitCodeForError(auditOutcomeErr([]auditModuleResult{row}, auditDerivation{})); code != ExitIntegrity {
		t.Errorf("exit %d, want %d", code, ExitIntegrity)
	}
}

// A retirement across snapshots: vuln-by-id answers from the record vuln-show
// serves, so the advisory the newer snapshot dropped lists no module, unscoped
// or in the walk; --timeline still shows the module and the retirement.
func TestVulnRetired_VulnByIDAgreesWithTheServedRecord(t *testing.T) {
	fixture, _, recs := retiredStore(t)
	show, _, err := runAside("vuln-show", jsonDocDepCoord, "--json", "--store-root", fixture)
	if err != nil || !strings.Contains(show, recs[1].ContentHash) || strings.Contains(show, disputeDroppedID) {
		t.Fatalf("vuln-show does not serve the newer record without %s (%v):\n%s", disputeDroppedID, err, show)
	}
	for _, args := range [][]string{
		{"vuln-by-id", disputeDroppedID},
		{"vuln-by-id", disputeDroppedID, "--walk-id", seedNewWalkID},
	} {
		stdout, stderr, rerr := runAside(append(args, "--store-root", fixture)...)
		if rerr != nil {
			t.Fatalf("%v: exit %d: %v\n%s", args, ExitCodeForError(rerr), rerr, stderr)
		}
		if strings.Contains(stdout, jsonDocDepCoord) || !strings.Contains(stdout, "affected by "+disputeDroppedID) {
			t.Errorf("%v lists a module whose served record does not report the advisory:\n%s", args, stdout)
		}
	}
	kept, _, err := runAside("vuln-by-id", jsonDocFindingID, "--json", "--store-root", fixture)
	if err != nil || !strings.Contains(kept, recs[1].ContentHash) {
		t.Errorf("vuln-by-id %s does not list the served record (%v):\n%s", jsonDocFindingID, err, kept)
	}
	timeline, stderr, err := runAside("vuln-by-id", disputeDroppedID, "--timeline", "--store-root", fixture)
	if err != nil || !strings.Contains(timeline, jsonDocDepCoord) {
		t.Errorf("--timeline lost the retired module (%v):\n%s\n%s", err, timeline, stderr)
	}
}
