package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	fetchsqlite "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// A fetch record written in a canonical shape this build cannot reproduce,
// through the real store and Run: readers compose over the rest and name it,
// a coordinate with nothing else is exit 4 for the commands that read its
// bytes, and an altered row is still the hash mismatch it always was.

// fetchAsideStore holds two measurements of jsonDocDep in jsonDocWalkID: a
// readable Verified one and a newer, weaker one respelt as another build would
// have stored it. With both set the readable one is respelt too; with alter set
// the newer one is instead altered after sealing.
func fetchAsideStore(t *testing.T, both, alter bool) (root, seal string) {
	t.Helper()
	root = asideStore(t, func(ctx context.Context, db sqlitestore.DB) {
		seedJSONDocWalk(t, ctx, db)
		store := fetchsqlite.New(db)
		var recs []fetchdomain.FactRecord
		for i, status := range []fetchdomain.VerificationStatus{fetchdomain.Verified, fetchdomain.VerifiedBySumDBOnly} {
			r := fetchtest.Record(t,
				fetchtest.Coordinate(jsonDocDep),
				fetchtest.PipelineVersion(fetchapp.PipelineVersion),
				fetchtest.Status(status),
				fetchtest.ModuleHash(fetchtest.H1(jsonDocHashValue(0, "zip"))),
				fetchtest.GoMod(jsonDocHashValue(0, "gomod")),
				fetchtest.FetchedAt(asideAt0.Add(time.Duration(i)*time.Hour)),
			)
			sealed, err := fetchdomain.Rehydrate(r)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.PutFetchRecord(ctx, sealed); err != nil {
				t.Fatalf("seeding the fetch record: %v", err)
			}
			recs = append(recs, r)
		}
		if alter {
			if _, err := db.DB().ExecContext(ctx, `UPDATE fetch_records SET verification_detail = 'rewritten' WHERE content_hash = ?`,
				recs[1].ContentHash); err != nil {
				t.Fatal(err)
			}
			return
		}
		seal = respellFetch(t, ctx, db, recs[1])
		if both {
			respellFetch(t, ctx, db, recs[0])
		}
	})
	return root, seal
}

func respellFetch(t *testing.T, ctx context.Context, db sqlitestore.DB, r fetchdomain.FactRecord) string {
	t.Helper()
	fetchedAt, seal := fetchtest.Respelt(t, r)
	if _, err := db.DB().ExecContext(ctx, `UPDATE fetch_records SET fetched_at = ?, content_hash = ? WHERE content_hash = ?`,
		fetchedAt, seal, r.ContentHash); err != nil {
		t.Fatal(err)
	}
	return seal
}

func TestFetchRecord_DriftedRecordSetAsideAndTheRestServed(t *testing.T) {
	root, seal := fetchAsideStore(t, false, false)

	// context names it inside its verification section, and nowhere else.
	stdout, stderr, err := runAside("context", jsonDocDep.String(), "--store-root", root)
	if err != nil {
		t.Fatalf("context = %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "Verification:    "+string(fetchdomain.Verified)+"\n") ||
		!strings.Contains(stdout, "Set aside:       "+jsonDocDep.String()+" content_hash "+seal) ||
		strings.Count(stdout+stderr, seal) != 1 {
		t.Errorf("context does not serve the readable record and name the other once:\n%s\n%s", stdout, stderr)
	}
	stdout, stderr, err = runAside("context", jsonDocDep.String(), "--json", "--store-root", root)
	if err != nil {
		t.Fatalf("context --json = %v\n%s", err, stderr)
	}
	var doc struct {
		Modules []struct {
			Verification struct {
				Status   string              `json:"status"`
				SetAside []map[string]string `json:"set_aside"`
			} `json:"verification"`
		} `json:"modules"`
	}
	if jerr := json.Unmarshal([]byte(stdout), &doc); jerr != nil || len(doc.Modules) != 1 {
		t.Fatalf("decoding: %v\n%s", jerr, stdout)
	}
	v := doc.Modules[0].Verification
	if v.Status != string(fetchdomain.Verified) || len(v.SetAside) != 1 || v.SetAside[0]["kind"] != fetchsqlite.RecordKind ||
		v.SetAside[0]["coordinate"] != jsonDocDep.String() || v.SetAside[0]["content_hash"] != seal ||
		v.SetAside[0]["reason"] != recordseal.SetAsideRemedy || strings.Contains(stderr, seal) {
		t.Errorf("verification = %+v, stderr %q; want the readable record with the other in set_aside", v, stderr)
	}

	// verification-coverage has no section for it: stderr on the text path, the
	// document under --json.
	stdout, stderr, err = runAside("verification-coverage", jsonDocWalkID, "--detail", "--store-root", root)
	if err != nil {
		t.Fatalf("verification-coverage = %v\n%s", err, stderr)
	}
	if strings.Count(stderr, seal) != 1 || !strings.Contains(stderr, "set aside "+fetchsqlite.RecordKind+" "+jsonDocDep.String()) ||
		!strings.Contains(stdout, "recorded status: "+string(fetchdomain.Verified)) {
		t.Errorf("verification-coverage does not serve the readable record and name the other once:\n%s\n%s", stdout, stderr)
	}
	stdout, stderr, err = runAside("verification-coverage", jsonDocWalkID, "--json", "--store-root", root)
	if err != nil {
		t.Fatalf("verification-coverage --json = %v\n%s", err, stderr)
	}
	var cov struct {
		SetAside []map[string]string `json:"set_aside"`
	}
	if jerr := json.Unmarshal([]byte(stdout), &cov); jerr != nil {
		t.Fatalf("decoding: %v\n%s", jerr, stdout)
	}
	if len(cov.SetAside) != 1 || cov.SetAside[0]["kind"] != fetchsqlite.RecordKind || cov.SetAside[0]["content_hash"] != seal ||
		strings.Contains(stderr, seal) {
		t.Errorf("set_aside = %+v, stderr %q; want the record in the document alone", cov.SetAside, stderr)
	}
}

func TestFetchRecord_EverythingSetAsideIsNotServable(t *testing.T) {
	root, seal := fetchAsideStore(t, true, false)

	// The commands that read a coordinate's fetched bytes; capability reads its
	// call graph record instead.
	for _, cmd := range []string{"callgraph", "license", "interface", "examples"} {
		t.Run(cmd, func(t *testing.T) {
			_, stderr, err := runAside(cmd, jsonDocDep.String(), "--store-root", root)
			assertNotServable(t, err, stderr, seal)
		})
	}

	stdout, stderr, err := runAside("context", jsonDocDep.String(), "--json", "--store-root", root)
	if err != nil {
		t.Fatalf("context --json = %v\n%s", err, stderr)
	}
	var doc struct {
		Modules []struct {
			Verification struct {
				Status, Error string
			} `json:"verification"`
		} `json:"modules"`
	}
	if jerr := json.Unmarshal([]byte(stdout), &doc); jerr != nil || len(doc.Modules) != 1 {
		t.Fatalf("decoding: %v\n%s", jerr, stdout)
	}
	if v := doc.Modules[0].Verification; v.Status != sectionStatusSetAside || !strings.Contains(v.Error, seal) {
		t.Errorf("verification = %+v, want set_aside naming %s", v, seal)
	}

	stdout, _, err = runAside("verification-coverage", jsonDocWalkID, "--detail", "--store-root", root)
	if err != nil || !strings.Contains(stdout, "every fetch record held for this module was set aside") {
		t.Errorf("verification-coverage = %v, want the module's reason to say it was set aside\n%s", err, stdout)
	}
}

// An altered fetch record is an integrity failure on every surface: exit 10
// with the integrity wording on the commands that read its bytes and on
// verification-coverage, the read error in context, and never set aside.
func TestFetchRecord_AlteredRecordIsAnIntegrityFailure(t *testing.T) {
	root, _ := fetchAsideStore(t, false, true)
	for _, cmd := range []string{"callgraph", "license", "interface", "examples"} {
		t.Run(cmd, func(t *testing.T) {
			_, stderr, err := runAside(cmd, jsonDocDep.String(), "--store-root", root)
			assertIntegrity(t, err, "fetch record integrity check failed")
			if strings.Contains(err.Error()+stderr, "set aside") {
				t.Errorf("an altered record was called set aside:\n%v\n%s", err, stderr)
			}
		})
	}
	_, _, err := runAside("verification-coverage", jsonDocWalkID, "--store-root", root)
	assertIntegrity(t, err, "fetch record integrity check failed")

	stdout, _, err := runAside("context", jsonDocDep.String(), "--json", "--store-root", root)
	if err != nil || !strings.Contains(stdout, `"status": "read_error"`) || !strings.Contains(stdout, "fetch record integrity check failed") {
		t.Errorf("context = %v, want the verification section to report the integrity failure\n%s", err, stdout)
	}
}

// audit states an altered fetch record as an integrity failure in its row and
// exits 10 once the table is out; a set-aside one reads (set aside) and an
// absent one (not fetched).
func TestAuditRow_FetchRecordIntegrityFailure(t *testing.T) {
	row := func(t *testing.T, root string) (auditModuleResult, error) {
		t.Helper()
		db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentRead)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		ctr := &Container{
			QueryFetch:   fetchapp.NewQueryFetchUseCase(fetchsqlite.New(db)),
			QueryLicense: testfakes.NewFakeQueryLicense(),
			QueryVuln:    testfakes.NewFakeQueryVuln(),
		}
		res, err := buildAuditResult(context.Background(), walkdomain.GraphNode{Coordinate: jsonDocDep}, vulnFrameAnchor{walkID: "walk-1"},
			"production", licdomain.NewLicenseOverrideSet(nil), nil, ctr, &bytes.Buffer{})
		if err != nil {
			t.Fatalf("buildAuditResult: %v", err)
		}
		return res, auditOutcomeErr([]auditModuleResult{res})
	}

	root, _ := fetchAsideStore(t, false, true)
	res, err := row(t, root)
	if res.Verification != "(integrity check failed)" {
		t.Errorf("Verification = %q, want (integrity check failed)", res.Verification)
	}
	assertIntegrity(t, err, "fetch record integrity check failed")

	root, _ = fetchAsideStore(t, true, false)
	// No licence is seeded, so the licence gate fires; the exit must not be the
	// integrity one.
	if res, err := row(t, root); res.Verification != "(set aside)" || ExitCodeForError(err) == ExitIntegrity {
		t.Errorf("every record set aside: Verification = %q, exit %v; want (set aside) and no integrity exit", res.Verification, err)
	}
	if res, err := row(t, asideStore(t, func(context.Context, sqlitestore.DB) {})); res.Verification != "(not fetched)" || ExitCodeForError(err) == ExitIntegrity {
		t.Errorf("no record: Verification = %q, exit %v; want (not fetched)", res.Verification, err)
	}
}

// divergentStore holds two measurements of jsonDocDep in jsonDocWalkID that
// disagree on the module hash.
func divergentStore(t *testing.T) string {
	t.Helper()
	return asideStore(t, func(ctx context.Context, db sqlitestore.DB) {
		seedJSONDocWalk(t, ctx, db)
		for i, zip := range []string{"zip-a", "zip-b"} {
			sealed := fetchtest.Sealed(t,
				fetchtest.Coordinate(jsonDocDep),
				fetchtest.PipelineVersion(fetchapp.PipelineVersion),
				fetchtest.Status(fetchdomain.Verified),
				fetchtest.ModuleHash(fetchtest.H1(jsonDocHashValue(i, zip))),
				fetchtest.GoMod(jsonDocHashValue(0, "gomod")),
				fetchtest.FetchedAt(asideAt0.Add(time.Duration(i)*time.Hour)),
			)
			if err := fetchsqlite.New(db).PutFetchRecord(ctx, sealed); err != nil {
				t.Fatalf("seeding the fetch record: %v", err)
			}
		}
	})
}

// Records that disagree are stated as divergent on every inspection surface:
// their own coverage class and count, outside unrecorded, at exit 0; their own
// audit cell; their own context status.
func TestFetchRecord_DivergentRecordsAreNotAbsent(t *testing.T) {
	root := divergentStore(t)

	stdout, stderr, err := runAside("verification-coverage", jsonDocWalkID, "--json", "--store-root", root)
	if err != nil {
		t.Fatalf("verification-coverage --json = %v\n%s", err, stderr)
	}
	var cov struct {
		Unrecorded, Divergent int
		Modules               []struct{ Coordinate, Class, Reason string }
	}
	if jerr := json.Unmarshal([]byte(stdout), &cov); jerr != nil {
		t.Fatalf("decoding: %v\n%s", jerr, stdout)
	}
	// The walk's root has no fetch record; it alone is unrecorded.
	if cov.Divergent != 1 || cov.Unrecorded != 1 {
		t.Errorf("divergent = %d, unrecorded = %d; want 1 and 1 (the root alone)", cov.Divergent, cov.Unrecorded)
	}
	for _, m := range cov.Modules {
		if m.Coordinate == jsonDocDep.String() &&
			(m.Class != fetchdomain.BucketDivergent.String() || !strings.Contains(m.Reason, "module_hash disagrees")) {
			t.Errorf("module row = %+v, want the divergent class with the disagreement", m)
		}
	}
	stdout, _, err = runAside("verification-coverage", jsonDocWalkID, "--store-root", root)
	divergentLine := regexp.MustCompile(`divergent fetch records\s+1\s`)
	unrecordedLine := regexp.MustCompile(`no fetch record\s+1\s`)
	if err != nil || !divergentLine.MatchString(stdout) || !unrecordedLine.MatchString(stdout) {
		t.Errorf("verification-coverage = %v, want one divergent and one unrecorded module\n%s", err, stdout)
	}

	stdout, _, err = runAside("context", jsonDocDep.String(), "--json", "--store-root", root)
	if err != nil || !strings.Contains(stdout, `"status": "divergent"`) || !strings.Contains(stdout, "module_hash disagrees") {
		t.Errorf("context = %v, want verification status divergent with the disagreement\n%s", err, stdout)
	}

	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentRead)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	ctr := &Container{
		QueryFetch:   fetchapp.NewQueryFetchUseCase(fetchsqlite.New(db)),
		QueryLicense: testfakes.NewFakeQueryLicense(),
		QueryVuln:    testfakes.NewFakeQueryVuln(),
	}
	res, err := buildAuditResult(context.Background(), walkdomain.GraphNode{Coordinate: jsonDocDep}, vulnFrameAnchor{walkID: "walk-1"},
		"production", licdomain.NewLicenseOverrideSet(nil), nil, ctr, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("buildAuditResult: %v", err)
	}
	if res.Verification != "(divergent fetch records)" || res.coverage.Bucket != fetchdomain.BucketDivergent || !res.coverage.Recorded {
		t.Errorf("audit row = %q, coverage %+v; want (divergent fetch records) counted apart", res.Verification, res.coverage)
	}
	if code := ExitCodeForError(auditOutcomeErr([]auditModuleResult{res})); code == ExitIntegrity {
		t.Errorf("a divergence made audit exit %d; its exit contribution is unchanged", code)
	}
}
