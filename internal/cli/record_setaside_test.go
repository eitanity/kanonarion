package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	stdlibsqlite "github.com/eitanity/kanonarion/internal/stdlib/adapters/store/sqlite"
	stdlibdomain "github.com/eitanity/kanonarion/internal/stdlib/domain"
	vulnsqlite "github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
	walksqlite "github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
)

// A walk, an extraction run, a scan run or a stdlib custody measurement written
// in a canonical shape this build cannot reproduce: a single read refuses at
// exit 4 with the statement, a listing keeps the rest and names it, and one
// altered byte is still exit 10. Through the real stores and Run.

// widenStoredRow rewrites the row of table whose idCol is id as a build with one
// more top-level field would have written it, resealed over those bytes; mutate,
// when set, then alters the bytes. hashCol, when set, is refiled under the new
// seal. It returns the new seal.
func widenStoredRow(t *testing.T, ctx context.Context, db sqlitestore.DB, table, blobCol, hashCol, idCol, id string,
	compressed bool, mutate func([]byte) []byte,
) string {
	t.Helper()
	var blob []byte
	if err := db.DB().QueryRowContext(ctx, `SELECT `+blobCol+` FROM `+table+` WHERE `+idCol+` = ?`, id).Scan(&blob); err != nil {
		t.Fatalf("reading %s %s: %v", table, id, err)
	}
	if compressed {
		raw, err := blobcodec.Decode(blob)
		if err != nil {
			t.Fatal(err)
		}
		blob = raw
	}
	var head struct {
		ContentHash string `json:"content_hash"`
	}
	if err := json.Unmarshal(blob, &head); err != nil {
		t.Fatal(err)
	}
	widened, seal := widenSealed(t, blob, head.ContentHash)
	if mutate != nil {
		widened = mutate(widened)
	}
	if compressed {
		widened = blobcodec.Encode(widened)
	}
	q, args := `UPDATE `+table+` SET `+blobCol+` = ? WHERE `+idCol+` = ?`, []any{widened, id}
	if hashCol != "" {
		q, args = `UPDATE `+table+` SET `+blobCol+` = ?, `+hashCol+` = ? WHERE `+idCol+` = ?`, []any{widened, seal, id}
	}
	if _, err := db.DB().ExecContext(ctx, q, args...); err != nil {
		t.Fatalf("installing the widened %s row: %v", table, err)
	}
	return seal
}

// assertNotServable checks a refusal is exit 4 with the direction-neutral
// statement naming seal, and nothing that reads as tampering.
func assertNotServable(t *testing.T, err error, stderr, seal string) {
	t.Helper()
	if code := ExitCodeForError(err); code != ExitNotFound {
		t.Fatalf("exit %d (%v), want %d", code, err, ExitNotFound)
	}
	for _, want := range []string{"that this build can serve", seal, recordseal.SetAsideRemedy} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not state %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "integrity") || strings.Contains(stderr, seal) {
		t.Errorf("refusal reads as tampering or names the record twice:\n%v\n%s", err, stderr)
	}
}

func assertIntegrity(t *testing.T, err error, wording string) {
	t.Helper()
	if code := ExitCodeForError(err); code != ExitIntegrity {
		t.Fatalf("exit %d (%v), want %d", code, err, ExitIntegrity)
	}
	if !strings.Contains(err.Error(), wording) {
		t.Errorf("refusal %q does not say %q", err, wording)
	}
}

func walkAsideStore(t *testing.T, mutate func([]byte) []byte) (root, seal string) {
	t.Helper()
	root = asideStore(t, func(ctx context.Context, db sqlitestore.DB) {
		seedJSONDocWalk(t, ctx, db)
		seedJSONDocSecondWalk(t, ctx, db)
		seal = widenStoredRow(t, ctx, db, "walks", "serialised", "content_hash", "id", jsonDocWalkID, true, mutate)
	})
	return root, seal
}

func TestWalk_DriftedWalkIsNotServable(t *testing.T) {
	root, seal := walkAsideStore(t, nil)

	for _, args := range [][]string{
		{"walk-show", jsonDocWalkID},
		{"walk-show", jsonDocWalkID, "--json"},
		{"walk-list", "--walk-id", jsonDocWalkID},
		{"walk-diff", jsonDocWalkID, jsonDocWalkID2},
		{"extract", "show", "absent"}, // control: unrelated to the walk
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			_, stderr, err := runAside(append(args, "--store-root", root)...)
			if args[0] == "extract" {
				if strings.Contains(stderr, seal) {
					t.Errorf("a command that never read the walk named it:\n%s", stderr)
				}
				return
			}
			assertNotServable(t, err, stderr, seal)
		})
	}

	// The listing reads its columns, not the record, so it keeps every walk.
	stdout, stderr, err := runAside("walk-list", "--store-root", root)
	if err != nil || !strings.Contains(stdout, jsonDocWalkID) || !strings.Contains(stdout, jsonDocWalkID2) {
		t.Errorf("walk-list = %v, want both walks listed\n%s\n%s", err, stdout, stderr)
	}
}

func TestWalk_AlteredWalkIsStillIntegrity(t *testing.T) {
	root, _ := walkAsideStore(t, flipRetiredByte)
	_, _, err := runAside("walk-show", jsonDocWalkID, "--store-root", root)
	assertIntegrity(t, err, "failed integrity check")
}

func extractAsideStore(t *testing.T, mutate func([]byte) []byte) (root, seal string) {
	t.Helper()
	root = asideStore(t, func(ctx context.Context, db sqlitestore.DB) {
		seedJSONDocExtractionRun(t, ctx, db)
		seal = widenStoredRow(t, ctx, db, "extraction_runs", "raw_record", "", "id", jsonDocExtractID, false, mutate)
	})
	return root, seal
}

func TestExtractShow_DriftedRunIsNotServable(t *testing.T) {
	root, seal := extractAsideStore(t, nil)
	_, stderr, err := runAside("extract", "show", jsonDocExtractID, "--store-root", root)
	assertNotServable(t, err, stderr, seal)

	// The listing reads its columns, so the run stays listed.
	stdout, _, err := runAside("extract", "list", "--store-root", root)
	if err != nil || !strings.Contains(stdout, jsonDocExtractID) {
		t.Errorf("extract-list = %v, want the run listed\n%s", err, stdout)
	}
}

func TestExtractShow_AlteredRunIsStillIntegrity(t *testing.T) {
	root, _ := extractAsideStore(t, flipRetiredByte)
	_, _, err := runAside("extract", "show", jsonDocExtractID, "--store-root", root)
	assertIntegrity(t, err, "extraction run integrity check failed")
}

const asideRunID2 = "01JS0NGARD0000000000000RN2"

// scanAsideStore holds two runs of one walk; the first is rewritten in a
// widened shape (mutated, if mutate is set).
func scanAsideStore(t *testing.T, mutate func([]byte) []byte) (root, seal string) {
	t.Helper()
	root = asideStore(t, func(ctx context.Context, db sqlitestore.DB) {
		seedJSONDocWalk(t, ctx, db)
		seedJSONDocVulnerabilities(t, ctx, db)
		store := vulnsqlite.New(db)
		first, found, err := store.GetWalkScanRun(ctx, jsonDocScanRunID)
		if err != nil || !found {
			t.Fatalf("reading the seeded run: %v", err)
		}
		second := first
		second.ID, second.ContentHash = asideRunID2, ""
		second.StartedAt, second.CompletedAt = first.StartedAt.Add(time.Hour), first.CompletedAt.Add(time.Hour)
		second, err = vulndomain.WalkScanRunHasher{}.SetContentHash(second)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.PutWalkScanRun(ctx, second); err != nil {
			t.Fatalf("seeding the second run: %v", err)
		}
		seal = widenStoredRow(t, ctx, db, "walk_scan_runs", "serialised", "content_hash", "id", jsonDocScanRunID, false, mutate)
	})
	return root, seal
}

func TestVulnScanShow_DriftedRunIsNotServable(t *testing.T) {
	root, seal := scanAsideStore(t, nil)
	_, stderr, err := runAside("vuln-scan-show", jsonDocScanRunID, "--store-root", root)
	assertNotServable(t, err, stderr, seal)

	_, stderr, err = runAside("vuln-scan-diff", jsonDocScanRunID, asideRunID2, "--store-root", root)
	assertNotServable(t, err, stderr, seal)
}

func TestVulnScanList_DriftedRunSetAsideAndListingKept(t *testing.T) {
	root, seal := scanAsideStore(t, nil)

	stdout, stderr, err := runAside("vuln-scan-list", "--store-root", root)
	if err != nil {
		t.Fatalf("vuln-scan-list = %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, asideRunID2) || strings.Contains(stdout, jsonDocScanRunID) {
		t.Errorf("stdout does not list the readable run alone:\n%s", stdout)
	}
	if strings.Count(stderr, seal) != 1 || !strings.Contains(stderr, "set aside walk scan run "+jsonDocScanRunID) ||
		!strings.Contains(stderr, recordseal.SetAsideRemedy) {
		t.Errorf("stderr does not name the run once with the remedy:\n%s", stderr)
	}

	stdout, stderr, err = runAside("vuln-scan-list", "--json", "--store-root", root)
	if err != nil {
		t.Fatalf("vuln-scan-list --json = %v\n%s", err, stderr)
	}
	var doc struct {
		SetAside []map[string]string `json:"set_aside"`
	}
	if jerr := json.Unmarshal([]byte(stdout), &doc); jerr != nil {
		t.Fatalf("decoding: %v\n%s", jerr, stdout)
	}
	if len(doc.SetAside) != 1 || doc.SetAside[0]["kind"] != vulnports.SetAsideKindRun ||
		doc.SetAside[0]["id"] != jsonDocScanRunID || doc.SetAside[0]["content_hash"] != seal ||
		doc.SetAside[0]["coordinate"] != "" {
		t.Errorf("set_aside = %+v, want the run by kind, id and seal", doc.SetAside)
	}
	if strings.Contains(stderr, seal) {
		t.Errorf("stderr repeats what the document carries:\n%s", stderr)
	}
}

// Tamper control: an altered run is still an integrity failure for a command
// that consumes it.
func TestVulnScanDiff_AlteredRunIsStillIntegrity(t *testing.T) {
	root, _ := scanAsideStore(t, flipRetiredByte)
	_, _, err := runAside("vuln-scan-diff", jsonDocScanRunID, asideRunID2, "--store-root", root)
	assertIntegrity(t, err, "integrity check failed")
}

// stdlibAsideStore holds two custody measurements of go1.26.4; the newer, and
// with both set the older too, is respelt at sub-second precision and resealed,
// which this build cannot reproduce. alter instead changes a value after sealing.
func stdlibAsideStore(t *testing.T, both, alter bool) (root, seal string) {
	t.Helper()
	root = asideStore(t, func(ctx context.Context, db sqlitestore.DB) {
		store := stdlibsqlite.New(db)
		var facts []stdlibdomain.Facts
		for i, spdx := range []string{"BSD-3-Clause", "MIT"} {
			f, err := stdlibdomain.FactsHasher{}.SetContentHash(stdlibdomain.Facts{
				GoVersion: "go1.26.4", AcquisitionRoute: stdlibdomain.RouteGoDev,
				Digests:            fetchdomain.ArtifactDigests{SHA256: "s256", SHA384: "s384", SHA512: "s512"},
				VerificationStatus: stdlibdomain.VerifiedGoDevChecksum, LicenseSPDX: spdx,
				AcquiredAt: asideAt0.Add(time.Duration(i) * time.Hour),
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Put(ctx, f); err != nil {
				t.Fatalf("seeding custody: %v", err)
			}
			facts = append(facts, f)
		}
		if alter {
			if _, err := db.DB().ExecContext(ctx, `UPDATE stdlib_facts SET license_spdx = 'MIU' WHERE license_spdx = 'MIT'`); err != nil {
				t.Fatal(err)
			}
			return
		}
		seal = respellCustody(t, ctx, db, facts[1])
		if both {
			respellCustody(t, ctx, db, facts[0])
		}
	})
	return root, seal
}

func respellCustody(t *testing.T, ctx context.Context, db sqlitestore.DB, f stdlibdomain.Facts) string {
	t.Helper()
	unsealed := f
	unsealed.ContentHash = ""
	raw, err := stdlibdomain.FactsHasher{}.Marshal(unsealed)
	if err != nil {
		t.Fatal(err)
	}
	stored := f.AcquiredAt.UTC().Format(time.RFC3339)
	respelt := strings.TrimSuffix(stored, "Z") + ".5Z"
	sum := sha256.Sum256(bytes.Replace(raw, []byte(stored), []byte(respelt), 1))
	seal := "sha256:" + hex.EncodeToString(sum[:])
	if _, err := db.DB().ExecContext(ctx, `UPDATE stdlib_facts SET acquired_at = ?, content_hash = ? WHERE content_hash = ?`,
		respelt, seal, f.ContentHash); err != nil {
		t.Fatal(err)
	}
	return seal
}

func TestStdlibCustody_DriftedMeasurementSetAside(t *testing.T) {
	root, seal := stdlibAsideStore(t, false, false)

	stdout, stderr, err := runAside("license", "stdlib@v1.26.4", "--history", "--store-root", root)
	if err != nil {
		t.Fatalf("license --history = %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "1 custody measurement(s)") || !strings.Contains(stdout, "BSD-3-Clause") {
		t.Errorf("stdout does not serve the readable measurement alone:\n%s", stdout)
	}
	if strings.Count(stderr, seal) != 1 || !strings.Contains(stderr, "set aside "+stdlibsqlite.RecordKind+" go1.26.4") {
		t.Errorf("stderr does not name the measurement once:\n%s", stderr)
	}

	root, seal = stdlibAsideStore(t, true, false)
	_, stderr, err = runAside("license", "stdlib@v1.26.4", "--store-root", root)
	assertNotServable(t, err, stderr, seal)
}

func TestStdlibCustody_AlteredMeasurementIsStillIntegrity(t *testing.T) {
	root, _ := stdlibAsideStore(t, false, true)
	_, _, err := runAside("license", "stdlib@v1.26.4", "--store-root", root)
	assertIntegrity(t, err, "stdlib facts integrity check failed")
}

// Every set_aside entry states its kind, and an identity that is not a module
// coordinate is stated as id, so a document drawing on several stores tells
// its rows apart.
func TestSetAsideJSON_StatesKindAndIdentityKey(t *testing.T) {
	rows := setAsideRows{
		{Kind: "licence record", ID: "example.com/m@v1.0.0", ContentHash: "sha256:aa"},
		{Kind: walksqlite.RecordKind, ID: "01WALK", ContentHash: "sha256:bb"},
		{Kind: vulnports.SetAsideKindRun, ID: "01RUN", ContentHash: "sha256:cc"},
		{Kind: stdlibsqlite.RecordKind, ID: "go1.26.4", ContentHash: "sha256:dd"},
	}
	raw, err := json.Marshal(rows.json())
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	want := []map[string]string{
		{"kind": "licence record", "coordinate": "example.com/m@v1.0.0"},
		{"kind": walksqlite.RecordKind, "id": "01WALK"},
		{"kind": vulnports.SetAsideKindRun, "id": "01RUN"},
		{"kind": stdlibsqlite.RecordKind, "id": "go1.26.4"},
	}
	for i, w := range want {
		for k, v := range w {
			if got[i][k] != v {
				t.Errorf("row %d %s = %q, want %q (%v)", i, k, got[i][k], v, got[i])
			}
		}
		if _, both := got[i]["id"]; both && got[i]["coordinate"] != "" {
			t.Errorf("row %d states both id and coordinate: %v", i, got[i])
		}
	}
	empty, _ := json.Marshal(setAsideRows{{}}.json())
	if !strings.Contains(string(empty), `"kind":""`) {
		t.Errorf("an unnamed kind is omitted: %s", empty)
	}
}

// A command that only decorates its answer with the walk degrades without it,
// and the walk is still named on stderr rather than dropped unseen.
func TestWalk_DriftedWalkNamedWhenACommandDegradesWithoutIt(t *testing.T) {
	var seal string
	root := asideStore(t, func(ctx context.Context, db sqlitestore.DB) {
		seedJSONDocWalk(t, ctx, db)
		seedJSONDocVulnerabilities(t, ctx, db)
		seal = widenStoredRow(t, ctx, db, "walks", "serialised", "content_hash", "id", jsonDocWalkID, true, nil)
	})
	_, stderr, err := runAside("vuln-scan-show", jsonDocScanRunID, "--store-root", root)
	if code := ExitCodeForError(err); code == ExitIntegrity || code == ExitNotFound {
		t.Fatalf("vuln-scan-show exit %d (%v), want the run shown", code, err)
	}
	if strings.Count(stderr, seal) != 1 || !strings.Contains(stderr, "set aside walk record "+jsonDocWalkID) {
		t.Errorf("stderr does not name the walk once:\n%s", stderr)
	}
}

// A store whose only run was set aside holds a run: the surveys name it and do
// not say the store or the walk has none.
func TestVulnScanList_OnlySetAsideRunsIsNotAZero(t *testing.T) {
	var seal string
	root := asideStore(t, func(ctx context.Context, db sqlitestore.DB) {
		seedJSONDocWalk(t, ctx, db)
		seedJSONDocVulnerabilities(t, ctx, db)
		seal = widenStoredRow(t, ctx, db, "walk_scan_runs", "serialised", "content_hash", "id", jsonDocScanRunID, false, nil)
	})
	for _, args := range [][]string{
		{"vuln-scan-list"}, {"vuln-scan-list", "--json"}, {"vuln-scan-list", jsonDocWalkID},
		{"vuln-scan-history", jsonDocWalkID}, {"vuln-scan-show", "01JS0NGARD0000000000000ZZZ", "--json"},
	} {
		stdout, stderr, err := runAside(append(args, "--store-root", root)...)
		all := stdout + stderr
		if err != nil {
			all += err.Error()
		}
		for _, claim := range []string{"holds no scan run", "no scan runs found", `"store_empty": true`, `"zero_result"`, "0 scan run"} {
			if strings.Contains(all, claim) {
				t.Errorf("%v claims %q over a store holding a set-aside run:\n%s", args, claim, all)
			}
		}
		if !strings.Contains(all, seal) {
			t.Errorf("%v does not name the set-aside run:\n%s", args, all)
		}
	}
}

// The same holds for every listing the collector serves: a licence listing
// whose only record was set aside does not say the store holds none.
func TestLicenceList_OnlySetAsideRecordsIsNotAZero(t *testing.T) {
	var seal string
	root := asideStore(t, func(ctx context.Context, db sqlitestore.DB) {
		seal = putLicence(t, ctx, db, asideLicence(t, asideGone, "MIT", 0.99, asideAt0), true, nil)
	})
	for _, args := range [][]string{{"license-list"}, {"license-list", "--json"}} {
		stdout, stderr, err := runAside(append(args, "--store-root", root)...)
		if err != nil {
			t.Fatalf("%v = %v", args, err)
		}
		if strings.Contains(stdout, "holds no license record") || strings.Contains(stdout, `"zero_result"`) {
			t.Errorf("%v claims a zero over a store holding a set-aside record:\n%s", args, stdout)
		}
		if !strings.Contains(stdout+stderr, seal) {
			t.Errorf("%v does not name the set-aside record:\n%s\n%s", args, stdout, stderr)
		}
	}
}
