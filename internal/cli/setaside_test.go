package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	vulnsqlite "github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	vulnapp "github.com/eitanity/kanonarion/internal/vuln/application"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// These run vuln-show over a real store holding a generation this build cannot
// reproduce, so the path from the stored row to the exit code is the one the
// binary takes.

func setAsideTestRecord(t *testing.T, at time.Time, id string) vuldomain.VulnerabilityRecord {
	t.Helper()
	rec, err := vuldomain.VulnerabilityRecordHasher{}.SetContentHash(vuldomain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       mustVulnCoord(t, "example.com/group", "v1.0.0"),
		WalkID:           fixtureWalkID,
		OverallStatus:    vuldomain.StatusAffected,
		DatabaseSnapshot: fixtureSnap,
		ScannedAt:        at,
		PipelineVersion:  vulnPipelineVersion,
		Rooting:          vuldomain.RootingIsolated,
		Findings:         []vuldomain.VulnerabilityFinding{{ID: id, Summary: "advisory " + id, AffectedRange: "< v9.0.0"}},
	})
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	return rec
}

// widenedBlob renders rec as a build with one more top-level field would have
// sealed it: the bytes hash to their own seal, and this build cannot reproduce
// them. It returns the blob and its seal.
func widenedBlob(t *testing.T, rec vuldomain.VulnerabilityRecord) ([]byte, string) {
	t.Helper()
	unsealed := rec
	unsealed.ContentHash = ""
	blob, err := vuldomain.VulnerabilityRecordHasher{}.Marshal(unsealed)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	blob = append([]byte(`{"a_field_this_build_does_not_have":["x"],`), blob[1:]...)
	sum := sha256.Sum256(blob)
	seal := "sha256:" + hex.EncodeToString(sum[:])
	return bytes.Replace(blob, []byte(`"content_hash":""`), []byte(`"content_hash":"`+seal+`"`), 1), seal
}

// setAsideStore holds the readable generations and one more whose stored row is
// replaced by rewrite's bytes, and returns the query use case over it.
func setAsideStore(t *testing.T, readable int, rewrite func(*testing.T, vuldomain.VulnerabilityRecord) ([]byte, string)) (QueryVulnUseCase, *vulnsqlite.Store, string) {
	t.Helper()
	ctx := t.Context()
	db, err := sqlitestore.Open(":memory:", vulnsqlite.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := vulnsqlite.New(db)

	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range readable {
		if err := store.PutVulnerabilityRecord(ctx, setAsideTestRecord(t, base.Add(time.Duration(i)*time.Hour), "GO-2025-0001")); err != nil {
			t.Fatalf("PutVulnerabilityRecord: %v", err)
		}
	}
	odd := setAsideTestRecord(t, base.Add(-time.Hour), "GO-2025-0002")
	if err := store.PutVulnerabilityRecord(ctx, odd); err != nil {
		t.Fatalf("PutVulnerabilityRecord: %v", err)
	}
	blob, seal := rewrite(t, odd)
	if _, err := db.DB().ExecContext(ctx,
		`UPDATE vulnerability_records SET serialised = ?, content_hash = ? WHERE content_hash = ?`,
		blob, seal, odd.ContentHash); err != nil {
		t.Fatalf("installing the odd row: %v", err)
	}
	return vulnapp.NewQueryVulnUseCase(store), store, seal
}

func runSetAsideVulnShow(uc QueryVulnUseCase, asJSON bool) (stdout, stderr string, err error) {
	var out, errOut bytes.Buffer
	err = runVulnShow(context.Background(), "example.com/group@v1.0.0", "", "", buildTargetFlags{}, false, asJSON, false,
		uc, testfakes.NewFakeQueryScanRuns(), testfakes.NewFakeQueryWalks(), nil, nil, &out, &errOut)
	return out.String(), errOut.String(), err
}

func TestVulnShow_ServesAroundADriftedGenerationAndNamesIt(t *testing.T) {
	uc, _, seal := setAsideStore(t, 2, widenedBlob)

	stdout, stderr, err := runSetAsideVulnShow(uc, false)
	if err != nil {
		t.Fatalf("vuln-show = %v, want the record composed over the readable generations", err)
	}
	if !strings.Contains(stdout, "GO-2025-0001") || strings.Contains(stdout, "GO-2025-0002") {
		t.Errorf("stdout does not serve the readable generations alone:\n%s", stdout)
	}
	if !strings.Contains(stderr, seal) || !strings.Contains(stderr, recordseal.SetAsideRemedy) {
		t.Errorf("stderr does not name the set-aside generation %s with what it means:\n%s", seal, stderr)
	}

	stdout, stderr, err = runSetAsideVulnShow(uc, true)
	if err != nil {
		t.Fatalf("vuln-show --json = %v", err)
	}
	var doc struct {
		SetAside []struct {
			ContentHash string `json:"content_hash"`
			Reason      string `json:"reason"`
		} `json:"set_aside"`
	}
	if jerr := json.Unmarshal([]byte(stdout), &doc); jerr != nil {
		t.Fatalf("decoding %q: %v", stdout, jerr)
	}
	if len(doc.SetAside) != 1 || doc.SetAside[0].ContentHash != seal || doc.SetAside[0].Reason != recordseal.SetAsideRemedy {
		t.Errorf("set_aside = %+v, want the one drifted generation %s inside the document", doc.SetAside, seal)
	}
	if stderr != "" {
		t.Errorf("--json wrote to stderr; the statement belongs in the document:\n%s", stderr)
	}
}

func TestVulnShow_AllDriftedIsNoServableRecord(t *testing.T) {
	uc, _, seal := setAsideStore(t, 0, widenedBlob)

	_, _, err := runSetAsideVulnShow(uc, false)
	if err == nil {
		t.Fatal("vuln-show = nil, want a refusal: no generation is one this build can serve")
	}
	if code := ExitCodeForError(err); code != ExitNotFound {
		t.Errorf("exit code = %d, want %d", code, ExitNotFound)
	}
	for _, want := range []string{"that this build can serve", seal, recordseal.SetAsideRemedy} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not say %q:\n%v", want, err)
		}
	}
}

func TestVulnShow_AlteredGenerationStillExitsIntegrity(t *testing.T) {
	flip := func(t *testing.T, rec vuldomain.VulnerabilityRecord) ([]byte, string) {
		t.Helper()
		blob, err := vuldomain.VulnerabilityRecordHasher{}.Marshal(rec)
		if err != nil {
			t.Fatalf("marshalling: %v", err)
		}
		at := bytes.Index(blob, []byte("advisory GO-2025-0002"))
		blob[at] = 'A'
		return blob, rec.ContentHash
	}
	uc, store, _ := setAsideStore(t, 2, flip)

	_, stderr, err := runSetAsideVulnShow(uc, false)
	if err == nil {
		t.Fatal("vuln-show = nil, want the integrity refusal")
	}
	if code := ExitCodeForError(err); code != ExitIntegrity {
		t.Errorf("exit code = %d, want %d", code, ExitIntegrity)
	}
	if !strings.Contains(err.Error(), "integrity check failed") || strings.Contains(err.Error(), recordseal.SetAsideRemedy) {
		t.Errorf("refusal is not the tamper wording:\n%v", err)
	}
	if stderr != "" {
		t.Errorf("an altered generation was stated as set aside:\n%s", stderr)
	}

	// The write that reconciles the group refuses too, and a scan carrying the
	// refusal exits on it.
	perr := store.PutVulnerabilityRecord(context.Background(), setAsideTestRecord(t, time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC), "GO-2025-0003"))
	if perr == nil {
		t.Fatal("PutVulnerabilityRecord = nil, want the integrity refusal")
	}
	if code := ExitCodeForError(fmt.Errorf("vuln scan failed: persisting isolated vulnerability record: %w", perr)); code != ExitIntegrity {
		t.Errorf("write exit code = %d, want %d: %v", code, ExitIntegrity, perr)
	}
}

// The scan states a set-aside generation once however many of its writes meet
// it, and on the writer it was pointed at.
func TestSetAsideRelay_StatesEachGenerationOnce(t *testing.T) {
	relay := newSetAsideRelay(nil)
	var errOut bytes.Buffer
	relay.to(&errOut)
	row := recordseal.SetAsideRow{Kind: "vulnerability record", ID: "example.com/group@v1.0.0", ContentHash: "sha256:aa"}
	relay.report([]recordseal.SetAsideRow{row})
	relay.report([]recordseal.SetAsideRow{row})
	if got := strings.Count(errOut.String(), "sha256:aa"); got != 1 {
		t.Errorf("the generation was stated %d times, want once:\n%s", got, errOut.String())
	}
	if !strings.Contains(errOut.String(), recordseal.SetAsideRemedy) {
		t.Errorf("the statement does not say what it means:\n%s", errOut.String())
	}
}
