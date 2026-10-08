package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	fetchsqlite "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	exsqlite "github.com/eitanity/kanonarion/internal/example/adapters/store/sqlite"
	exapp "github.com/eitanity/kanonarion/internal/example/application"
	exdomain "github.com/eitanity/kanonarion/internal/example/domain"
	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	licsqlite "github.com/eitanity/kanonarion/internal/license/adapters/store/sqlite"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
)

// A licence or example generation written in a canonical shape this build
// cannot reproduce is set aside and named, through the real stores and Run, so
// the wiring from store to stderr, document and exit code is what is under test.

var (
	asideMixed = coordinatetest.MustNew("example.com/mixed", "v1.0.0")
	asideGone  = coordinatetest.MustNew("example.com/gone", "v1.0.0")
	asideAt0   = time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
)

// widenSealed returns raw as a build with one more top-level field would have
// written it, resealed over those bytes, and the new seal.
func widenSealed(t *testing.T, raw []byte, seal string) ([]byte, string) {
	t.Helper()
	widened := append([]byte(`{"retired_field":"a shape this build never had",`), raw[1:]...)
	stamped := []byte(`"content_hash":"` + seal + `"`)
	if bytes.Count(widened, stamped) != 1 {
		t.Fatalf("fixture has %d top-level seals, want 1", bytes.Count(widened, stamped))
	}
	sum := sha256.Sum256(bytes.Replace(widened, stamped, []byte(`"content_hash":""`), 1))
	resealed := "sha256:" + hex.EncodeToString(sum[:])
	return bytes.Replace(widened, stamped, []byte(`"content_hash":"`+resealed+`"`), 1), resealed
}

// flipRetiredByte alters one byte of a widened row so it no longer hashes to
// its seal.
func flipRetiredByte(b []byte) []byte {
	at := bytes.Index(b, []byte("a shape this build never had"))
	b[at] = 'A'
	return b
}

// asideStore opens a migrated scratch store and hands its handle to seed.
func asideStore(t *testing.T, seed func(context.Context, sqlitestore.DB)) string {
	t.Helper()
	root := t.TempDir()
	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := sqlitestore.Apply(db, allMigrations()); err != nil {
		t.Fatalf("migrating the store: %v", err)
	}
	seed(context.Background(), db)
	return root
}

// seedFetch records coord as fetched, so the extracting commands reach their
// cache read.
func seedFetch(t *testing.T, ctx context.Context, db sqlitestore.DB, coord coordinate.ModuleCoordinate) {
	t.Helper()
	sealed := fetchtest.Sealed(t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion(fetchapp.PipelineVersion),
		fetchtest.Status(fetchdomain.Verified),
		fetchtest.ModuleHash(fetchtest.H1(jsonDocHashValue(0, "zip"))),
		fetchtest.GoMod(jsonDocHashValue(0, "gomod")),
	)
	if err := fetchsqlite.New(db).PutFetchRecord(ctx, sealed); err != nil {
		t.Fatalf("seeding the fetch record for %s: %v", coord, err)
	}
}

func asideLicence(t *testing.T, coord coordinate.ModuleCoordinate, spdx string, confidence float64, at time.Time) licdomain.LicenseRecord {
	t.Helper()
	r := licdomain.LicenseRecord{
		SchemaVersion:     licdomain.LicenseSchemaVersion,
		Ecosystem:         fetchdomain.EcosystemGo,
		Coordinate:        coord,
		PrimarySPDX:       spdx,
		PrimaryConfidence: confidence,
		LicenseFiles: []licdomain.LicenseFileEntry{
			{Path: "LICENSE", SPDX: spdx, Confidence: confidence, FileHash: "sha256:abc", FileSize: 100},
		},
		OverallStatus:    licdomain.LicenseStatusDetected,
		ExtractedAt:      at,
		PipelineVersion:  licapp.PipelineVersion,
		ArtefactIdentity: jsonDocArtefactIdentity(0),
	}
	sealed, err := licdomain.LicenseRecordHasher{}.SetContentHash(r)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	return sealed
}

// putLicence writes rec; when drift is set the stored row is then rewritten in
// a widened shape (mutated, if mutate is set). It returns the seal it is filed
// under.
func putLicence(t *testing.T, ctx context.Context, db sqlitestore.DB, rec licdomain.LicenseRecord, drift bool, mutate func([]byte) []byte) string {
	t.Helper()
	if err := licsqlite.New(db).PutLicenseRecord(ctx, rec); err != nil {
		t.Fatalf("PutLicenseRecord: %v", err)
	}
	if !drift {
		return rec.ContentHash
	}
	raw, err := licdomain.LicenseRecordHasher{}.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	blob, seal := widenSealed(t, raw, rec.ContentHash)
	if mutate != nil {
		blob = mutate(blob)
	}
	if _, err := db.DB().ExecContext(ctx, `UPDATE licence_records SET serialised = ?, content_hash = ? WHERE content_hash = ?`,
		blobcodec.Encode(blob), seal, rec.ContentHash); err != nil {
		t.Fatalf("installing the drifted row: %v", err)
	}
	return seal
}

// licenceAsideStore holds asideMixed with a readable generation and a drifted
// one composition would otherwise serve, fetched so `license` reaches its
// cache read. With gone set, asideGone holds only a drifted generation.
func licenceAsideStore(t *testing.T, gone bool, mutate func([]byte) []byte) (root, mixedSeal, goneSeal string) {
	t.Helper()
	root = asideStore(t, func(ctx context.Context, db sqlitestore.DB) {
		seedFetch(t, ctx, db, asideMixed)
		putLicence(t, ctx, db, asideLicence(t, asideMixed, "MIT", 0.90, asideAt0), false, nil)
		mixedSeal = putLicence(t, ctx, db, asideLicence(t, asideMixed, "Apache-2.0", 0.99, asideAt0.Add(time.Hour)), true, mutate)
		if gone {
			goneSeal = putLicence(t, ctx, db, asideLicence(t, asideGone, "MIT", 0.99, asideAt0), true, nil)
		}
	})
	return root, mixedSeal, goneSeal
}

func runAside(args ...string) (string, string, error) {
	var stdout, stderr bytes.Buffer
	err := Run(args, &stdout, &stderr)
	return stdout.String(), stderr.String(), err
}

// asideDoc is the part of any document that names set-aside generations.
type asideDoc struct {
	ContentHash string `json:"content_hash"`
	SetAside    []struct {
		Coordinate      string `json:"coordinate"`
		PipelineVersion string `json:"pipeline_version"`
		ContentHash     string `json:"content_hash"`
		Reason          string `json:"reason"`
	} `json:"set_aside"`
}

func (d asideDoc) hashes() map[string]string {
	out := map[string]string{}
	for _, a := range d.SetAside {
		out[a.ContentHash] = a.Coordinate
		if a.Reason != recordseal.SetAsideRemedy {
			out[a.ContentHash] = "wrong reason: " + a.Reason
		}
	}
	return out
}

// TestLicence_DriftedGenerationNamedOnStderr: the text read serves the readable
// generation and states the set-aside one on stderr, once.
func TestLicence_DriftedGenerationNamedOnStderr(t *testing.T) {
	root, seal, _ := licenceAsideStore(t, false, nil)

	stdout, stderr, err := runAside("license", asideMixed.String(), "--store-root", root)
	if err != nil {
		t.Fatalf("license = %v, want the readable generation served\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "MIT") || strings.Contains(stdout, "Apache-2.0") || strings.Contains(stdout, seal) {
		t.Errorf("stdout does not serve the readable generation alone:\n%s", stdout)
	}
	if strings.Count(stderr, seal) != 1 || !strings.Contains(stderr, "set aside licence record") ||
		!strings.Contains(stderr, recordseal.SetAsideRemedy) {
		t.Errorf("stderr does not name %s once with the remedy:\n%s", seal, stderr)
	}
}

// TestLicence_DriftedGenerationInTheDocument: under --json the set-aside
// generation is inside the document and not on stderr.
func TestLicence_DriftedGenerationInTheDocument(t *testing.T) {
	root, seal, _ := licenceAsideStore(t, false, nil)

	stdout, stderr, err := runAside("license", asideMixed.String(), "--json", "--store-root", root)
	if err != nil {
		t.Fatalf("license --json = %v\n%s", err, stderr)
	}
	var doc asideDoc
	if jerr := json.Unmarshal([]byte(stdout), &doc); jerr != nil {
		t.Fatalf("decoding the document: %v\n%s", jerr, stdout)
	}
	if h := doc.hashes(); len(h) != 1 || h[seal] != asideMixed.String() {
		t.Errorf("set_aside = %+v, want only %s for %s", doc.SetAside, seal, asideMixed)
	}
	if doc.ContentHash == seal || doc.ContentHash == "" {
		t.Errorf("served %q, want the readable generation", doc.ContentHash)
	}
	if strings.Contains(stderr, seal) {
		t.Errorf("stderr repeats what the document carries:\n%s", stderr)
	}
}

// TestLicence_EveryGenerationDriftedExitsNotFound: a read with nothing this
// build can serve is exit 4 with the statement, never exit 10.
func TestLicence_EveryGenerationDriftedExitsNotFound(t *testing.T) {
	root, _, seal := licenceAsideStore(t, true, nil)

	_, stderr, err := runAside("license", asideGone.String(), "--history", "--store-root", root)
	if code := ExitCodeForError(err); code != ExitNotFound {
		t.Fatalf("exit %d (%v), want %d", code, err, ExitNotFound)
	}
	for _, want := range []string{"that this build can serve", seal, recordseal.SetAsideRemedy} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not state %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "integrity check failed") || strings.Contains(stderr, seal) {
		t.Errorf("refusal reads as tampering or names the generation twice:\n%v\n%s", err, stderr)
	}
}

// TestLicenceList_SetAsideIsNamedAndTheListingKept: a coordinate with nothing
// servable is left out and named, the other is served from its readable
// generation, and the listing succeeds; text names on stderr, --json in the
// document.
func TestLicenceList_SetAsideIsNamedAndTheListingKept(t *testing.T) {
	root, mixedSeal, goneSeal := licenceAsideStore(t, true, nil)

	stdout, stderr, err := runAside("license-list", "--json", "--store-root", root)
	if err != nil {
		t.Fatalf("license-list --json = %v, want the listing kept\n%s", err, stderr)
	}
	var doc struct {
		asideDoc
		Records []struct {
			Module string `json:"module"`
		} `json:"records"`
	}
	if jerr := json.Unmarshal([]byte(stdout), &doc); jerr != nil {
		t.Fatalf("decoding the document: %v\n%s", jerr, stdout)
	}
	if len(doc.Records) != 1 || !strings.Contains(stdout, asideMixed.Path()) {
		t.Errorf("records = %+v, want only %s", doc.Records, asideMixed)
	}
	if h := doc.hashes(); len(h) != 2 || h[mixedSeal] != asideMixed.String() || h[goneSeal] != asideGone.String() {
		t.Errorf("set_aside = %+v, want %s and %s", doc.SetAside, mixedSeal, goneSeal)
	}
	if strings.Contains(stderr, mixedSeal) || strings.Contains(stderr, goneSeal) {
		t.Errorf("stderr repeats what the document carries:\n%s", stderr)
	}

	stdout, stderr, err = runAside("license-list", "--store-root", root)
	if err != nil {
		t.Fatalf("license-list = %v\n%s", err, stderr)
	}
	if strings.Contains(stdout, asideGone.Path()) || !strings.Contains(stdout, asideMixed.Path()) {
		t.Errorf("text listing does not keep only %s:\n%s", asideMixed, stdout)
	}
	if strings.Count(stderr, mixedSeal) != 1 || strings.Count(stderr, goneSeal) != 1 {
		t.Errorf("stderr does not name each set-aside generation once:\n%s", stderr)
	}
}

// TestLicence_AlteredGenerationStillExitsIntegrity is the control: one byte
// flipped is exit 10 with the integrity wording, on the read and the listing.
func TestLicence_AlteredGenerationStillExitsIntegrity(t *testing.T) {
	root, seal, _ := licenceAsideStore(t, false, flipRetiredByte)

	for _, args := range [][]string{
		{"license", asideMixed.String(), "--history", "--store-root", root},
		{"license-list", "--store-root", root},
	} {
		_, stderr, err := runAside(args...)
		if code := ExitCodeForError(err); code != ExitIntegrity {
			t.Fatalf("%s: exit %d (%v), want %d", args[0], code, err, ExitIntegrity)
		}
		if !strings.Contains(err.Error(), "license record integrity check failed") ||
			strings.Contains(err.Error(), recordseal.SetAsideRemedy) || strings.Contains(stderr, seal) {
			t.Errorf("%s: altered generation excused as drift:\n%v\n%s", args[0], err, stderr)
		}
	}
}

func asideExample(t *testing.T, coord coordinate.ModuleCoordinate, names []string, failures int, at time.Time) exdomain.ExampleRecord {
	t.Helper()
	examples := make([]exdomain.ExampleEntry, 0, len(names))
	for _, n := range names {
		symbol, sub := exdomain.DeriveAssociatedSymbol(n)
		examples = append(examples, exdomain.ExampleEntry{
			Name: n, Package: "mod_test", AssociatedSymbol: symbol, SubExample: sub, Body: "{}", Validates: true,
		})
	}
	parse := make([]exdomain.ParseFailure, 0, failures)
	for i := range failures {
		parse = append(parse, exdomain.ParseFailure{File: "broken" + string(rune('a'+i)) + "_test.go", Error: "expected declaration"})
	}
	r := exdomain.ExampleRecord{
		SchemaVersion:    exdomain.ExampleSchemaVersion,
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord,
		Examples:         examples,
		ParseFailures:    parse,
		OverallStatus:    exdomain.ExampleStatusFound,
		ExtractedAt:      at,
		PipelineVersion:  exapp.PipelineVersion,
		ArtefactIdentity: jsonDocArtefactIdentity(0),
	}
	sealed, err := exdomain.ExampleRecordHasher{}.SetContentHash(r)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	return sealed
}

// putExample writes rec; when drift is set the stored row is then rewritten in
// a widened shape (mutated, if mutate is set) and its index re-keyed. It
// returns the seal it is filed under.
func putExample(t *testing.T, ctx context.Context, db sqlitestore.DB, rec exdomain.ExampleRecord, drift bool, mutate func([]byte) []byte) string {
	t.Helper()
	if err := exsqlite.New(db).PutExampleRecord(ctx, rec); err != nil {
		t.Fatalf("PutExampleRecord: %v", err)
	}
	if !drift {
		return rec.ContentHash
	}
	raw, err := exdomain.ExampleRecordHasher{}.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	blob, seal := widenSealed(t, raw, rec.ContentHash)
	if mutate != nil {
		blob = mutate(blob)
	}
	if _, err := db.DB().ExecContext(ctx, `UPDATE example_records SET serialised = ?, content_hash = ? WHERE content_hash = ?`,
		blobcodec.Encode(blob), seal, rec.ContentHash); err != nil {
		t.Fatalf("installing the drifted row: %v", err)
	}
	if _, err := db.DB().ExecContext(ctx, `UPDATE example_index SET record_content_hash = ? WHERE record_content_hash = ?`,
		seal, rec.ContentHash); err != nil {
		t.Fatalf("re-keying the drifted row's index: %v", err)
	}
	return seal
}

// exampleAsideStore holds asideMixed with a readable generation (parse
// failures) and a drifted clean one composition would otherwise serve, fetched
// so `examples` reaches its cache read. With gone set, asideGone holds two
// drifted generations: a single one is listed from its columns undecoded.
func exampleAsideStore(t *testing.T, gone bool, mutate func([]byte) []byte) (root, mixedSeal string, goneSeals []string) {
	t.Helper()
	root = asideStore(t, func(ctx context.Context, db sqlitestore.DB) {
		seedFetch(t, ctx, db, asideMixed)
		putExample(t, ctx, db, asideExample(t, asideMixed, []string{"ExampleAlpha"}, 2, asideAt0), false, nil)
		mixedSeal = putExample(t, ctx, db, asideExample(t, asideMixed, []string{"ExampleAlpha", "ExampleBeta"}, 0, asideAt0.Add(time.Hour)), true, mutate)
		if gone {
			for i := range 2 {
				goneSeals = append(goneSeals, putExample(t, ctx, db,
					asideExample(t, asideGone, []string{"ExampleAlpha"}, i, asideAt0.Add(time.Duration(i)*time.Hour)), true, nil))
			}
		}
	})
	return root, mixedSeal, goneSeals
}

// TestExamples_DriftedGenerationNamedOnStderr: the text read serves the
// readable generation and states the set-aside one on stderr, once.
func TestExamples_DriftedGenerationNamedOnStderr(t *testing.T) {
	root, seal, _ := exampleAsideStore(t, false, nil)

	stdout, stderr, err := runAside("examples", asideMixed.String(), "--store-root", root)
	if err != nil {
		t.Fatalf("examples = %v, want the readable generation served\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "1 example(s)") || strings.Contains(stdout, "ExampleBeta") {
		t.Errorf("stdout does not serve the readable generation alone:\n%s", stdout)
	}
	if strings.Count(stderr, seal) != 1 || !strings.Contains(stderr, "set aside example record") ||
		!strings.Contains(stderr, recordseal.SetAsideRemedy) {
		t.Errorf("stderr does not name %s once with the remedy:\n%s", seal, stderr)
	}
}

// TestExamples_DriftedGenerationInTheDocument: under --json the set-aside
// generation is inside the document, beside the record's own keys.
func TestExamples_DriftedGenerationInTheDocument(t *testing.T) {
	root, seal, _ := exampleAsideStore(t, false, nil)

	stdout, stderr, err := runAside("examples", asideMixed.String(), "--json", "--store-root", root)
	if err != nil {
		t.Fatalf("examples --json = %v\n%s", err, stderr)
	}
	var doc struct {
		asideDoc
		Served   string `json:"ContentHash"`
		Examples []struct{ Name string }
	}
	if jerr := json.Unmarshal([]byte(stdout), &doc); jerr != nil {
		t.Fatalf("decoding the document: %v\n%s", jerr, stdout)
	}
	if h := doc.hashes(); len(h) != 1 || h[seal] != asideMixed.String() {
		t.Errorf("set_aside = %+v, want only %s", doc.SetAside, seal)
	}
	if doc.Served == seal || len(doc.Examples) != 1 {
		t.Errorf("served %s with %d examples, want the readable generation", doc.Served, len(doc.Examples))
	}
	if strings.Contains(stderr, seal) {
		t.Errorf("stderr repeats what the document carries:\n%s", stderr)
	}
}

// TestExamples_EveryGenerationDriftedExitsNotFound: a read with nothing this
// build can serve is exit 4 with the statement, never exit 10.
func TestExamples_EveryGenerationDriftedExitsNotFound(t *testing.T) {
	root, _, seals := exampleAsideStore(t, true, nil)

	_, stderr, err := runAside("examples-list", asideGone.String(), "--store-root", root)
	if code := ExitCodeForError(err); code != ExitNotFound {
		t.Fatalf("exit %d (%v), want %d", code, err, ExitNotFound)
	}
	for _, want := range []string{"that this build can serve", seals[0], seals[1], recordseal.SetAsideRemedy} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not state %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "integrity check failed") || strings.Contains(stderr, seals[0]) {
		t.Errorf("refusal reads as tampering or names the generation twice:\n%v\n%s", err, stderr)
	}
}

// TestExamplesList_SetAsideIsNamedAndTheListingKept: the listing keeps the
// servable coordinate and names all three set-aside generations in the
// document.
func TestExamplesList_SetAsideIsNamedAndTheListingKept(t *testing.T) {
	root, mixedSeal, goneSeals := exampleAsideStore(t, true, nil)

	stdout, stderr, err := runAside("examples-list", "--json", "--store-root", root)
	if err != nil {
		t.Fatalf("examples-list --json = %v, want the listing kept\n%s", err, stderr)
	}
	var doc struct {
		asideDoc
		Records []json.RawMessage `json:"records"`
	}
	if jerr := json.Unmarshal([]byte(stdout), &doc); jerr != nil {
		t.Fatalf("decoding the document: %v\n%s", jerr, stdout)
	}
	if len(doc.Records) != 1 || strings.Contains(string(doc.Records[0]), asideGone.Path()) {
		t.Errorf("records = %s, want only %s", stdout, asideMixed)
	}
	h := doc.hashes()
	if len(h) != 3 || h[mixedSeal] != asideMixed.String() || h[goneSeals[0]] != asideGone.String() || h[goneSeals[1]] != asideGone.String() {
		t.Errorf("set_aside = %+v, want %s, %v", doc.SetAside, mixedSeal, goneSeals)
	}
	if strings.Contains(stderr, mixedSeal) {
		t.Errorf("stderr repeats what the document carries:\n%s", stderr)
	}
}

// TestExamples_AlteredGenerationStillExitsIntegrity is the control: one byte
// flipped is exit 10 with the integrity wording.
func TestExamples_AlteredGenerationStillExitsIntegrity(t *testing.T) {
	root, seal, _ := exampleAsideStore(t, false, flipRetiredByte)

	for _, args := range [][]string{
		{"examples-list", asideMixed.String(), "--store-root", root},
		{"examples-list", "--store-root", root},
	} {
		_, stderr, err := runAside(args...)
		if code := ExitCodeForError(err); code != ExitIntegrity {
			t.Fatalf("%v: exit %d (%v), want %d", args, code, err, ExitIntegrity)
		}
		if !strings.Contains(err.Error(), "example record integrity check failed") ||
			strings.Contains(err.Error(), recordseal.SetAsideRemedy) || strings.Contains(stderr, seal) {
			t.Errorf("%v: altered generation excused as drift:\n%v\n%s", args, err, stderr)
		}
	}
}

// TestContext_LicenceAndExampleSectionsNameWhatTheySetAside: the context
// document's licence and examples sections carry their set-aside generations,
// and a section with nothing servable says so in its status.
func TestContext_LicenceAndExampleSectionsNameWhatTheySetAside(t *testing.T) {
	chdirWithGoMod(t, "")
	root := asideStore(t, func(ctx context.Context, db sqlitestore.DB) {
		putLicence(t, ctx, db, asideLicence(t, asideMixed, "MIT", 0.90, asideAt0), false, nil)
		putLicence(t, ctx, db, asideLicence(t, asideMixed, "Apache-2.0", 0.99, asideAt0.Add(time.Hour)), true, nil)
		for i := range 2 {
			putExample(t, ctx, db, asideExample(t, asideMixed, []string{"ExampleAlpha"}, i, asideAt0.Add(time.Duration(i)*time.Hour)), true, nil)
		}
	})

	stdout, stderr, err := runAside("context", asideMixed.String(), "--json", "--store-root", root)
	if err != nil {
		t.Fatalf("context --json = %v\n%s", err, stderr)
	}
	var wrapped struct {
		Modules []json.RawMessage `json:"modules"`
	}
	if jerr := json.Unmarshal([]byte(stdout), &wrapped); jerr != nil || len(wrapped.Modules) != 1 {
		t.Fatalf("decoding the document (%v): want one module\n%s", jerr, stdout)
	}
	var doc struct {
		License struct {
			asideDoc
			Status string `json:"status"`
			SPDX   string `json:"spdx"`
		} `json:"license"`
		Examples struct {
			asideDoc
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"examples"`
	}
	if jerr := json.Unmarshal(wrapped.Modules[0], &doc); jerr != nil {
		t.Fatalf("decoding the module: %v\n%s", jerr, stdout)
	}
	if doc.License.SPDX != "MIT" || len(doc.License.SetAside) != 1 {
		t.Fatalf("licence section = %+v, want MIT served and one generation set aside", doc.License)
	}
	if doc.Examples.Status != sectionStatusSetAside || len(doc.Examples.SetAside) != 2 ||
		!strings.Contains(doc.Examples.Error, recordseal.SetAsideRemedy) {
		t.Errorf("examples section = %+v, want status %s naming both generations", doc.Examples, sectionStatusSetAside)
	}
	if strings.Contains(stderr, "set aside") {
		t.Errorf("stderr repeats what the document carries:\n%s", stderr)
	}

	stdout, stderr, err = runAside("context", asideMixed.String(), "--store-root", root)
	if err != nil {
		t.Fatalf("context = %v\n%s", err, stderr)
	}
	for _, want := range []string{
		"Set aside:       " + asideMixed.String() + " content_hash " + doc.License.SetAside[0].ContentHash,
		"Examples:        (no record this build can serve — ",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("text does not state %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stderr, "set aside") {
		t.Errorf("stderr repeats what the text carries:\n%s", stderr)
	}
}

// TestAuditLicenceResolution_NothingServableIsStated: an audit row whose every
// licence generation was set aside says so, rather than keeping the status it
// had before the read.
func TestAuditLicenceResolution_NothingServableIsStated(t *testing.T) {
	none := &recordseal.NothingServable{Kind: "licence record", ID: asideGone.String(), Aside: &recordseal.SetAside{
		Rows: []recordseal.SetAsideRow{{ContentHash: "sha256:aa", Reason: recordseal.ErrGenerationDrift}},
	}}
	display, status, resolved, reason, _ := auditLicenceResolution(licdomain.LicenseRecord{}, false, none, "", "")
	if display != "(set aside)" || status != "(set aside)" || resolved != "" || reason != "no_record" {
		t.Errorf("resolution = (%q, %q, %q, %q), want the set-aside status with nothing resolved", display, status, resolved, reason)
	}
}
