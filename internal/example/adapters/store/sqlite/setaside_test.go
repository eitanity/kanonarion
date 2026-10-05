package sqlite_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/coordinate"
	examplesqlite "github.com/eitanity/kanonarion/internal/example/adapters/store/sqlite"
	domain2 "github.com/eitanity/kanonarion/internal/example/domain"
	"github.com/eitanity/kanonarion/internal/example/ports"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

// An example generation written in a canonical shape this build cannot
// reproduce must not take its coordinate's reads and writes down with it. A
// store written by one build never holds one, so these tests build it by hand.

// driftedBlob returns rec's stored bytes as a build with one more top-level
// field would have written them, sealed over those bytes, and that seal.
func driftedBlob(t *testing.T, rec domain2.ExampleRecord) ([]byte, string) {
	t.Helper()
	raw, err := domain2.ExampleRecordHasher{}.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	widened := append([]byte(`{"retired_field":"a shape this build never had",`), raw[1:]...)
	stamped := []byte(`"content_hash":"` + rec.ContentHash + `"`)
	if bytes.Count(widened, stamped) != 1 {
		t.Fatalf("fixture has %d top-level seals, want 1", bytes.Count(widened, stamped))
	}
	sum := sha256.Sum256(bytes.Replace(widened, stamped, []byte(`"content_hash":""`), 1))
	seal := "sha256:" + hex.EncodeToString(sum[:])
	out := bytes.Replace(widened, stamped, []byte(`"content_hash":"`+seal+`"`), 1)
	if ok, serr := recordseal.SelfConsistent(out, seal); serr != nil || !ok {
		t.Fatalf("drift fixture is not self-consistent (%v, %v); it would prove nothing", ok, serr)
	}
	return out, seal
}

// installDrifted puts rec, then replaces its stored row with the drifted bytes
// (mutated, if mutate is set), re-keys its index rows, and returns the seal the
// row is filed under.
func installDrifted(t *testing.T, s *examplesqlite.Store, rec domain2.ExampleRecord, mutate func([]byte) []byte) string {
	t.Helper()
	if err := s.PutExampleRecord(context.Background(), rec); err != nil {
		t.Fatalf("PutExampleRecord: %v", err)
	}
	blob, seal := driftedBlob(t, rec)
	if mutate != nil {
		blob = mutate(blob)
	}
	db := s.InternalDB().DB()
	if _, err := db.Exec(`UPDATE example_records SET serialised = ?, content_hash = ? WHERE content_hash = ?`,
		blobcodec.Encode(blob), seal, rec.ContentHash); err != nil {
		t.Fatalf("installing the drifted row: %v", err)
	}
	if _, err := db.Exec(`UPDATE example_index SET record_content_hash = ? WHERE record_content_hash = ?`,
		seal, rec.ContentHash); err != nil {
		t.Fatalf("re-keying the drifted row's index: %v", err)
	}
	return seal
}

// flipRetired alters one byte of the stored bytes, so they no longer hash to
// their seal.
func flipRetired(b []byte) []byte {
	at := bytes.Index(b, []byte("a shape this build never had"))
	b[at] = 'A'
	return b
}

// reported collects what the store names through ReportSetAside.
func reported(s *examplesqlite.Store) *[]recordseal.SetAsideRow {
	var rows []recordseal.SetAsideRow
	s.ReportSetAside(func(r []recordseal.SetAsideRow) { rows = append(rows, r...) })
	return &rows
}

func namedSet(rows []recordseal.SetAsideRow) map[string]bool {
	out := map[string]bool{}
	for _, r := range rows {
		out[r.ContentHash] = true
	}
	return out
}

var asideAt = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

// cleanAndDegraded writes coord's two generations: a readable one with parse
// failures and, drifted, a clean one composition would otherwise serve. It
// returns the readable record and the drifted seal.
func cleanAndDegraded(t *testing.T, s *examplesqlite.Store, coord coordinate.ModuleCoordinate) (domain2.ExampleRecord, string) {
	t.Helper()
	artefact := fetchtest.ZipArtefact("same-bytes=").String()
	degraded := ledgerRecord(t, coord, domain2.ExampleStatusFound, []string{"ExampleAlpha"}, 2, asideAt, artefact)
	if err := s.PutExampleRecord(context.Background(), degraded); err != nil {
		t.Fatalf("PutExampleRecord: %v", err)
	}
	clean := ledgerRecord(t, coord, domain2.ExampleStatusFound, []string{"ExampleAlpha", "ExampleBeta"}, 0,
		asideAt.Add(time.Hour), artefact)
	return degraded, installDrifted(t, s, clean, nil)
}

// allDrifted writes coord's two generations and drifts both.
func allDrifted(t *testing.T, s *examplesqlite.Store, coord coordinate.ModuleCoordinate) []string {
	t.Helper()
	artefact := fetchtest.ZipArtefact("same-bytes=").String()
	var seals []string
	for i := range 2 {
		rec := ledgerRecord(t, coord, domain2.ExampleStatusFound, []string{"ExampleAlpha"}, i,
			asideAt.Add(time.Duration(i)*time.Hour), artefact)
		seals = append(seals, installDrifted(t, s, rec, nil))
	}
	return seals
}

// TestSetAside_ComposedReadServesTheRestAndNamesIt: the drifted generation is
// the one composition would serve, so serving it or refusing would both show.
func TestSetAside_ComposedReadServesTheRestAndNamesIt(t *testing.T) {
	s := openTestStore(t)
	rows := reported(s)
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	readable, seal := cleanAndDegraded(t, s, coord)

	got, found, err := s.GetExampleRecord(context.Background(), coord, ledgerPipeline)
	if err != nil || !found {
		t.Fatalf("GetExampleRecord = (found %v, %v), want the readable generation served", found, err)
	}
	if got.ContentHash != readable.ContentHash {
		t.Errorf("served %s, want the readable %s", got.ContentHash, readable.ContentHash)
	}
	if len(*rows) != 1 || (*rows)[0].ContentHash != seal {
		t.Fatalf("named %v, want exactly the drifted %s", namedSet(*rows), seal)
	}
	r := (*rows)[0]
	if r.Kind != examplesqlite.RecordKind || r.ID != coord.String() || r.Generation.PipelineVersion != ledgerPipeline ||
		!errors.Is(r.Reason, recordseal.ErrGenerationDrift) {
		t.Errorf("row = %+v, want an example record row for %s classified as drift", r, coord)
	}
}

// TestSetAside_EveryGenerationDriftedIsNothingServable: records are held and
// none this build can serve, which is neither absence nor tampering.
func TestSetAside_EveryGenerationDriftedIsNothingServable(t *testing.T) {
	s := openTestStore(t)
	rows := reported(s)
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	seals := allDrifted(t, s, coord)

	_, found, err := s.GetExampleRecord(context.Background(), coord, ledgerPipeline)
	var none *recordseal.NothingServable
	if !errors.As(err, &none) || found {
		t.Fatalf("GetExampleRecord = (found %v, %v), want *recordseal.NothingServable", found, err)
	}
	if errors.Is(err, ports.ErrExampleIntegrity) {
		t.Errorf("drift reported as integrity: %v", err)
	}
	named := namedSet(*rows)
	if len(none.Aside.Rows) != 2 || !named[seals[0]] || !named[seals[1]] {
		t.Errorf("refusal %+v / named %v, want both %v", none, named, seals)
	}
}

// TestSetAside_ListingAndSymbolLookupKeepTheOtherModules: one module with
// nothing servable, one whose clean generation is drifted, one ordinary. Both
// the listing and the symbol lookup keep the other two and name what they set
// aside, without failing.
func TestSetAside_ListingAndSymbolLookupKeepTheOtherModules(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	rows := reported(s)

	gone := mustCoord(t, "example.com/gone", "v1.0.0")
	goneSeals := allDrifted(t, s, gone)
	mixed := mustCoord(t, "example.com/mixed", "v1.0.0")
	readable, mixedSeal := cleanAndDegraded(t, s, mixed)
	plain := mustCoord(t, "example.com/plain", "v1.0.0")
	if err := s.PutExampleRecord(ctx, ledgerRecord(t, plain, domain2.ExampleStatusFound, []string{"ExampleAlpha"}, 0,
		asideAt, fetchtest.ZipArtefact("plain=").String())); err != nil {
		t.Fatalf("PutExampleRecord: %v", err)
	}

	sums, err := s.ListExampleRecords(ctx, ports.ExampleFilter{})
	if err != nil {
		t.Fatalf("ListExampleRecords = %v, want the listing kept", err)
	}
	listed := map[string]string{}
	for _, sum := range sums {
		listed[sum.ModulePath] = sum.ContentHash
	}
	if _, ok := listed[gone.Path()]; ok || len(listed) != 2 || listed[mixed.Path()] != readable.ContentHash {
		t.Errorf("listed %v, want mixed (served %s) and plain only", listed, readable.ContentHash)
	}

	refs, ferr := s.FindBySymbol(ctx, "Alpha", ledgerPipeline, coordinate.ModuleSet{})
	if ferr != nil {
		t.Fatalf("FindBySymbol = %v, want the other modules' answers", ferr)
	}
	found := map[string]bool{}
	for _, r := range refs {
		found[r.ModulePath] = true
	}
	if found[gone.Path()] || !found[mixed.Path()] || !found[plain.Path()] || len(refs) != 2 {
		t.Errorf("FindBySymbol = %+v, want one ref each from mixed and plain", refs)
	}
	if beta, berr := s.FindBySymbol(ctx, "Beta", ledgerPipeline, coordinate.ModuleSet{}); berr != nil || len(beta) != 0 {
		t.Errorf("FindBySymbol(Beta) = %+v, %v; the drifted generation's examples were served", beta, berr)
	}

	named := namedSet(*rows)
	if !named[goneSeals[0]] || !named[goneSeals[1]] || !named[mixedSeal] {
		t.Errorf("named %v, want %v and %s", named, goneSeals, mixedSeal)
	}
}

// TestSetAside_IdenticalGenerationSkipsADriftedRow: a drifted row cannot be
// shown to restate this measurement, so it is skipped and named.
func TestSetAside_IdenticalGenerationSkipsADriftedRow(t *testing.T) {
	s := openTestStore(t)
	rows := reported(s)
	local, err := coordinate.NewLocalCoordinate("example.com/mod")
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}
	artefact := fetchtest.ZipArtefact("tree-one=").String()
	seal := installDrifted(t, s, ledgerRecord(t, local, domain2.ExampleStatusFound, []string{"ExampleAlpha"}, 0, asideAt, artefact), nil)

	fresh := ledgerRecord(t, local, domain2.ExampleStatusFound, []string{"ExampleAlpha"}, 0, asideAt.Add(time.Hour), artefact)
	_, found, gerr := s.IdenticalGeneration(context.Background(), fresh)
	if gerr != nil || found {
		t.Fatalf("IdenticalGeneration = (found %v, %v), want nothing held and no error", found, gerr)
	}
	if len(*rows) != 1 || (*rows)[0].ContentHash != seal {
		t.Errorf("named %v, want %s", namedSet(*rows), seal)
	}
}

// TestSetAside_AlteredRowStillFailsIntegrity is the control: one byte flipped
// fails every leg with the integrity sentinel, and nothing is set aside.
func TestSetAside_AlteredRowStillFailsIntegrity(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	rows := reported(s)
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("same-bytes=").String()
	if err := s.PutExampleRecord(ctx, ledgerRecord(t, coord, domain2.ExampleStatusFound, []string{"ExampleAlpha"}, 2, asideAt, artefact)); err != nil {
		t.Fatalf("PutExampleRecord: %v", err)
	}
	altered := ledgerRecord(t, coord, domain2.ExampleStatusFound, []string{"ExampleAlpha"}, 0, asideAt.Add(time.Hour), artefact)
	installDrifted(t, s, altered, flipRetired)

	_, _, gerr := s.GetExampleRecord(ctx, coord, ledgerPipeline)
	_, lerr := s.ListExampleRecords(ctx, ports.ExampleFilter{})
	_, ferr := s.FindBySymbol(ctx, "Alpha", ledgerPipeline, coordinate.ModuleSet{})
	same := ledgerRecord(t, coord, domain2.ExampleStatusFound, []string{"ExampleAlpha"}, 0, asideAt.Add(2*time.Hour), artefact)
	_, _, ierr := s.IdenticalGeneration(ctx, same)
	for name, err := range map[string]error{
		"GetExampleRecord": gerr, "ListExampleRecords": lerr, "FindBySymbol": ferr, "IdenticalGeneration": ierr,
	} {
		if !errors.Is(err, ports.ErrExampleIntegrity) || errors.Is(err, recordseal.ErrGenerationDrift) {
			t.Errorf("%s = %v, want the integrity failure and not drift", name, err)
		}
	}
	if len(*rows) != 0 {
		t.Errorf("an altered row was set aside: %v", namedSet(*rows))
	}
}

// TestSetAside_IntactBytesFiledUnderAnotherSealFailIntegrity: bytes that hash to
// their own seal but sit under a different column value are an altered row.
func TestSetAside_IntactBytesFiledUnderAnotherSealFailIntegrity(t *testing.T) {
	s := openTestStore(t)
	rows := reported(s)
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	seal := installDrifted(t, s, ledgerRecord(t, coord, domain2.ExampleStatusFound, []string{"ExampleAlpha"}, 0, asideAt,
		fetchtest.ZipArtefact("same-bytes=").String()), nil)
	if _, err := s.InternalDB().DB().Exec(`UPDATE example_records SET content_hash = ? WHERE content_hash = ?`,
		"sha256:"+hex.EncodeToString(make([]byte, 32)), seal); err != nil {
		t.Fatalf("re-filing the row: %v", err)
	}

	_, _, err := s.GetExampleRecord(context.Background(), coord, ledgerPipeline)
	if !errors.Is(err, ports.ErrExampleIntegrity) {
		t.Errorf("GetExampleRecord = %v, want the integrity failure", err)
	}
	if len(*rows) != 0 {
		t.Errorf("a re-filed row was set aside: %v", namedSet(*rows))
	}
}
