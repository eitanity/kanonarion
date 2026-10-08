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
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	licensesqlite "github.com/eitanity/kanonarion/internal/license/adapters/store/sqlite"
	domain2 "github.com/eitanity/kanonarion/internal/license/domain"
	"github.com/eitanity/kanonarion/internal/license/ports"
)

// A licence generation written in a canonical shape this build cannot reproduce
// must not take its coordinate's reads and writes down with it. A store written
// by one build never holds one, so these tests build it by hand.

// driftedBlob returns rec's stored bytes as a build with one more top-level
// field would have written them, sealed over those bytes, and that seal.
func driftedBlob(t *testing.T, rec domain2.LicenseRecord) ([]byte, string) {
	t.Helper()
	raw, err := domain2.LicenseRecordHasher{}.Marshal(rec)
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
// (mutated, if mutate is set) and returns the seal the row is filed under.
func installDrifted(t *testing.T, s *licensesqlite.Store, rec domain2.LicenseRecord, mutate func([]byte) []byte) string {
	t.Helper()
	if err := s.PutLicenseRecord(context.Background(), rec); err != nil {
		t.Fatalf("PutLicenseRecord: %v", err)
	}
	blob, seal := driftedBlob(t, rec)
	if mutate != nil {
		blob = mutate(blob)
	}
	if _, err := s.InternalDB().DB().Exec(
		`UPDATE licence_records SET serialised = ?, content_hash = ? WHERE content_hash = ?`,
		blobcodec.Encode(blob), seal, rec.ContentHash); err != nil {
		t.Fatalf("installing the drifted row: %v", err)
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
func reported(s *licensesqlite.Store) *[]recordseal.SetAsideRow {
	var rows []recordseal.SetAsideRow
	s.ReportSetAside(func(r []recordseal.SetAsideRow) { rows = append(rows, r...) })
	return &rows
}

func hashesOf(rows []recordseal.SetAsideRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.ContentHash)
	}
	return out
}

var asideAt = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

// TestSetAside_ComposedReadServesTheRestAndNamesIt: the drifted generation is
// the one composition would serve (highest confidence), so serving it or
// refusing the read would both show.
func TestSetAside_ComposedReadServesTheRestAndNamesIt(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	rows := reported(s)
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("tree-one=").String()

	readable := ledgerRecord(t, coord, "MIT", 0.90, asideAt, artefact)
	if err := s.PutLicenseRecord(ctx, readable); err != nil {
		t.Fatalf("PutLicenseRecord: %v", err)
	}
	seal := installDrifted(t, s, ledgerRecord(t, coord, "Apache-2.0", 0.99, asideAt.Add(time.Hour), artefact), nil)

	got, found, err := s.GetLicenseRecord(ctx, coord, "1.1.0")
	if err != nil || !found {
		t.Fatalf("GetLicenseRecord = (found %v, %v), want the readable generation served", found, err)
	}
	if got.ContentHash != readable.ContentHash {
		t.Errorf("served %s, want the readable %s", got.ContentHash, readable.ContentHash)
	}
	if hs := hashesOf(*rows); len(hs) != 1 || hs[0] != seal {
		t.Fatalf("named %v, want exactly the drifted %s", hs, seal)
	}
	r := (*rows)[0]
	if r.Kind != licensesqlite.RecordKind || r.ID != coord.String() || r.Generation.PipelineVersion != "1.1.0" ||
		!errors.Is(r.Reason, recordseal.ErrGenerationDrift) {
		t.Errorf("row = %+v, want a licence record row for %s at 1.1.0 classified as drift", r, coord)
	}
}

// TestSetAside_EveryGenerationDriftedIsNothingServable: records are held and
// none this build can serve, which is neither absence nor tampering.
func TestSetAside_EveryGenerationDriftedIsNothingServable(t *testing.T) {
	s := openTestStore(t)
	rows := reported(s)
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	seal := installDrifted(t, s, ledgerRecord(t, coord, "MIT", 0.99, asideAt, fetchtest.ZipArtefact("tree-one=").String()), nil)

	_, found, err := s.GetLicenseRecord(context.Background(), coord, "1.1.0")
	var none *recordseal.NothingServable
	if !errors.As(err, &none) || found {
		t.Fatalf("GetLicenseRecord = (found %v, %v), want *recordseal.NothingServable", found, err)
	}
	if errors.Is(err, ports.ErrLicenceIntegrity) {
		t.Errorf("drift reported as integrity: %v", err)
	}
	if len(none.Aside.Rows) != 1 || none.Aside.Rows[0].ContentHash != seal || none.ID != coord.String() {
		t.Errorf("refusal = %+v, want it to name %s for %s", none, seal, coord)
	}
	if hs := hashesOf(*rows); len(hs) != 1 || hs[0] != seal {
		t.Errorf("named %v, want %s", hs, seal)
	}
}

// TestSetAside_ListingKeepsTheOtherRows: one coordinate with nothing servable,
// one whose newest generation is drifted, one ordinary. The listing keeps the
// second and third, drops the first, and names both drifted generations.
func TestSetAside_ListingKeepsTheOtherRows(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	rows := reported(s)
	artefact := fetchtest.ZipArtefact("tree-one=").String()

	gone := mustCoord(t, "example.com/gone", "v1.0.0")
	goneSeal := installDrifted(t, s, ledgerRecord(t, gone, "MIT", 0.99, asideAt, artefact), nil)

	mixed := mustCoord(t, "example.com/mixed", "v1.0.0")
	mixedReadable := ledgerRecord(t, mixed, "MIT", 0.90, asideAt, artefact)
	if err := s.PutLicenseRecord(ctx, mixedReadable); err != nil {
		t.Fatalf("PutLicenseRecord: %v", err)
	}
	mixedSeal := installDrifted(t, s, ledgerRecord(t, mixed, "Apache-2.0", 0.99, asideAt.Add(time.Hour), artefact), nil)

	plain := mustCoord(t, "example.com/plain", "v1.0.0")
	if err := s.PutLicenseRecord(ctx, ledgerRecord(t, plain, "BSD-3-Clause", 0.99, asideAt, artefact)); err != nil {
		t.Fatalf("PutLicenseRecord: %v", err)
	}

	sums, err := s.ListLicenseRecords(ctx, ports.LicenseFilter{})
	if err != nil {
		t.Fatalf("ListLicenseRecords = %v, want the listing kept", err)
	}
	listed := map[string]string{}
	for _, sum := range sums {
		listed[sum.ModulePath] = sum.ContentHash
	}
	if _, ok := listed[gone.Path()]; ok || len(listed) != 2 {
		t.Errorf("listed %v, want mixed and plain only", listed)
	}
	if listed[mixed.Path()] != mixedReadable.ContentHash {
		t.Errorf("mixed served %s, want the readable %s", listed[mixed.Path()], mixedReadable.ContentHash)
	}
	named := map[string]bool{}
	for _, h := range hashesOf(*rows) {
		named[h] = true
	}
	if !named[goneSeal] || !named[mixedSeal] {
		t.Errorf("named %v, want %s and %s", hashesOf(*rows), goneSeal, mixedSeal)
	}
}

// TestSetAside_IdenticalGenerationSkipsADriftedRow: a drifted row cannot be
// shown to restate this measurement, so the write is not refused over it; it is
// skipped and named.
func TestSetAside_IdenticalGenerationSkipsADriftedRow(t *testing.T) {
	s := openTestStore(t)
	rows := reported(s)
	local, err := coordinate.NewLocalCoordinate("example.com/mod")
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}
	artefact := fetchtest.ZipArtefact("tree-one=").String()
	seal := installDrifted(t, s, ledgerRecord(t, local, "MIT", 0.98, asideAt, artefact), nil)

	fresh := ledgerRecord(t, local, "MIT", 0.98, asideAt.Add(time.Hour), artefact)
	_, found, gerr := s.IdenticalGeneration(context.Background(), fresh)
	if gerr != nil || found {
		t.Fatalf("IdenticalGeneration = (found %v, %v), want nothing held and no error", found, gerr)
	}
	if hs := hashesOf(*rows); len(hs) != 1 || hs[0] != seal {
		t.Errorf("named %v, want %s", hs, seal)
	}
}

// TestSetAside_AlteredRowStillFailsIntegrity is the control: one byte flipped
// fails every leg with the integrity sentinel, and nothing is set aside.
func TestSetAside_AlteredRowStillFailsIntegrity(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	rows := reported(s)
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("tree-one=").String()
	if err := s.PutLicenseRecord(ctx, ledgerRecord(t, coord, "MIT", 0.90, asideAt, artefact)); err != nil {
		t.Fatalf("PutLicenseRecord: %v", err)
	}
	installDrifted(t, s, ledgerRecord(t, coord, "MIT", 0.99, asideAt.Add(time.Hour), artefact), flipRetired)

	_, _, gerr := s.GetLicenseRecord(ctx, coord, "1.1.0")
	_, lerr := s.ListLicenseRecords(ctx, ports.LicenseFilter{})
	_, _, ierr := s.IdenticalGeneration(ctx, ledgerRecord(t, coord, "MIT", 0.99, asideAt.Add(2*time.Hour), artefact))
	for name, err := range map[string]error{"GetLicenseRecord": gerr, "ListLicenseRecords": lerr, "IdenticalGeneration": ierr} {
		if !errors.Is(err, ports.ErrLicenceIntegrity) || errors.Is(err, recordseal.ErrGenerationDrift) {
			t.Errorf("%s = %v, want the integrity failure and not drift", name, err)
		}
	}
	if len(*rows) != 0 {
		t.Errorf("an altered row was set aside: %v", hashesOf(*rows))
	}
}

// TestSetAside_IntactBytesFiledUnderAnotherSealFailIntegrity: bytes that hash to
// their own seal but sit under a different column value are an altered row.
func TestSetAside_IntactBytesFiledUnderAnotherSealFailIntegrity(t *testing.T) {
	s := openTestStore(t)
	rows := reported(s)
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	seal := installDrifted(t, s, ledgerRecord(t, coord, "MIT", 0.99, asideAt, fetchtest.ZipArtefact("tree-one=").String()), nil)
	if _, err := s.InternalDB().DB().Exec(`UPDATE licence_records SET content_hash = ? WHERE content_hash = ?`,
		"sha256:"+hex.EncodeToString(make([]byte, 32)), seal); err != nil {
		t.Fatalf("re-filing the row: %v", err)
	}

	_, _, err := s.GetLicenseRecord(context.Background(), coord, "1.1.0")
	if !errors.Is(err, ports.ErrLicenceIntegrity) {
		t.Errorf("GetLicenseRecord = %v, want the integrity failure", err)
	}
	if len(*rows) != 0 {
		t.Errorf("a re-filed row was set aside: %v", hashesOf(*rows))
	}
}
