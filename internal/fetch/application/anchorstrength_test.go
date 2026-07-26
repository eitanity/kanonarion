package application_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// modcacheUseCase builds a --from-modcache use case over the given fact store,
// logging into buf. Its blob store holds nothing, so a record written by the
// network path reads as unreadable here and the fetch proceeds to the write side
// — which is the situation the strength guard exists for.
func modcacheUseCase(t *testing.T, facts ports.FactStore, buf *bytes.Buffer) *application.FetchModuleUseCase {
	t.Helper()
	return modcacheUseCaseWithBlobs(t, facts, newModcacheBlob(t), buf)
}

// modcacheUseCaseWithBlobs is modcacheUseCase over an explicit blob store, so a
// test can choose whether the artefacts a network run left behind are readable
// from module-cache mode.
func modcacheUseCaseWithBlobs(t *testing.T, facts ports.FactStore, blobs ports.BlobStore, buf *bytes.Buffer) *application.FetchModuleUseCase {
	t.Helper()
	zipHash := domain2.ModuleHash{Algorithm: "h1", Value: "zip-abc="}
	goModHash := domain2.ModuleHash{Algorithm: "h1", Value: "mod-abc="}
	log := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return application.NewFetchModuleUseCase(
		downloadWithHashes(testCoord, zipHash, goModHash),
		&fakeVCS{}, blobs, facts,
		&fakeSumDB{result: ports.SumDBResult{Available: true, ZipHash: zipHash, GoModHash: goModHash}},
		fixedClock{fixedTime}, fakeStopwatch{}, "test-0.1.0", log,
	).WithModcacheMode()
}

// delegatingModcacheBlobs used to special-case the "modcache:" handle namespace
// the module-cache store once owned. There is no namespace left to special-case:
// every mode addresses an artefact by the identity it measured, so a store either
// holds those bytes or does not, and delegation is the ordinary path. It is now
// a plain in-memory store kept under its old name so the tests below still read
// as "the blob store module-cache mode is wired with".
type delegatingModcacheBlobs struct{ *fakeBlob }

// seedStoredRecord stores a record for testCoord with the given status and mode,
// whose artefacts the blob store does not hold (the shape a network run leaves
// behind for a module-cache run that cannot reach the same bytes).
func seedStoredRecord(t *testing.T, facts *fakeFacts, status domain2.VerificationStatus, mode domain2.AcquisitionMode) domain2.FactRecord {
	t.Helper()
	sealed := fetchtest.Record(t,
		fetchtest.Coordinate(testCoord),
		fetchtest.ModuleHash(fetchtest.H1("seed==")),
		fetchtest.GoModHash(fetchtest.H1("seedmod==")),
		fetchtest.Status(status),
		fetchtest.FetchedAt(fixedTime),
		fetchtest.PipelineVersion("test-0.1.0"),
		fetchtest.Content("fake:seed-zip"),
		fetchtest.GoMod("fake:seed-gomod"),
		fetchtest.AcquisitionMode(mode),
	)
	resealed, serr := domain2.Rehydrate(sealed)
	if serr != nil {
		t.Fatalf("sealing seed record: %v", serr)
	}
	if err := facts.PutFetchRecord(context.Background(), resealed); err != nil {
		t.Fatalf("seeding record: %v", err)
	}
	return sealed
}

func storedRecord(t *testing.T, facts *fakeFacts) domain2.FactRecord {
	t.Helper()
	r, ok, err := facts.GetFetchRecord(context.Background(), testCoord, "test-0.1.0")
	if err != nil || !ok {
		t.Fatalf("reading stored record: ok=%v err=%v", ok, err)
	}
	return r.FactRecord
}

// TestModcacheReMeasurementNeverDemotesAStoredRecord is the regression guard for
// the reported defect: a --from-modcache run replaced a network run's record in
// place, demoting its verification anchor and swapping its portable
// content-addressed handle for a mode-locked one, which the next plain run could
// not read.
//
// It sweeps every verification status a stored record can carry against the one
// status the module-cache path can produce (VerifiedBySumDBOnly — local go.sum is
// its only anchor), and runs each case twice: unforced and forced. --force means
// "re-measure this module now", never "permit a weaker anchor to replace a
// stronger fact", so the outcome must be identical both ways. The full
// (existing, incoming) matrix over the strength order is covered in the domain,
// where the ranking lives: see TestReplacementWeakensAnchor_EveryStatusPair.
func TestModcacheReMeasurementNeverDemotesAStoredRecord(t *testing.T) {
	cases := []struct {
		existing      domain2.VerificationStatus
		wantOverwrite bool
	}{
		{domain2.Verified, false},                   // stronger: transparency log AND git source
		{domain2.VerifiedBySumDBOnly, true},         // equal: a genuine re-measurement still lands
		{domain2.VerifiedByGoSum, true},             // weaker: an upgrade still lands
		{domain2.LocalSource, true},                 // weaker
		{domain2.UnverifiedNoSumDB, true},           // weakest
		{domain2.UnverifiedHashMismatch, true},      // weakest
		{domain2.UnverifiedMissingOrigin, true},     // weakest
		{domain2.UnverifiedGoModInconsistent, true}, // weakest
		{domain2.UnverifiedNoVCS, true},             // weakest
		{domain2.UnverifiedVCSToolMissing, true},    // weakest
		{domain2.VerificationStatus(""), true},      // a record written before statuses existed
		{domain2.VerificationStatus("Newer"), true}, // unrecognised, ranks equal-lowest
	}
	for _, tc := range cases {
		for _, force := range []bool{false, true} {
			existing := string(tc.existing)
			if existing == "" {
				existing = "empty"
			}
			t.Run(fmt.Sprintf("%s/force=%v", existing, force), func(t *testing.T) {
				facts := newFakeFacts()
				seeded := seedStoredRecord(t, facts, tc.existing, domain2.AcquisitionProxy)
				var buf bytes.Buffer
				uc := modcacheUseCase(t, facts, &buf)

				res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord, Force: force})
				if err != nil {
					t.Fatalf("Execute: %v", err)
				}

				stored := storedRecord(t, facts)
				if tc.wantOverwrite {
					if stored.ContentHash == seeded.ContentHash {
						t.Errorf("an equal-or-stronger re-measurement did not overwrite the stored record: "+
							"existing=%q incoming=%q", tc.existing, domain2.VerifiedBySumDBOnly)
					}
					if stored.AcquisitionMode != string(domain2.AcquisitionModcache) {
						t.Errorf("stored AcquisitionMode = %q, want %q", stored.AcquisitionMode, domain2.AcquisitionModcache)
					}
					return
				}
				if stored.ContentHash != seeded.ContentHash {
					t.Errorf("a weaker re-measurement replaced the stored record (force=%v): "+
						"status %q -> %q, handle %q -> %q", force,
						seeded.VerificationStatus, stored.VerificationStatus,
						seeded.ContentLocation, stored.ContentLocation)
				}
				// What the refused run RETURNS depends on whether it can read the kept
				// record's artefacts; both directions are pinned separately below. Here
				// the seeded artefacts are absent from this run's store, so the caller
				// gets the artefacts this run measured rather than an address it
				// cannot read.
				if res.Record.ContentLocation == seeded.ContentLocation {
					t.Errorf("refused run returned the kept record's artefacts %q, which this run cannot read",
						res.Record.ContentLocation)
				}
			})
		}
	}
}

// TestRefusedDowngradeReturnsTheKeptRecordWhenItIsReadable is the ordinary
// production shape of a refusal: the artefacts the network run stored are
// addressed by identity, so the module-cache run can read them too, the kept
// network record is fully usable by the run that was refused, and it is what the
// caller gets.
func TestRefusedDowngradeReturnsTheKeptRecordWhenItIsReadable(t *testing.T) {
	facts := newFakeFacts()
	blobs := newFakeBlob()
	seeded := seedStoredRecord(t, facts, domain2.Verified, domain2.AcquisitionProxy)
	if err := blobs.Put(context.Background(), fetchtest.ZipIdentity(t, seeded), strings.NewReader("seed-zip")); err != nil {
		t.Fatalf("seeding zip blob: %v", err)
	}
	if err := blobs.Put(context.Background(), fetchtest.GoModIdentity(t, seeded), strings.NewReader("seed-gomod")); err != nil {
		t.Fatalf("seeding go.mod blob: %v", err)
	}

	var buf bytes.Buffer
	uc := modcacheUseCaseWithBlobs(t, facts, delegatingModcacheBlobs{fakeBlob: blobs}, &buf)
	// Forced, because an unforced run over readable artefacts is a cache hit and
	// never reaches the write side at all.
	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord, Force: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Record.ContentHash != seeded.ContentHash {
		t.Errorf("refused run returned %q/%q, want the kept record",
			res.Record.VerificationStatus, res.Record.ContentLocation)
	}
	if got := storedRecord(t, facts); got.ContentHash != seeded.ContentHash {
		t.Error("the stored record was replaced by the weaker measurement")
	}
}

// TestRefusedDowngradeReturnsMeasuredArtefactsWhenKeptRecordIsUnreadable pins the
// interaction between the two halves of the fix. The read side re-fetches a
// record whose blobs this run cannot resolve; the write side then refuses to
// overwrite it. Returning the kept record would hand back the same unreadable
// handle the re-fetch existed to avoid, so the store keeps the stronger fact
// while the caller gets the artefacts this run actually measured.
func TestRefusedDowngradeReturnsMeasuredArtefactsWhenKeptRecordIsUnreadable(t *testing.T) {
	facts := newFakeFacts()
	seeded := seedStoredRecord(t, facts, domain2.Verified, domain2.AcquisitionProxy)
	var buf bytes.Buffer
	uc := modcacheUseCase(t, facts, &buf)

	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Record.ContentLocation == seeded.ContentLocation {
		t.Error("the caller was handed the unreadable handle the re-fetch existed to avoid")
	}
	if got := storedRecord(t, facts); got.ContentHash != seeded.ContentHash {
		t.Error("the stored record was replaced by the weaker measurement")
	}
}

// TestRefusedDowngradeLogsBothStatusesAndModes pins the operator-visible half of
// the fix: a --from-modcache run over a network-verified store must be visibly a
// no-op, naming what it kept and what it discarded, rather than silently doing
// nothing.
func TestRefusedDowngradeLogsBothStatusesAndModes(t *testing.T) {
	facts := newFakeFacts()
	seedStoredRecord(t, facts, domain2.Verified, domain2.AcquisitionProxy)
	var buf bytes.Buffer
	uc := modcacheUseCase(t, facts, &buf)

	if _, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	logged := buf.String()
	var warnLines []string
	for _, line := range strings.Split(strings.TrimSpace(logged), "\n") {
		if strings.Contains(line, "level=WARN") {
			warnLines = append(warnLines, line)
		}
	}
	if len(warnLines) != 1 {
		t.Fatalf("want exactly one WARN, got %d:\n%s", len(warnLines), logged)
	}
	for _, want := range []string{
		"record_write_refused_weaker_verification",
		"existing_verification_status=Verified",
		"incoming_verification_status=VerifiedBySumDBOnly",
		"existing_acquisition_mode=proxy",
		"incoming_acquisition_mode=modcache",
		"force=false",
	} {
		if !strings.Contains(warnLines[0], want) {
			t.Errorf("WARN does not name %q:\n%s", want, warnLines[0])
		}
	}
}

// TestRefusedDowngradeIsAuditedWithTheForceFlag closes the provenance gap the
// ticket's investigation ran into: audit.jsonl recorded a demotion as an
// ordinary second fact_record_written entry, with no record of what it displaced
// or whether the run was forced, so the vector could not be reconstructed.
func TestRefusedDowngradeIsAuditedWithTheForceFlag(t *testing.T) {
	facts := newFakeFacts()
	seedStoredRecord(t, facts, domain2.Verified, domain2.AcquisitionProxy)
	sink := newFakeAudit()
	var buf bytes.Buffer
	uc := modcacheUseCase(t, facts, &buf).WithAudit(sink)

	if _, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord, Force: true}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	e := sink.only(t)
	if e.Type != audit.EventFactRecordWriteRefused {
		t.Fatalf("audit event type = %q, want %q", e.Type, audit.EventFactRecordWriteRefused)
	}
	want := map[string]any{
		"module":                       testCoord.Path(),
		"version":                      testCoord.Version(),
		"existing_verification_status": string(domain2.Verified),
		"incoming_verification_status": string(domain2.VerifiedBySumDBOnly),
		"existing_acquisition_mode":    string(domain2.AcquisitionProxy),
		"incoming_acquisition_mode":    string(domain2.AcquisitionModcache),
		"force":                        true,
	}
	for k, v := range want {
		if got := e.Payload[k]; got != v {
			t.Errorf("audit payload[%q] = %v, want %v", k, got, v)
		}
	}
}

// TestExplicitDowngradeFlagIsTheOnlyWayToWeakenAnAnchor pins the escape hatch and
// its separation from --force: only the operator saying so replaces a stronger
// record, and doing so is itself recorded.
func TestExplicitDowngradeFlagIsTheOnlyWayToWeakenAnAnchor(t *testing.T) {
	facts := newFakeFacts()
	seeded := seedStoredRecord(t, facts, domain2.Verified, domain2.AcquisitionProxy)
	sink := newFakeAudit()
	var buf bytes.Buffer
	uc := modcacheUseCase(t, facts, &buf).WithAudit(sink).WithAllowVerificationDowngrade(true)

	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Record.ContentHash == seeded.ContentHash {
		t.Fatal("the explicit downgrade flag did not replace the stronger record")
	}
	stored := storedRecord(t, facts)
	if stored.VerificationStatus != string(domain2.VerifiedBySumDBOnly) {
		t.Errorf("stored VerificationStatus = %q, want %q", stored.VerificationStatus, domain2.VerifiedBySumDBOnly)
	}
	if stored.AcquisitionMode != string(domain2.AcquisitionModcache) {
		t.Errorf("stored AcquisitionMode = %q, want %q", stored.AcquisitionMode, domain2.AcquisitionModcache)
	}
	if e := sink.only(t); e.Type != audit.EventFactRecordDowngraded {
		t.Errorf("audit event type = %q, want %q", e.Type, audit.EventFactRecordDowngraded)
	}
}

// TestNetworkRecordSurvivesAModcacheRunAndStillHitsTheCache is the end-to-end
// shape of the reported symptom. Before the fix the two modes flip-flopped: the
// modcache run overwrote the network record with a handle the local blob store
// rejects, and the next network run re-fetched, so the cache never settled for a
// coordinate touched by both.
func TestNetworkRecordSurvivesAModcacheRunAndStillHitsTheCache(t *testing.T) {
	facts := newFakeFacts()
	blobs := newFakeBlob()
	seeded := seedStoredRecord(t, facts, domain2.Verified, domain2.AcquisitionProxy)
	// The blobs a network run would have written, under the identities the record
	// names, so the record's artefacts resolve.
	if err := blobs.Put(context.Background(), fetchtest.ZipIdentity(t, seeded), strings.NewReader("seed-zip")); err != nil {
		t.Fatalf("seeding zip blob: %v", err)
	}
	if err := blobs.Put(context.Background(), fetchtest.GoModIdentity(t, seeded), strings.NewReader("seed-gomod")); err != nil {
		t.Fatalf("seeding go.mod blob: %v", err)
	}

	// Run 2: --from-modcache. It cannot read the network handles, so it re-fetches
	// and reaches the write side — where its weaker anchor is refused.
	var buf bytes.Buffer
	if _, err := modcacheUseCase(t, facts, &buf).Execute(context.Background(),
		application.FetchRequest{Coordinate: testCoord}); err != nil {
		t.Fatalf("modcache Execute: %v", err)
	}
	if got := storedRecord(t, facts); got.ContentLocation != seeded.ContentLocation {
		t.Fatalf("modcache run replaced the network handle: %q", got.ContentLocation)
	}

	// Run 3: back on the network path. A proxy that refuses to download proves the
	// record was served from cache rather than re-fetched.
	network := newUseCaseWithSumDB(
		&fakeProxy{dlErr: errors.New("download must not run: the cache should have settled")},
		&fakeVCS{}, blobs, facts, disabledSumDB(),
	)
	res, err := network.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("network Execute: %v", err)
	}
	if !res.FromCache {
		t.Error("the network run re-fetched: the two modes are still flip-flopping")
	}
}

// TestReadFailureBeforeOverwriteFailsTheFetch keeps the guard from degrading into
// a silent overwrite: if the existing record cannot be read, whether the write
// would demote it is undecidable, so the fetch fails rather than guessing.
func TestReadFailureBeforeOverwriteFailsTheFetch(t *testing.T) {
	// Force=true skips the cache check, so the pre-overwrite read is the first
	// GetFetchRecord this fetch makes.
	facts := &readFailingFacts{fakeFacts: newFakeFacts(), failAfter: 0}
	var buf bytes.Buffer
	uc := modcacheUseCase(t, facts, &buf)

	_, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord, Force: true})
	if err == nil {
		t.Fatal("a fact-store read failure before the overwrite was swallowed")
	}
	if !strings.Contains(err.Error(), "reading existing records before append") {
		t.Errorf("error does not name the failing step: %v", err)
	}
}

// readFailingFacts fails GetFetchRecord from call failAfter+1 onward, so a test
// can let the cache check succeed and fail only the pre-overwrite read.
type readFailingFacts struct {
	*fakeFacts
	failAfter int
	calls     int
}

func (f *readFailingFacts) GetFetchRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pv string) (domain2.CompositeRecord, bool, error) {
	f.calls++
	if f.calls > f.failAfter {
		return domain2.CompositeRecord{}, false, errors.New("fact store unavailable")
	}
	return f.fakeFacts.GetFetchRecord(ctx, coord, pv)
}
