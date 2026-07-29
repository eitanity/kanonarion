package domain_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// composeRecord builds a sealed generation for one coordinate. Every knob the
// ladder reads is a parameter, so a test can say which rung it is exercising.
type composeSpec struct {
	rooting      domain.Rooting
	completeness string
	snapshotAt   time.Time
	scannedAt    time.Time
	findings     []domain.VulnerabilityFinding
	status       domain.VulnerabilityStatus
	unscanReason domain.UnscanReason
}

func composeRecord(t *testing.T, s composeSpec) domain.VulnerabilityRecord {
	t.Helper()
	if s.snapshotAt.IsZero() {
		s.snapshotAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	if s.scannedAt.IsZero() {
		s.scannedAt = time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	}
	if s.status == "" {
		s.status = domain.StatusClean
		if len(s.findings) > 0 {
			s.status = domain.StatusAffected
		}
	}
	rec, err := domain.VulnerabilityRecordHasher{}.SetContentHash(domain.VulnerabilityRecord{
		Ecosystem:  fetchdomain.EcosystemGo,
		Coordinate: coordinatetest.MustNew("github.com/foo/bar", "v1.0.0"),
		WalkID:     "walk-1",
		Findings:   s.findings,
		DatabaseSnapshot: domain.DatabaseSnapshot{
			Source: "test", Version: s.snapshotAt.Format(time.RFC3339), RetrievedAt: s.snapshotAt,
		},
		OverallStatus:         s.status,
		UnscanReason:          s.unscanReason,
		ScannedAt:             s.scannedAt,
		PipelineVersion:       "v16",
		CallGraphCompleteness: s.completeness,
		Rooting:               s.rooting,
	})
	if err != nil {
		t.Fatalf("sealing compose fixture: %v", err)
	}
	return rec
}

func advisory(id string) []domain.VulnerabilityFinding {
	return []domain.VulnerabilityFinding{{ID: id, Summary: "summary of " + id, AffectedRange: "< v2"}}
}

// Compose refuses to answer about nothing. Absence is the store's word, not a
// composition of zero records.
func TestCompose_NoRecords(t *testing.T) {
	t.Parallel()
	if _, err := domain.Compose(nil); !errors.Is(err, domain.ErrNoRecordsToCompose) {
		t.Fatalf("Compose(nil) = %v, want ErrNoRecordsToCompose", err)
	}
}

// Rung 1: a later all-clear does not retire a finding. Recency is not a reason,
// and the ledger keeps both so the transition is auditable rather than silent.
func TestCompose_LaterCleanDoesNotRetireAFinding(t *testing.T) {
	t.Parallel()
	affected := composeRecord(t, composeSpec{
		rooting: domain.RootingIsolated, findings: advisory("GO-2026-0001"),
		scannedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
	})
	clean := composeRecord(t, composeSpec{
		rooting:   domain.RootingIsolated,
		scannedAt: time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC),
	})

	got, err := domain.Compose([]domain.VulnerabilityRecord{affected, clean})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.ContentHash != affected.ContentHash {
		t.Fatalf("composed %s, want the finding-bearing record", got.OverallStatus)
	}
}

// Rung 2: among records reporting nothing, the analysed one wins. A scan that
// could not look is not evidence of absence, however recent it is.
func TestCompose_AnalysedOutranksACoverageGap(t *testing.T) {
	t.Parallel()
	analysed := composeRecord(t, composeSpec{
		rooting: domain.RootingIsolated, status: domain.StatusClean,
		scannedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
	})
	gap := composeRecord(t, composeSpec{
		rooting: domain.RootingIsolated, status: domain.StatusUnscannable,
		unscanReason: domain.UnscanReasonNoGoMod,
		scannedAt:    time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC),
	})

	got, err := domain.Compose([]domain.VulnerabilityRecord{analysed, gap})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.ContentHash != analysed.ContentHash {
		t.Fatalf("composed the coverage gap over the analysed record")
	}
}

// Rung 3, and the correction this conversion turns on: a newer scan against a
// newer advisory database, backed by a weaker call graph, must not displace a
// better-founded record. Serving it would replace an established reachability
// answer with an unresolved one and call it an update.
func TestCompose_WeakerCallGraphDoesNotWinOnRecency(t *testing.T) {
	t.Parallel()
	wellFounded := composeRecord(t, composeSpec{
		rooting:      domain.RootingIsolated,
		completeness: string(callgraphdomain.CompletenessBuiltWithBodies),
		findings:     advisory("GO-2026-0001"),
		snapshotAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		scannedAt:    time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
	})
	newerButWeaker := composeRecord(t, composeSpec{
		rooting:      domain.RootingIsolated,
		completeness: string(callgraphdomain.CompletenessMetadataOnly),
		findings:     advisory("GO-2026-0001"),
		snapshotAt:   time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		scannedAt:    time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC),
	})

	got, err := domain.Compose([]domain.VulnerabilityRecord{wellFounded, newerButWeaker})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.ContentHash != wellFounded.ContentHash {
		t.Fatalf("composed the metadata-only scan over the built graph — recency stood in for authority")
	}
}

// Rung 4: at equal completeness the newer advisory database wins, because that
// axis is monotone — a later database knows about strictly more advisories.
func TestCompose_NewerSnapshotWinsAtEqualCompleteness(t *testing.T) {
	t.Parallel()
	older := composeRecord(t, composeSpec{
		rooting:      domain.RootingIsolated,
		completeness: string(callgraphdomain.CompletenessBuiltWithBodies),
		findings:     advisory("GO-2026-0001"),
		snapshotAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	newer := composeRecord(t, composeSpec{
		rooting:      domain.RootingIsolated,
		completeness: string(callgraphdomain.CompletenessBuiltWithBodies),
		findings:     advisory("GO-2026-0001"),
		snapshotAt:   time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	})

	got, err := domain.Compose([]domain.VulnerabilityRecord{older, newer})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if got.ContentHash != newer.ContentHash {
		t.Fatalf("composed the older snapshot at equal completeness")
	}
}

// Composition never merges: the record it serves is one that was stored, so its
// content hash still describes it. A merged answer would carry a hash
// describing neither measurement, which is the evidence chain gone.
func TestCompose_ServesAStoredRecordThatStillVerifies(t *testing.T) {
	t.Parallel()
	a := composeRecord(t, composeSpec{rooting: domain.RootingIsolated, findings: advisory("GO-2026-0001")})
	b := composeRecord(t, composeSpec{
		rooting: domain.RootingTargetRooted, scannedAt: time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC),
	})

	got, err := domain.Compose([]domain.VulnerabilityRecord{a, b})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if verr := (domain.VulnerabilityRecordHasher{}).VerifyContentHash(got); verr != nil {
		t.Fatalf("composed record does not verify: %v", verr)
	}
}

// ComposeAt never crosses the frame boundary. A caller asking about the
// isolated analysis is told there is none rather than being handed the
// target-rooted answer, which was computed against a different build.
func TestComposeAt_DoesNotCrossTheFrameBoundary(t *testing.T) {
	t.Parallel()
	targetRooted := composeRecord(t, composeSpec{rooting: domain.RootingTargetRooted})

	if _, ok, err := domain.ComposeAt([]domain.VulnerabilityRecord{targetRooted}, domain.RootingIsolated); err != nil || ok {
		t.Fatalf("ComposeAt(isolated) = found %v, err %v; want not found", ok, err)
	}
	got, ok, err := domain.ComposeAt([]domain.VulnerabilityRecord{targetRooted}, domain.RootingTargetRooted)
	if err != nil || !ok {
		t.Fatalf("ComposeAt(target-rooted) = found %v, err %v", ok, err)
	}
	if got.ContentHash != targetRooted.ContentHash {
		t.Fatalf("ComposeAt served the wrong record")
	}
}

// Records written before the frame was recorded still answer a frame-scoped
// read, but only while nothing in the group states a frame. Otherwise a store
// that has not been re-scanned would report "never measured" for every module.
func TestComposeAt_UnrecordedFrameAnswersOnlyWhileNoneIsStated(t *testing.T) {
	t.Parallel()
	legacy := composeRecord(t, composeSpec{rooting: domain.RootingUnrecorded})

	got, ok, err := domain.ComposeAt([]domain.VulnerabilityRecord{legacy}, domain.RootingIsolated)
	if err != nil || !ok {
		t.Fatalf("legacy-only group: found %v, err %v; want the legacy record", ok, err)
	}
	if got.ContentHash != legacy.ContentHash {
		t.Fatalf("legacy-only group served the wrong record")
	}

	stated := composeRecord(t, composeSpec{
		rooting: domain.RootingTargetRooted, scannedAt: time.Date(2026, 3, 3, 0, 0, 0, 0, time.UTC),
	})
	if _, ok, err := domain.ComposeAt([]domain.VulnerabilityRecord{legacy, stated}, domain.RootingIsolated); err != nil || ok {
		t.Fatalf("once a frame is stated, the unrecorded rows must stop matching: found %v, err %v", ok, err)
	}
}

// Composition is a function of the records, not of the order they arrive in.
func TestCompose_IsOrderIndependent(t *testing.T) {
	t.Parallel()
	recs := []domain.VulnerabilityRecord{
		composeRecord(t, composeSpec{rooting: domain.RootingIsolated, findings: advisory("GO-2026-0001")}),
		composeRecord(t, composeSpec{rooting: domain.RootingIsolated, findings: advisory("GO-2026-0002")}),
		composeRecord(t, composeSpec{rooting: domain.RootingIsolated, status: domain.StatusClean}),
	}
	forward, err := domain.Compose(recs)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	reversed := []domain.VulnerabilityRecord{recs[2], recs[1], recs[0]}
	backward, err := domain.Compose(reversed)
	if err != nil {
		t.Fatalf("Compose(reversed): %v", err)
	}
	if forward.ContentHash != backward.ContentHash {
		t.Fatalf("composition depends on input order: %s vs %s", forward.ContentHash, backward.ContentHash)
	}
}

// TestCompletenessRung_CoversEveryCallGraphLevel pins this domain's local rung
// ladder to the call-graph domain that owns the levels. A level added there and
// not here would silently fall to the bottom rung, which would let a new,
// better fidelity lose to an unrecorded one.
//
// The rung function is unexported, so the ordering is exercised through Compose:
// each level must beat the one below it.
func TestCompletenessRung_CoversEveryCallGraphLevel(t *testing.T) {
	t.Parallel()
	// Most complete first. Unknown is last: it is the zero value, and a record
	// that consulted no call graph must not displace one that did.
	// Taken from the domain that owns the ladder, in its published order, rather
	// than copied here: a copy is exactly how a level gets added there and misses
	// the rung function this test exists to pin.
	ladder := callgraphdomain.CompletenessLevels()
	for i := 0; i+1 < len(ladder); i++ {
		better := composeRecord(t, composeSpec{
			rooting: domain.RootingIsolated, completeness: string(ladder[i]),
			findings: advisory("GO-2026-0001"),
			// The weaker record is deliberately the newer one on every other axis,
			// so a pass can only come from the completeness rung.
			snapshotAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			scannedAt:  time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		})
		worse := composeRecord(t, composeSpec{
			rooting: domain.RootingIsolated, completeness: string(ladder[i+1]),
			findings:   advisory("GO-2026-0001"),
			snapshotAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			scannedAt:  time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC),
		})
		got, err := domain.Compose([]domain.VulnerabilityRecord{worse, better})
		if err != nil {
			t.Fatalf("Compose(%s vs %s): %v", ladder[i], ladder[i+1], err)
		}
		if got.ContentHash != better.ContentHash {
			t.Fatalf("%s lost to %s — the rung ladder does not cover both levels", ladder[i], ladder[i+1])
		}
	}
}

// The frame is a new field, so it must be absent from the canonical bytes when
// unset. That is the whole mechanism behind "no record is rehashed and no
// pipeline version is bumped": every stored record predates the field and
// carries none, so its sealed shape is unchanged.
func TestRooting_IsAbsentFromTheCanonicalFormWhenUnrecorded(t *testing.T) {
	t.Parallel()
	unrecorded := composeRecord(t, composeSpec{rooting: domain.RootingUnrecorded})
	blob, err := domain.VulnerabilityRecordHasher{}.Marshal(unrecorded)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(blob), "rooting") {
		t.Fatalf("an unrecorded frame emitted a rooting key: %s", blob)
	}

	stated := composeRecord(t, composeSpec{rooting: domain.RootingIsolated})
	statedBlob, err := domain.VulnerabilityRecordHasher{}.Marshal(stated)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var fields map[string]json.RawMessage
	if uerr := json.Unmarshal(statedBlob, &fields); uerr != nil {
		t.Fatalf("unmarshalling sealed record: %v", uerr)
	}
	if string(fields["rooting"]) != `"isolated"` {
		t.Fatalf("stated frame serialised as %s, want \"isolated\"", fields["rooting"])
	}
	// Stating the frame changes the seal, which is what makes the claim
	// tamper-evident rather than a label beside the record.
	if stated.ContentHash == unrecorded.ContentHash {
		t.Fatalf("the frame is outside the content hash — the claim is not covered by the seal")
	}
	// And the round trip keeps it, so a read never invents "not recorded".
	back, err := domain.VulnerabilityRecordHasher{}.Unmarshal(statedBlob)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if domain.RecordRooting(back) != domain.RootingIsolated {
		t.Fatalf("round trip lost the frame: %q", domain.RecordRooting(back))
	}
}

// The unrecorded frame renders as a statement rather than as a blank, so a
// report never shows an empty column a reader has to guess at.
func TestRooting_String(t *testing.T) {
	t.Parallel()
	if got := domain.RootingUnrecorded.String(); got != "not recorded" {
		t.Fatalf("RootingUnrecorded.String() = %q", got)
	}
	if domain.RootingUnrecorded.IsRecorded() {
		t.Fatal("the zero frame reports itself as recorded")
	}
	for _, r := range []domain.Rooting{domain.RootingIsolated, domain.RootingTargetRooted} {
		if !r.IsRecorded() || r.String() != string(r) {
			t.Fatalf("%q does not render as itself", r)
		}
	}
}

// TestComposeAt_TwoRootsAreTwoFrames is the regression for a defect measured on
// a working store rather than reasoned about.
//
// While the frame recorded only "target-rooted" and not WHICH target, a
// coordinate-rooted walk of golang.org/x/text@v0.37.0 landed in the same frame
// as a project walk of a consumer that reached it. Running later and computing
// no reachability, it displaced the consumer's "reachable" finding with one that
// had never asked the question — the dimension rule's failure reappearing inside
// the dimension.
func TestComposeAt_TwoRootsAreTwoFrames(t *testing.T) {
	t.Parallel()
	consumer := coordinatetest.MustNew("github.com/pbinitiative/zenbpm", "local")
	itself := coordinatetest.MustNew("golang.org/x/text", "v0.37.0")

	inConsumer := composeRecord(t, composeSpec{
		rooting:   domain.TargetRootedAt(consumer),
		findings:  advisory("GO-2026-5970"),
		scannedAt: time.Date(2026, 7, 28, 12, 2, 56, 0, time.UTC),
	})
	inItself := composeRecord(t, composeSpec{
		rooting:   domain.TargetRootedAt(itself),
		findings:  advisory("GO-2026-5970"),
		scannedAt: time.Date(2026, 7, 28, 12, 3, 50, 0, time.UTC),
	})
	all := []domain.VulnerabilityRecord{inConsumer, inItself}

	// The later scan rooted elsewhere does not answer for the consumer.
	got, ok, err := domain.ComposeAt(all, domain.TargetRootedAt(consumer))
	if err != nil || !ok {
		t.Fatalf("ComposeAt(consumer) = found %v, err %v", ok, err)
	}
	if got.ContentHash != inConsumer.ContentHash {
		t.Fatalf("a scan rooted at %s answered for %s", itself, consumer)
	}
	got, ok, err = domain.ComposeAt(all, domain.TargetRootedAt(itself))
	if err != nil || !ok {
		t.Fatalf("ComposeAt(itself) = found %v, err %v", ok, err)
	}
	if got.ContentHash != inItself.ContentHash {
		t.Fatalf("the frame rooted at %s served the consumer's record", itself)
	}

	// A root never scanned is absence, not the nearest other root.
	other := coordinatetest.MustNew("example.com/unrelated", "local")
	if _, ok, err := domain.ComposeAt(all, domain.TargetRootedAt(other)); err != nil || ok {
		t.Fatalf("ComposeAt(unscanned root) = found %v, err %v; want not found", ok, err)
	}
}

// The frame reports what it is rooted at, and the bare pre-root value keeps
// saying "target-rooted, root unstated" rather than being read as some root.
func TestRooting_TargetIsPartOfTheFrame(t *testing.T) {
	t.Parallel()
	target := coordinatetest.MustNew("github.com/pbinitiative/zenbpm", "local")
	frame := domain.TargetRootedAt(target)

	if !frame.IsRecorded() || !frame.IsTargetRooted() {
		t.Fatalf("%q does not report itself as a recorded target-rooted frame", frame)
	}
	if got := frame.RootTarget(); got != target.String() {
		t.Fatalf("RootTarget() = %q, want %q", got, target)
	}
	if frame == domain.TargetRootedAt(coordinatetest.MustNew("example.com/other", "local")) {
		t.Fatal("two roots produced the same frame")
	}

	if !domain.RootingTargetRooted.IsTargetRooted() {
		t.Fatal("the bare target-rooted value must still read as target-rooted")
	}
	if got := domain.RootingTargetRooted.RootTarget(); got != "" {
		t.Fatalf("the bare value named a root: %q", got)
	}
	for _, r := range []domain.Rooting{domain.RootingIsolated, domain.RootingUnrecorded} {
		if r.IsTargetRooted() || r.RootTarget() != "" {
			t.Fatalf("%q reported a target root", r)
		}
	}
}
