package application_test

import (
	"context"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/license/application"
	"github.com/eitanity/kanonarion/internal/license/domain"
)

// synthDetermination is an obviously invented determination, for the reason
// synthDeclaration gives: a fixture that reads like a real operator's finding
// is one copy-paste away from a published document.
func synthDetermination(spdx string) domain.LicenseOverride {
	return domain.LicenseOverride{
		SPDX:       spdx,
		DeclaredBy: "test-operator@example.invalid",
		DeclaredOn: "2026-09-19",
		Basis:      "synthetic fixture; no upstream source was read",
	}
}

func determinationSet(key string, o domain.LicenseOverride) domain.LicenseOverrideSet {
	return domain.NewLicenseOverrideSet(map[string]domain.LicenseOverride{key: o})
}

// seedUngranted records a module the detector read and found no licence in, and
// whose archive holds no licence file to read — the dgoogauth shape: source, a
// README, and no grant the detector recognises.
func seedUngranted(
	t *testing.T,
	licences *fakeLicenseStore,
	coord coordinate.ModuleCoordinate,
	copyrightStatus domain.CopyrightStatus,
) {
	t.Helper()
	rec := domain.LicenseRecord{
		SchemaVersion:   domain.LicenseSchemaVersion,
		Coordinate:      coord,
		OverallStatus:   domain.LicenseStatusNone,
		CopyrightStatus: copyrightStatus,
		PipelineVersion: application.PipelineVersion,
	}
	var h domain.LicenseRecordHasher
	rec, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := licences.PutLicenseRecord(context.Background(), rec); err != nil {
		t.Fatalf("PutLicenseRecord: %v", err)
	}
}

// TestGenerateNotice_DeterminationClearsNoLicenceFound is the ticket's case: a
// module whose grant is not in any file the detector recognises resolves to
// None, and the operator's recorded determination settles it. The entry
// publishes the operator's identifier and says both that it is theirs and what
// the detector found.
func TestGenerateNotice_DeterminationClearsNoLicenceFound(t *testing.T) {
	licences := &fakeLicenseStore{}
	coord := mustCoord(t, "example.com/ungranted", "v1.0.0")
	seedUngranted(t, licences, coord, domain.CopyrightStatusFound)

	ov := synthDetermination("Apache-2.0")
	uc := buildNoticeUseCase(t, nil, nil, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
		Overrides:   determinationSet("example.com/ungranted", ov),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.ReviewItems) != 0 {
		t.Fatalf("the determination did not clear the gate: %v", result.ReviewItems)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(result.Entries))
	}
	e := result.Entries[0]
	if e.SPDX != "Apache-2.0" {
		t.Errorf("published identity = %q, want the operator's Apache-2.0", e.SPDX)
	}
	if e.Determination == nil {
		t.Fatal("the entry does not say the identity was determined by a person")
	}
	if e.Determination.Override.DeclaredBy != ov.DeclaredBy ||
		e.Determination.Override.DeclaredOn != ov.DeclaredOn ||
		e.Determination.Override.Basis != ov.Basis {
		t.Errorf("provenance not carried through: %+v", e.Determination.Override)
	}
	if e.Determination.Override.Key != "example.com/ungranted" || e.Determination.Override.VersionPinned {
		t.Errorf("matched key not stamped: key=%q pinned=%v",
			e.Determination.Override.Key, e.Determination.Override.VersionPinned)
	}
	if !strings.Contains(e.Determination.DetectorFinding, "no licence") {
		t.Errorf("detector finding = %q, want it to report what the detector found",
			e.Determination.DetectorFinding)
	}
}

// TestGenerateNotice_NoDeterminationStillRefuses is the control: the same
// module with nothing recorded still fires the gate, and the review item says
// the operator can settle it.
func TestGenerateNotice_NoDeterminationStillRefuses(t *testing.T) {
	licences := &fakeLicenseStore{}
	coord := mustCoord(t, "example.com/ungranted", "v1.0.0")
	seedUngranted(t, licences, coord, domain.CopyrightStatusFound)

	uc := buildNoticeUseCase(t, nil, nil, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.Entries) != 0 {
		t.Fatalf("a module with no determination was published: %+v", result.Entries)
	}
	if len(result.ReviewItems) != 1 {
		t.Fatalf("got %d review items, want 1", len(result.ReviewItems))
	}
	if !result.ReviewItems[0].UndeterminedLicence {
		t.Error("the review item is not marked as one a determination can clear")
	}
}

// TestGenerateNotice_DeterminationOfAnotherModuleDoesNotCarry: the set is
// resolved per coordinate, so a determination recorded for a different module
// settles nothing here. Without this, any non-empty override set would look
// like it worked on the module under test.
func TestGenerateNotice_DeterminationOfAnotherModuleDoesNotCarry(t *testing.T) {
	licences := &fakeLicenseStore{}
	coord := mustCoord(t, "example.com/ungranted", "v1.0.0")
	seedUngranted(t, licences, coord, domain.CopyrightStatusFound)

	uc := buildNoticeUseCase(t, nil, nil, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
		Overrides:   determinationSet("example.com/somethingelse", synthDetermination("MIT")),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.ReviewItems) != 1 || len(result.Entries) != 0 {
		t.Fatalf("a determination for another module cleared this one: entries=%+v reviews=%+v",
			result.Entries, result.ReviewItems)
	}
}

// TestGenerateNotice_DeterminationElectsAnAmbiguousArm: an ambiguity is the
// other gate a determination clears, and the licence text the module DOES ship
// is still reproduced verbatim beside it.
func TestGenerateNotice_DeterminationElectsAnAmbiguousArm(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	licences := &fakeLicenseStore{}

	coord := mustCoord(t, "example.com/ambiguous", "v1.0.0")
	const text = "a licence text the detector could not settle"
	seedModule(t, facts, blobs, licences, coord, "MIT",
		"Copyright 2021 SYNTHETIC-FIXTURE-HOLDER", text,
		domain.LicenceStatusAmbiguous, domain.CopyrightStatusFound)

	uc := buildNoticeUseCase(t, facts, blobs, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
		Overrides:   determinationSet("example.com/ambiguous", synthDetermination("BSD-3-Clause")),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.ReviewItems) != 0 {
		t.Fatalf("the election did not clear the ambiguity: %v", result.ReviewItems)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(result.Entries))
	}
	e := result.Entries[0]
	if e.SPDX != "BSD-3-Clause" {
		t.Errorf("published identity = %q, want the elected BSD-3-Clause", e.SPDX)
	}
	if len(e.LicenseTexts) != 1 || e.LicenseTexts[0].Content != text {
		t.Errorf("the shipped licence text was not reproduced: %+v", e.LicenseTexts)
	}
	if e.Determination == nil || !strings.Contains(e.Determination.DetectorFinding, "ambiguous") {
		t.Errorf("the entry does not report what the detector made of the module: %+v", e.Determination)
	}
}

// TestGenerateNotice_DeterminationDoesNotClearAFailedExtraction: a failed
// extraction measured nothing, so there is no detector answer for a
// determination to supersede and the remedy is still to make the measurement.
func TestGenerateNotice_DeterminationDoesNotClearAFailedExtraction(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	licences := &fakeLicenseStore{}

	coord := mustCoord(t, "example.com/failed", "v1.0.0")
	seedModule(t, facts, blobs, licences, coord, "", "", "",
		domain.LicenseStatusExtractionFailed, domain.CopyrightStatusNoneFound)

	uc := buildNoticeUseCase(t, facts, blobs, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
		Overrides:   determinationSet("example.com/failed", synthDetermination("MIT")),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.Entries) != 0 {
		t.Fatalf("a failed extraction was published on a determination: %+v", result.Entries)
	}
	if len(result.ReviewItems) != 1 {
		t.Fatalf("got %d review items, want 1", len(result.ReviewItems))
	}
	if result.ReviewItems[0].UndeterminedLicence {
		t.Error("a failed extraction is marked as a determination can clear it; it cannot")
	}
}

// TestGenerateNotice_DeterminationIsTheIdentityOnAMeasuredModule: where the
// detector DID settle on an identity and the operator has recorded a different
// one, the document publishes the operator's — the answer license-compat, audit
// and license-list already give for that module — and marks it. A document
// disagreeing with every other surface about the same module is the defect this
// rule exists to prevent.
func TestGenerateNotice_DeterminationIsTheIdentityOnAMeasuredModule(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	licences := &fakeLicenseStore{}

	coord := mustCoord(t, "example.com/detected", "v1.0.0")
	const text = "MIT License text"
	seedModule(t, facts, blobs, licences, coord, "MIT",
		"Copyright 2020 SYNTHETIC-FIXTURE-HOLDER", text,
		domain.LicenseStatusDetected, domain.CopyrightStatusFound)

	uc := buildNoticeUseCase(t, facts, blobs, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
		Overrides:   determinationSet("example.com/detected", synthDetermination("BSD-2-Clause")),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(result.Entries))
	}
	e := result.Entries[0]
	if e.SPDX != "BSD-2-Clause" {
		t.Errorf("published identity = %q, want the operator's BSD-2-Clause", e.SPDX)
	}
	if e.Determination == nil || e.Determination.DetectorFinding != "MIT" {
		t.Errorf("the detector's own answer is not reported beside it: %+v", e.Determination)
	}
	if len(e.LicenseTexts) != 1 || e.LicenseTexts[0].Content != text {
		t.Errorf("the shipped licence text was dropped: %+v", e.LicenseTexts)
	}
}

// TestGenerateNotice_UnattributedDeterminationStillSettles: an override
// recorded as a bare identifier — the form every config file written before the
// attributed one holds, and the one `config set` writes — settles the module
// too. The entry then carries no provenance, which the document must say rather
// than imply an author.
func TestGenerateNotice_UnattributedDeterminationStillSettles(t *testing.T) {
	licences := &fakeLicenseStore{}
	coord := mustCoord(t, "example.com/ungranted", "v1.0.0")
	seedUngranted(t, licences, coord, domain.CopyrightStatusFound)

	uc := buildNoticeUseCase(t, nil, nil, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
		Overrides:   determinationSet("example.com/ungranted", domain.LicenseOverride{SPDX: "MIT"}),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.ReviewItems) != 0 {
		t.Fatalf("a bare determination did not clear the gate: %v", result.ReviewItems)
	}
	if len(result.Entries) != 1 || result.Entries[0].Determination == nil {
		t.Fatalf("entries = %+v, want one marked as an operator determination", result.Entries)
	}
	if result.Entries[0].Determination.Override.Attributed() {
		t.Error("a bare determination reports as attributed; it names nobody")
	}
}

// TestGenerateNotice_DeterminationDoesNotSubstituteForExtraction: a module with
// no licence record at all has not been measured, and a determination recorded
// ahead of the measurement is a guess. The remedy stays "run kanonarion
// license".
func TestGenerateNotice_DeterminationDoesNotSubstituteForExtraction(t *testing.T) {
	licences := &fakeLicenseStore{}
	coord := mustCoord(t, "example.com/norecord", "v1.0.0")

	uc := buildNoticeUseCase(t, nil, nil, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
		Overrides:   determinationSet("example.com/norecord", synthDetermination("MIT")),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.Entries) != 0 {
		t.Fatalf("an unmeasured module was published on a determination: %+v", result.Entries)
	}
	if len(result.ReviewItems) != 1 || result.ReviewItems[0].UndeterminedLicence {
		t.Fatalf("review items = %+v, want one that extraction — not a determination — clears",
			result.ReviewItems)
	}
}
