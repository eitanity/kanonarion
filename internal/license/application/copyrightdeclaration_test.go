package application_test

import (
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/license/application"
	"github.com/eitanity/kanonarion/internal/license/domain"
)

// synthDeclaration is an obviously invented declaration. Real copyright lines
// are never invented in tests: a fixture that reads like a genuine upstream
// attribution is one copy-paste away from a published document.
func synthDeclaration(line string) domain.CopyrightDeclaration {
	return domain.CopyrightDeclaration{
		Copyright:  line,
		DeclaredBy: "test-operator@example.invalid",
		DeclaredOn: "2026-08-25",
		Basis:      "synthetic fixture; no upstream source was read",
	}
}

// TestGenerateNotice_DeclarationClearsMissingCopyright: a module whose archive
// carries no copyright, with a declaration recorded, is attributed rather than
// held back — and the entry says the line is the operator's.
func TestGenerateNotice_DeclarationClearsMissingCopyright(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	licences := &fakeLicenseStore{}

	coord := mustCoord(t, "example.com/nocopyright", "v1.0.0")
	seedModule(t, facts, blobs, licences, coord, "Apache-2.0",
		"", "Apache License text", domain.LicenseStatusDetected, domain.CopyrightStatusNoneFound)

	decl := synthDeclaration("Copyright SYNTHETIC-FIXTURE-HOLDER")
	uc := buildNoticeUseCase(t, facts, blobs, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
		Declarations: domain.NewCopyrightDeclarationSet(map[string]domain.CopyrightDeclaration{
			"example.com/nocopyright": decl,
		}),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.ReviewItems) != 0 {
		t.Fatalf("declaration did not clear the gate: %v", result.ReviewItems)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(result.Entries))
	}
	e := result.Entries[0]
	if e.Declaration == nil {
		t.Fatal("entry carries no declaration")
	}
	if !e.DeclarationAttributes() {
		t.Error("DeclarationAttributes() = false; with nothing extracted the declaration IS the attribution")
	}
	if e.Declaration.Copyright != decl.Copyright || e.Declaration.Basis != decl.Basis {
		t.Errorf("declaration not carried through: %+v", *e.Declaration)
	}
	if e.Declaration.Key != "example.com/nocopyright" || e.Declaration.VersionPinned {
		t.Errorf("matched key not stamped: key=%q pinned=%v", e.Declaration.Key, e.Declaration.VersionPinned)
	}
}

// TestGenerateNotice_ExtractedCopyrightBeatsDeclaration is the falsifying case
// for the whole feature.
//
// A module that HAS an extracted copyright and ALSO has a declaration must
// attribute the extracted line. The naive implementation — resolve the
// declaration first and use it when present — passes every other test in this
// file and silently replaces a measurement with an assertion, which is the one
// outcome the store's claim to hold evidence cannot survive.
func TestGenerateNotice_ExtractedCopyrightBeatsDeclaration(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	licences := &fakeLicenseStore{}

	coord := mustCoord(t, "example.com/hascopyright", "v1.0.0")
	const extracted = "Copyright 2020 EXTRACTED-FROM-ARCHIVE"
	seedModule(t, facts, blobs, licences, coord, "MIT",
		extracted, "MIT License text", domain.LicenseStatusDetected, domain.CopyrightStatusFound)

	decl := synthDeclaration("Copyright 1999 DECLARED-BY-A-HUMAN")
	uc := buildNoticeUseCase(t, facts, blobs, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
		Declarations: domain.NewCopyrightDeclarationSet(map[string]domain.CopyrightDeclaration{
			"example.com/hascopyright": decl,
		}),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(result.Entries))
	}
	e := result.Entries[0]

	if len(e.Copyrights) != 1 || e.Copyrights[0] != extracted {
		t.Errorf("attributed copyrights = %v, want exactly [%q]: the measured line must be what the document attributes",
			e.Copyrights, extracted)
	}
	for _, c := range e.Copyrights {
		if c == decl.Copyright {
			t.Errorf("the declared line %q was merged into the attributed copyrights", c)
		}
	}
	if e.DeclarationAttributes() {
		t.Error("DeclarationAttributes() = true beside an extracted notice: the assertion has displaced the measurement")
	}
	if e.Declaration == nil {
		t.Error("the declaration was dropped; it is retained as corroboration, not discarded")
	}
}

// TestGenerateNotice_NoDeclarationStillRefuses: the module with neither an
// extracted copyright nor a declaration is still held back, and names itself.
func TestGenerateNotice_NoDeclarationStillRefuses(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	licences := &fakeLicenseStore{}

	declared := mustCoord(t, "example.com/declared", "v1.0.0")
	bare := mustCoord(t, "example.com/bare", "v1.0.0")
	for _, c := range []coordinate.ModuleCoordinate{declared, bare} {
		seedModule(t, facts, blobs, licences, c, "Apache-2.0",
			"", "Apache License text", domain.LicenseStatusDetected, domain.CopyrightStatusNoneFound)
	}

	uc := buildNoticeUseCase(t, facts, blobs, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{declared, bare},
		Declarations: domain.NewCopyrightDeclarationSet(map[string]domain.CopyrightDeclaration{
			"example.com/declared": synthDeclaration("Copyright SYNTHETIC-FIXTURE-HOLDER"),
		}),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.ReviewItems) != 1 {
		t.Fatalf("got %d review items, want exactly the one undeclared module: %v", len(result.ReviewItems), result.ReviewItems)
	}
	item := result.ReviewItems[0]
	if item.Coordinate != bare {
		t.Errorf("review item names %v, want %v", item.Coordinate, bare)
	}
	if !item.MissingCopyright {
		t.Error("MissingCopyright = false; the caller cannot key the remedy to the gate that fired")
	}
}

// TestGenerateNotice_DeclarationDoesNotSupplyAMissingLicence: a declaration is
// a copyright line, not a grant. A module with no licence stays under review
// however thoroughly its copyright is recorded.
func TestGenerateNotice_DeclarationDoesNotSupplyAMissingLicence(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	licences := &fakeLicenseStore{}

	coord := mustCoord(t, "example.com/nolicence", "v1.0.0")
	seedModule(t, facts, blobs, licences, coord, "",
		"", "", domain.LicenseStatusNone, domain.CopyrightStatusNoneFound)

	uc := buildNoticeUseCase(t, facts, blobs, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
		Declarations: domain.NewCopyrightDeclarationSet(map[string]domain.CopyrightDeclaration{
			"example.com/nolicence": synthDeclaration("Copyright SYNTHETIC-FIXTURE-HOLDER"),
		}),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.ReviewItems) != 1 {
		t.Fatalf("got %d review items, want 1", len(result.ReviewItems))
	}
	if result.ReviewItems[0].Reason != "no license found" {
		t.Errorf("reason = %q, want the licence gate to be what fired", result.ReviewItems[0].Reason)
	}
	if result.ReviewItems[0].MissingCopyright {
		t.Error("MissingCopyright = true on a licence-gate refusal; the copyright remedy does not apply")
	}
}
