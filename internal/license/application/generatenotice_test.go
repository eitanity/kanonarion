package application_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/license/application"
	"github.com/eitanity/kanonarion/internal/license/domain"
)

// buildNoticeUseCase is a test helper that wires a GenerateNoticeUseCase with
// fakes and pre-populated stores.
func buildNoticeUseCase(
	t *testing.T,
	facts *fakeFactStore,
	blobs *fakeBlobStore,
	licences *fakeLicenseStore,
) *application.GenerateNoticeUseCase {
	t.Helper()
	if facts == nil {
		facts = &fakeFactStore{}
	}
	if blobs == nil {
		blobs = &fakeBlobStore{}
	}
	if licences == nil {
		licences = &fakeLicenseStore{}
	}
	return application.NewGenerateNoticeUseCase(
		licences, facts, blobs,
		application.PipelineVersion,
	)
}

// seedModule is a helper that stores a fact record, module zip, and license record
// for coord using the given SPDX identifier and copyright line.
func seedModule(
	t *testing.T,
	facts *fakeFactStore,
	blobs *fakeBlobStore,
	licences *fakeLicenseStore,
	coord coordinate.ModuleCoordinate,
	spdx string,
	copyright string,
	licenseText string,
	status domain.LicenseStatus,
	copyrightStatus domain.CopyrightStatus,
) {
	t.Helper()

	zipData := buildModuleZip(t, coord, map[string]string{"LICENSE": licenseText})

	putFact(t, facts, blobs, coord, zipData)

	var stmts []domain.CopyrightStatement
	if copyright != "" {
		stmts = domain.ExtractCopyright("LICENSE", []byte(copyright+"\n"))
	}

	rec := domain.LicenseRecord{
		SchemaVersion:   domain.LicenseSchemaVersion,
		Coordinate:      coord,
		PrimarySPDX:     spdx,
		OverallStatus:   status,
		CopyrightStatus: copyrightStatus,
		PipelineVersion: application.PipelineVersion,
		LicenseFiles: []domain.LicenseFileEntry{
			{
				Path:                "LICENSE",
				SPDX:                spdx,
				Confidence:          0.99,
				CopyrightStatements: stmts,
			},
		},
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

// TestGenerateNotice_HappyPath verifies that two clean modules produce sorted
// NoticeEntries with verbatim license text and copyright statements.
func TestGenerateNotice_HappyPath(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	licences := &fakeLicenseStore{}

	// Seed two modules in reverse alphabetical order to verify sort.
	coordB := mustCoord(t, "example.com/b", "v1.0.0")
	coordA := mustCoord(t, "example.com/a", "v2.0.0")

	seedModule(t, facts, blobs, licences, coordB, "Apache-2.0",
		"Copyright 2021 B Authors", "Apache License text", domain.LicenseStatusDetected, domain.CopyrightStatusFound)
	seedModule(t, facts, blobs, licences, coordA, "MIT",
		"Copyright 2020 A Authors", "MIT License text", domain.LicenseStatusDetected, domain.CopyrightStatusFound)

	uc := buildNoticeUseCase(t, facts, blobs, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coordB, coordA},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if len(result.ReviewItems) != 0 {
		t.Fatalf("unexpected review items: %v", result.ReviewItems)
	}
	if len(result.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(result.Entries))
	}

	// Verify sorted order: a before b.
	if result.Entries[0].Coordinate.Path() != "example.com/a" {
		t.Errorf("entries[0].Path = %q, want example.com/a", result.Entries[0].Coordinate.Path())
	}
	if result.Entries[1].Coordinate.Path() != "example.com/b" {
		t.Errorf("entries[1].Path = %q, want example.com/b", result.Entries[1].Coordinate.Path())
	}

	// Verify verbatim text.
	if len(result.Entries[0].LicenseTexts) == 0 {
		t.Fatal("entries[0]: no license texts")
	}
	if result.Entries[0].LicenseTexts[0].Content != "MIT License text" {
		t.Errorf("entries[0] license text = %q, want MIT License text", result.Entries[0].LicenseTexts[0].Content)
	}

	// Verify copyright.
	if len(result.Entries[0].Copyrights) == 0 {
		t.Fatal("entries[0]: no copyrights")
	}
	if result.Entries[0].Copyrights[0] != "Copyright 2020 A Authors" {
		t.Errorf("entries[0] copyright = %q", result.Entries[0].Copyrights[0])
	}
}

// TestGenerateNotice_AmbiguousTriggersReview verifies that an Ambiguous module
// is added to ReviewItems, not Entries.
func TestGenerateNotice_AmbiguousTriggersReview(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	licences := &fakeLicenseStore{}

	coord := mustCoord(t, "example.com/ambig", "v1.0.0")
	seedModule(t, facts, blobs, licences, coord, "MIT",
		"Copyright 2021 Someone", "License text", domain.LicenceStatusAmbiguous, domain.CopyrightStatusFound)

	uc := buildNoticeUseCase(t, facts, blobs, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.Entries) != 0 {
		t.Fatalf("expected no entries, got %d", len(result.Entries))
	}
	if len(result.ReviewItems) != 1 {
		t.Fatalf("expected 1 review item, got %d", len(result.ReviewItems))
	}
	if result.ReviewItems[0].Coordinate != coord {
		t.Errorf("review item coordinate = %v, want %v", result.ReviewItems[0].Coordinate, coord)
	}
}

// TestGenerateNotice_MultipleProducesEntry verifies that a Multiple-license
// module is included verbatim in the notice (not flagged for review), since
// verbatim inclusion of all root-level license texts satisfies attribution for
// compound and multi-file distributions.
func TestGenerateNotice_MultipleProducesEntry(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	licences := &fakeLicenseStore{}

	coord := mustCoord(t, "example.com/multi", "v1.0.0")
	seedModule(t, facts, blobs, licences, coord, "MIT",
		"Copyright 2021 Someone", "License text", domain.LicenseStatusMultiple, domain.CopyrightStatusFound)

	uc := buildNoticeUseCase(t, facts, blobs, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.ReviewItems) != 0 {
		t.Fatalf("expected 0 review items, got %d", len(result.ReviewItems))
	}
	if len(result.Entries) != 1 {
		t.Fatalf("expected 1 notice entry, got %d", len(result.Entries))
	}
}

// TestGenerateNotice_MissingCopyrightTriggersReview verifies that a module with
// NoneFound copyright status is flagged for review.
func TestGenerateNotice_MissingCopyrightTriggersReview(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	licences := &fakeLicenseStore{}

	coord := mustCoord(t, "example.com/nocopy", "v1.0.0")
	seedModule(t, facts, blobs, licences, coord, "MIT",
		"", "MIT License\n", domain.LicenseStatusDetected, domain.CopyrightStatusNoneFound)

	uc := buildNoticeUseCase(t, facts, blobs, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.Entries) != 0 {
		t.Fatalf("expected no entries, got %d", len(result.Entries))
	}
	if len(result.ReviewItems) != 1 {
		t.Fatalf("expected 1 review item, got %d", len(result.ReviewItems))
	}
}

// TestGenerateNotice_MissingRecord verifies that a module with no license
// record is flagged for review rather than causing an error.
func TestGenerateNotice_MissingRecord(t *testing.T) {
	uc := buildNoticeUseCase(t, nil, nil, nil)
	coord := mustCoord(t, "example.com/unanalysed", "v1.0.0")

	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.ReviewItems) != 1 {
		t.Fatalf("expected 1 review item, got %d", len(result.ReviewItems))
	}
}

// TestGenerateNotice_EmbeddedComponentTexts verifies that a module with
// vendored/subdirectory embedded components has their license texts collected
// into NoticeEntry.EmbeddedComponents.
func TestGenerateNotice_EmbeddedComponentTexts(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	licences := &fakeLicenseStore{}

	coord := mustCoord(t, "example.com/bundle", "v1.0.0")

	// Build zip with root LICENSE and a vendored BSD-3-Clause component.
	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE": "MIT License text",
		"vendor/github.com/google/snappy/LICENSE": "BSD-3-Clause text",
	})
	putFact(t, facts, blobs, coord, zipData)

	rootStmts := domain.ExtractCopyright("LICENSE", []byte("Copyright 2020 Authors\n"))
	licFiles := []domain.LicenseFileEntry{
		{
			Path:                "LICENSE",
			SPDX:                "MIT",
			Confidence:          0.99,
			IsVendored:          false,
			CopyrightStatements: rootStmts,
		},
		{
			Path:       "vendor/github.com/google/snappy/LICENSE",
			SPDX:       "BSD-3-Clause",
			Confidence: 0.97,
			IsVendored: true,
		},
	}
	rec := domain.LicenseRecord{
		SchemaVersion:   domain.LicenseSchemaVersion,
		Coordinate:      coord,
		PrimarySPDX:     "MIT",
		OverallStatus:   domain.LicenseStatusDetected,
		CopyrightStatus: domain.CopyrightStatusFound,
		PipelineVersion: application.PipelineVersion,
		LicenseFiles:    licFiles,
		EffectiveSet:    domain.DeriveEffectiveLicenseSet(licFiles),
	}
	var h domain.LicenseRecordHasher
	rec, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := licences.PutLicenseRecord(context.Background(), rec); err != nil {
		t.Fatalf("PutLicenseRecord: %v", err)
	}

	uc := buildNoticeUseCase(t, facts, blobs, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.ReviewItems) != 0 {
		t.Fatalf("unexpected review items: %v", result.ReviewItems)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(result.Entries))
	}

	entry := result.Entries[0]
	// Root license text must be present.
	if len(entry.LicenseTexts) != 1 || entry.LicenseTexts[0].Content != "MIT License text" {
		t.Errorf("root LicenseTexts: %v", entry.LicenseTexts)
	}
	// Embedded component must be present.
	if len(entry.EmbeddedComponents) != 1 {
		t.Fatalf("EmbeddedComponents: got %d, want 1", len(entry.EmbeddedComponents))
	}
	comp := entry.EmbeddedComponents[0]
	if comp.PathPrefix != "vendor/github.com/google/snappy" {
		t.Errorf("EmbeddedComponents[0].PathPrefix = %q", comp.PathPrefix)
	}
	if len(comp.SPDXs) != 1 || comp.SPDXs[0] != "BSD-3-Clause" {
		t.Errorf("EmbeddedComponents[0].SPDXs = %v", comp.SPDXs)
	}
	if len(comp.LicenseTexts) != 1 {
		t.Fatalf("EmbeddedComponents[0].LicenseTexts: got %d, want 1", len(comp.LicenseTexts))
	}
	if comp.LicenseTexts[0].Content != "BSD-3-Clause text" {
		t.Errorf("embedded license content = %q, want BSD-3-Clause text", comp.LicenseTexts[0].Content)
	}
}

// TestGenerateNotice_Deterministic verifies that repeated calls with the same
// input produce identical ordering (regression test for sort stability).
func TestGenerateNotice_Deterministic(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	licences := &fakeLicenseStore{}

	coords := []coordinate.ModuleCoordinate{
		mustCoord(t, "example.com/z", "v1.0.0"),
		mustCoord(t, "example.com/a", "v1.0.0"),
		mustCoord(t, "example.com/m", "v1.0.0"),
	}
	for _, c := range coords {
		seedModule(t, facts, blobs, licences, c, "MIT",
			"Copyright 2021 Author", "MIT License text",
			domain.LicenseStatusDetected, domain.CopyrightStatusFound)
	}

	uc := buildNoticeUseCase(t, facts, blobs, licences)

	var paths1, paths2 []string
	for i := range 2 {
		result, err := uc.Generate(context.Background(), application.NoticeRequest{Coordinates: coords})
		if err != nil {
			t.Fatalf("run %d: Generate: %v", i, err)
		}
		var paths []string
		for _, e := range result.Entries {
			paths = append(paths, e.Coordinate.Path())
		}
		if i == 0 {
			paths1 = paths
		} else {
			paths2 = paths
		}
	}

	for i := range paths1 {
		if paths1[i] != paths2[i] {
			t.Errorf("non-deterministic: run1[%d]=%q run2[%d]=%q", i, paths1[i], i, paths2[i])
		}
	}
}

// TestGenerateNotice_ExcludesUnbuiltPaths is the ticket's regression case: a
// fixture module carrying a licence file under testdata/ and one outside it.
// Only the second is emitted.
//
// The three sibling forms of the same rule ride along, because they are the
// same defect: "_"- and "."-prefixed directories are ignored by the go tool
// exactly as testdata is, while examples/ and a nested vendor/ ARE compiled and
// must survive. A fix that drops those two has broken embedded-component
// detection for the case it was built for.
func TestGenerateNotice_ExcludesUnbuiltPaths(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	licences := &fakeLicenseStore{}

	coord := mustCoord(t, "example.com/fixtures", "v1.0.0")

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE": "MIT License text",
		// Never compiled: must not reach the document.
		"testdata/LICENSE":             "GPL-2.0 fixture text",
		"deep/testdata/corpus/LICENSE": "GPL-2.0 fixture text",
		"_ignored/LICENSE":             "GPL-2.0 fixture text",
		".hidden/LICENSE":              "GPL-2.0 fixture text",
		// Compiled and linkable: must reach the document.
		"examples/LICENSE":                        "BSD-3-Clause examples text",
		"vendor/github.com/google/snappy/LICENSE": "BSD-3-Clause vendored text",
	})
	putFact(t, facts, blobs, coord, zipData)

	rootStmts := domain.ExtractCopyright("LICENSE", []byte("Copyright 2020 Authors\n"))
	licFiles := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99, CopyrightStatements: rootStmts},
		{Path: "testdata/LICENSE", SPDX: "GPL-2.0", Confidence: 0.95},
		{Path: "deep/testdata/corpus/LICENSE", SPDX: "GPL-2.0", Confidence: 0.95},
		{Path: "_ignored/LICENSE", SPDX: "GPL-2.0", Confidence: 0.95},
		{Path: ".hidden/LICENSE", SPDX: "GPL-2.0", Confidence: 0.95},
		{Path: "examples/LICENSE", SPDX: "BSD-3-Clause", Confidence: 0.97},
		{Path: "vendor/github.com/google/snappy/LICENSE", SPDX: "BSD-3-Clause", Confidence: 0.97, IsVendored: true},
	}
	rec := domain.LicenseRecord{
		SchemaVersion:   domain.LicenseSchemaVersion,
		Coordinate:      coord,
		PrimarySPDX:     "MIT",
		OverallStatus:   domain.LicenseStatusDetected,
		CopyrightStatus: domain.CopyrightStatusFound,
		PipelineVersion: application.PipelineVersion,
		LicenseFiles:    licFiles,
		EffectiveSet:    domain.DeriveEffectiveLicenseSet(licFiles),
	}
	var h domain.LicenseRecordHasher
	rec, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := licences.PutLicenseRecord(context.Background(), rec); err != nil {
		t.Fatalf("PutLicenseRecord: %v", err)
	}

	uc := buildNoticeUseCase(t, facts, blobs, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(result.Entries))
	}

	var got []string
	for _, c := range result.Entries[0].EmbeddedComponents {
		got = append(got, c.PathPrefix)
		for _, lf := range c.LicenseTexts {
			if strings.Contains(lf.Content, "fixture") {
				t.Errorf("fixture content reached the document via %s (%s)", c.PathPrefix, lf.Path)
			}
		}
	}
	want := []string{"examples", "vendor/github.com/google/snappy"}
	if !slices.Equal(got, want) {
		t.Errorf("embedded components = %v, want %v", got, want)
	}

	// The derived set still holds every component: the exclusion belongs to
	// this consumer, not to the derivation.
	if len(rec.EffectiveSet.Components) != 6 {
		t.Errorf("EffectiveSet.Components = %d, want 6 (derivation must stay faithful to the zip)",
			len(rec.EffectiveSet.Components))
	}
}

// TestGenerateNotice_UnclassifiedRootFileIsRecordedNotReproduced pins the
// second half of the fix: a root-level licence-named file the detector could
// not classify is recorded — path, size, hash, any sub-threshold fragment —
// and its bytes are NOT reproduced, because printing unidentified bytes under
// the module's identifier asserts a grant they do not make.
//
// A NOTICE file is the exception: it declares no licence either, but
// Apache-2.0 section 4(d) requires it to travel with the work, so it is
// reproduced verbatim and labelled as a notice rather than as a licence.
func TestGenerateNotice_UnclassifiedRootFileIsRecordedNotReproduced(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	licences := &fakeLicenseStore{}

	coord := mustCoord(t, "example.com/unclassifiable", "v1.0.0")

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE":         "MIT License text",
		"LICENSE-LOGO":    "https://example.com/logo.png",
		"NOTICE":          "This product includes software developed by Someone.",
		"LICENSE-PARTIAL": "how to apply these terms to your new programs",
	})
	putFact(t, facts, blobs, coord, zipData)

	rootStmts := domain.ExtractCopyright("LICENSE", []byte("Copyright 2020 Authors\n"))
	licFiles := []domain.LicenseFileEntry{
		{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99, CopyrightStatements: rootStmts},
		{Path: "LICENSE-LOGO", FileSize: 28, FileHash: "sha256:deadbeef"},
		{Path: "LICENSE-PARTIAL", FileSize: 45, FileHash: "sha256:cafebabe",
			LowConfidenceSPDX: "AGPL-3.0", LowConfidenceCoverage: 0.11},
		{Path: "NOTICE", FileSize: 52, FileHash: "sha256:facefeed"},
	}
	rec := domain.LicenseRecord{
		SchemaVersion:   domain.LicenseSchemaVersion,
		Coordinate:      coord,
		PrimarySPDX:     "MIT",
		OverallStatus:   domain.LicenseStatusDetected,
		CopyrightStatus: domain.CopyrightStatusFound,
		PipelineVersion: application.PipelineVersion,
		LicenseFiles:    licFiles,
		EffectiveSet:    domain.DeriveEffectiveLicenseSet(licFiles),
	}
	var h domain.LicenseRecordHasher
	rec, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := licences.PutLicenseRecord(context.Background(), rec); err != nil {
		t.Fatalf("PutLicenseRecord: %v", err)
	}

	uc := buildNoticeUseCase(t, facts, blobs, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(result.Entries))
	}

	byPath := map[string]domain.NoticeLicenseFile{}
	for _, lf := range result.Entries[0].LicenseTexts {
		byPath[lf.Path] = lf
	}
	if len(byPath) != 4 {
		t.Fatalf("LicenseTexts paths = %v, want 4", byPath)
	}

	if lf := byPath["LICENSE"]; lf.Classification != domain.ClassificationLicence ||
		lf.SPDX != "MIT" || lf.Content != "MIT License text" {
		t.Errorf("LICENSE = %+v, want classified MIT with verbatim text", lf)
	}

	logo := byPath["LICENSE-LOGO"]
	if logo.Classification != domain.ClassificationUnclassified {
		t.Errorf("LICENSE-LOGO classification = %v, want Unclassified", logo.Classification)
	}
	if logo.Content != "" {
		t.Errorf("LICENSE-LOGO content reproduced: %q — unidentified bytes must be recorded, not printed", logo.Content)
	}
	if logo.SPDX != "" {
		t.Errorf("LICENSE-LOGO SPDX = %q, want empty — it must not borrow the module's identifier", logo.SPDX)
	}
	if logo.FileSize != 28 || logo.FileHash != "sha256:deadbeef" {
		t.Errorf("LICENSE-LOGO record = %d bytes %s, want the stored size and hash", logo.FileSize, logo.FileHash)
	}

	partial := byPath["LICENSE-PARTIAL"]
	if partial.Content != "" || partial.LowConfidenceSPDX != "AGPL-3.0" || partial.LowConfidenceCoverage != 0.11 {
		t.Errorf("LICENSE-PARTIAL = %+v, want recorded with its low-confidence fragment", partial)
	}

	notice := byPath["NOTICE"]
	if notice.Classification != domain.ClassificationNotice {
		t.Errorf("NOTICE classification = %v, want Notice", notice.Classification)
	}
	if notice.Content == "" {
		t.Error("NOTICE content withheld — Apache-2.0 section 4(d) requires it to travel with the work")
	}
	if notice.SPDX != "" {
		t.Errorf("NOTICE SPDX = %q, want empty — a notice declares no licence", notice.SPDX)
	}
}
