package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/license/domain"
)

func composeRecord(t *testing.T, coord coordinate.ModuleCoordinate, spdx string, confidence float64, at time.Time, artefact string) domain.LicenseRecord {
	t.Helper()
	r := domain.LicenseRecord{
		SchemaVersion:     domain.LicenseSchemaVersion,
		Ecosystem:         fetchdomain.EcosystemGo,
		Coordinate:        coord,
		PrimarySPDX:       spdx,
		PrimaryConfidence: confidence,
		OverallStatus:     domain.LicenseStatusDetected,
		ExtractedAt:       at,
		PipelineVersion:   "1.1.0",
		ArtefactIdentity:  artefact,
	}
	var h domain.LicenseRecordHasher
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

func composeCoord(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	return c
}

// TestCompose_IdentifiedRecordSupersedesUnidentified pins the upgrade path every
// module in the store is about to take: one legacy record naming no artefact,
// then a modern one naming the bytes it read. The legacy record cannot be shown
// to describe the same artefact, so it must not compete with the one that can —
// and it must not be reported as a conflict either, or the first re-extraction
// of any module would make it unreadable.
func TestCompose_IdentifiedRecordSupersedesUnidentified(t *testing.T) {
	t.Parallel()

	coord := composeCoord(t, "example.com/mod", "v1.0.0")
	legacy := composeRecord(t, coord, "MIT", 0.99, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), "")
	modern := composeRecord(t, coord, "Apache-2.0", 0.60, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		fetchtest.ZipArtefact("measured=").String())

	served, err := domain.Compose([]domain.LicenseRecord{legacy, modern})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	// Served despite its LOWER confidence: the ladder only orders records that
	// describe the same artefact, and the legacy record does not say which it
	// describes.
	if served.PrimarySPDX != "Apache-2.0" {
		t.Errorf("Compose served %q, want the record that names the artefact it read", served.PrimarySPDX)
	}
}

// TestCompose_TwoArtefactsForOnePinnedVersionIsReported pins the disagreement
// that has no ladder. Two records each naming a DIFFERENT artefact for one
// pinned version describe two different sets of bytes, so serving either answers
// a question about bytes the caller never named.
func TestCompose_TwoArtefactsForOnePinnedVersionIsReported(t *testing.T) {
	t.Parallel()

	coord := composeCoord(t, "example.com/mod", "v1.0.0")
	first := composeRecord(t, coord, "MIT", 0.99, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		fetchtest.ZipArtefact("bytes-one=").String())
	second := composeRecord(t, coord, "MIT", 0.99, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		fetchtest.ZipArtefact("bytes-two=").String())

	_, err := domain.Compose([]domain.LicenseRecord{first, second})
	var conflict domain.LicenceConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("Compose returned %v, want a LicenceConflict", err)
	}
	if conflict.Field != "artefact_identity" {
		t.Errorf("conflict names field %q, want artefact_identity", conflict.Field)
	}
}

// TestCompose_LocalCoordinateServesTheLastObservation pins the exemption. A
// local version pins no content — the working tree behind it is re-read every
// run — so its records are a sequence of observations, not competing claims. The
// confidence ladder would serve a state of the tree that no longer exists, which
// is how deleting a LICENSE file silently fails to register.
func TestCompose_LocalCoordinateServesTheLastObservation(t *testing.T) {
	t.Parallel()

	coord := composeCoord(t, "example.com/mod", "v0.0.0")
	if !coord.IsLocal() {
		t.Skipf("v0.0.0 is not the local version in this build; the exemption is keyed on IsLocal")
	}
	earlier := composeRecord(t, coord, "MIT", 0.99, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		fetchtest.ZipArtefact("tree-before=").String())
	later := composeRecord(t, coord, "", 0.0, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		fetchtest.ZipArtefact("tree-after=").String())

	served, err := domain.Compose([]domain.LicenseRecord{earlier, later})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if served.ContentHash != later.ContentHash {
		t.Errorf("Compose served an earlier observation of a mutating working tree; the licence removal would not register")
	}
}

// TestCompose_NoLicenceFoundDoesNotContradictOneThatWas pins why the conflict
// rule requires both SPDX values to be non-empty. A record that identified no
// licence makes no claim about WHICH licence, so pairing it with a detection is
// not a relicensing.
func TestCompose_NoLicenceFoundDoesNotContradictOneThatWas(t *testing.T) {
	t.Parallel()

	coord := composeCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("same-bytes=").String()
	none := composeRecord(t, coord, "", 0.0, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), artefact)
	found := composeRecord(t, coord, "MIT", 0.0, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact)

	served, err := domain.Compose([]domain.LicenseRecord{none, found})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if served.PrimarySPDX != "MIT" {
		t.Errorf("Compose served %q, want MIT", served.PrimarySPDX)
	}
}

// TestCompose_NearEqualConfidenceDisagreementIsReported pins the band rather
// than exact equality. The numbers are the ones measured on the maintainer's
// store: a real detection at 0.98816568047337283 against one at 0.99, naming
// different licence families. Exact equality would serve AGPL silently on a
// 0.002 margin.
func TestCompose_NearEqualConfidenceDisagreementIsReported(t *testing.T) {
	t.Parallel()

	coord := composeCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("same-bytes=").String()
	mit := composeRecord(t, coord, "MIT", 0.98816568047337283, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), artefact)
	agpl := composeRecord(t, coord, "AGPL-3.0-only", 0.99, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact)

	_, err := domain.Compose([]domain.LicenseRecord{mit, agpl})
	var conflict domain.LicenceConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("Compose returned %v, want a LicenceConflict: a 0.002 confidence margin silently changed the licence family", err)
	}
	if conflict.Field != "primary_spdx" {
		t.Errorf("conflict names field %q, want primary_spdx", conflict.Field)
	}
}

// TestCompose_ClearlyWeakerDisagreementIsStillARefinement pins the other edge of
// the band: outside it, the ladder resolves and no conflict is reported.
func TestCompose_ClearlyWeakerDisagreementIsStillARefinement(t *testing.T) {
	t.Parallel()

	coord := composeCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("same-bytes=").String()
	weak := composeRecord(t, coord, "MIT", 0.55, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), artefact)
	strong := composeRecord(t, coord, "AGPL-3.0-only", 0.99, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact)

	served, err := domain.Compose([]domain.LicenseRecord{weak, strong})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if served.PrimarySPDX != "AGPL-3.0-only" {
		t.Errorf("Compose served %q, want the confident AGPL-3.0-only", served.PrimarySPDX)
	}
}

// TestCompose_NoRecords is the programming-error case: absence is the store's
// answer, not composition's.
func TestCompose_NoRecords(t *testing.T) {
	t.Parallel()

	if _, err := domain.Compose(nil); !errors.Is(err, domain.ErrNoRecordsToCompose) {
		t.Errorf("Compose(nil) = %v, want ErrNoRecordsToCompose", err)
	}
}
