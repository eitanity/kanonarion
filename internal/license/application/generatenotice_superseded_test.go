package application_test

import (
	"context"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/license/application"
	"code.eitanity.com/kanonarion/internal/license/domain"
)

// supersededLicences holds generations no read composes: the composed read
// answers absence, the history lists them.
type supersededLicences struct {
	*fakeLicenseStore
	held []domain.LicenseRecord
}

func (s supersededLicences) GetLicenseRecord(context.Context, coordinate.ModuleCoordinate, string) (domain.LicenseRecord, bool, error) {
	return domain.LicenseRecord{}, false, nil
}

func (s supersededLicences) ListLicenseRecordsFor(context.Context, coordinate.ModuleCoordinate, string) ([]domain.LicenseRecord, error) {
	return s.held, nil
}

// supersedingFacts names every artefact in ids as superseded.
type supersedingFacts struct {
	*fakeFactStore
	ids map[string]bool
}

func (f supersedingFacts) SupersededLocalArtefacts(context.Context, coordinate.ModuleCoordinate) (map[string]bool, error) {
	return f.ids, nil
}

// A published coordinate whose only licence generations derive from a
// superseded directory read is reported as exactly that, with the command that
// measures the published module — not as one that was never extracted.
func TestGenerateNotice_SupersededOnlyCoordinateSaysSo(t *testing.T) {
	coord := mustCoord(t, "github.com/foo/uuid", "v1.6.0")
	held := []domain.LicenseRecord{{Coordinate: coord, ArtefactIdentity: "zip:h1:dir="}}
	uc := application.NewGenerateNoticeUseCase(
		supersededLicences{&fakeLicenseStore{}, held},
		supersedingFacts{&fakeFactStore{}, map[string]bool{"zip:h1:dir=": true}},
		&fakeBlobStore{}, application.PipelineVersion,
	)
	res, err := uc.Generate(context.Background(), application.NoticeRequest{Coordinates: []coordinate.ModuleCoordinate{coord}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(res.ReviewItems) != 1 || !strings.Contains(res.ReviewItems[0].Reason, "superseded by identity") ||
		!strings.Contains(res.ReviewItems[0].Reason, "kanonarion license github.com/foo/uuid@v1.6.0") {
		t.Errorf("review = %+v, want the superseded-generation statement and its remedy", res.ReviewItems)
	}

	// Control: a generation that is not superseded keeps the plain absence.
	uc = application.NewGenerateNoticeUseCase(
		supersededLicences{&fakeLicenseStore{}, held},
		supersedingFacts{&fakeFactStore{}, nil},
		&fakeBlobStore{}, application.PipelineVersion,
	)
	res, err = uc.Generate(context.Background(), application.NoticeRequest{Coordinates: []coordinate.ModuleCoordinate{coord}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(res.ReviewItems) != 1 || strings.Contains(res.ReviewItems[0].Reason, "superseded") {
		t.Errorf("review = %+v, want the plain absence", res.ReviewItems)
	}
}
