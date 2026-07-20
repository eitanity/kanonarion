package cli

import (
	"bytes"
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"

	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
)

func diffCoords() (coordinate.ModuleCoordinate, coordinate.ModuleCoordinate) {
	return coordinate.ModuleCoordinate{Path: "example.com/m", Version: "v1.0.0"},
		coordinate.ModuleCoordinate{Path: "example.com/m", Version: "v2.0.0"}
}

// A missing record on either side => ExitNotFound (absence surfaced, never
// reported as "no change"). This is the handler-level contract; the renderer
// and the diff use case are tested separately.
func TestLicenseDiffWith_RecordNotFound(t *testing.T) {
	a, b := diffCoords()
	ctr := &Container{DiffLicense: &testfakes.FakeDiffLicense{
		Err: &licapp.ErrLicenseRecordNotFound{Coordinate: a},
	}}
	var out bytes.Buffer
	err := licenseDiffWith(context.Background(), ctr, a, b, &out)
	requireExit(t, err, ExitNotFound)
}

// A successful diff renders (text mode) and exits 0.
func TestLicenseDiffWith_RendersDiff(t *testing.T) {
	a, b := diffCoords()
	ctr := &Container{DiffLicense: &testfakes.FakeDiffLicense{Result: licdomain.LicenseDiff{}}}
	var out bytes.Buffer
	if err := licenseDiffWith(context.Background(), ctr, a, b, &out); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if out.Len() == 0 {
		t.Error("expected rendered diff output")
	}
}
