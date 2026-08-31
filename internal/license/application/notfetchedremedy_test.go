package application_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/license/application"
	"github.com/eitanity/kanonarion/internal/license/ports"
)

// The project's own root sits in the store at the local version, which the
// proxy cannot serve, so a refusal naming 'kanonarion fetch' leaves the reader
// with no way to obtain the licence at all.
func TestExecute_LocalCoordinateRefusalNamesARunnableRemedy(t *testing.T) {
	uc := buildUseCase(t, nil, nil, nil)
	coord, err := coordinate.NewLocalCoordinate("example.com/mod")
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}

	_, err = uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if !errors.Is(err, ports.ErrModuleNotFetched) {
		t.Fatalf("Execute error = %v, want ErrModuleNotFetched", err)
	}
	assertLocalRemedyIsRunnable(t, err)
}

func assertLocalRemedyIsRunnable(t *testing.T, err error) {
	t.Helper()
	got := err.Error()
	if strings.Contains(got, "kanonarion fetch") {
		t.Errorf("refusal names 'kanonarion fetch', which refuses a local coordinate: %s", got)
	}
	if !strings.Contains(got, "kanonarion walk --gomod ./go.mod --analyse-root") {
		t.Errorf("refusal does not name the walk that ingests the project's tree: %s", got)
	}
}
