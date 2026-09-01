package application_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/example/application"
	"github.com/eitanity/kanonarion/internal/example/ports"
)

// Same hole as the licence surface: the local root cannot be fetched, so the
// refusal has to name the walk that ingests the working tree.
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
	got := err.Error()
	if strings.Contains(got, "kanonarion fetch") {
		t.Errorf("refusal names 'kanonarion fetch', which refuses a local coordinate: %s", got)
	}
	if !strings.Contains(got, "kanonarion walk --gomod ./go.mod --analyse-root") {
		t.Errorf("refusal does not name the walk that ingests the project's tree: %s", got)
	}
}
