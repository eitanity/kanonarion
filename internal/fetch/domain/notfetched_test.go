package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
)

// The proxy has no artefact for a coordinate at the local version, so naming
// 'kanonarion fetch' for one sends the reader to a command that refuses it.
func TestNotFetchedRemedy_LocalCoordinateNamesTheRootIngestingWalk(t *testing.T) {
	coord, err := coordinate.NewLocalCoordinate("example.com/mod")
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}
	got := domain.NotFetchedRemedy(coord)
	if strings.Contains(got, "kanonarion fetch") {
		t.Errorf("remedy for %s names 'kanonarion fetch', which cannot reach it: %q", coord, got)
	}
	if !strings.Contains(got, "kanonarion walk --gomod ./go.mod --analyse-root") {
		t.Errorf("remedy for %s does not name the walk that ingests the tree: %q", coord, got)
	}
}

func TestNotFetchedRemedy_PublishedCoordinateNamesFetchWithTheCoordinate(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.2.3")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	got := domain.NotFetchedRemedy(coord)
	if want := "run 'kanonarion fetch example.com/mod@v1.2.3' first"; got != want {
		t.Errorf("remedy = %q, want %q", got, want)
	}
}
