package domain_test

import (
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	"code.eitanity.com/kanonarion/internal/fetch/domain"
	"code.eitanity.com/kanonarion/internal/fetch/fetchtest"
)

// A local-source row under a published coordinate is left out of the read and
// counted; the published rows are composed untouched.
func TestSupersededLocalGenerations_PublishedCoordinate(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	published := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.ModuleHash(fetchtest.H1("pub==")))
	local := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("local-0.1.0"),
		fetchtest.Status(domain.LocalSource), fetchtest.ModuleHash(fetchtest.H1("dir==")))

	kept, superseded := domain.SupersededLocalGenerations(coord, []domain.FactRecord{published, local})
	if len(kept) != 1 || kept[0].ContentHash != published.ContentHash {
		t.Errorf("kept = %v, want only the published record", kept)
	}
	if len(superseded) != 1 || superseded[0].ContentHash != local.ContentHash {
		t.Errorf("superseded = %v, want only the local-source record", superseded)
	}
	if d := domain.FindDivergence(kept); d != nil {
		t.Errorf("the kept rows diverge: %v", d)
	}
	if d := domain.FindDivergence([]domain.FactRecord{published, local}); d == nil {
		t.Error("control: the two rows composed together must diverge, or this test proves nothing")
	}
}

// At the local identity every row is local source and every row is composed:
// they are the sequence of reads of one directory.
func TestSupersededLocalGenerations_LocalCoordinateKeepsAll(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/mod", coordinate.LocalVersion)
	a := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.Status(domain.LocalSource), fetchtest.ModuleHash(fetchtest.H1("a==")))
	b := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.Status(domain.LocalSource), fetchtest.ModuleHash(fetchtest.H1("b==")))

	kept, superseded := domain.SupersededLocalGenerations(coord, []domain.FactRecord{a, b})
	if len(kept) != 2 || len(superseded) != 0 {
		t.Errorf("kept %d, superseded %d; want 2 and 0", len(kept), len(superseded))
	}
}

// The artefacts named superseded are those only local-source rows carry: an
// identity a published row also carries is the published artefact.
func TestSupersededLocalArtefacts(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	published := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.ModuleHash(fetchtest.H1("pub==")))
	local := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.Status(domain.LocalSource), fetchtest.ModuleHash(fetchtest.H1("dir==")))
	sameBytes := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.Status(domain.LocalSource), fetchtest.ModuleHash(fetchtest.H1("pub==")))

	ids, err := domain.SupersededLocalArtefacts(coord, []domain.FactRecord{published, local, sameBytes})
	if err != nil {
		t.Fatalf("SupersededLocalArtefacts: %v", err)
	}
	if len(ids) != 1 || !ids[fetchtest.ZipArtefact("dir==").String()] {
		t.Errorf("superseded = %v, want only the directory's artefact", ids)
	}
	if ids, err := domain.SupersededLocalArtefacts(coord, []domain.FactRecord{published}); err != nil || len(ids) != 0 {
		t.Errorf("a ledger with no local row supersedes nothing: %v, %v", ids, err)
	}
}
