package domain_test

import (
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/iface/domain"
)

// TestNamesAnalysedContent_AbsenceIsNotAValueTwoRecordsShare covers every way a
// record can fail to say which artefact it read. Each of them is a record that
// must not be recognised as stating the same extraction as any other, and the
// reason is the same in all three: absence cannot show agreement.
func TestNamesAnalysedContent_AbsenceIsNotAValueTwoRecordsShare(t *testing.T) {
	t.Parallel()

	named := withArtefact(artefactTestRecord(t), fetchtest.ZipArtefact("tree-one="))
	unnamed := artefactTestRecord(t)
	corrupt := artefactTestRecord(t)
	corrupt.ArtefactIdentity = "not-an-identity"

	cases := []struct {
		name string
		rec  domain.InterfaceRecord
		want bool
	}{
		{name: "a record naming the artefact it read", rec: named, want: true},
		// Every generation written before the field existed looks like this, and
		// two of them are not evidence of one tree.
		{name: "a record naming no artefact", rec: unnamed, want: false},
		// A corrupt identity is kept distinct from an absent one everywhere else,
		// and it shows no more than an absent one does about what was read.
		{name: "a record whose artefact identity cannot be read", rec: corrupt, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := domain.NamesAnalysedContent(tc.rec); got != tc.want {
				t.Errorf("NamesAnalysedContent = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSameMeasurement_IgnoresOnlyTheClock. A re-extraction that came back saying
// what the ledger already says differs in exactly one thing: when it was taken.
// Everything else the record states is compared, including the provenance.
func TestSameMeasurement_IgnoresOnlyTheClock(t *testing.T) {
	t.Parallel()

	first := withArtefact(artefactTestRecord(t), fetchtest.ZipArtefact("tree-one="))
	var h domain.InterfaceRecordHasher
	sealed, err := h.SetContentHash(first)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	later := first
	later.ExtractedAt = first.ExtractedAt.Add(time.Hour)
	resealed, err := h.SetContentHash(later)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if resealed.ContentHash == sealed.ContentHash {
		t.Fatal("the two runs sealed identically; the fixture is not exercising the case")
	}
	same, err := domain.SameMeasurement(sealed, resealed)
	if err != nil {
		t.Fatalf("SameMeasurement: %v", err)
	}
	if !same {
		t.Error("two runs differing only in the clock were read as two measurements")
	}

	// Different bytes, same conclusion. The artefact identity is provenance, and
	// it is compared: two extractions that read different trees are two
	// measurements even where they agree about what they found.
	elsewhere := withArtefact(artefactTestRecord(t), fetchtest.ZipArtefact("tree-two="))
	same, err = domain.SameMeasurement(sealed, elsewhere)
	if err != nil {
		t.Fatalf("SameMeasurement: %v", err)
	}
	if same {
		t.Error("two extractions of different artefacts were read as one measurement")
	}

	// The claim itself changed.
	changed := first
	changed.Packages = []domain.PackageInterface{{ImportPath: "example.com/mod", Name: "mod"}}
	same, err = domain.SameMeasurement(sealed, changed)
	if err != nil {
		t.Fatalf("SameMeasurement: %v", err)
	}
	if same {
		t.Error("a changed finding was read as the measurement already held")
	}
}

// TestSameMeasurement_TheFETCHMeasurementIsNotPartOfTheMEASUREMENT is the case a
// scratch-store road test found and no unit test had.
//
// The project root is re-ingested on every run, so the fetch ledger appends a new
// record each time and SourceContentHash — which names that record, not the bytes
// — moves. Measured: three runs over one unchanged tree, one artefact identity,
// three source content hashes. Comparing it would make every re-read of an
// unchanged tree a new measurement.
func TestSameMeasurement_TheFETCHMeasurementIsNotPartOfTheMEASUREMENT(t *testing.T) {
	t.Parallel()

	first := withArtefact(artefactTestRecord(t), fetchtest.ZipArtefact("tree-one="))
	first.SourceContentHash = "sha256:first-ingest"

	// The same tree, re-ingested: one artefact identity, a second fetch record.
	reingested := first
	reingested.SourceContentHash = "sha256:second-ingest"
	reingested.ExtractedAt = first.ExtractedAt.Add(time.Hour)

	same, err := domain.SameMeasurement(first, reingested)
	if err != nil {
		t.Fatalf("SameMeasurement: %v", err)
	}
	if !same {
		t.Error("a re-ingest of one unchanged tree was read as a second measurement")
	}
}

// TestSameMeasurement_AnUnnamedArtefactMatchesNothing is what makes dropping the
// fetch hash sound. That drop rests on the artefact identity being compared and
// being a content address; a record that names no artefact supplies neither, so
// two of them are not one measurement on the strength of two fields neither of
// them carries.
func TestSameMeasurement_AnUnnamedArtefactMatchesNothing(t *testing.T) {
	t.Parallel()

	unnamed := artefactTestRecord(t)
	other := artefactTestRecord(t)
	other.ExtractedAt = unnamed.ExtractedAt.Add(time.Hour)

	same, err := domain.SameMeasurement(unnamed, other)
	if err != nil {
		t.Fatalf("SameMeasurement: %v", err)
	}
	if same {
		t.Error("two records naming no artefact were read as one measurement")
	}

	// And one of each: a named record is not shown to be the same measurement as
	// one that says nothing about what it read.
	named := withArtefact(artefactTestRecord(t), fetchtest.ZipArtefact("tree-one="))
	same, err = domain.SameMeasurement(named, unnamed)
	if err != nil {
		t.Fatalf("SameMeasurement: %v", err)
	}
	if same {
		t.Error("a record naming no artefact matched one that names its own")
	}
}
