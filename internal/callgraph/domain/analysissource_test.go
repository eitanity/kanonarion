package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// TestAnalysisSources_CoversTheDimension: consumers that must cover the source
// axis range over this list rather than restating it, so a value added to the
// type and omitted here would silently narrow every one of them.
func TestAnalysisSources_CoversTheDimension(t *testing.T) {
	t.Parallel()

	got := domain.AnalysisSources()
	want := map[domain.AnalysisSource]bool{
		domain.AnalysisSourceModuleZip:  false,
		domain.AnalysisSourceWorktree:   false,
		domain.AnalysisSourceUnrecorded: false,
	}
	for _, s := range got {
		if _, ok := want[s]; !ok {
			t.Errorf("AnalysisSources() lists %q, which the type does not define", s)
			continue
		}
		want[s] = true
	}
	for s, seen := range want {
		if !seen {
			t.Errorf("AnalysisSources() omits %q, so every consumer ranging over it misses that source", s)
		}
	}
}

// TestRecordAnalysisSource_UnknownSourceHasNoDiscriminator: a source written by
// a newer generation is returned as it stands — inventing a value would assert
// provenance no record states — and it carries no discriminator, because this
// generation does not know which field would identify one.
func TestRecordAnalysisSource_UnknownSourceHasNoDiscriminator(t *testing.T) {
	t.Parallel()

	rec := domain.CallGraphRecord{
		AnalysisSource:   domain.AnalysisSource("vcs-checkout"),
		ArtefactIdentity: "zip:h1:one=",
		WorktreeDigest:   "sha256:tree",
	}
	source, discriminator := domain.RecordAnalysisSource(rec)
	if source != domain.AnalysisSource("vcs-checkout") {
		t.Errorf("source = %q, want the value the record carries, unaltered", source)
	}
	if discriminator != "" {
		t.Errorf("discriminator = %q, want empty: this generation cannot know which field identifies an unknown source", discriminator)
	}
}

// TestNamesAnalysedContent_AbsenceIsNotAValueTwoRecordsShare covers every way a
// record can fail to say which content it read. Each of them is a record that
// must not be recognised as stating the same analysis as any other, and the
// reason is the same one in all four: absence cannot show agreement.
func TestNamesAnalysedContent_AbsenceIsNotAValueTwoRecordsShare(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		rec  domain.CallGraphRecord
		want bool
	}{
		{
			name: "a zip naming the artefact it read",
			rec: domain.CallGraphRecord{
				AnalysisSource:   domain.AnalysisSourceModuleZip,
				ArtefactIdentity: "zip:h1:one=",
			},
			want: true,
		},
		{
			// The tree digest is inapplicable to a zip, so its absence says nothing.
			name: "a zip naming no artefact",
			rec: domain.CallGraphRecord{
				AnalysisSource: domain.AnalysisSourceModuleZip,
				WorktreeDigest: "analysed-sha256:tree",
			},
			want: false,
		},
		{
			name: "a working tree naming the tree it read",
			rec: domain.CallGraphRecord{
				AnalysisSource: domain.AnalysisSourceWorktree,
				WorktreeDigest: "analysed-sha256:tree",
			},
			want: true,
		},
		{
			// Every generation written before the digest field existed looks like
			// this, and two of them are not evidence of one tree.
			name: "a working tree naming no tree",
			rec: domain.CallGraphRecord{
				AnalysisSource:   domain.AnalysisSourceWorktree,
				ArtefactIdentity: "zip:h1:one=",
			},
			want: false,
		},
		{
			name: "a record naming no source at all",
			rec: domain.CallGraphRecord{
				ArtefactIdentity: "zip:h1:one=",
				WorktreeDigest:   "analysed-sha256:tree",
			},
			want: false,
		},
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

// TestRestatesAnalysis_IgnoresWhichFetchSuppliedTheBytes.
//
// A local root is never served from the fetch cache, so every project walk that
// analyses it appends a fresh fetch record sealed under its own clock. The
// analysis reads the identical bytes — the artefact identity is a content
// address and does not move — but the record's SourceContentHash points at the
// new fetch measurement. Comparing that made every walk-then-extract of an
// unchanged tree look like a new analysis.
func TestRestatesAnalysis_IgnoresWhichFetchSuppliedTheBytes(t *testing.T) {
	t.Parallel()

	held := domain.CallGraphRecord{
		SchemaVersion:     domain.CallGraphSchemaVersion,
		Algorithm:         domain.AlgorithmCHA,
		AnalysisSource:    domain.AnalysisSourceModuleZip,
		ArtefactIdentity:  "zip:h1:same-bytes=",
		SourceContentHash: "sha256:first-fetch",
		Nodes:             []domain.CallNode{{ID: "example.com/mod.Root", Symbol: "Root"}},
	}
	// The next walk re-ingested the same tree, so only the fetch measurement moved.
	fresh := held
	fresh.SourceContentHash = "sha256:second-fetch"

	same, err := domain.RestatesAnalysis(fresh, held)
	if err != nil {
		t.Fatalf("RestatesAnalysis: %v", err)
	}
	if !same {
		t.Error("a re-ingest of identical bytes was read as a different analysis")
	}

	// The control: different bytes are a different analysis, and the artefact
	// identity is what says so.
	edited := fresh
	edited.ArtefactIdentity = "zip:h1:other-bytes="
	same, err = domain.RestatesAnalysis(edited, held)
	if err != nil {
		t.Fatalf("RestatesAnalysis: %v", err)
	}
	if same {
		t.Error("an analysis of different bytes was read as a repeat")
	}
}

// TestRestatesAnalysis_RefusesARecordNamingNoAnalysedContent, on BOTH sides.
// Dropping the fetch provenance is only sound because the artefact identity is
// compared; a record that carries none has nothing left that names the bytes,
// so it must match nothing — including another that names none.
func TestRestatesAnalysis_RefusesARecordNamingNoAnalysedContent(t *testing.T) {
	t.Parallel()

	named := domain.CallGraphRecord{
		SchemaVersion:    domain.CallGraphSchemaVersion,
		Algorithm:        domain.AlgorithmCHA,
		AnalysisSource:   domain.AnalysisSourceModuleZip,
		ArtefactIdentity: "zip:h1:same-bytes=",
	}
	unnamed := named
	unnamed.AnalysisSource = domain.AnalysisSourceUnrecorded
	unnamed.ArtefactIdentity = ""

	for _, tc := range []struct {
		name        string
		fresh, held domain.CallGraphRecord
	}{
		{"the fresh record names nothing", unnamed, named},
		{"the held record names nothing", named, unnamed},
		{"neither names anything", unnamed, unnamed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			same, err := domain.RestatesAnalysis(tc.fresh, tc.held)
			if err != nil {
				t.Fatalf("RestatesAnalysis: %v", err)
			}
			if same {
				t.Error("a record naming no analysed content was matched")
			}
		})
	}
}
