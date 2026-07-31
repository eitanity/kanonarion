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
