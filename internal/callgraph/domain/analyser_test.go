package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// analyserVersionsUnderTest spans the versions this repository has pinned plus
// neighbours on either side, so the never-identical rule below is measured
// across a range rather than on one lucky pair.
var analyserVersionsUnderTest = []domain.AnalyserVersion{
	"v0.46.0", "v0.47.0", "v0.48.0", "v0.49.0", "v0.50.0", "v1.0.0",
}

// TestAnalyserIdentity_ObservedNeverRendersAsInferred is the control decision 3
// rests on.
//
// Every row that predates the column has its analyser INFERRED from a date,
// because the value was never recorded anywhere. A reader who cannot tell that
// from a version the extracting binary actually named will treat a guess as a
// measurement — on the one field whose purpose is to say what the graph could
// and could not see.
//
// It is asserted over the CROSS PRODUCT, not pairwise on one version: an
// observed v0.49.0 must not render as an inferred v0.49.0, and it must not
// render as an inferred v0.47.0 either. Both are surfaces where a reader
// compares two rows side by side.
func TestAnalyserIdentity_ObservedNeverRendersAsInferred(t *testing.T) {
	t.Parallel()

	for _, observedVersion := range analyserVersionsUnderTest {
		observed := domain.ObservedAnalyser(observedVersion)
		for _, inferredVersion := range analyserVersionsUnderTest {
			inferred := domain.InferredAnalyser(inferredVersion)

			if observed.String() == inferred.String() {
				t.Errorf("observed %s and inferred %s render the same sentence %q",
					observedVersion, inferredVersion, observed.String())
			}
			if observed.Column() == inferred.Column() {
				t.Errorf("observed %s and inferred %s store the same column value %q",
					observedVersion, inferredVersion, observed.Column())
			}
			// The compact rendering is a THIRD surface a reader compares two rows
			// on — the disagreement notice lists them side by side — so it carries
			// the same rule as the sentence and the column.
			if observed.Short() == inferred.Short() {
				t.Errorf("observed %s and inferred %s render the same short form %q",
					observedVersion, inferredVersion, observed.Short())
			}
			if observed.IsInferred() {
				t.Errorf("observed %s reports itself inferred", observedVersion)
			}
			if !inferred.IsInferred() {
				t.Errorf("inferred %s does not report itself inferred", inferredVersion)
			}
		}

		// A guess must also not read like a measurement to someone skimming: the
		// sentence has to SAY it was inferred, not merely differ by a version.
		if !strings.Contains(domain.InferredAnalyser(observedVersion).String(), "INFERRED") {
			t.Errorf("inferred %s does not say so: %q",
				observedVersion, domain.InferredAnalyser(observedVersion).String())
		}
		if strings.Contains(observed.String(), "INFERRED") {
			t.Errorf("observed %s claims to be inferred: %q", observedVersion, observed.String())
		}
		// A bare version in the compact form would read as the plain fact beside a
		// marked one, which is the whole failure this axis is guarding against.
		if !strings.Contains(observed.Short(), "observed") {
			t.Errorf("the short form of an observed %s states no strength: %q", observedVersion, observed.Short())
		}
		if !strings.Contains(domain.InferredAnalyser(observedVersion).Short(), "inferred") {
			t.Errorf("the short form of an inferred %s states no strength: %q",
				observedVersion, domain.InferredAnalyser(observedVersion).Short())
		}
	}
}

// TestAnalyserIdentity_EveryRenderingNamesTheLibrary pins that a version never
// appears on its own. A record carries three versions — toolchain, pipeline,
// analyser — and a bare "v0.49.0" is readable as any of them.
func TestAnalyserIdentity_EveryRenderingNamesTheLibrary(t *testing.T) {
	t.Parallel()

	for _, v := range analyserVersionsUnderTest {
		for _, id := range []domain.AnalyserIdentity{domain.ObservedAnalyser(v), domain.InferredAnalyser(v)} {
			if !strings.Contains(id.String(), domain.AnalyserModulePath) {
				t.Errorf("%q does not name %s", id.String(), domain.AnalyserModulePath)
			}
			if !strings.Contains(id.String(), string(v)) {
				t.Errorf("%q does not carry the version %s", id.String(), v)
			}
		}
	}
}

// TestAnalyserIdentity_ZeroValue states what a row that says nothing renders
// as, and refuses a provenance with no version behind it.
func TestAnalyserIdentity_ZeroValue(t *testing.T) {
	t.Parallel()

	var zero domain.AnalyserIdentity
	if zero.Recorded() {
		t.Error("the zero identity reports itself recorded")
	}
	if zero.String() != "not recorded" {
		t.Errorf("zero identity renders %q, want %q", zero.String(), "not recorded")
	}
	if zero.Short() != "not recorded" {
		t.Errorf("zero identity's short form is %q, want %q", zero.Short(), "not recorded")
	}
	if zero.Column() != "" {
		t.Errorf("zero identity stores %q, want the empty column", zero.Column())
	}

	// A provenance is a statement ABOUT a version. With no version it states
	// nothing, and a row carrying "observed:" with nothing after it would claim a
	// measurement that names no library.
	if got := domain.ObservedAnalyser(""); got != zero {
		t.Errorf("ObservedAnalyser(\"\") = %+v, want the zero identity", got)
	}
	if got := domain.InferredAnalyser(""); got != zero {
		t.Errorf("InferredAnalyser(\"\") = %+v, want the zero identity", got)
	}
}

// TestParseAnalyserColumn_RoundTrips checks that what the store writes is what
// it reads back, with the provenance intact.
func TestParseAnalyserColumn_RoundTrips(t *testing.T) {
	t.Parallel()

	var zero domain.AnalyserIdentity
	for _, want := range []domain.AnalyserIdentity{
		zero,
		domain.ObservedAnalyser("v0.49.0"),
		domain.InferredAnalyser("v0.47.0"),
	} {
		got, err := domain.ParseAnalyserColumn(want.Column())
		if err != nil {
			t.Fatalf("ParseAnalyserColumn(%q): %v", want.Column(), err)
		}
		if got != want {
			t.Errorf("ParseAnalyserColumn(%q) = %+v, want %+v", want.Column(), got, want)
		}
	}
}

// TestParseAnalyserColumn_RefusesMalformed pins that an unreadable column value
// is an error rather than an absence.
//
// Reading it as "not recorded" would silently drop a claim the store is
// carrying, and the reader would never learn the row said something.
func TestParseAnalyserColumn_RefusesMalformed(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"v0.49.0",           // a bare version: no provenance, so no strength
		"observed:",         // a strength with nothing behind it
		":v0.49.0",          // an empty provenance
		"guessed:v0.49.0",   // a provenance nothing writes
		"OBSERVED:v0.49.0",  // provenance is a value, not a spelling
		"inferred v0.47.0",  // the separator matters
		"observed v0.49.0:", // and so does its position
	} {
		got, err := domain.ParseAnalyserColumn(value)
		if err == nil {
			t.Errorf("ParseAnalyserColumn(%q) accepted it as %+v", value, got)
			continue
		}
		if !errors.Is(err, domain.ErrMalformedAnalyserColumn) {
			t.Errorf("ParseAnalyserColumn(%q) = %v, want ErrMalformedAnalyserColumn", value, err)
		}
	}
}

// analyserRecord is a record carrying nothing but a coordinate and an analyser,
// which is all the disagreement read looks at.
func analyserRecord(t *testing.T, id domain.AnalyserIdentity) domain.CallGraphRecord {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	return domain.CallGraphRecord{Coordinate: coord, Analyser: id}
}

// TestAnalyserDisagreementAmong states exactly when a composed read speaks.
//
// The silent cases are as load-bearing as the loud one: a store whose records
// were all written by one binary must gain no line anywhere, or the statement
// becomes noise on every answer and stops being read.
func TestAnalyserDisagreementAmong(t *testing.T) {
	t.Parallel()

	observed49 := domain.ObservedAnalyser("v0.49.0")
	inferred47 := domain.InferredAnalyser("v0.47.0")
	inferred49 := domain.InferredAnalyser("v0.49.0")

	tests := []struct {
		name     string
		states   []domain.AnalyserIdentity
		want     bool
		wantSaid []string
		wantHow  []domain.AnalyserProvenance
	}{
		{
			name:   "one generation says nothing",
			states: []domain.AnalyserIdentity{{}},
		},
		{
			name:   "every generation names the same version",
			states: []domain.AnalyserIdentity{observed49, observed49},
		},
		{
			name: "one names a version and the others say nothing",
			// An unrecorded row establishes no version, so it contradicts none. This
			// is the rule ToolchainIdentity.Key applies to an unnamed GOROOT: "I
			// could not tell" is not a value to disagree with.
			states: []domain.AnalyserIdentity{observed49, {}, {}},
		},
		{
			name: "one version, stated at two strengths",
			// Both rows were parsed by v0.49.0. How confidently the store can say so
			// differs; what parsed them does not.
			states: []domain.AnalyserIdentity{observed49, inferred49},
		},
		{
			name:     "two versions",
			states:   []domain.AnalyserIdentity{observed49, inferred47},
			want:     true,
			wantSaid: []string{"v0.47.0", "v0.49.0"},
		},
		{
			name:     "two versions among generations that say nothing",
			states:   []domain.AnalyserIdentity{{}, inferred47, {}, observed49},
			want:     true,
			wantSaid: []string{"v0.47.0", "v0.49.0"},
		},
		{
			// One of the two versions is stated at both strengths, so the list has to
			// order within a version as well as between versions — and it names both
			// entries, because which of them is a guess is what a reader deciding
			// what to trust is asking.
			name:     "two versions, one of them stated twice",
			states:   []domain.AnalyserIdentity{observed49, inferred49, inferred47},
			want:     true,
			wantSaid: []string{"v0.47.0", "v0.49.0", "v0.49.0"},
			wantHow:  []domain.AnalyserProvenance{domain.AnalyserInferred, domain.AnalyserInferred, domain.AnalyserObserved},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			records := make([]domain.CallGraphRecord, 0, len(tc.states))
			for _, st := range tc.states {
				records = append(records, analyserRecord(t, st))
			}
			d, got := domain.AnalyserDisagreementAmong(records, records[0])
			if got != tc.want {
				t.Fatalf("AnalyserDisagreementAmong = %v, want %v", got, tc.want)
			}
			if !tc.want {
				return
			}
			said := make([]string, 0, len(d.Identities))
			for _, id := range d.Identities {
				said = append(said, string(id.Version))
			}
			if strings.Join(said, ",") != strings.Join(tc.wantSaid, ",") {
				t.Errorf("named %v, want %v (ordered)", said, tc.wantSaid)
			}
			for i, want := range tc.wantHow {
				if d.Identities[i].Provenance != want {
					t.Errorf("identity %d is %q, want %q (ordered within a version)",
						i, d.Identities[i].Provenance, want)
				}
			}
			if d.Served != records[0].Analyser {
				t.Errorf("served identity %+v, want %+v", d.Served, records[0].Analyser)
			}
			// The sentence has to carry the strength of each value, or a reader
			// comparing two version numbers cannot see which one is a guess.
			if !strings.Contains(d.Summary(), "(inferred)") {
				t.Errorf("summary hides that a value was inferred: %q", d.Summary())
			}
			if !strings.Contains(d.Summary(), domain.AnalyserModulePath) {
				t.Errorf("summary does not name the library: %q", d.Summary())
			}
		})
	}
}
