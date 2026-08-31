package domain

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// AnalyserVersion is the golang.org/x/tools version that type-checked a module
// and built the SSA a call graph was computed over.
//
// It is not the Go toolchain and it is not the pipeline version. The toolchain
// compiles the code and supplies the stdlib; x/tools is what READS it, and a
// library that predates a language construct degrades the graph two ways. Loudly
// — type-checking fails and the record is LoadFailed. Silently — SSA builds
// anyway and misses the construct, so CHA under-reports and a callers answer
// comes back short with nothing said. Without this the two graphs are peers.
//
// It is a DIMENSION, not a ladder. A newer analyser is not automatically a
// better answer about a module, so nothing here ranks two values; composition
// reports that they differ and leaves the choice to the completeness ladder.
type AnalyserVersion string

// AnalyserUnrecorded is the zero value: nothing says which library parsed this.
const AnalyserUnrecorded AnalyserVersion = ""

// Recorded reports whether a version is stated at all.
func (v AnalyserVersion) Recorded() bool { return v != AnalyserUnrecorded }

// AnalyserProvenance says HOW the store came to state an analyser version, and
// it travels with the version rather than beside it.
//
// The two strengths are not the same claim and must never render the same way.
// An OBSERVED version is the extracting binary naming its own linked library at
// the moment it built the graph. An INFERRED one is a guess, reconstructed after
// the fact from when the record was written against this repository's own pin
// history — the analyser version was never recorded on those rows, anywhere, so
// there is nothing to recover. On a field whose whole purpose is to say what the
// graph could and could not see, an inferred value that reads as observed is
// worse than an absent one: it invites a reader to treat a guess as a
// measurement.
type AnalyserProvenance string

const (
	// AnalyserProvenanceUnrecorded is the zero value: no version is stated, so
	// there is no provenance to state either.
	AnalyserProvenanceUnrecorded AnalyserProvenance = ""
	// AnalyserObserved is the extracting binary's own build info, read at
	// extraction.
	AnalyserObserved AnalyserProvenance = "observed"
	// AnalyserInferred is derived from the record's extraction date against the
	// pin history of this repository's go.mod. It is evidence about the producer,
	// not a measurement the record ever made.
	AnalyserInferred AnalyserProvenance = "inferred"
)

// AnalyserIdentity is what a stored row says about the library that parsed the
// module, together with how it came to say it.
//
// The pair is one value rather than two fields on the row, and that is the point
// rather than tidiness: a reader cannot select the version without also
// selecting the provenance, so there is no projection of this fact in which a
// guess can pass for a measurement.
type AnalyserIdentity struct {
	// Version is the x/tools version, when one is established.
	Version AnalyserVersion
	// Provenance is how it came to be stated. Never AnalyserProvenanceUnrecorded
	// alongside a version, and never anything else without one — see the
	// constructors, which are the only way to build a non-zero value.
	Provenance AnalyserProvenance
}

// ObservedAnalyser is the identity of a binary that read its own build info. An
// empty version yields the zero identity: a provenance with nothing to be the
// provenance OF states nothing.
func ObservedAnalyser(v AnalyserVersion) AnalyserIdentity {
	if !v.Recorded() {
		return AnalyserIdentity{}
	}
	return AnalyserIdentity{Version: v, Provenance: AnalyserObserved}
}

// InferredAnalyser is the identity a back-fill reconstructs from a date. Like
// ObservedAnalyser, an empty version yields the zero identity.
func InferredAnalyser(v AnalyserVersion) AnalyserIdentity {
	if !v.Recorded() {
		return AnalyserIdentity{}
	}
	return AnalyserIdentity{Version: v, Provenance: AnalyserInferred}
}

// Recorded reports whether this row states an analyser at all.
func (a AnalyserIdentity) Recorded() bool { return a.Version.Recorded() }

// IsObserved reports whether the version was read from the extracting binary.
func (a AnalyserIdentity) IsObserved() bool { return a.Provenance == AnalyserObserved }

// IsInferred reports whether the version was reconstructed from a date.
func (a AnalyserIdentity) IsInferred() bool { return a.Provenance == AnalyserInferred }

// String renders the identity for a human, and an inferred value never renders
// as an observed one. The sentence is the guard: a bare version number beside
// another bare version number is exactly the reading this type exists to stop.
func (a AnalyserIdentity) String() string {
	switch {
	case a.IsObserved():
		return AnalyserModulePath + " " + string(a.Version)
	case a.IsInferred():
		return AnalyserModulePath + " " + string(a.Version) +
			" (INFERRED from the extraction date; this record never recorded one)"
	default:
		return "not recorded"
	}
}

// AnalyserModulePath is the library the version names. It is spelled out on
// every rendering so a reader is never left to guess which of the three versions
// on a record — toolchain, pipeline, analyser — they are looking at.
const AnalyserModulePath = "golang.org/x/tools"

// Short renders the identity where the library has already been named — a list
// of several identities in one sentence — as the version plus its strength.
//
// The strength is spelled out on BOTH, never only on the weaker one. A list
// reading "v0.47.0 (inferred) and v0.49.0" invites the reader to take the
// unmarked one as the plain fact and the marked one as the caveat; marking both
// makes them two claims of stated strength, which is what they are.
func (a AnalyserIdentity) Short() string {
	if !a.Recorded() {
		return "not recorded"
	}
	return string(a.Version) + " (" + string(a.Provenance) + ")"
}

// analyserColumnSeparator divides the provenance from the version in the stored
// column value.
const analyserColumnSeparator = ":"

// Column renders the identity as the single string a store column holds.
//
// One column, not two, and the provenance leads. A store that kept the version
// in a column of its own would let every query, index and export read the number
// without the strength behind it — and the first such read is where a guess
// becomes a measurement. The zero identity is the empty string, which is what
// every row carries until something states otherwise.
func (a AnalyserIdentity) Column() string {
	if !a.Recorded() {
		return ""
	}
	return string(a.Provenance) + analyserColumnSeparator + string(a.Version)
}

// ErrMalformedAnalyserColumn is returned for a stored analyser value that names
// no known provenance.
var ErrMalformedAnalyserColumn = errors.New("malformed analyser column value")

// ParseAnalyserColumn reads back what Column wrote.
//
// A value it does not understand is an ERROR rather than an absence. Only two
// things write this column — the extraction write leg and the back-fill — and
// both write a provenance; a third value can only be a hand-edited row, and
// reading one as "not recorded" would silently drop a claim the store is
// carrying. An empty value is not malformed: it is every row that states
// nothing.
func ParseAnalyserColumn(s string) (AnalyserIdentity, error) {
	if s == "" {
		return AnalyserIdentity{}, nil
	}
	prov, version, ok := strings.Cut(s, analyserColumnSeparator)
	if !ok || version == "" {
		return AnalyserIdentity{}, fmt.Errorf("%w: %q carries no provenance prefix", ErrMalformedAnalyserColumn, s)
	}
	switch AnalyserProvenance(prov) {
	case AnalyserObserved:
		return ObservedAnalyser(AnalyserVersion(version)), nil
	case AnalyserInferred:
		return InferredAnalyser(AnalyserVersion(version)), nil
	case AnalyserProvenanceUnrecorded:
		return AnalyserIdentity{}, fmt.Errorf("%w: %q names an empty provenance", ErrMalformedAnalyserColumn, s)
	default:
		return AnalyserIdentity{}, fmt.Errorf("%w: %q names provenance %q, which is neither %q nor %q",
			ErrMalformedAnalyserColumn, s, prov, AnalyserObserved, AnalyserInferred)
	}
}

// AnalyserDisagreement is what a composed read STATES when the generations it
// composed were not all built by the same analyser.
//
// It is a statement, never a refusal, and it decides nothing. Which generation
// wins is the completeness ladder's question and this does not touch it: two
// graphs built by libraries that understood the code differently were peers on
// that ladder before, and they are peers on it now — the difference is that a
// reader can see it. Making it a conflict would strand coordinates over a fact
// that ranks nothing.
type AnalyserDisagreement struct {
	// Coordinate is the module the composed generations describe.
	Coordinate coordinate.ModuleCoordinate
	// Served is what the generation the ladder chose says about its analyser. It
	// may be the zero identity: a served record that states none is exactly the
	// case a reader most needs to see beside two that do.
	Served AnalyserIdentity
	// Identities are the distinct analysers the composed generations state,
	// ordered by version then provenance. Only generations that state one appear:
	// "this record does not say" establishes no version and so contradicts none,
	// on the same rule ToolchainIdentity.Key applies to an unnamed GOROOT.
	Identities []AnalyserIdentity
}

// Summary renders the disagreement as one sentence for a human.
//
// The library is named once and each version carries its strength, rather than
// every entry repeating the whole identity: a sentence that says the same caveat
// three times is one a reader skips, and the caveat is the point.
func (d AnalyserDisagreement) Summary() string {
	stated := make([]string, 0, len(d.Identities))
	inferred := false
	for _, id := range d.Identities {
		stated = append(stated, id.Short())
		inferred = inferred || id.IsInferred()
	}
	line := fmt.Sprintf(
		"the generations of %s were not all parsed by the same %s: %s; the one served names %s. "+
			"A library predating a language construct can build a graph that silently omits it, "+
			"so these generations are not interchangeable evidence",
		d.Coordinate, AnalyserModulePath, strings.Join(stated, " and "), d.Served.Short())
	if inferred {
		// Only where one is: explaining a term the sentence does not use is how a
		// notice becomes noise.
		line += ". An (inferred) version was reconstructed from the record's extraction date, never recorded by it"
	}
	return line
}

// AnalyserDisagreementAmong reports whether the generations composed for one
// coordinate state more than one analyser VERSION, and what they state.
//
// Grouping is on the version alone. Two rows at one version, one observed and
// one inferred, were parsed by the same library — the difference between them is
// how confidently the store can say so, which is a statement about the rows and
// not a disagreement about the graph. Both identities are still listed, because
// a reader deciding what to trust needs to see which of the versions is a guess.
func AnalyserDisagreementAmong(records []CallGraphRecord, served CallGraphRecord) (AnalyserDisagreement, bool) {
	versions := make(map[AnalyserVersion]bool)
	seen := make(map[AnalyserIdentity]bool)
	var identities []AnalyserIdentity
	for i := range records {
		id := records[i].Analyser
		if !id.Recorded() {
			continue
		}
		versions[id.Version] = true
		if !seen[id] {
			seen[id] = true
			identities = append(identities, id)
		}
	}
	if len(versions) < 2 {
		return AnalyserDisagreement{}, false
	}
	sort.Slice(identities, func(i, j int) bool {
		if identities[i].Version != identities[j].Version {
			return identities[i].Version < identities[j].Version
		}
		return identities[i].Provenance < identities[j].Provenance
	})
	return AnalyserDisagreement{
		Coordinate: served.Coordinate,
		Served:     served.Analyser,
		Identities: identities,
	}, true
}
