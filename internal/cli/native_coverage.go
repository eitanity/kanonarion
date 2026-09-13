package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"
	nativedomain "github.com/eitanity/kanonarion/internal/native/domain"
)

// This file states, on the read surfaces, what kanonarion knows and does not
// know about the native code a module ships.
//
// A cgo module can carry a whole C library inside its own published zip and
// compile it into the binary — the SQLite amalgamation inside
// github.com/mattn/go-sqlite3 is eight megabytes of exactly that. Kanonarion
// records it. Nothing it records can be matched against an advisory database,
// because it has no non-Go advisory source, no version comparator for versions
// that are not semver, and no identity scheme to join them on. That work is a
// separate question with its own cost and it is deliberately not begun here.
//
// What IS done here is to say so. A module that ships SQLite and a module that
// ships no C at all both read "Clean" today, and a reader cannot tell them
// apart — which is this product's own defect class: an absence that is not
// stated is indistinguishable from a measurement that found nothing.
//
// Everything below is DERIVED AT READ TIME from the stored native record.
// Nothing is written into a vulnerability record and no stored byte moves, so
// no scan pipeline version is owed: a vulnerability record's content hash
// covers what the scan measured, and the scan did not measure this.

// nativeCoverageState is the five-valued answer to "what is known about native
// code in this module?".
//
// Five, not two. The four presences a native record can carry are already
// distinct facts, and "no record at all" is a fifth that must never be folded
// into any of them: it means nobody looked, and reporting it as an absence
// would be the same silence this states.
type nativeCoverageState string

const (
	// nativeStateNotExamined means no native record is held for this module at
	// the generation this build serves. Nobody looked. It is NOT "no native
	// code".
	nativeStateNotExamined nativeCoverageState = "not_examined"
	// nativeStateAbsent means the module was examined and compiles no native
	// source of its own, and its cgo directives name nothing external. A
	// measured answer.
	nativeStateAbsent nativeCoverageState = "absent"
	// nativeStateLinkedNotShipped means the module compiles no native source of
	// its own but links an external native library the host provides. Something
	// native reaches the binary and no version can be read for it from these
	// bytes.
	nativeStateLinkedNotShipped nativeCoverageState = "linked_not_shipped"
	// nativeStateUnidentified means native source is compiled in and no recipe
	// named the library it belongs to. Sources were found; no component was
	// named. A coverage gap, and not a finding.
	nativeStateUnidentified nativeCoverageState = "present_unidentified"
	// nativeStateIdentified means native source is compiled in and a recipe
	// named the library. This is the state that carries an unsearched component.
	nativeStateIdentified nativeCoverageState = "present_identified"
)

// nativeCoverageComponent is one identified native component and what was, and
// was not, established about it.
type nativeCoverageComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Confidence is how the version was established; "declared" means it was
	// read verbatim from a named declaration in compiled source.
	Confidence string `json:"confidence"`
	// PURL is the identity this component carries in the SBOM too, so a reader
	// can join the two documents on one string.
	PURL string `json:"purl"`
	// AdvisoriesSearched is false on every component this build reports. It is
	// stated rather than omitted because an absent key reads as a producer that
	// does not track the question.
	AdvisoriesSearched bool `json:"advisories_searched"`
}

// nativeCoverage is the machine-readable statement about one module's native
// code, and the value the text surface renders.
//
// It is emitted whole on every record a deriving producer publishes, including
// the states with nothing in them, because a consumer must read one key rather
// than infer a fact from a key's absence.
type nativeCoverage struct {
	State nativeCoverageState `json:"state"`
	// UnsearchedComponents is the count an agent acts on: how many identified
	// native components in this module were never checked against an advisory
	// database. Zero in every state but present_identified.
	UnsearchedComponents int `json:"unsearched_components"`
	// Statement is the one-line answer, worded identically on the text surface
	// and here, so a reader of either sees the same claim.
	Statement string `json:"statement"`
	// Components is empty except in present_identified. Never nil, so a consumer
	// iterates uniformly whatever the answer was.
	Components []nativeCoverageComponent `json:"components"`
	// Generation is the detection generation the record was measured at, and
	// ArtefactIdentity the verified module zip it was read from. Both empty when
	// no record is held — there is then nothing to attribute.
	Generation       string `json:"generation,omitempty"`
	ArtefactIdentity string `json:"artefact_identity,omitempty"`
}

// nativeCoverageOf derives the statement for one module from its stored record.
//
// found is false when no record is held. That is a different answer from every
// presence a record can carry, and it gets its own state rather than the
// nearest one.
func nativeCoverageOf(rec nativedomain.Record, found bool) nativeCoverage {
	out := nativeCoverage{Components: []nativeCoverageComponent{}}
	if !found {
		out.State = nativeStateNotExamined
		out.Statement = "this module's artefact was not examined for native code compiled into the binary, " +
			"so nothing is known either way — run: kanonarion native <module>@<version>"
		return out
	}
	out.Generation = rec.PipelineVersion + "+recipes." + rec.RecipeCatalogueVersion
	out.ArtefactIdentity = rec.ArtefactIdentity

	switch rec.Presence {
	case nativedomain.PresenceAbsent:
		out.State = nativeStateAbsent
		out.Statement = "no native source is compiled into a binary from this module's own artefact, " +
			"so there is no native component here to search advisories for"
	case nativedomain.PresenceLinkedNotShipped:
		out.State = nativeStateLinkedNotShipped
		out.Statement = "this module compiles no native source of its own; it links an external native library " +
			"the host provides, whose version cannot be read from these bytes and whose advisories were not searched"
	case nativedomain.PresenceUnidentified:
		out.State = nativeStateUnidentified
		out.Statement = fmt.Sprintf(
			"%d native source file(s) are compiled into the binary from this module's artefact and no recipe names "+
				"the library they belong to, so no component could be named and no advisories could be searched",
			len(rec.Sources))
	case nativedomain.PresenceIdentified:
		out.State = nativeStateIdentified
		for _, c := range rec.Components {
			out.Components = append(out.Components, nativeCoverageComponent{
				Name:       c.Name,
				Version:    c.Version,
				Confidence: string(c.Confidence),
				PURL:       nativedomain.ComponentPURL(c),
			})
		}
		out.UnsearchedComponents = len(out.Components)
		out.Statement = fmt.Sprintf(
			"%s compiled into the binary from this module's artefact; %s advisories were NOT searched — "+
				"kanonarion has no non-Go advisory source, so this module's verdict covers its Go code only",
			nativeComponentList(out.Components), pluralise(len(out.Components), "its", "their"))
	default:
		// A presence this build does not recognise. It is reported as itself
		// rather than laddered onto a neighbour: an unknown answer is not an
		// absence, and guessing which one it is closest to is how a coverage gap
		// becomes an all-clear.
		out.State = nativeCoverageState(rec.Presence)
		out.Statement = fmt.Sprintf("this module's native record states a presence this build does not recognise (%q), "+
			"so nothing is concluded from it", rec.Presence)
	}
	return out
}

// nativeComponentList renders the components for the statement line, e.g.
// "SQLite 3.53.0" or "SQLite 3.53.0 and zlib 1.3".
func nativeComponentList(cs []nativeCoverageComponent) string {
	names := make([]string, 0, len(cs))
	for _, c := range cs {
		names = append(names, c.Name+" "+c.Version)
	}
	switch len(names) {
	case 0:
		return "a native component"
	case 1:
		return names[0]
	default:
		return joinWithAnd(names)
	}
}

// joinWithAnd renders a list in prose: "a, b and c".
func joinWithAnd(names []string) string {
	out := ""
	for i, n := range names {
		switch {
		case i == 0:
			out = n
		case i == len(names)-1:
			out += " and " + n
		default:
			out += ", " + n
		}
	}
	return out
}

// printNativeCoverage writes the statement under a rendered vulnerability
// record.
//
// It prints in every state, the empty ones included. A module whose native
// record says "absent" has been measured and the line says so; leaving the line
// off there would make the statement's presence the signal, and a reader would
// have to know the tool's conventions to read an absent line as an answer.
func printNativeCoverage(stdout io.Writer, cov *nativeCoverage) {
	if cov == nil {
		return
	}
	_, _ = fmt.Fprintf(stdout, "  Native code:     %s\n", cov.State)
	_, _ = fmt.Fprintf(stdout, "                   %s\n", cov.Statement)
	for _, c := range cov.Components {
		_, _ = fmt.Fprintf(stdout, "                   %s %s (%s, %s) — advisories not searched\n",
			c.Name, c.Version, c.Confidence, c.PURL)
	}
	if cov.Generation != "" {
		_, _ = fmt.Fprintf(stdout, "                   measured at native generation %s from %s\n",
			cov.Generation, cov.ArtefactIdentity)
	}
}

// isNativeComponentPURL reports whether a component in a generated document is
// a native component rather than a Go module. The purl type is the test: a
// native component is the only thing kanonarion emits that is not
// "pkg:golang/".
func isNativeComponentPURL(purl string) bool {
	return strings.HasPrefix(purl, "pkg:"+nativedomain.PURLTypeGeneric+"/")
}

// nativeWalkCoords returns the module coordinates a walk resolved, or nil when
// the walk cannot be read. A walk that cannot be read yields no statement
// rather than an empty one: "nothing to report" and "could not look" are the
// two answers this whole surface exists to keep apart.
func nativeWalkCoords(ctx context.Context, walks QueryWalksUseCase, walkID string) []coordinate.ModuleCoordinate {
	if walks == nil || walkID == "" {
		return nil
	}
	rec, err := walks.GetWalk(ctx, walkID)
	if err != nil {
		return nil
	}
	coords := make([]coordinate.ModuleCoordinate, 0, len(rec.Graph.Nodes))
	for _, n := range rec.Graph.Nodes {
		coords = append(coords, n.Coordinate)
	}
	return coords
}

// nativeRecordReader is the read this file needs: one module's stored native
// record. It is an interface so the surfaces can be tested without a store, and
// so nothing here depends on the native application package's concrete type.
type nativeRecordReader interface {
	Get(ctx context.Context, coord coordinate.ModuleCoordinate) (nativedomain.Record, bool, error)
}

// deriveNativeCoverage reads one module's record and derives its statement.
//
// A nil reader yields nil — the caller then publishes no statement at all,
// which says "this producer does not derive it" rather than asserting an
// absence it did not measure.
//
// A read FAILURE also yields nil rather than a state. The one error this read
// produces is the store holding records that describe two different artefacts
// for one pinned version, and answering "not examined" there would report a
// contradiction as an absence.
func deriveNativeCoverage(
	ctx context.Context,
	reader nativeRecordReader,
	coord coordinate.ModuleCoordinate,
) *nativeCoverage {
	if reader == nil {
		return nil
	}
	rec, found, err := reader.Get(ctx, coord)
	if err != nil {
		return nil
	}
	cov := nativeCoverageOf(rec, found)
	return &cov
}

// nativeWalkRollup is the walk-level statement a scan report carries: every
// module in the scanned build whose artefact ships a native component nothing
// searched advisories for, and every module whose native source could not be
// named.
//
// It is a rollup and not a per-module list because that is the shape the rest of
// the scan report uses — failed modules, unscannable reasons — and a reader of a
// 300-module scan needs the exception, not a line per module.
type nativeWalkRollup struct {
	// Unsearched names each module carrying identified native components, with
	// those components, in coordinate order.
	Unsearched []nativeWalkModule `json:"unsearched"`
	// Unidentified names each module whose artefact compiles native source no
	// recipe could name, in coordinate order. A different fact, and also not a
	// finding.
	Unidentified []string `json:"unidentified"`
	// NotExamined counts the modules in the scanned build holding no native
	// record at all. A count rather than a list: on a build where nothing has
	// been examined this is every module, and the number is the statement.
	NotExamined int `json:"not_examined"`
	// Components is the total number of identified native components across
	// Unsearched — the single number an agent reads to learn that this scan's
	// verdict does not cover everything in the binary.
	Components int `json:"components"`
}

// nativeWalkModule is one module in the rollup and the native components its
// artefact ships.
type nativeWalkModule struct {
	Module     string                    `json:"module"`
	Components []nativeCoverageComponent `json:"components"`
}

// nativeRollupOver derives the walk-level statement for a set of module
// coordinates.
//
// A nil reader yields nil: the report then carries no statement, which says the
// producer does not derive one. A read failure for one module is skipped rather
// than failing the report — the scan's own answer is still true, and the
// alternative is a whole scan report withheld because one record disagreed with
// itself.
func nativeRollupOver(
	ctx context.Context,
	reader nativeRecordReader,
	coords []coordinate.ModuleCoordinate,
) *nativeWalkRollup {
	if reader == nil {
		return nil
	}
	out := nativeWalkRollup{Unsearched: []nativeWalkModule{}, Unidentified: []string{}}
	for _, coord := range coords {
		rec, found, err := reader.Get(ctx, coord)
		if err != nil {
			continue
		}
		cov := nativeCoverageOf(rec, found)
		switch cov.State {
		case nativeStateNotExamined:
			out.NotExamined++
		case nativeStateUnidentified:
			out.Unidentified = append(out.Unidentified, coord.String())
		case nativeStateIdentified:
			out.Unsearched = append(out.Unsearched, nativeWalkModule{Module: coord.String(), Components: cov.Components})
			out.Components += len(cov.Components)
		case nativeStateAbsent, nativeStateLinkedNotShipped:
			// Measured, and nothing here is unsearched. Neither contributes to a
			// rollup of exceptions.
		default:
			// An unrecognised presence is left out of every bucket rather than put
			// in the nearest one.
		}
	}
	// The module coordinate is unique within a walk's node list, so both sorts
	// are total orders and the report is deterministic.
	sort.Slice(out.Unsearched, func(i, j int) bool { return out.Unsearched[i].Module < out.Unsearched[j].Module })
	sort.Strings(out.Unidentified)
	return &out
}

// empty reports whether the rollup has nothing to state beyond counts.
func (r *nativeWalkRollup) empty() bool {
	return r == nil || (len(r.Unsearched) == 0 && len(r.Unidentified) == 0)
}

// writeNativeRollup prints the walk-level statement on a scan report.
//
// It prints only the exceptions. A scan where every module was examined and
// none ships native code has nothing to add, and the per-module read is where a
// reader asks about one module.
func writeNativeRollup(w io.Writer, r *nativeWalkRollup) {
	if r.empty() {
		return
	}
	if len(r.Unsearched) > 0 {
		_, _ = fmt.Fprintf(w, "Native components in this build, advisories NOT searched (%d component(s) in %d module(s)):\n",
			r.Components, len(r.Unsearched))
		_, _ = fmt.Fprintln(w,
			"  This scan covers Go code. Kanonarion has no non-Go advisory source, so nothing below was checked")
		_, _ = fmt.Fprintln(w,
			"  against any advisory database. These are not findings, and their absence from the findings above is not an all-clear.")
		for _, m := range r.Unsearched {
			_, _ = fmt.Fprintf(w, "  %s\n", m.Module)
			for _, c := range m.Components {
				_, _ = fmt.Fprintf(w, "    %s %s (%s, %s)\n", c.Name, c.Version, c.Confidence, c.PURL)
			}
		}
	}
	if len(r.Unidentified) > 0 {
		_, _ = fmt.Fprintf(w, "Native source compiled in but not identified (%d module(s)):\n", len(r.Unidentified))
		_, _ = fmt.Fprintln(w,
			"  These modules compile native source into the binary and no recipe names the library it belongs to,")
		_, _ = fmt.Fprintln(w,
			"  so no component could be named. Run 'kanonarion native <module>@<version>' to see the files.")
		for _, m := range r.Unidentified {
			_, _ = fmt.Fprintf(w, "  %s\n", m)
		}
	}
}

// writeNativeUnidentifiedCaveat states, on a run's own channel, which modules
// ship native source the document could not name a component for.
//
// The SBOM itself says nothing about this. An inventory lists what is there and
// CycloneDX gives it no field for "something is here and we cannot identify
// it"; a caveat injected into the document would be a claim the format does not
// support. The same rule already governs the pre-modules caveat, which travels
// beside the document for exactly this reason.
func writeNativeUnidentifiedCaveat(w io.Writer, r *nativeWalkRollup) error {
	if r == nil || len(r.Unidentified) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w,
		"caveat: %d module(s) in this walk compile native source into the binary that no recipe could name, "+
			"so this document carries NO component for it — it is present and unidentified, not absent:\n",
		len(r.Unidentified)); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	for _, m := range r.Unidentified {
		if _, err := fmt.Fprintf(w, "  %s\n", m); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if _, err := fmt.Fprintln(w,
		"  Run 'kanonarion native <module>@<version>' to see the files it compiles in."); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}
