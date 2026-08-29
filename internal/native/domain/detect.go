package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Detector accumulates the native files of one artefact and reports what they
// establish. It takes files one at a time so a module carrying tens of
// megabytes of amalgamated C is never held in memory all at once.
type Detector struct {
	// evidence is keyed by name and version so one library declaring its
	// version in both a header and an amalgamated source is one component with
	// two pieces of evidence, while genuinely disagreeing declarations stay two
	// components and neither is chosen over the other.
	evidence map[componentKey][]Evidence
	sources  []Source
	// linked is keyed on the whole entry so one directive read once is one
	// entry, while the same library named by two directives — or by one
	// directive in two files — stays two pieces of evidence.
	linked map[LinkedLibrary]bool
}

// componentKey identifies a component by what its own sources said it is.
type componentKey struct{ name, version string }

// NewDetector returns an empty Detector.
func NewDetector() *Detector {
	return &Detector{
		evidence: map[componentKey][]Evidence{},
		sources:  nil,
		linked:   map[LinkedLibrary]bool{},
	}
}

// AddDirectives records the libraries the cgo preamble of one Go file names as
// linked. rel is the file's path inside the artefact, relative to the module
// root.
//
// It is separate from Add because the two read different files: what is linked
// is declared in Go, what is compiled is the native source beside it. A module
// can do either without the other, and both are recorded.
func (d *Detector) AddDirectives(rel, preamble string) {
	for _, l := range LinkedLibrariesIn(rel, preamble) {
		d.linked[l] = true
	}
}

// Add records one native source file the build compiles. rel is the file's
// path inside the artefact, relative to the module root.
func (d *Detector) Add(rel string, content []byte) {
	sum := sha256.Sum256(content)
	d.sources = append(d.sources, Source{
		File:   rel,
		Bytes:  int64(len(content)),
		SHA256: hex.EncodeToString(sum[:]),
	})
	for _, r := range Recipes() {
		for version, decl := range matchMacro(r.Macro, content) {
			k := componentKey{name: r.Component, version: version}
			d.evidence[k] = append(d.evidence[k], Evidence{File: rel, Declaration: decl})
		}
	}
}

// Result returns the identified components, the file evidence and the linked
// libraries, all in canonical order.
//
// Sources lists every file added, matched or not. That is what makes an
// unidentified component reportable rather than silent: the reader is told
// which files carry native code even when no recipe names the library they
// belong to. LinkedLibraries is returned whatever the sources say, so a module
// that ships nothing and links something is not reported as carrying nothing.
func (d *Detector) Result() (components []Component, sources []Source, linked []LinkedLibrary) {
	for k, ev := range d.evidence {
		SortEvidence(ev)
		components = append(components, Component{
			Name:       k.name,
			Version:    k.version,
			Confidence: ConfidenceDeclared,
			Evidence:   ev,
		})
	}
	SortComponents(components)
	sources = append(sources, d.sources...)
	SortSources(sources)
	for l := range d.linked {
		linked = append(linked, l)
	}
	SortLinkedLibraries(linked)
	return components, sources, linked
}

// PresenceOf states the four-valued answer the record carries.
//
// The linked-but-not-shipped rung sits between absence and presence because it
// is neither: nothing native is in these bytes, and something native still
// reaches the binary. Only an external link earns it — a module whose sole
// directive is `-ldl` links the C runtime every cgo binary links, and putting
// that under a distinct value would make the value mean nothing.
func PresenceOf(components []Component, sources []Source, linked []LinkedLibrary) Presence {
	switch {
	case len(sources) == 0 && HasExternalLink(linked):
		return PresenceLinkedNotShipped
	case len(sources) == 0:
		return PresenceAbsent
	case len(components) == 0:
		return PresenceUnidentified
	default:
		return PresenceIdentified
	}
}

// EvidenceLess is the canonical ordering for Evidence: where the declaration
// was read, then what it said. Both fields are keyed, so two distinct pieces of
// evidence always have a defined order and the sealed bytes never depend on the
// order the artefact was walked in.
func EvidenceLess(a, b Evidence) bool {
	if a.File != b.File {
		return a.File < b.File
	}
	return a.Declaration < b.Declaration
}

// SortEvidence orders evidence by EvidenceLess.
func SortEvidence(ev []Evidence) {
	sort.Slice(ev, func(i, j int) bool { return EvidenceLess(ev[i], ev[j]) })
}

// ComponentLess is the canonical ordering for Component: the library's name,
// then the version its own sources declared, then the basis of the claim.
func ComponentLess(a, b Component) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	return a.Confidence < b.Confidence
}

// SortComponents orders components by ComponentLess.
func SortComponents(cs []Component) {
	sort.Slice(cs, func(i, j int) bool { return ComponentLess(cs[i], cs[j]) })
}

// SourceLess is the canonical ordering for Source: the path, then the digest
// and size of what was read there.
func SourceLess(a, b Source) bool {
	if a.File != b.File {
		return a.File < b.File
	}
	if a.SHA256 != b.SHA256 {
		return a.SHA256 < b.SHA256
	}
	return a.Bytes < b.Bytes
}

// SortSources orders sources by SourceLess.
func SortSources(ss []Source) {
	sort.Slice(ss, func(i, j int) bool { return SourceLess(ss[i], ss[j]) })
}

// Hash returns the deterministic content hash of a measurement: what was
// examined, what was concluded, and every file and declaration the conclusion
// rests on. Callers must sort the collections first; Hash does not re-sort, so
// the digest describes exactly what is serialised.
func Hash(
	coordinate, artefactIdentity, pipelineVersion, recipeCatalogueVersion string,
	presence Presence,
	components []Component,
	sources []Source,
	linked []LinkedLibrary,
) string {
	var b strings.Builder
	fmt.Fprintf(&b, "M|%s|%s|%s|%s|%s\n",
		coordinate, artefactIdentity, pipelineVersion, recipeCatalogueVersion, presence)
	for _, c := range components {
		fmt.Fprintf(&b, "C|%s|%s|%s\n", c.Name, c.Version, c.Confidence)
		for _, e := range c.Evidence {
			fmt.Fprintf(&b, "E|%s|%s\n", e.File, e.Declaration)
		}
	}
	for _, s := range sources {
		fmt.Fprintf(&b, "S|%s|%d|%s\n", s.File, s.Bytes, s.SHA256)
	}
	for _, l := range linked {
		fmt.Fprintf(&b, "L|%s|%s|%s|%s\n", l.Name, l.Kind, l.File, l.Directive)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}
