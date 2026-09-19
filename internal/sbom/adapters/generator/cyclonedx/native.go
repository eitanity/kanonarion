package cyclonedx

import (
	"fmt"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/eitanity/kanonarion/internal/coordinate"
	nativedomain "github.com/eitanity/kanonarion/internal/native/domain"
	"github.com/eitanity/kanonarion/internal/sbom/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// A cgo module may carry a whole third-party C library inside its own published
// zip and compile it into the binary. github.com/mattn/go-sqlite3 is the case
// this was built for: eight megabytes of the SQLite amalgamation, declaring its
// own version in a macro, shipped in every binary that imports the module.
//
// That library is not a Go module. It has no module path, no proxy zip and no
// `pkg:golang/` identity, so for as long as the component list was Go-only it
// could not appear in the artefact whose purpose is to list what ships. It is
// emitted here as a component in its own right, under the purl type the
// specification reserves for software that is not published in a registry.
//
// Three rules hold everything below together:
//
//   - Only an IDENTIFIED component is emitted. A measurement that found native
//     source and could not name the library has no identity to put in an
//     inventory, so it contributes nothing here; the run states it separately.
//   - Nothing is asserted that was not read. No download URL, no checksum
//     qualifier, no CPE. Each would be a claim about an upstream release nobody
//     fetched, in a document whose reader cannot re-run the tool. What WAS read
//     — the file, and the declaration verbatim — travels with the component as
//     CycloneDX evidence.
//   - Go components are untouched. Their purls, their fields and their order are
//     exactly what they were; native components are appended after them.

const (
	// nativeComponentProperty marks a component as native rather than Go, so a
	// consumer filtering the list does not have to parse the purl type.
	nativeComponentProperty = "kanonarion:component:native"
	// nativeHostProperty names a Go module whose artefact ships this component's
	// source. It repeats when more than one module ships the same library at the
	// same version; CycloneDX permits a property name to recur.
	nativeHostProperty = "kanonarion:native:host_module"
	// nativeGenerationProperty records the detection generation the measurement
	// was taken at — the detection logic and the recipe catalogue together — so a
	// reader can tell a component named by an older catalogue from one named now.
	nativeGenerationProperty = "kanonarion:native:generation"
	// nativeArtefactProperty names the verified module zip the declaration was
	// read out of. It is what this component's integrity actually rests on: the
	// bytes were extracted from an artefact the fetch ledger had already hashed,
	// so the component inherits that artefact's verification and needs no trust
	// story of its own.
	nativeArtefactProperty = "kanonarion:native:host_artefact"
	// nativeAdvisoriesProperty states that no advisory database was searched for
	// this component. An SBOM asserts no vulnerabilities either way — that is a
	// standing decision and this does not change it — but a reader who finds a C
	// library in a Go inventory will ask, and the honest answer is that
	// kanonarion has no non-Go advisory source and did not look.
	nativeAdvisoriesProperty = "kanonarion:native:advisories_searched"
	// nativeLicenceProperty states that this component's licence was not
	// determined. The licence pipeline reads the LICENSE files of a Go module's
	// artefact; a C library inside one of those artefacts was never in its scope,
	// so the silence here is a limit of what was measured and not a finding that
	// the library is unlicensed. It is said on the component because the
	// document-level licence statement counts the Go components it covers.
	nativeLicenceProperty = "kanonarion:native:licence_determined"
	// nativeConfidenceProperty records how the version was established, in the
	// vocabulary the measurement itself uses.
	nativeConfidenceProperty = "kanonarion:native:confidence"
)

// nativeComponent is one identified native library, gathered across every Go
// module in the walk whose artefact ships it.
//
// Identity is (name, version). Two modules that amalgamate the same library at
// the same version ship one component, named once, with both modules recorded
// as hosts — rather than two entries a reader would have to reconcile. Two
// modules shipping DIFFERENT versions are two components, because they are.
type nativeComponent struct {
	comp nativedomain.Component
	// hosts is every module whose artefact ships this component's source, in
	// coordinate order.
	hosts []string
	// hostRefs is the bom-ref of each host's own component, so the dependency
	// graph can record that the host module brings this library in.
	hostRefs []string
	// artefacts is the verified zip identity each host's declaration was read
	// from, in the same order as hosts.
	artefacts []string
	// evidence is every declaration that established this name and version,
	// across all hosts, de-duplicated and ordered.
	evidence []nativeEvidence
}

// nativeEvidence is one declaration a recipe matched, and where it was read.
type nativeEvidence struct {
	host        string
	file        string
	declaration string
}

// collectNativeComponents gathers the identified native components of every
// module in the walk, and separately names the modules whose native source
// could not be identified.
//
// unidentified is returned rather than emitted because a component with no name
// and no version is not a component. Naming it in the document would mean
// inventing an identity for it; leaving it out silently would mean the reader
// cannot tell "we looked and found nothing" from "we looked, found something,
// and could not say what". The caller states it on the run's own channel.
//
// hostRef maps a module coordinate to the bom-ref the document gave that
// module's component, which is how the dependency graph links the two.
func collectNativeComponents(
	nodes []walkdomain.GraphNode,
	records map[coordinate.ModuleCoordinate]nativedomain.Record,
	hostRef func(coordinate.ModuleCoordinate) string,
) (components []nativeComponent, unidentified []string) {
	if len(records) == 0 {
		return nil, nil
	}
	byPURL := map[string]*nativeComponent{}
	for _, node := range nodes {
		rec, ok := records[node.Coordinate]
		if !ok {
			continue
		}
		host := node.Coordinate.String()
		switch rec.Presence {
		case nativedomain.PresenceUnidentified:
			unidentified = append(unidentified, host)
			continue
		case nativedomain.PresenceIdentified:
			// Fall through to the emission below.
		case nativedomain.PresenceAbsent, nativedomain.PresenceLinkedNotShipped:
			// Neither ships native source from this artefact, so neither can put a
			// component in a list of what this artefact contributes. A linked
			// library the module never ships is a real coverage limit, but it is one
			// no version can be read for from these bytes, so there is no identity
			// to state and this is not the slice that states it.
			continue
		default:
			// A presence this build does not recognise contributes no component. It
			// cannot be read as an absence either, so it is left to the surfaces
			// that render the record itself.
			continue
		}
		for _, c := range rec.Components {
			purl := nativedomain.ComponentPURL(c)
			if purl == "" {
				// A component missing a name or a version has no identity. It cannot
				// be emitted and it is not an unidentified measurement either, so it
				// is skipped rather than given a made-up purl.
				continue
			}
			agg, seen := byPURL[purl]
			if !seen {
				agg = &nativeComponent{comp: c}
				byPURL[purl] = agg
			}
			agg.hosts = append(agg.hosts, host)
			agg.hostRefs = append(agg.hostRefs, hostRef(node.Coordinate))
			agg.artefacts = append(agg.artefacts, rec.ArtefactIdentity)
			for _, e := range c.Evidence {
				agg.evidence = append(agg.evidence, nativeEvidence{host: host, file: e.File, declaration: e.Declaration})
			}
		}
	}

	components = make([]nativeComponent, 0, len(byPURL))
	for _, agg := range byPURL {
		sortNativeAggregate(agg)
		components = append(components, *agg)
	}
	// Ordered by purl, which is unique across the set by construction, so this is
	// a total order and the document is byte-identical for identical inputs.
	sort.Slice(components, func(i, j int) bool {
		return nativedomain.ComponentPURL(components[i].comp) < nativedomain.ComponentPURL(components[j].comp)
	})
	sort.Strings(unidentified)
	return components, unidentified
}

// sortNativeAggregate puts one component's hosts and evidence into a fixed
// order. Hosts and artefacts are sorted together because they are read as
// pairs — the Nth artefact is the zip the Nth host's declaration came out of.
func sortNativeAggregate(agg *nativeComponent) {
	idx := make([]int, len(agg.hosts))
	for i := range idx {
		idx[i] = i
	}
	// The host coordinate is unique within one component: a module appears once
	// in a walk's node list, so no two entries tie here.
	sort.Slice(idx, func(a, b int) bool { return agg.hosts[idx[a]] < agg.hosts[idx[b]] })
	hosts := make([]string, len(idx))
	refs := make([]string, len(idx))
	arts := make([]string, len(idx))
	for i, at := range idx {
		hosts[i], refs[i], arts[i] = agg.hosts[at], agg.hostRefs[at], agg.artefacts[at]
	}
	agg.hosts, agg.hostRefs, agg.artefacts = hosts, refs, arts

	sort.Slice(agg.evidence, func(i, j int) bool {
		if agg.evidence[i].host != agg.evidence[j].host {
			return agg.evidence[i].host < agg.evidence[j].host
		}
		if agg.evidence[i].file != agg.evidence[j].file {
			return agg.evidence[i].file < agg.evidence[j].file
		}
		return agg.evidence[i].declaration < agg.evidence[j].declaration
	})
	agg.evidence = dedupeNativeEvidence(agg.evidence)
}

// dedupeNativeEvidence drops repeats from an already-sorted evidence list. One
// declaration read from one file in one module is one piece of evidence however
// many times it was collected.
func dedupeNativeEvidence(in []nativeEvidence) []nativeEvidence {
	out := in[:0]
	for i, e := range in {
		if i > 0 && e == in[i-1] {
			continue
		}
		out = append(out, e)
	}
	return out
}

// buildNativeComponent maps one gathered native library to a CycloneDX
// component.
//
// It carries no hashes. A <hashes> block on a component states the digest of
// THAT component's artefact, and kanonarion never held one: it read a
// declaration inside a Go module's zip. The zip it was read from is named in a
// property instead, where it says what it is.
func buildNativeComponent(n nativeComponent, pipelineVersion string) cdx.Component {
	purl := nativedomain.ComponentPURL(n.comp)
	comp := cdx.Component{
		BOMRef:      purl,
		Type:        cdx.ComponentTypeLibrary,
		Name:        n.comp.Name,
		Version:     n.comp.Version,
		PackageURL:  purl,
		Description: nativeDescription(n),
		Properties:  nativeProperties(n, pipelineVersion),
		Evidence:    nativeEvidenceBlock(n),
	}
	return comp
}

// nativeDescription says, in one sentence, what this component is and how it
// got into the binary — because a C library in a list of Go modules is the one
// entry a reader will not expect and cannot place.
func nativeDescription(n nativeComponent) string {
	hosts := strings.Join(n.hosts, ", ")
	noun := "module"
	if len(n.hosts) != 1 {
		noun = "modules"
	}
	return "Native library compiled into the binary from source shipped inside the published zip of Go " +
		noun + " " + hosts + ". Not a Go module and not fetched from any registry: its version was read " +
		"verbatim from a declaration in that source. Its advisories were not searched."
}

// nativeProperties records what the measurement established and what it did
// not, in a fixed order so the document is deterministic.
func nativeProperties(n nativeComponent, pipelineVersion string) *[]cdx.Property {
	props := []cdx.Property{
		{Name: "kanonarion:ecosystem", Value: domain.EcosystemNative},
		{Name: "kanonarion:pipeline_version", Value: pipelineVersion},
		{Name: nativeComponentProperty, Value: "true"},
	}
	for _, h := range n.hosts {
		props = append(props, cdx.Property{Name: nativeHostProperty, Value: h})
	}
	for _, a := range n.artefacts {
		if a != "" {
			props = append(props, cdx.Property{Name: nativeArtefactProperty, Value: a})
		}
	}
	props = append(props,
		// The domain's own word for how the version was established, not a number.
		// CycloneDX's evidence confidence is a 0-to-1 float, and there is no
		// measured probability here to put in one: "declared" means the version was
		// read verbatim out of a named macro in compiled source, and inventing 0.9
		// for it would publish a precision nobody measured.
		cdx.Property{Name: nativeConfidenceProperty, Value: string(n.comp.Confidence)},
		cdx.Property{Name: nativeGenerationProperty, Value: nativedomain.PipelineFingerprint()},
		// False on every component this build emits. It is stated rather than
		// omitted because an absent key reads as a producer that does not track
		// the question, and the question — "was this library checked against an
		// advisory database?" — is exactly the one a reader arrives with.
		cdx.Property{Name: nativeAdvisoriesProperty, Value: "false"},
		cdx.Property{Name: nativeLicenceProperty, Value: "false"},
	)
	return &props
}

// nativeEvidenceBlock renders what established this component's identity, using
// CycloneDX's own evidence structure rather than prose: the concluded version,
// the technique that reached it, and every file and declaration it was read
// from.
//
// source-code-analysis is the accurate technique. Nothing was inferred from a
// file name, a path or a heuristic; a named macro was matched in source the
// build compiles and its string literal taken verbatim.
func nativeEvidenceBlock(n nativeComponent) *cdx.Evidence {
	if len(n.evidence) == 0 {
		return nil
	}
	// The schema requires a confidence on every method, so a rung this build
	// cannot put a number on contributes no methods at all — the occurrences
	// below still carry every declaration and the file it was read in. Emitting a
	// made-up number to satisfy a required field is the one thing that must not
	// happen here: the number would then be read as a measurement.
	score, scored := nativeConfidenceScore(n.comp.Confidence)

	// One method per DISTINCT declaration, and one occurrence per file.
	//
	// A method carries the matched text and not the file it came from, so a
	// library that states its version in both a .c and its .h — which SQLite
	// does — would otherwise contribute two entries a reader cannot tell apart.
	// Two identical methods do not make an identification twice as well
	// established. The places it was read are the occurrences' job, and each of
	// those is distinct because a file appears once.
	methods := make([]cdx.EvidenceIdentityMethod, 0, len(n.evidence))
	occurrences := make([]cdx.EvidenceOccurrence, 0, len(n.evidence))
	seenDecl := make(map[string]struct{}, len(n.evidence))
	for _, e := range n.evidence {
		if _, dup := seenDecl[e.declaration]; !dup && scored {
			seenDecl[e.declaration] = struct{}{}
			methods = append(methods, cdx.EvidenceIdentityMethod{
				Technique:  cdx.EvidenceIdentityTechniqueSourceCodeAnalysis,
				Confidence: &score,
				Value:      e.declaration,
			})
		}
		occurrences = append(occurrences, cdx.EvidenceOccurrence{
			Location:          e.host + ":" + e.file,
			AdditionalContext: e.declaration,
		})
	}
	identity := cdx.EvidenceIdentity{
		Field:          cdx.EvidenceIdentityFieldTypeVersion,
		ConcludedValue: n.comp.Version,
	}
	if scored {
		identity.Confidence = &score
		identity.Methods = &methods
	}
	identities := []cdx.EvidenceIdentity{identity}
	return &cdx.Evidence{
		Identity:    &cdx.EvidenceIdentityChoice{Identities: &identities},
		Occurrences: &occurrences,
	}
}

// nativeDependencyEdges reports, per host module bom-ref, the native components
// that module's artefact brings into the binary.
//
// It is what makes the new component reachable in the document's dependency
// graph instead of floating loose in the component list: a reader walking from
// the subject to what it ships arrives at the C library through the Go module
// that carries it, which is how it actually gets there.
func nativeDependencyEdges(components []nativeComponent) map[string][]string {
	if len(components) == 0 {
		return nil
	}
	edges := map[string][]string{}
	for _, n := range components {
		purl := nativedomain.ComponentPURL(n.comp)
		for _, ref := range n.hostRefs {
			if ref == "" {
				continue
			}
			edges[ref] = append(edges[ref], purl)
		}
	}
	return edges
}

// assertNativePURL refuses a native component whose purl is not the generic
// type. It is the counterpart of the Go-only assertion on the module
// components: each half of the list states which scheme it is allowed to use,
// so a bug that crossed them stops the document rather than publishing it.
func assertNativePURL(purl string) error {
	if strings.HasPrefix(purl, "pkg:"+nativedomain.PURLTypeGeneric+"/") {
		return nil
	}
	return fmt.Errorf("%w: %q", domain.ErrNonGenericComponent, purl)
}

// nativeConfidenceScore maps the measurement's own word for how a version was
// established onto the 0-to-1 number CycloneDX requires on every evidence
// method.
//
// "declared" is 1, and that is a reading of the rung rather than a guess at a
// probability. It means the version was taken verbatim from the named macro the
// library publishes as part of its own API, in a source file the build
// compiles. There is no inference step in that chain to be less than certain
// about: either the declaration is there and says 3.53.0, or the recipe did not
// match and no component was named at all. The measurement deliberately has one
// rung today, and its own rule is that a weaker basis earns a LOWER rung rather
// than being reported as this one — so a rung added later arrives here needing
// its own number, and until it has one it is refused.
//
// ok is false for any rung with no mapping. The caller then emits no method,
// because the alternative is inventing a number for a required field, and a
// number in this document is read as something that was measured.
func nativeConfidenceScore(c nativedomain.Confidence) (score float32, ok bool) {
	if c == nativedomain.ConfidenceDeclared {
		return 1, true
	}
	return 0, false
}
