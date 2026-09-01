// Package cyclonedx implements ports.SBOMGenerator producing CycloneDX 1.6 JSON.
// Output is deterministic: identical inputs always produce byte-identical documents.
package cyclonedx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
	"github.com/eitanity/kanonarion/internal/sbom/domain"
	"github.com/eitanity/kanonarion/internal/sbom/ports"
	stdlibdomain "github.com/eitanity/kanonarion/internal/stdlib/domain"
	vendordomain "github.com/eitanity/kanonarion/internal/vendortree/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

const (
	generatorName   = "kanonarion"
	purlTypeGolang  = "golang"
	timestampFormat = time.RFC3339
)

// Generator produces CycloneDX 1.6 JSON SBOMs.
type Generator struct {
	pipelineVersion string
}

// New returns a new Generator.
func New(pipelineVersion string) *Generator {
	return &Generator{pipelineVersion: pipelineVersion}
}

// GeneratorMetadata implements ports.SBOMGenerator.
func (g *Generator) GeneratorMetadata() ports.GeneratorMetadata {
	return ports.GeneratorMetadata{
		Name:    generatorName,
		Version: g.pipelineVersion,
	}
}

// Generate implements ports.SBOMGenerator.
func (g *Generator) Generate(
	ctx context.Context,
	walk walkdomain.WalkRecord,
	licenses map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord,
	req ports.GenerateRequest,
) (domain.SBOMRecord, error) {
	bom, undetermined, err := g.buildBOM(walk, licenses, req)
	if err != nil {
		return domain.SBOMRecord{}, fmt.Errorf("building cyclonedx bom: %w", err)
	}

	content, err := marshalBOM(bom)
	if err != nil {
		return domain.SBOMRecord{}, fmt.Errorf("marshalling cyclonedx bom: %w", err)
	}

	sum := sha256.Sum256(content)
	contentHash := hex.EncodeToString(sum[:])

	id := deterministicID(walk.ID, req.PipelineVersion)

	ts, _ := documentTimestamp(walk, licenses, req)

	return domain.SBOMRecord{
		ID:                 id,
		Ecosystem:          domain.EcosystemGo,
		WalkID:             walk.ID,
		Format:             domain.CycloneDX16,
		Content:            content,
		ContentHash:        contentHash,
		GeneratedAt:        ts,
		PipelineVersion:    req.PipelineVersion,
		Operator:           req.Operator,
		LicensesIncomplete: len(undetermined) > 0,
	}, nil
}

// buildBOM constructs the CycloneDX BOM document from the supplied facts,
// returning the bom-refs of every component in it that carries no licence
// identity.
func (g *Generator) buildBOM(
	walk walkdomain.WalkRecord,
	licenses map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord,
	req ports.GenerateRequest,
) (*cdx.BOM, []string, error) {
	// The document's subject is decided once, here, and both places that
	// describe it read that decision: metadata.component and the subject's own
	// entry in the component list. Deriving them separately is what let a stamped
	// document carry two purls for one module, and put the operator's licence on
	// only one of them.
	subj := resolveSubject(walk.Graph.Target, licenses, req)

	bom := &cdx.BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  cdx.SpecVersion1_6,
		JSONSchema:   "http://cyclonedx.org/schema/bom-1.6.schema.json",
		Version:      1,
		SerialNumber: "urn:uuid:" + deterministicUUID(walk.ID, req.PipelineVersion),
	}

	// Metadata.
	ts, tsDerived := documentTimestamp(walk, licenses, req)
	bom.Metadata = &cdx.Metadata{
		Timestamp: ts.UTC().Format(timestampFormat),
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{
				{
					Type:    cdx.ComponentTypeApplication,
					Name:    generatorName,
					Version: req.PipelineVersion,
				},
			},
		},
		Component: subj.metadataComponent(req.PipelineVersion),
	}
	// Record the build environment the graph was resolved for. GOOS/GOARCH gate
	// build-constraint file selection, so the component set is only valid for this
	// platform; a consumer must know it to reproduce or trust the SBOM.
	props := buildEnvProperties(walk.Graph.BuildEnv)
	props = append(props, timestampBasisProperties(tsDerived, licenceExtractionTime(licenses))...)
	if len(props) > 0 {
		bom.Metadata.Properties = &props
	}

	// Artefact digests are carried on the graph nodes (from the fetch fact
	// record), keyed here by component identity so the assembled components can
	// emit their <hashes>. Nodes without digests (local main, stdlib, legacy or
	// failed fetches) simply have no entry and emit no hashes.
	digestsByRef := make(map[domain.ModuleRef]fetchdomain.ArtifactDigests, len(walk.Graph.Nodes))
	stdlibFactsByRef := make(map[domain.ModuleRef]*walkdomain.StdlibFacts, 1)
	// The assembly policy speaks in ModuleRefs; the recorded origins are keyed by
	// the coordinate the fetch ledger measured. This carries one back to the
	// other so a component can be matched to its own origin fact.
	coordByRef := make(map[domain.ModuleRef]coordinate.ModuleCoordinate, len(walk.Graph.Nodes))
	for _, node := range walk.Graph.Nodes {
		coordByRef[moduleRef(node.Coordinate)] = node.Coordinate
		if !node.Digests.IsZero() {
			digestsByRef[moduleRef(node.Coordinate)] = node.Digests
		}
		if node.Stdlib != nil {
			stdlibFactsByRef[moduleRef(node.Coordinate)] = node.Stdlib
		}
	}

	// Components — assembly policy (inclusion, license attach, ordering,
	// incomplete-license determination) lives in sbom/domain.
	inputs := make([]domain.ComponentInput, 0, len(walk.Graph.Nodes))
	for _, node := range walk.Graph.Nodes {
		// The standard library ships with the toolchain under the Go project's
		// BSD-3-Clause licence and has no fetched licence record. Its licence
		// resolves through walkdomain.StdlibLicense — the source tarball's
		// extracted LICENSE facts when present, the published constant for a
		// legacy or offline node that carries none — the shared rule every
		// surface applies, so it is never counted as an unknown-licence gap.
		if node.ResolutionSource == walkdomain.ResolutionStdlib {
			spdx, _ := walkdomain.StdlibLicense(node.Stdlib)
			inputs = append(inputs, domain.ComponentInput{
				Module:      moduleRef(node.Coordinate),
				HasLicense:  true,
				PrimarySPDX: spdx,
			})
			continue
		}
		lic, hasLic := licenses[node.Coordinate]
		// A component's licence clause states what governs that component's
		// code. Reading the record through coverage keeps an embedded font's or
		// a documentation licence out of it — the SBOM would otherwise assert a
		// Go library is licensed OFL-1.1.
		covered := licensedomain.ReadCoverage(lic)
		input := domain.ComponentInput{
			Module:      moduleRef(node.Coordinate),
			HasLicense:  hasLic,
			PrimarySPDX: covered.PrimarySPDX,
			Expression:  covered.Expression,
			Copyright:   copyrightString(lic),
		}
		// The subject's component entry carries the clause the subject carries,
		// which is the same clause metadata.component states — extracted, or
		// stamped by --main-license when the extraction reached none.
		//
		// Keying this on the ABSENCE OF A LICENCE RECORD instead is what let the
		// stamp miss: a subject whose extraction ran and resolved to no licence
		// has a record, so the stamp was applied to metadata.component and
		// withheld from the component list, and the undetermined count — which
		// reads the component list — named the operator's own module anyway.
		if subj.is(node.Coordinate) && subj.licenseSPDX != "" {
			input.HasLicense = true
			input.PrimarySPDX = subj.licenseSPDX
			input.Expression = ""
		}
		inputs = append(inputs, input)
	}
	assembled, undeterminedRefs := domain.AssembleComponents(inputs)
	components := make([]cdx.Component, 0, len(assembled))
	for _, c := range assembled {
		comp := buildComponent(subj.rewrite(c.Module), c.License, c.Copyright, req.PipelineVersion,
			digestsByRef[c.Module], stdlibFactsByRef[c.Module], originFor(req, coordByRef[c.Module]))
		if subj.isRef(c.Module) && subj.isApplication {
			comp.Type = cdx.ComponentTypeApplication
		}
		if !strings.HasPrefix(comp.PackageURL, "pkg:"+purlTypeGolang+"/") {
			return nil, nil, fmt.Errorf("%w: %q", domain.ErrNonGoComponent, comp.PackageURL)
		}
		components = append(components, comp)
	}
	bom.Components = &components

	// Dependency graph — an entry per component with the root at the metadata
	// component. Edges come from the resolved walk graph (From → To), already
	// deterministic. bom-refs are the component purls.
	deps := buildDependencies(components, bom.Metadata.Component, walk.Graph, subj)
	bom.Dependencies = &deps

	// The document's subject is the artefact being shipped, so it is judged by
	// the same rule as everything it links: the assembly policy never sees it —
	// it is not a graph node — and a subject with no licence clause would
	// otherwise be the one component in a distributed document whose licensing
	// nobody counted.
	undetermined := make([]string, 0, len(undeterminedRefs)+1)
	seen := make(map[string]struct{}, len(undeterminedRefs)+1)
	addUndetermined := func(ref string) {
		if ref == "" {
			return
		}
		if _, dup := seen[ref]; dup {
			return
		}
		seen[ref] = struct{}{}
		undetermined = append(undetermined, ref)
	}
	if bom.Metadata.Component != nil && bom.Metadata.Component.Licenses == nil {
		addUndetermined(bom.Metadata.Component.BOMRef)
	}
	for _, m := range undeterminedRefs {
		addUndetermined(modulePURL(subj.rewrite(m)))
	}

	// Scope statements. Vendor coverage is emitted whenever a tree was read, full
	// coverage included: an artefact that describes a smaller set than the build
	// without saying so reads as complete. Licence completeness is emitted only
	// when something is undetermined, because the schema requires an annotation
	// to name its subjects and a complete document has none to name; the
	// component list saying so of every entry is the statement in that case.
	var annotations []cdx.Annotation
	if req.VendorScope != nil {
		annotations = append(annotations, vendorScopeAnnotation(*req.VendorScope, req.ComponentsScopedToBinary, req.PipelineVersion, ts, documentSubject(bom)))
	}
	if len(undetermined) > 0 {
		annotations = append(annotations, licenceCompletenessAnnotation(undetermined, len(components), req.PipelineVersion, ts))
	}
	if len(annotations) > 0 {
		bom.Annotations = &annotations
	}

	return bom, undetermined, nil
}

// documentSubject returns the bom-ref of the document's subject component, which
// is what a statement about the document as a whole is annotating. Empty when
// there is no subject, in which case the annotation carries no subjects and the
// caller has nothing to point at.
func documentSubject(bom *cdx.BOM) []cdx.BOMReference {
	if bom.Metadata == nil || bom.Metadata.Component == nil || bom.Metadata.Component.BOMRef == "" {
		return nil
	}
	return []cdx.BOMReference{cdx.BOMReference(bom.Metadata.Component.BOMRef)}
}

// licenceCompletenessBOMRef identifies the licence-completeness annotation.
// Fixed, so the document re-emits byte-identically from the same inputs.
const licenceCompletenessBOMRef = "kanonarion:licence-completeness"

// licenceCompletenessAnnotation states, where a reader meets the component list,
// how many of this document's components carry no licence identity and which
// they are.
//
// The console that produced the document is not where the document is read. A
// consumer who receives only the artefact has no other way to tell a component
// whose licence is genuinely undetermined from one whose licence nobody looked
// for, and either reading is a licensing decision made on silence. Naming them
// with their count makes the omission part of what the document says.
//
// The subjects are the undetermined components themselves, so a consumer
// resolving "what does this document say about this component" reaches the
// statement by bom-ref rather than having to read the whole annotation list.
func licenceCompletenessAnnotation(undetermined []string, componentCount int, pipelineVersion string, ts time.Time) cdx.Annotation {
	subjects := make([]cdx.BOMReference, 0, len(undetermined))
	for _, ref := range undetermined {
		subjects = append(subjects, cdx.BOMReference(ref))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Licence completeness of this document: %d of the %d component(s) inventoried here carry no licence identity, and are named as this annotation's subjects.",
		len(undetermined), componentCount)
	b.WriteString(" A component with no licences block is one whose licence kanonarion could not determine — no licence file was found for it, or the files that were found match no known SPDX licence text.")
	b.WriteString(" It is not a statement that the component is unlicensed, and it must not be read as permission to use it:")
	for _, ref := range undetermined {
		fmt.Fprintf(&b, " %s;", ref)
	}
	return cdx.Annotation{
		BOMRef:   licenceCompletenessBOMRef,
		Subjects: &subjects,
		Annotator: &cdx.Annotator{
			Component: &cdx.Component{
				Type:    cdx.ComponentTypeApplication,
				Name:    generatorName,
				Version: pipelineVersion,
			},
		},
		Timestamp: ts.UTC().Format(timestampFormat),
		Text:      b.String(),
	}
}

// vendorScopeBOMRef identifies the vendor-scope annotation. Fixed, so the
// document re-emits byte-identically from the same inputs.
const vendorScopeBOMRef = "kanonarion:vendor-scope"

// vendorScopeAnnotation states what this document covers of the vendored tree
// the project holds: the tree's module count, how many the component list
// describes, and every module it does not with the reason it does not.
//
// It is emitted whenever a vendored tree was read, including when coverage is
// complete. Full coverage stated is a fact a reader can rely on; full coverage
// left to silence is indistinguishable from a narrowing nobody mentioned, and
// in an air-gapped project — where the vendored tree IS the build and there is
// no proxy to check against — walking modules.txt by hand is the only other way
// to find out.
//
// A module contributing no package is named as out of scope by construction,
// not as a gap. `go mod vendor` writes its heading and vendors no directory, so
// its absence from the document is correct; rendering a correct absence as
// drift is the false positive this distinction exists to prevent.
//
// Every field derives from inputs the document already carries — the fixed
// bom-ref, the domain-sorted uncovered list, the generator component and the
// document's own clock-free timestamp — so determinism is untouched.
func vendorScopeAnnotation(scope vendordomain.VendorScope, scopedToBinary bool, pipelineVersion string, ts time.Time, subjects []cdx.BOMReference) cdx.Annotation {
	var b strings.Builder
	fmt.Fprintf(&b, "Scope of this document against the project's vendored tree: vendor/modules.txt lists %d module(s); this document describes %d of them.",
		scope.TreeModules, scope.Covered)
	if scopedToBinary {
		b.WriteString(" This document's components are scoped to a single binary's import closure, so it describes the modules that binary reaches rather than the whole build.")
	}
	if scope.FullyCovered() {
		b.WriteString(" Every module in the vendored tree is described here.")
	} else {
		fmt.Fprintf(&b, " The %d it does not describe, and why:", len(scope.Uncovered))
		for _, u := range scope.Uncovered {
			fmt.Fprintf(&b, " %s %s — %s", u.Path, u.Version, u.Reason)
			if u.PackageLines > 0 {
				fmt.Fprintf(&b, " (%d package line(s))", u.PackageLines)
			}
			b.WriteString(";")
		}
		b.WriteString(" A package line is a package `go mod vendor` wrote under the module heading across all build constraints; it is not a count of what this build compiles.")
	}
	return cdx.Annotation{
		BOMRef:   vendorScopeBOMRef,
		Subjects: &subjects,
		Annotator: &cdx.Annotator{
			Component: &cdx.Component{
				Type:    cdx.ComponentTypeApplication,
				Name:    generatorName,
				Version: pipelineVersion,
			},
		},
		Timestamp: ts.UTC().Format(timestampFormat),
		Text:      b.String(),
	}
}

// moduleRef projects a fetch ModuleCoordinate onto the sbom-domain identity.
func moduleRef(coord coordinate.ModuleCoordinate) domain.ModuleRef {
	return domain.ModuleRef{Path: coord.Path(), Version: coord.Version()}
}

// buildComponent maps an assembled domain Component to a CycloneDX Component.
// digests, when present, are emitted as the component's <hashes>; a zero value
// (local main, legacy or failed fetch) yields no hashes rather than fabricated
// ones. origin, when present, is the module's recorded provenance and is the
// only thing that produces an externalReference.
func buildComponent(
	mod domain.ModuleRef,
	spdx, copyright, pipelineVersion string,
	digests fetchdomain.ArtifactDigests,
	stdlib *walkdomain.StdlibFacts,
	origin ports.ModuleOrigin,
) cdx.Component {
	if mod.Path == walkdomain.StdlibModulePath {
		return buildStdlibComponent(mod, spdx, pipelineVersion, digests, stdlib)
	}
	purl := modulePURL(mod)
	comp := cdx.Component{
		BOMRef:     purl,
		Type:       cdx.ComponentTypeLibrary,
		Name:       mod.Path,
		Version:    mod.Version,
		PackageURL: purl,
		Properties: &[]cdx.Property{
			{Name: "kanonarion:ecosystem", Value: domain.EcosystemGo},
			{Name: "kanonarion:pipeline_version", Value: pipelineVersion},
		},
	}
	if refs := moduleExternalReferences(origin); refs != nil {
		comp.ExternalReferences = refs
	}

	if hashes := digestHashes(digests); hashes != nil {
		comp.Hashes = hashes
	}
	if spdx != "" {
		choice := cdx.LicenseChoice{}
		if isSPDXExpression(spdx) {
			choice.Expression = spdx
		} else {
			choice.License = &cdx.License{ID: spdx}
		}
		comp.Licenses = &cdx.Licenses{choice}
	}
	if copyright != "" {
		comp.Copyright = copyright
	}

	return comp
}

// moduleExternalReferences builds a module component's external references from
// what the fetch ledger recorded, and returns nil when it recorded nothing.
//
// Nothing here is derived from the module path. A path is an import identity,
// not an address: github.com/oklog/ulid/v2 names no repository GitHub serves
// (the major-version suffix is a module-path element), golang.org/x/mod is not
// a forge URL, and a proxy zip URL for a module the proxy never carried names a
// download that cannot happen. Every such reference in a shipped document is an
// assertion nobody measured, in an artefact whose reader cannot re-run the
// tool.
//
// There is no distribution reference. The ledger records the route the bytes
// arrived by and the blob handle they were filed under, not a public download
// address, so nothing here can support one. The standard-library component is
// the exception and keeps its own: it has a recorded source URL to emit.
func moduleExternalReferences(origin ports.ModuleOrigin) *[]cdx.ExternalReference {
	if origin.VCSURL == "" {
		return nil
	}
	ref := cdx.ExternalReference{Type: cdx.ERTypeVCS, URL: origin.VCSURL}
	switch {
	case origin.VCSRef != "" && origin.VCSCommit != "":
		ref.Comment = "the module zip was cross-verified against " + origin.VCSRef + " at commit " + origin.VCSCommit
	case origin.VCSCommit != "":
		ref.Comment = "the module zip was cross-verified against commit " + origin.VCSCommit
	}
	return &[]cdx.ExternalReference{ref}
}

// originFor returns the recorded origin for a coordinate, or the zero value when
// the caller supplied none for it.
func originFor(req ports.GenerateRequest, coord coordinate.ModuleCoordinate) ports.ModuleOrigin {
	if req.ModuleOrigins == nil {
		return ports.ModuleOrigin{}
	}
	return req.ModuleOrigins[coord]
}

// digestHashes renders artefact digests as CycloneDX hashes in fixed algorithm
// order (SHA-256, SHA-384, SHA-512). Only the recommended SHA-2 family is
// emitted — never MD5 or SHA-1. Returns nil when no digests are present so the
// caller omits the <hashes> block entirely.
func digestHashes(d fetchdomain.ArtifactDigests) *[]cdx.Hash {
	if d.IsZero() {
		return nil
	}
	var hashes []cdx.Hash
	if d.SHA256 != "" {
		hashes = append(hashes, cdx.Hash{Algorithm: cdx.HashAlgoSHA256, Value: d.SHA256})
	}
	if d.SHA384 != "" {
		hashes = append(hashes, cdx.Hash{Algorithm: cdx.HashAlgoSHA384, Value: d.SHA384})
	}
	if d.SHA512 != "" {
		hashes = append(hashes, cdx.Hash{Algorithm: cdx.HashAlgoSHA512, Value: d.SHA512})
	}
	if len(hashes) == 0 {
		return nil
	}
	return &hashes
}

// buildDependencies emits a CycloneDX dependencies array: one entry per
// component plus the metadata (root) component, with dependsOn populated from
// the resolved graph edges. Every entry carries a (possibly empty) dependsOn —
// an allowed CDX pattern — and entries are sorted by ref for determinism.
//
// Graph coordinates are projected through the subject, so a stamped subject
// appears here under the one identity the rest of the document gives it. Left
// unprojected, the array carried two entries for the subject — its stamped
// bom-ref and its graph coordinate — each repeating the whole dependency set,
// and a consumer resolving the document saw two artefacts where there is one.
func buildDependencies(components []cdx.Component, root *cdx.Component, graph walkdomain.Graph, subj subject) []cdx.Dependency {
	purlOf := func(c coordinate.ModuleCoordinate) string {
		return modulePURL(subj.rewrite(moduleRef(c)))
	}
	adjacency := make(map[string]map[string]struct{})
	for _, e := range graph.Edges {
		from := purlOf(e.From)
		to := purlOf(e.To)
		if adjacency[from] == nil {
			adjacency[from] = make(map[string]struct{})
		}
		adjacency[from][to] = struct{}{}
	}
	dependsOn := func(adjKey string) *[]string {
		on := make([]string, 0, len(adjacency[adjKey]))
		for ref := range adjacency[adjKey] {
			on = append(on, ref)
		}
		sort.Strings(on)
		return &on
	}

	deps := make([]cdx.Dependency, 0, len(components)+1)
	seen := make(map[string]struct{}, len(components)+1)
	add := func(ref, adjKey string) {
		if ref == "" {
			return
		}
		if _, dup := seen[ref]; dup {
			return
		}
		seen[ref] = struct{}{}
		deps = append(deps, cdx.Dependency{Ref: ref, Dependencies: dependsOn(adjKey)})
	}

	if root != nil {
		add(root.BOMRef, purlOf(graph.Target))
	}
	for _, c := range components {
		add(c.BOMRef, c.BOMRef)
	}
	// Ref cannot tie: the `seen` set above admits one entry per ref, so this is a
	// total order over the elements that reach it.
	sort.Slice(deps, func(i, j int) bool { return deps[i].Ref < deps[j].Ref })
	return deps
}

// buildStdlibComponent builds the CycloneDX component for the synthetic
// standard-library node. It differs from an ordinary module component: the
// stdlib is not a proxy artefact, so it carries the real Go source repository as
// its VCS reference and no proxy-zip distribution URL (which would 404).
//
// When chain-of-custody facts are present it emits the source-tarball digests as
// <hashes>, the acquired source tarball as a distribution reference, the
// googlesource commit as a VCS reference, and properties recording the
// verification status and the anchor limitation — which anchors that particular
// measurement reached, which it did not, and the ceiling that holds on every
// route: weaker than a module's sumdb transparency-log entry, and never present
// in the project's go.sum.
func buildStdlibComponent(mod domain.ModuleRef, spdx, pipelineVersion string, digests fetchdomain.ArtifactDigests, facts *walkdomain.StdlibFacts) cdx.Component {
	purl := modulePURL(mod)
	if spdx == "" {
		spdx = walkdomain.StdlibLicenseSPDX
	}
	comp := cdx.Component{
		BOMRef:     purl,
		Type:       cdx.ComponentTypeLibrary,
		Name:       mod.Path,
		Version:    mod.Version,
		PackageURL: purl,
		Description: "Go standard library (toolchain-provided); not a fetched module. " +
			"Included so vulnerability and platform coverage span the standard library.",
		ExternalReferences: stdlibExternalReferences(facts),
		Properties:         stdlibProperties(pipelineVersion, facts),
	}
	if hashes := digestHashes(digests); hashes != nil {
		comp.Hashes = hashes
	}
	comp.Licenses = &cdx.Licenses{cdx.LicenseChoice{License: &cdx.License{ID: spdx}}}
	return comp
}

// stdlibExternalReferences builds the stdlib component's external references:
// always the Go source repository (VCS) and website; plus, when facts are
// present, the canonical source-tarball distribution URL and — when resolved —
// the googlesource commit as an additional VCS anchor.
func stdlibExternalReferences(facts *walkdomain.StdlibFacts) *[]cdx.ExternalReference {
	vcsURL := "https://go.googlesource.com/go"
	if facts != nil && facts.VCSURL != "" {
		vcsURL = facts.VCSURL
	}
	refs := []cdx.ExternalReference{
		{Type: cdx.ERTypeVCS, URL: vcsURL},
		{Type: cdx.ERTypeWebsite, URL: "https://go.dev/"},
	}
	if facts != nil {
		if facts.SourceURL != "" {
			refs = append(refs, cdx.ExternalReference{Type: cdx.ERTypeDistribution, URL: facts.SourceURL})
		}
		if facts.VCSCommit != "" {
			refs = append(refs, cdx.ExternalReference{
				Type:    cdx.ERTypeVCS,
				URL:     vcsURL,
				Comment: "release tag " + facts.VCSRef + " → commit " + facts.VCSCommit,
			})
		}
	}
	return &refs
}

// stdlibProperties builds the stdlib component's properties. Beyond the base
// ecosystem/pipeline/stdlib markers it records, when facts are present, the
// go.dev/dl verification status and detail, the published tarball checksum, and
// the anchor limitation — what this component's integrity actually rests on,
// derived from the status that was reached rather than stated as a fixed
// sentence about the route a connected run happens to take.
func stdlibProperties(pipelineVersion string, facts *walkdomain.StdlibFacts) *[]cdx.Property {
	props := []cdx.Property{
		{Name: "kanonarion:ecosystem", Value: domain.EcosystemGo},
		{Name: "kanonarion:pipeline_version", Value: pipelineVersion},
		{Name: "kanonarion:component:stdlib", Value: "true"},
	}
	if facts != nil {
		if facts.VerificationStatus != "" {
			props = append(props, cdx.Property{Name: "kanonarion:stdlib:verification", Value: facts.VerificationStatus})
		}
		if facts.VerificationDetail != "" {
			props = append(props, cdx.Property{Name: "kanonarion:stdlib:verification_detail", Value: facts.VerificationDetail})
		}
		if facts.PublishedSHA256 != "" {
			props = append(props, cdx.Property{Name: "kanonarion:stdlib:published_sha256", Value: facts.PublishedSHA256})
		}
		props = append(props, cdx.Property{
			Name:  "kanonarion:stdlib:anchor_limitation",
			Value: stdlibdomain.AnchorLimitation(stdlibdomain.VerificationStatus(facts.VerificationStatus), facts.VCSCommit != ""),
		})
	}
	return &props
}

// buildEnvProperties renders the resolved build environment as CycloneDX
// metadata properties, emitting only the values that were captured so a record
// with no build environment (a non-project walk, or a pre-BuildEnv record)
// contributes none. The ordering is fixed (goos, goarch, go_version) for
// deterministic output.
func buildEnvProperties(env walkdomain.BuildEnv) []cdx.Property {
	var props []cdx.Property
	add := func(key, value string) {
		if value != "" {
			props = append(props, cdx.Property{Name: "kanonarion:build:" + key, Value: value})
		}
	}
	add("goos", env.GOOS)
	add("goarch", env.GOARCH)
	add("go_version", env.GoVersion)
	return props
}

// subject is the document's subject, decided once from the walk target and the
// caller's stamp.
//
// It exists because the subject is described in two places — metadata.component
// and its own entry in the component list — and those two descriptions must be
// the same description. Derived separately, they were not: a stamped run put
// the release version and the operator's licence on metadata.component while
// the component list still carried the module at the synthetic version "local"
// with no licence, so one document asserted two purls for one module, and the
// undetermined-licence count read the copy the stamp never reached.
//
// The stamp applies only to a project SBOM, whose subject is the local main
// module. The synthetic "local" version is the reliable signal: a walk rooted at
// a published module carries a real semver target, is a library at its own
// version, and is left alone.
type subject struct {
	// target is the walk target coordinate: the graph node the subject is.
	target coordinate.ModuleCoordinate
	// ref is the subject's identity in the document, after any version stamp.
	ref domain.ModuleRef
	// licenseSPDX is the licence clause the subject carries, whether extracted
	// or stamped. Empty means the subject is unlicensed.
	licenseSPDX string
	// copyright is the copyright statement from the subject's licence record.
	copyright string
	// isApplication marks the subject as a compiled application rather than a
	// library — CycloneDX's expected type for a top-level binary.
	isApplication bool
	// stamped reports that a version stamp was applied, so the subject's
	// identity differs from its graph coordinate and references to it need
	// projecting.
	stamped bool
}

// resolveSubject derives the document's subject from the walk target, the
// licence records and the caller's stamp.
func resolveSubject(
	target coordinate.ModuleCoordinate,
	licenses map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord,
	req ports.GenerateRequest,
) subject {
	lic, hasLic := licenses[target]
	covered := licensedomain.ReadCoverage(lic)
	s := subject{
		target:      target,
		ref:         moduleRef(target),
		licenseSPDX: domain.LicenseClause(hasLic, covered.PrimarySPDX, covered.Expression),
		copyright:   copyrightString(lic),
	}
	if target.Version() != coordinate.LocalVersion {
		return s
	}
	s.isApplication = true
	if req.MainComponentVersion != "" {
		s.ref.Version = req.MainComponentVersion
		s.stamped = true
	}
	if s.licenseSPDX == "" {
		s.licenseSPDX = req.MainComponentLicense
	}
	return s
}

// is reports whether a coordinate is the document's subject.
func (s subject) is(c coordinate.ModuleCoordinate) bool { return c == s.target }

// isRef reports whether a module ref is the subject's graph identity.
func (s subject) isRef(m domain.ModuleRef) bool { return m == moduleRef(s.target) }

// rewrite projects a module ref onto the identity the document gives it: the
// subject's graph coordinate becomes its stamped identity, everything else
// passes through. It is what keeps purls, bom-refs, dependency entries and the
// undetermined-licence list naming one module once.
func (s subject) rewrite(m domain.ModuleRef) domain.ModuleRef {
	if s.stamped && s.isRef(m) {
		return s.ref
	}
	return m
}

// metadataComponent builds the document's primary component from the subject.
// The root component is the compiled subject, not a fetched artefact, so it
// carries no zip digests; and it asserts no origin, because the fetch ledger
// holds no measurement of a module nobody fetched.
func (s subject) metadataComponent(pipelineVersion string) *cdx.Component {
	comp := buildComponent(s.ref, s.licenseSPDX, s.copyright, pipelineVersion,
		fetchdomain.ArtifactDigests{}, nil, ports.ModuleOrigin{})
	if s.isApplication {
		comp.Type = cdx.ComponentTypeApplication
	}
	return &comp
}

// isSPDXExpression reports whether s is a compound SPDX expression (contains
// OR, AND, or WITH operators or parentheses). Simple SPDX identifiers are
// encoded as cdx.License{ID}; expressions use cdx.LicenseChoice{Expression}.
func isSPDXExpression(s string) bool {
	return strings.Contains(s, " OR ") ||
		strings.Contains(s, " AND ") ||
		strings.Contains(s, " WITH ") ||
		strings.ContainsRune(s, '(')
}

// copyrightString aggregates copyright verbatim statements from all license files
// into a single newline-joined string. Returns "" when no statements are found.
// Statements are already sorted (per domain.SortFiles), so output is deterministic.
func copyrightString(lic licensedomain.LicenseRecord) string {
	if lic.CopyrightStatus != licensedomain.CopyrightStatusFound {
		return ""
	}
	seen := make(map[string]struct{})
	var parts []string
	for _, f := range lic.LicenseFiles {
		for _, s := range f.CopyrightStatements {
			if _, dup := seen[s.Verbatim]; dup {
				continue
			}
			seen[s.Verbatim] = struct{}{}
			parts = append(parts, s.Verbatim)
		}
	}
	return strings.Join(parts, "\n")
}

// modulePURL returns the Package URL for a module.
func modulePURL(mod domain.ModuleRef) string {
	return "pkg:" + purlTypeGolang + "/" + mod.Path + "@" + mod.Version
}

// documentTimestamp resolves what this document's metadata timestamp carries and
// whether that value is derived rather than a creation time.
//
// CycloneDX defines metadata.timestamp as when the BOM was created. A caller who
// supplies one is answering that question, and it is used verbatim. A caller who
// supplies none leaves the question unanswerable here — this generator holds no
// clock, because reading one would mean the same recorded inputs stop producing
// the same bytes — so the document falls back to the newest licence extraction
// time among its inputs and says, in its own metadata, that it did. A derived
// value labelled as derived is a true statement about the evidence; the same
// value in an unlabelled creation field is a false statement about the document.
func documentTimestamp(
	walk walkdomain.WalkRecord,
	licenses map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord,
	req ports.GenerateRequest,
) (ts time.Time, derived bool) {
	if !req.DocumentTimestamp.IsZero() {
		return req.DocumentTimestamp.UTC().Truncate(time.Second), false
	}
	return derivedTimestamp(walk, licenses), true
}

// timestampBasisProperties record what metadata.timestamp means in this document
// and, separately, the input-derived time it might otherwise be confused with.
//
// The licence extraction time is emitted whichever basis applies. It is a fact
// about the evidence — when the licence facts under these components were last
// measured — and a reader who wants it should not have to infer it from a field
// that may or may not be it. CycloneDX metadata.lifecycles is the other candidate
// home and is not one: its entries name a phase, and carry no timestamp.
func timestampBasisProperties(derived bool, licenceExtraction time.Time) []cdx.Property {
	basis := "caller-supplied document creation time"
	if derived {
		basis = "derived: newest licence extraction time among this document's inputs; no creation time was supplied, and this generator reads no clock"
	}
	props := []cdx.Property{{Name: "kanonarion:document:timestamp_basis", Value: basis}}
	if !licenceExtraction.IsZero() {
		props = append(props, cdx.Property{
			Name:  "kanonarion:licence:newest_extraction",
			Value: licenceExtraction.UTC().Format(timestampFormat),
		})
	}
	return props
}

// licenceExtractionTime returns the newest ExtractedAt among the licence records
// this document was built from, zero when there are none.
func licenceExtractionTime(licenses map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord) time.Time {
	var t time.Time
	// A maximum, so the map order cannot reach the answer: the kept value is the
	// same instant whichever record is seen first, and no record's identity is
	// published beside it.
	for _, lic := range licenses {
		if lic.ExtractedAt.After(t) {
			t = lic.ExtractedAt
		}
	}
	return t.UTC().Truncate(time.Second)
}

// derivedTimestamp returns the maximum ExtractedAt from licence records, rounded
// to second precision. When no licence data is present it falls back through the
// walk's own clock-injected timestamps so empty or failed-target walks (which
// have a zero Graph.ResolvedAt) still get a meaningful, deterministic value
// rather than the zero time.
func derivedTimestamp(
	walk walkdomain.WalkRecord,
	licenses map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord,
) time.Time {
	t := licenceExtractionTime(licenses)
	for _, fallback := range []time.Time{
		walk.Graph.ResolvedAt,
		walk.CompletedAt,
		walk.StartedAt,
	} {
		if !t.IsZero() {
			break
		}
		t = fallback
	}
	return t.UTC().Truncate(time.Second)
}

// deterministicID returns a stable record ID derived from the generation inputs.
func deterministicID(walkID string, pipelineVersion string) string {
	key := walkID + "|" + pipelineVersion
	sum := sha256.Sum256([]byte(key))
	return "sbom-" + hex.EncodeToString(sum[:])[:24]
}

// deterministicUUID returns a UUID-shaped string derived from the generation inputs.
// It is not a proper UUID v5 but is stable and unique for the same inputs.
func deterministicUUID(walkID string, pipelineVersion string) string {
	key := "sbom-uuid|" + walkID + "|" + pipelineVersion
	sum := sha256.Sum256([]byte(key))
	h := hex.EncodeToString(sum[:])
	// Format as 8-4-4-4-12.
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// marshalBOM serialises the BOM to canonical JSON with sorted keys and consistent indentation.
func marshalBOM(bom *cdx.BOM) ([]byte, error) {
	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	if err := enc.EncodeVersion(bom, cdx.SpecVersion1_6); err != nil {
		return nil, fmt.Errorf("encoding cyclonedx bom: %w", err)
	}

	// Re-marshal through encoding/json to guarantee sorted keys.
	var raw any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		return nil, fmt.Errorf("re-parsing cyclonedx json: %w", err)
	}
	canonical, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("canonical json marshal: %w", err)
	}
	return canonical, nil
}
