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
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
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
	vulnerabilities []vulndomain.VulnerabilityRecord,
	req ports.GenerateRequest,
) (domain.SBOMRecord, error) {
	bom, licensesIncomplete, err := g.buildBOM(walk, licenses, vulnerabilities, req)
	if err != nil {
		return domain.SBOMRecord{}, fmt.Errorf("building cyclonedx bom: %w", err)
	}

	content, err := marshalBOM(bom)
	if err != nil {
		return domain.SBOMRecord{}, fmt.Errorf("marshalling cyclonedx bom: %w", err)
	}

	sum := sha256.Sum256(content)
	contentHash := hex.EncodeToString(sum[:])

	id := deterministicID(walk.ID, req.WalkScanRunID, req.PipelineVersion)

	return domain.SBOMRecord{
		ID:                 id,
		Ecosystem:          domain.EcosystemGo,
		WalkID:             walk.ID,
		WalkScanRunID:      req.WalkScanRunID,
		Format:             domain.CycloneDX16,
		Content:            content,
		ContentHash:        contentHash,
		GeneratedAt:        deterministicTimestamp(walk, licenses),
		PipelineVersion:    req.PipelineVersion,
		Operator:           req.Operator,
		LicensesIncomplete: licensesIncomplete,
	}, nil
}

// buildBOM constructs the CycloneDX BOM document from the supplied facts.
func (g *Generator) buildBOM(
	walk walkdomain.WalkRecord,
	licenses map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord,
	vulnerabilities []vulndomain.VulnerabilityRecord,
	req ports.GenerateRequest,
) (*cdx.BOM, bool, error) {
	bom := &cdx.BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  cdx.SpecVersion1_6,
		JSONSchema:   "http://cyclonedx.org/schema/bom-1.6.schema.json",
		Version:      1,
		SerialNumber: "urn:uuid:" + deterministicUUID(walk.ID, req.WalkScanRunID, req.PipelineVersion),
	}

	// Metadata.
	ts := deterministicTimestamp(walk, licenses)
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
		Component: moduleComponent(walk.Graph.Target, licenses, req.PipelineVersion, mainComponentOptionsFor(walk.Graph.Target, req)),
	}
	// Record the build environment the graph was resolved for. GOOS/GOARCH gate
	// build-constraint file selection, so the component set is only valid for this
	// platform; a consumer must know it to reproduce or trust the SBOM.
	if props := buildEnvProperties(walk.Graph.BuildEnv); props != nil {
		bom.Metadata.Properties = props
	}

	// Artefact digests are carried on the graph nodes (from the fetch fact
	// record), keyed here by component identity so the assembled components can
	// emit their <hashes>. Nodes without digests (local main, stdlib, legacy or
	// failed fetches) simply have no entry and emit no hashes.
	digestsByRef := make(map[domain.ModuleRef]fetchdomain.ArtifactDigests, len(walk.Graph.Nodes))
	stdlibFactsByRef := make(map[domain.ModuleRef]*walkdomain.StdlibFacts, 1)
	for _, node := range walk.Graph.Nodes {
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
		// BSD-3-Clause licence and has no fetched licence record. Its licence is
		// now extracted from the source tarball's LICENSE file (carried on the
		// node); fall back to the constant only for a legacy or offline node that
		// carries no facts, so it is never counted as an unknown-licence gap.
		if node.ResolutionSource == walkdomain.ResolutionStdlib {
			inputs = append(inputs, domain.ComponentInput{
				Module:      moduleRef(node.Coordinate),
				HasLicense:  true,
				PrimarySPDX: stdlibComponentLicense(node.Stdlib),
			})
			continue
		}
		lic, hasLic := licenses[node.Coordinate]
		inputs = append(inputs, domain.ComponentInput{
			Module:      moduleRef(node.Coordinate),
			HasLicense:  hasLic,
			PrimarySPDX: lic.PrimarySPDX,
			Expression:  lic.Expression,
			Copyright:   copyrightString(lic),
		})
	}
	assembled, licensesIncomplete := domain.AssembleComponents(inputs)
	components := make([]cdx.Component, 0, len(assembled))
	for _, c := range assembled {
		comp := buildComponent(c.Module, c.License, c.Copyright, req.PipelineVersion, digestsByRef[c.Module], stdlibFactsByRef[c.Module])
		if !strings.HasPrefix(comp.PackageURL, "pkg:"+purlTypeGolang+"/") {
			return nil, false, fmt.Errorf("%w: %q", domain.ErrNonGoComponent, comp.PackageURL)
		}
		components = append(components, comp)
	}
	bom.Components = &components

	// Dependency graph — an entry per component with the root at the metadata
	// component. Edges come from the resolved walk graph (From → To), already
	// deterministic. bom-refs are the component purls.
	deps := buildDependencies(components, bom.Metadata.Component, walk.Graph)
	bom.Dependencies = &deps

	// Vulnerabilities — dedup/aggregation policy lives in sbom/domain.
	if len(vulnerabilities) > 0 {
		findings := make([]domain.FindingInput, 0)
		for _, rec := range vulnerabilities {
			ref := moduleRef(rec.Coordinate)
			for _, f := range rec.Findings {
				findings = append(findings, domain.FindingInput{
					Module:        ref,
					ID:            f.ID,
					Summary:       f.Summary,
					SeverityLabel: severityLabel(f.Severity),
				})
			}
		}
		cdxVulns := buildVulnerabilities(domain.AggregateVulnerabilities(findings))
		bom.Vulnerabilities = &cdxVulns
	}

	return bom, licensesIncomplete, nil
}

// moduleRef projects a fetch ModuleCoordinate onto the sbom-domain identity.
func moduleRef(coord coordinate.ModuleCoordinate) domain.ModuleRef {
	return domain.ModuleRef{Path: coord.Path, Version: coord.Version}
}

// buildComponent maps an assembled domain Component to a CycloneDX Component.
// digests, when present, are emitted as the component's <hashes>; a zero value
// (local main, legacy or failed fetch) yields no hashes rather than fabricated
// ones.
func buildComponent(mod domain.ModuleRef, spdx, copyright, pipelineVersion string, digests fetchdomain.ArtifactDigests, stdlib *walkdomain.StdlibFacts) cdx.Component {
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
		ExternalReferences: &[]cdx.ExternalReference{
			{
				Type: cdx.ERTypeVCS,
				URL:  "https://" + mod.Path,
			},
			{
				Type: cdx.ERTypeDistribution,
				URL:  "https://proxy.golang.org/" + mod.Path + "/@v/" + mod.Version + ".zip",
			},
		},
		Properties: &[]cdx.Property{
			{Name: "kanonarion:ecosystem", Value: domain.EcosystemGo},
			{Name: "kanonarion:pipeline_version", Value: pipelineVersion},
		},
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
// an allowed CDX pattern — and entries are sorted by ref for determinism. The
// root's edges are those leaving the walk target coordinate, which may differ
// from the metadata component's own bom-ref when a version override is applied.
func buildDependencies(components []cdx.Component, root *cdx.Component, graph walkdomain.Graph) []cdx.Dependency {
	adjacency := make(map[string]map[string]struct{})
	for _, e := range graph.Edges {
		from := modulePURL(moduleRef(e.From))
		to := modulePURL(moduleRef(e.To))
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
		add(root.BOMRef, modulePURL(moduleRef(graph.Target)))
	}
	for _, c := range components {
		add(c.BOMRef, c.BOMRef)
	}
	sort.Slice(deps, func(i, j int) bool { return deps[i].Ref < deps[j].Ref })
	return deps
}

// stdlibLicenseSPDX is the SPDX identifier for the Go standard library. The Go
// project (and therefore the standard library that ships with the toolchain) is
// distributed under BSD-3-Clause, so the synthetic stdlib component carries it
// rather than being reported as an unknown-licence coverage gap.
const stdlibLicenseSPDX = "BSD-3-Clause"

// stdlibComponentLicense resolves the SPDX identifier for the stdlib component:
// the licence extracted from the source tarball's LICENSE file when facts are
// present, falling back to the known BSD-3-Clause constant only for a legacy or
// offline node that carries no facts (so the SBOM never counts stdlib as an
// unknown-licence gap).
func stdlibComponentLicense(facts *walkdomain.StdlibFacts) string {
	if facts != nil && facts.LicenseSPDX != "" {
		return facts.LicenseSPDX
	}
	return stdlibLicenseSPDX
}

// buildStdlibComponent builds the CycloneDX component for the synthetic
// standard-library node. It differs from an ordinary module component: the
// stdlib is not a proxy artefact, so it carries the real Go source repository as
// its VCS reference and no proxy-zip distribution URL (which would 404).
//
// When chain-of-custody facts are present it emits the source-tarball digests as
// <hashes>, the go.dev/dl source tarball as a distribution reference, the
// googlesource commit as a VCS reference, and properties recording the
// verification status and the honest limitation — the stdlib anchor is a
// published checksum plus a source-repo tag, weaker than a module's sumdb
// transparency-log entry, and it never appears in the project's go.sum.
func buildStdlibComponent(mod domain.ModuleRef, spdx, pipelineVersion string, digests fetchdomain.ArtifactDigests, facts *walkdomain.StdlibFacts) cdx.Component {
	purl := modulePURL(mod)
	if spdx == "" {
		spdx = stdlibLicenseSPDX
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
// an explicit note that this anchor is weaker than sumdb and absent from go.sum.
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
			Value: "integrity anchored to go.dev/dl published checksum and googlesource tag/commit; weaker than a module sumdb transparency-log entry and never present in go.sum",
		})
	}
	return &props
}

// buildEnvProperties renders the resolved build environment as CycloneDX
// metadata properties, emitting only the values that were captured so a record
// with no build environment (a non-project walk, or a pre-BuildEnv record)
// produces no properties block. The ordering is fixed (goos, goarch, go_version)
// for deterministic output.
func buildEnvProperties(env walkdomain.BuildEnv) *[]cdx.Property {
	var props []cdx.Property
	add := func(key, value string) {
		if value != "" {
			props = append(props, cdx.Property{Name: "kanonarion:build:" + key, Value: value})
		}
	}
	add("goos", env.GOOS)
	add("goarch", env.GOARCH)
	add("go_version", env.GoVersion)
	if len(props) == 0 {
		return nil
	}
	return &props
}

// mainComponentOptions carries the subject-specific overrides applied to the
// SBOM's primary component (metadata.component). They are meaningful only for a
// project SBOM whose subject is the local main module — a compiled binary at the
// synthetic version "local" with no fetched licence record.
type mainComponentOptions struct {
	// versionOverride replaces the subject's "local" version (and the PURL and
	// distribution URL derived from it) with a resolvable coordinate, e.g. a
	// release tag. Empty leaves the graph version untouched.
	versionOverride string
	// licenseSPDX is attached to the subject when it has no fetched licence
	// record. Empty leaves the subject unlicensed.
	licenseSPDX string
	// isApplication marks the subject as a compiled application rather than a
	// library — CycloneDX's expected type for a top-level binary.
	isApplication bool
}

// mainComponentOptionsFor derives the subject overrides for a walk. Overrides
// apply only when the subject is the local main module (a project SBOM): its
// synthetic "local" version is the reliable signal, since a walk rooted at a
// published module carries a real semver target and is left as a library at its
// own version. A subject that is the local main module is always an application;
// version and licence overrides are applied only when the caller supplied them.
func mainComponentOptionsFor(target coordinate.ModuleCoordinate, req ports.GenerateRequest) mainComponentOptions {
	if target.Version != coordinate.LocalVersion {
		return mainComponentOptions{}
	}
	return mainComponentOptions{
		versionOverride: req.MainComponentVersion,
		licenseSPDX:     req.MainComponentLicense,
		isApplication:   true,
	}
}

// moduleComponent builds the metadata primary component for the walk target,
// applying any subject-specific overrides (version, licence, application type).
func moduleComponent(
	coord coordinate.ModuleCoordinate,
	licenses map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord,
	pipelineVersion string,
	opts mainComponentOptions,
) *cdx.Component {
	lic, hasLic := licenses[coord]
	ref := moduleRef(coord)
	if opts.versionOverride != "" {
		ref.Version = opts.versionOverride
	}
	spdx := domain.LicenseClause(hasLic, lic.PrimarySPDX, lic.Expression)
	if spdx == "" {
		spdx = opts.licenseSPDX
	}
	// The metadata (root) component is the compiled subject, not a fetched
	// artefact, so it carries no zip digests.
	comp := buildComponent(ref, spdx, copyrightString(lic), pipelineVersion, fetchdomain.ArtifactDigests{}, nil)
	if opts.isApplication {
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

// buildVulnerabilities maps aggregated domain vulnerabilities to CycloneDX.
func buildVulnerabilities(aggregated []domain.AggregatedVulnerability) []cdx.Vulnerability {
	result := make([]cdx.Vulnerability, 0, len(aggregated))
	for _, v := range aggregated {
		ratings := []cdx.VulnerabilityRating{
			{Severity: mapSeverityLabel(v.SeverityLabel)},
		}
		affects := make([]cdx.Affects, 0, len(v.Affected))
		for _, m := range v.Affected {
			affects = append(affects, cdx.Affects{Ref: modulePURL(m)})
		}
		result = append(result, cdx.Vulnerability{
			BOMRef:      v.ID,
			ID:          v.ID,
			Description: v.Summary,
			Ratings:     &ratings,
			Affects:     &affects,
		})
	}
	return result
}

// severityLabel extracts the severity label from a kanonarion Severity,
// returning "" when severity is absent.
func severityLabel(s *vulndomain.Severity) string {
	if s == nil {
		return ""
	}
	return s.Label
}

// mapSeverityLabel converts a kanonarion severity label to a CycloneDX Severity.
func mapSeverityLabel(label string) cdx.Severity {
	switch label {
	case "CRITICAL":
		return cdx.SeverityCritical
	case "HIGH":
		return cdx.SeverityHigh
	case "MEDIUM":
		return cdx.SeverityMedium
	case "LOW":
		return cdx.SeverityLow
	default:
		return cdx.SeverityUnknown
	}
}

// modulePURL returns the Package URL for a module.
func modulePURL(mod domain.ModuleRef) string {
	return "pkg:" + purlTypeGolang + "/" + mod.Path + "@" + mod.Version
}

// deterministicTimestamp returns the maximum ExtractedAt from licence records,
// rounded to second precision. When no licence data is present it falls back
// through the walk's own clock-injected timestamps so empty or failed-target
// walks (which have a zero Graph.ResolvedAt) still get a meaningful,
// deterministic GeneratedAt rather than the zero time.
func deterministicTimestamp(
	walk walkdomain.WalkRecord,
	licenses map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord,
) time.Time {
	var t time.Time
	for _, lic := range licenses {
		if lic.ExtractedAt.After(t) {
			t = lic.ExtractedAt
		}
	}
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
func deterministicID(walkID string, scanRunID *string, pipelineVersion string) string {
	key := walkID + "|" + pipelineVersion
	if scanRunID != nil {
		key += "|" + *scanRunID
	}
	sum := sha256.Sum256([]byte(key))
	return "sbom-" + hex.EncodeToString(sum[:])[:24]
}

// deterministicUUID returns a UUID-shaped string derived from the generation inputs.
// It is not a proper UUID v5 but is stable and unique for the same inputs.
func deterministicUUID(walkID string, scanRunID *string, pipelineVersion string) string {
	key := "sbom-uuid|" + walkID + "|" + pipelineVersion
	if scanRunID != nil {
		key += "|" + *scanRunID
	}
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
