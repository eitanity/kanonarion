// Package cyclonedx implements ports.SBOMGenerator producing CycloneDX 1.5 JSON.
// Output is deterministic: identical inputs always produce byte-identical documents.
package cyclonedx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

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

// Generator produces CycloneDX 1.5 JSON SBOMs.
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
	licenses map[fetchdomain.ModuleCoordinate]licensedomain.LicenseRecord,
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
		Format:             domain.CycloneDX15,
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
	licenses map[fetchdomain.ModuleCoordinate]licensedomain.LicenseRecord,
	vulnerabilities []vulndomain.VulnerabilityRecord,
	req ports.GenerateRequest,
) (*cdx.BOM, bool, error) {
	bom := &cdx.BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  cdx.SpecVersion1_5,
		JSONSchema:   "http://cyclonedx.org/schema/bom-1.5.schema.json",
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
		Component: moduleComponent(walk.Graph.Target, licenses, req.PipelineVersion),
	}

	// Components — assembly policy (inclusion, license attach, ordering,
	// incomplete-license determination) lives in sbom/domain.
	inputs := make([]domain.ComponentInput, 0, len(walk.Graph.Nodes))
	for _, node := range walk.Graph.Nodes {
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
		comp := buildComponent(c.Module, c.License, c.Copyright, req.PipelineVersion)
		if !strings.HasPrefix(comp.PackageURL, "pkg:"+purlTypeGolang+"/") {
			return nil, false, fmt.Errorf("%w: %q", domain.ErrNonGoComponent, comp.PackageURL)
		}
		components = append(components, comp)
	}
	bom.Components = &components

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
func moduleRef(coord fetchdomain.ModuleCoordinate) domain.ModuleRef {
	return domain.ModuleRef{Path: coord.Path, Version: coord.Version}
}

// buildComponent maps an assembled domain Component to a CycloneDX Component.
func buildComponent(mod domain.ModuleRef, spdx, copyright, pipelineVersion string) cdx.Component {
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

// moduleComponent builds the metadata primary component for the walk target.
func moduleComponent(
	coord fetchdomain.ModuleCoordinate,
	licenses map[fetchdomain.ModuleCoordinate]licensedomain.LicenseRecord,
	pipelineVersion string,
) *cdx.Component {
	lic, hasLic := licenses[coord]
	comp := buildComponent(moduleRef(coord), domain.LicenseClause(hasLic, lic.PrimarySPDX, lic.Expression), copyrightString(lic), pipelineVersion)
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
	licenses map[fetchdomain.ModuleCoordinate]licensedomain.LicenseRecord,
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
	if err := enc.EncodeVersion(bom, cdx.SpecVersion1_5); err != nil {
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
