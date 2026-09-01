package cli

import (
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/license/domain"
)

// licenseDocument is what `license <coord> --json` answers with.
//
// It exists to break the link between a domain type's Go field names and a
// published CLI surface. The command used to EMBED domain.LicenseRecord, which
// carries no json tags, so the record's Go field names were the wire contract:
// renaming a field in the domain — an ordinary refactor, invisible to anything
// that reads the tree — silently changed keys of a document consumers parse.
// Nothing in the suite would have reported it, because nothing had a copy of the
// old keys to compare against.
//
// This view is the contract, and the domain types are free again. A rename there
// now moves an assignment in this file and stops; a rename HERE is a change to
// the surface, made deliberately and read as one. It is also what the rest of
// internal/cli already does — `license-list`, `license-diff` and `license-compat`
// each project onto views of their own with explicit tags, and this was the one
// command in the tree still publishing domain structs.
//
// -- the projection is TOTAL --
//
// Every level is projected, not just the top one. LicenseFileEntry, AltMatch,
// CopyrightStatement, EffectiveLicenseSet, EmbeddedComponent, PackageLicense and
// ProvenanceSummary each get a view below, because most of this document lives
// under `license_files` and `effective_set` and a rename of, say,
// LicenseFileEntry.FileHash is exactly the silent break this view was opened to
// stop. A half-projected document is also the worse contract: snake_case at the
// top and Go identifiers underneath makes a consumer carry two conventions
// through one payload, where the uniform PascalCase it replaced was at least
// predictable.
//
// So: no domain struct may be reachable from this type. Adding a field here that
// holds one — embedded or named — reopens the link for everything under it, and
// TestCLIViewsAreTotalProjections refuses it. Scalars, strings, numbers, bools
// and slices of those are values and travel as they are; domain.Obligations is
// the one exception and carries its own explicit tags already.
//
// Three rules for anyone editing it:
//
//	the keys are snake_case and explicit, one tag per field at every depth, so
//	the wire name is stated rather than derived from a Go identifier.
//
//	the VALUES are the record's, unconverted. Nothing is reformatted, rounded,
//	stringified or re-ordered on the way through, and a nil slice stays null
//	while an empty one stays [] — those are different answers.
//
//	field order follows the domain type's, because the encoder writes fields in
//	declaration order and a reader comparing this document with the record it
//	came from should not have to hunt.
type licenseDocument struct {
	SchemaVersion     string                      `json:"schema_version"`
	Ecosystem         string                      `json:"ecosystem"`
	Coordinate        coordinate.ModuleCoordinate `json:"coordinate"`
	Role              string                      `json:"role"`
	PrimarySPDX       string                      `json:"primary_spdx"`
	Expression        string                      `json:"expression"`
	ExpressionBasis   string                      `json:"expression_basis"`
	BundledSPDXs      []string                    `json:"bundled_spdxs"`
	PrimaryConfidence float64                     `json:"primary_confidence"`
	LicenseFiles      []licenseFileJSON           `json:"license_files"`
	EffectiveSet      licenseEffectiveSetJSON     `json:"effective_set"`
	PackageLicenses   []licensePackageJSON        `json:"package_licenses"`
	OverallStatus     domain.LicenseStatus        `json:"overall_status"`
	CopyrightStatus   domain.CopyrightStatus      `json:"copyright_status"`
	Provenance        licenseProvenanceJSON       `json:"provenance"`
	FailureDetail     string                      `json:"failure_detail"`
	ExtractedAt       time.Time                   `json:"extracted_at"`
	PipelineVersion   string                      `json:"pipeline_version"`
	ContentHash       string                      `json:"content_hash"`
	ArtefactIdentity  string                      `json:"artefact_identity"`
	SourceContentHash string                      `json:"source_content_hash"`
	Obligations       domain.Obligations          `json:"obligations"`
	// ElectiveObligations carries per-arm obligations when the expression is a
	// disjunction (a dual licence): the obligations in force are those of the arm
	// the consumer elects, an operator decision recorded via license_overrides —
	// never resolved here.
	//
	// Its KEYS are SPDX identifiers — data, not field names — so they are the
	// one place in this document where a capital letter is correct.
	ElectiveObligations map[string]domain.Obligations `json:"elective_obligations,omitempty"`
	// BindingObligations carries per-arm obligations when the expression is a
	// conjunction: every arm binds at once, so `obligations` above is their
	// union and this says which arm imposed which duty. Without it the union
	// is a verdict — what a consumer must do, with no licence to attribute it
	// to — and it is the ElectiveObligations shape deliberately, because the
	// two answer the same question about different operators.
	//
	// Its KEYS are SPDX identifiers, on the same reading as the field above.
	BindingObligations map[string]domain.Obligations `json:"binding_obligations,omitempty"`
	// ArmGrants names the licence file granting each arm, present only when the
	// expression's basis says the arms were granted one file each. That file is
	// the only statement of what its arm covers — LICENSE.docs is
	// documentation, LICENSE.libyaml is vendored C — and it is the fact a
	// licence record never used to publish.
	//
	// Its KEYS are SPDX identifiers, on the same reading as the fields above.
	ArmGrants map[string][]string `json:"arm_grants,omitempty"`
	// ObligationsReading qualifies `obligations` above when it must not be read
	// as the set the consumer owes: across separately granted arms it is an
	// upper bound, because which arms bind depends on which covered artefacts
	// reach the consumer's binary and no licence record answers that. Empty —
	// the ordinary case — `obligations` is the owed set and needs no
	// qualification.
	ObligationsReading string `json:"obligations_reading,omitempty"`
}

// licenseFileJSON is one licence-named file found in the module.
type licenseFileJSON struct {
	Path       string  `json:"path"`
	SPDX       string  `json:"spdx"`
	Confidence float64 `json:"confidence"`
	FileHash   string  `json:"file_hash"`
	FileSize   int64   `json:"file_size"`
	IsVendored bool    `json:"is_vendored"`
	IsPerFile  bool    `json:"is_per_file"`
	// AltMatches is non-empty when the detector produced several candidates.
	AltMatches []licenseAltMatchJSON `json:"alt_matches"`
	// CopyrightStatements is null when copyright extraction has not run, which
	// is a different answer from an empty list; the projection keeps them apart.
	CopyrightStatements []licenseCopyrightJSON `json:"copyright_statements"`
	// LowConfidence* carry a recognisable licence fragment found below the
	// detector's coverage floor. They are spelled as `context --json` spells
	// them, because it is the same fact.
	LowConfidenceSPDX     string  `json:"low_confidence_spdx"`
	LowConfidenceCoverage float64 `json:"low_confidence_coverage"`
	// Coverage says what this licence governs: the module's code, the
	// documentation it ships, or third-party material it carries. It is
	// emitted always, including for the ordinary code licence — an omitempty
	// here would make "governs the code" indistinguishable from "this build
	// does not derive coverage", and absence is not one of the answers.
	Coverage domain.LicenseCoverage `json:"coverage"`
}

// licenseAltMatchJSON is an alternative identification for a licence file.
type licenseAltMatchJSON struct {
	SPDX       string  `json:"spdx"`
	Confidence float64 `json:"confidence"`
}

// licenseCopyrightJSON is one copyright notice. Spelled as
// contextCopyrightStatement spells it: one fact, one spelling.
type licenseCopyrightJSON struct {
	Verbatim string   `json:"verbatim"`
	Holders  []string `json:"holders"`
	Years    string   `json:"years"`
	Source   string   `json:"source"`
}

// licenseEffectiveSetJSON is the union of root-level and embedded-component
// licences, derived from the licence files on every load.
type licenseEffectiveSetJSON struct {
	RootSPDXs  []string               `json:"root_spdxs"`
	Components []licenseComponentJSON `json:"components"`
	AllSPDXs   []string               `json:"all_spdxs"`
}

// licenseComponentJSON is one third-party component bundled inside the module.
type licenseComponentJSON struct {
	PathPrefix string   `json:"path_prefix"`
	SPDXs      []string `json:"spdxs"`
}

// licensePackageJSON is the licence governing one non-root sub-package.
type licensePackageJSON struct {
	PackagePath string  `json:"package_path"`
	SPDX        string  `json:"spdx"`
	Confidence  float64 `json:"confidence"`
	SourceFile  string  `json:"source_file"`
}

// licenseProvenanceJSON is the contribution-licensing chain of title.
type licenseProvenanceJSON struct {
	Signals    []domain.ProvenanceSignal     `json:"signals"`
	Confidence domain.ChainOfTitleConfidence `json:"confidence"`
}

// newLicenseDocument projects a record onto the view.
//
// Field-by-field assignments rather than a conversion or a copy helper: the
// point of the view is that adding a field to a domain type does not add a key
// to the wire, and only an explicit assignment has that property.
func newLicenseDocument(r domain.LicenseRecord) licenseDocument {
	// The document publishes the record read through what each of its licences
	// covers, so `expression`, `expression_basis` and `primary_spdx` name the
	// module's own licensing rather than the union of every grant the archive
	// carries. The record is left as measured — those three are inside its
	// content hash — and `content_hash` below still names the stored bytes.
	coverage := domain.ReadCoverage(r)
	reading := readLicenceObligations(r)
	doc := licenseDocument{
		SchemaVersion:     r.SchemaVersion,
		Ecosystem:         r.Ecosystem,
		Coordinate:        r.Coordinate,
		Role:              r.Role,
		PrimarySPDX:       coverage.PrimarySPDX,
		Expression:        coverage.Expression,
		ExpressionBasis:   coverage.Basis,
		BundledSPDXs:      r.BundledSPDXs,
		PrimaryConfidence: r.PrimaryConfidence,
		LicenseFiles:      licenseFilesJSONOf(r.LicenseFiles, coverage.ByPath),
		EffectiveSet:      licenseEffectiveSetJSONOf(r.EffectiveSet),
		PackageLicenses:   licensePackagesJSONOf(r.PackageLicenses),
		OverallStatus:     r.OverallStatus,
		CopyrightStatus:   r.CopyrightStatus,
		Provenance:        licenseProvenanceJSONOf(r.Provenance),
		FailureDetail:     r.FailureDetail,
		ExtractedAt:       r.ExtractedAt,
		PipelineVersion:   r.PipelineVersion,
		ContentHash:       r.ContentHash,
		ArtefactIdentity:  r.ArtefactIdentity,
		SourceContentHash: r.SourceContentHash,
		Obligations:       reading.Set,
	}
	if len(reading.Arms) > 0 {
		doc.BindingObligations = make(map[string]domain.Obligations, len(reading.Arms))
		for _, arm := range reading.Arms {
			doc.BindingObligations[arm] = domain.LookupObligations(arm)
		}
		doc.ArmGrants = reading.Grants
		if reading.Maximal {
			doc.ObligationsReading = obligationsReadingMaximal
		}
	}
	if arms := domain.DisjunctionArms(coverage.Expression); len(arms) >= 2 {
		doc.ElectiveObligations = make(map[string]domain.Obligations, len(arms))
		for _, arm := range arms {
			doc.ElectiveObligations[arm] = domain.LookupObligations(arm)
		}
	}
	return doc
}

// The slice projections below all share one shape, and the nil test is the
// reason each is written out rather than folded into a generic helper's
// happy path: a nil slice marshals to null and an empty one to [], those are
// different answers on this surface, and the projection must not turn one into
// the other on the way through.

func licenseFilesJSONOf(in []domain.LicenseFileEntry, coverage map[string]domain.LicenseCoverage) []licenseFileJSON {
	if in == nil {
		return nil
	}
	out := make([]licenseFileJSON, 0, len(in))
	for _, f := range in {
		out = append(out, licenseFileJSON{
			Path:                  f.Path,
			SPDX:                  f.SPDX,
			Confidence:            f.Confidence,
			FileHash:              f.FileHash,
			FileSize:              f.FileSize,
			IsVendored:            f.IsVendored,
			IsPerFile:             f.IsPerFile,
			AltMatches:            licenseAltMatchesJSONOf(f.AltMatches),
			CopyrightStatements:   licenseCopyrightsJSONOf(f.CopyrightStatements),
			LowConfidenceSPDX:     f.LowConfidenceSPDX,
			LowConfidenceCoverage: f.LowConfidenceCoverage,
			Coverage:              coverage[f.Path],
		})
	}
	return out
}

func licenseAltMatchesJSONOf(in []domain.AltMatch) []licenseAltMatchJSON {
	if in == nil {
		return nil
	}
	out := make([]licenseAltMatchJSON, 0, len(in))
	for _, a := range in {
		out = append(out, licenseAltMatchJSON{SPDX: a.SPDX, Confidence: a.Confidence})
	}
	return out
}

func licenseCopyrightsJSONOf(in []domain.CopyrightStatement) []licenseCopyrightJSON {
	if in == nil {
		return nil
	}
	out := make([]licenseCopyrightJSON, 0, len(in))
	for _, c := range in {
		out = append(out, licenseCopyrightJSON{
			Verbatim: c.Verbatim, Holders: c.Holders, Years: c.Years, Source: c.Source,
		})
	}
	return out
}

func licenseEffectiveSetJSONOf(s domain.EffectiveLicenseSet) licenseEffectiveSetJSON {
	return licenseEffectiveSetJSON{
		RootSPDXs:  s.RootSPDXs,
		Components: licenseComponentsJSONOf(s.Components),
		AllSPDXs:   s.AllSPDXs,
	}
}

func licenseComponentsJSONOf(in []domain.EmbeddedComponent) []licenseComponentJSON {
	if in == nil {
		return nil
	}
	out := make([]licenseComponentJSON, 0, len(in))
	for _, c := range in {
		out = append(out, licenseComponentJSON{PathPrefix: c.PathPrefix, SPDXs: c.SPDXs})
	}
	return out
}

func licensePackagesJSONOf(in []domain.PackageLicense) []licensePackageJSON {
	if in == nil {
		return nil
	}
	out := make([]licensePackageJSON, 0, len(in))
	for _, p := range in {
		out = append(out, licensePackageJSON{
			PackagePath: p.PackagePath, SPDX: p.SPDX, Confidence: p.Confidence, SourceFile: p.SourceFile,
		})
	}
	return out
}

func licenseProvenanceJSONOf(p domain.ProvenanceSummary) licenseProvenanceJSON {
	return licenseProvenanceJSON{Signals: p.Signals, Confidence: p.Confidence}
}
