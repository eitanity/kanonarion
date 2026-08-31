package cli

import (
	"bytes"
	"encoding/json"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	domain "github.com/eitanity/kanonarion/internal/license/domain"
)

// The guard on the boundary `license --json` now has.
//
// The command used to embed domain.LicenseRecord and, through it, every type
// hanging off it — so the Go field names of seven domain structs were the wire
// contract, and a rename anywhere in that tree was a silent break of a published
// surface. These tests hold the boundary from three sides: the wire names are
// the view's and nothing else's, the values behind them are the record's and
// nothing else's, and no domain struct is reachable from the view to reopen the
// link at a level nobody is looking at.

// licenseWireNames is the wire spelling of every domain field this surface
// publishes, keyed by the type it belongs to.
//
// Written out rather than derived from the Go name by a rule, because a rule is
// a second implementation of the rename and would agree with a mistake made the
// same way twice. This is the mapping a consumer sees; changing a line here is
// changing the surface, and adding a field to one of these domain types fails
// the coverage check below until somebody decides its wire name.
var licenseWireNames = map[string]map[string]string{
	"LicenseRecord": {
		"SchemaVersion":     "schema_version",
		"Ecosystem":         "ecosystem",
		"Coordinate":        "coordinate",
		"Role":              "role",
		"PrimarySPDX":       "primary_spdx",
		"Expression":        "expression",
		"ExpressionBasis":   "expression_basis",
		"BundledSPDXs":      "bundled_spdxs",
		"PrimaryConfidence": "primary_confidence",
		"LicenseFiles":      "license_files",
		"EffectiveSet":      "effective_set",
		"PackageLicenses":   "package_licenses",
		"OverallStatus":     "overall_status",
		"CopyrightStatus":   "copyright_status",
		"Provenance":        "provenance",
		"FailureDetail":     "failure_detail",
		"ExtractedAt":       "extracted_at",
		"PipelineVersion":   "pipeline_version",
		"ContentHash":       "content_hash",
		"ArtefactIdentity":  "artefact_identity",
		"SourceContentHash": "source_content_hash",
	},
	"LicenseFileEntry": {
		"Path":                  "path",
		"SPDX":                  "spdx",
		"Confidence":            "confidence",
		"FileHash":              "file_hash",
		"FileSize":              "file_size",
		"IsVendored":            "is_vendored",
		"IsPerFile":             "is_per_file",
		"AltMatches":            "alt_matches",
		"CopyrightStatements":   "copyright_statements",
		"LowConfidenceSPDX":     "low_confidence_spdx",
		"LowConfidenceCoverage": "low_confidence_coverage",
	},
	"AltMatch": {
		"SPDX":       "spdx",
		"Confidence": "confidence",
	},
	"CopyrightStatement": {
		"Verbatim": "verbatim",
		"Holders":  "holders",
		"Years":    "years",
		"Source":   "source",
	},
	"EffectiveLicenseSet": {
		"RootSPDXs":  "root_spdxs",
		"Components": "components",
		"AllSPDXs":   "all_spdxs",
	},
	"EmbeddedComponent": {
		"PathPrefix": "path_prefix",
		"SPDXs":      "spdxs",
	},
	"PackageLicense": {
		"PackagePath": "package_path",
		"SPDX":        "spdx",
		"Confidence":  "confidence",
		"SourceFile":  "source_file",
	},
	"ProvenanceSummary": {
		"Signals":    "signals",
		"Confidence": "confidence",
	},
}

// licenseDomainTypes pairs each projected domain type with the view that
// publishes it, so the coverage check can be driven off the domain rather than
// off a list somebody has to remember to extend.
func licenseDomainTypes() []struct {
	name         string
	domain, view reflect.Type
} {
	return []struct {
		name         string
		domain, view reflect.Type
	}{
		{"LicenseRecord", reflect.TypeOf(domain.LicenseRecord{}), reflect.TypeOf(licenseDocument{})},
		{"LicenseFileEntry", reflect.TypeOf(domain.LicenseFileEntry{}), reflect.TypeOf(licenseFileJSON{})},
		{"AltMatch", reflect.TypeOf(domain.AltMatch{}), reflect.TypeOf(licenseAltMatchJSON{})},
		{"CopyrightStatement", reflect.TypeOf(domain.CopyrightStatement{}), reflect.TypeOf(licenseCopyrightJSON{})},
		{"EffectiveLicenseSet", reflect.TypeOf(domain.EffectiveLicenseSet{}), reflect.TypeOf(licenseEffectiveSetJSON{})},
		{"EmbeddedComponent", reflect.TypeOf(domain.EmbeddedComponent{}), reflect.TypeOf(licenseComponentJSON{})},
		{"PackageLicense", reflect.TypeOf(domain.PackageLicense{}), reflect.TypeOf(licensePackageJSON{})},
		{"ProvenanceSummary", reflect.TypeOf(domain.ProvenanceSummary{}), reflect.TypeOf(licenseProvenanceJSON{})},
	}
}

// licenseRecordForWire is a record with every field of every projected type set
// to something distinguishable, so a value that travelled to the wrong key is
// visible rather than hidden behind two zero values that happen to match.
//
// The two slices with three states — nil, empty, populated — are represented at
// each, because null and [] are different answers and the projection has to
// carry the difference rather than normalise it.
func licenseRecordForWire(t *testing.T) domain.LicenseRecord {
	t.Helper()
	return domain.LicenseRecord{
		SchemaVersion:     "5",
		Ecosystem:         "go",
		Coordinate:        makeLicenseCoord(t),
		Role:              domain.LicenseRoleRootDeclaration,
		PrimarySPDX:       "MIT",
		Expression:        "MIT OR Apache-2.0",
		ExpressionBasis:   "root file names both grants",
		BundledSPDXs:      []string{"BSD-3-Clause"},
		PrimaryConfidence: 0.97,
		LicenseFiles: []domain.LicenseFileEntry{
			{
				Path: "LICENSE", SPDX: "MIT", Confidence: 0.97,
				FileHash: "sha256:aa", FileSize: 12, IsVendored: false, IsPerFile: false,
				// Two of each, because a projection that reverses or re-sorts a
				// nested list is a value change, and one element cannot show it.
				AltMatches: []domain.AltMatch{
					{SPDX: "Apache-2.0", Confidence: 0.41},
					{SPDX: "BSD-2-Clause", Confidence: 0.22},
				},
				CopyrightStatements: []domain.CopyrightStatement{
					{Verbatim: "Copyright (c) 2020 Example", Holders: []string{"Example", "Example Two"},
						Years: "2020", Source: "LICENSE"},
					{Verbatim: "Copyright (c) 2021 Other", Holders: []string{"Other"},
						Years: "2021", Source: "LICENSE"},
				},
				LowConfidenceSPDX: "AGPL-3.0", LowConfidenceCoverage: 0.12,
			},
			// The nil arms: a file with no alternative match and no copyright
			// extraction is not a file with none of either.
			{Path: "vendor/dep/LICENSE", SPDX: "BSD-3-Clause", Confidence: 1, IsVendored: true},
			// The empty arms, beside them.
			{Path: "sub/LICENSE", SPDX: "Apache-2.0", Confidence: 1,
				AltMatches: []domain.AltMatch{}, CopyrightStatements: []domain.CopyrightStatement{}},
		},
		EffectiveSet: domain.EffectiveLicenseSet{
			RootSPDXs: []string{"MIT"},
			Components: []domain.EmbeddedComponent{
				{PathPrefix: "vendor/dep", SPDXs: []string{"BSD-3-Clause"}},
				{PathPrefix: "vendor/other", SPDXs: []string{"ISC", "MIT"}},
			},
			AllSPDXs: []string{"Apache-2.0", "BSD-3-Clause", "MIT"},
		},
		PackageLicenses: []domain.PackageLicense{
			{PackagePath: "sub", SPDX: "Apache-2.0", Confidence: 1, SourceFile: "sub/LICENSE"},
			{PackagePath: "sub/two", SPDX: "ISC", Confidence: 0.9, SourceFile: "sub/two/LICENSE"},
		},
		OverallStatus:   domain.LicenseStatusDetected,
		CopyrightStatus: domain.CopyrightStatusNoneFound,
		Provenance: domain.ProvenanceSummary{
			Signals: []domain.ProvenanceSignal{
				domain.ProvenanceSignalDCORequired, domain.ProvenanceSignalAuthorsFile,
			},
			Confidence: domain.ChainOfTitleMedium,
		},
		FailureDetail:     "none",
		ExtractedAt:       time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC),
		PipelineVersion:   "1.3.0",
		ContentHash:       "sha256:bb",
		ArtefactIdentity:  "zip:h1:cc=",
		SourceContentHash: "sha256:dd",
	}
}

// licenseJSONOf renders the document the command writes.
func licenseJSONOf(t *testing.T, r domain.LicenseRecord) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := printLicenseRecord(r, false, true, &buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// licenseKeyPaths walks a decoded document and returns every object key with the
// path it sits at, so a measurement of this surface is of the WHOLE document
// rather than of its top level.
//
// electiveObligationsKey is skipped as a container of keys: its members are SPDX
// identifiers, which are data the record carries, not names this view chose.
func licenseKeyPaths(v any, at string, into map[string]string) {
	switch n := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(n))
		for k := range n {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			path := at + "/" + k
			into[path] = k
			if at == "" && k == "elective_obligations" {
				continue
			}
			licenseKeyPaths(n[k], path, into)
		}
	case []any:
		for _, e := range n {
			licenseKeyPaths(e, at+"[]", into)
		}
	}
}

// TestLicenseJSONPublishesNoGoFieldNameAtAnyDepth is the ticket's measurement,
// taken over the whole document rather than its top level.
//
// Half a rename is not a smaller version of this fix: snake_case at the top with
// Go identifiers underneath makes a consumer carry two conventions through one
// payload, which is worse than the uniform PascalCase it replaced.
func TestLicenseJSONPublishesNoGoFieldNameAtAnyDepth(t *testing.T) {
	out := licenseJSONOf(t, licenseRecordForWire(t))
	var doc any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("license --json does not decode: %v\n%s", err, out)
	}
	paths := map[string]string{}
	licenseKeyPaths(doc, "", paths)

	snake := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	var bad []string
	for path, key := range paths {
		if !snake.MatchString(key) {
			bad = append(bad, path)
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Errorf("license --json publishes %d key(s) that are not snake_case:\n  %s\n"+
			"a Go field name on the wire, at any depth, means a domain rename breaks this surface silently:\n%s",
			len(bad), strings.Join(bad, "\n  "), out)
	}
	if len(paths) < 30 {
		t.Errorf("the fixture reaches only %d key(s); it is not exercising the nested types this test "+
			"exists to measure", len(paths))
	}
}

// TestLicenseViewRenamesKeysAndChangesNoValue is the other half: the rename
// moved names and nothing else, everywhere.
//
// The proof is a whole-document comparison against the shape this command used
// to publish — the domain record embedded, plus the obligations beside it. That
// reference is rendered, every key in it is rewritten through the map above, and
// the result must equal the document the command writes today. Nothing is
// compared field by field and nothing is skipped: a value converted, reordered,
// dropped, invented, or a nil slice normalised to [] at any depth fails here.
func TestLicenseViewRenamesKeysAndChangesNoValue(t *testing.T) {
	rec := licenseRecordForWire(t)

	// The old contract, reproduced exactly: what `license --json` emitted before
	// the view existed.
	type wasPublished struct {
		domain.LicenseRecord
		Obligations         domain.Obligations            `json:"obligations"`
		ElectiveObligations map[string]domain.Obligations `json:"elective_obligations,omitempty"`
	}
	was := wasPublished{LicenseRecord: rec, Obligations: domain.LookupObligations(rec.PrimarySPDX)}
	if arms := domain.DisjunctionArms(rec.Expression); len(arms) >= 2 {
		was.ElectiveObligations = make(map[string]domain.Obligations, len(arms))
		for _, arm := range arms {
			was.ElectiveObligations[arm] = domain.LookupObligations(arm)
		}
	}
	oldRaw, err := json.Marshal(was)
	if err != nil {
		t.Fatal(err)
	}

	// One flat rename, because no Go field name on this surface maps to two
	// different wire names — asserted rather than assumed.
	rename := map[string]string{}
	for typ, fields := range licenseWireNames {
		for goName, wire := range fields {
			if prior, seen := rename[goName]; seen && prior != wire {
				t.Fatalf("%s.%s wants wire name %q but another type publishes %q under the same Go name; "+
					"the rename is no longer a pure renaming and this proof does not apply",
					typ, goName, wire, prior)
			}
			rename[goName] = wire
		}
	}

	var oldDoc any
	if err := json.Unmarshal(oldRaw, &oldDoc); err != nil {
		t.Fatal(err)
	}
	renamed := licenseRenameKeys(oldDoc, "", rename)

	var newDoc any
	if err := json.Unmarshal(licenseJSONOf(t, rec), &newDoc); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(renamed, newDoc) {
		gotRaw, _ := json.MarshalIndent(newDoc, "", "  ")
		wantRaw, _ := json.MarshalIndent(renamed, "", "  ")
		t.Errorf("the document is not the old one with its keys renamed — a value changed somewhere:\n"+
			"--- the old document, keys renamed ---\n%s\n--- what the command writes ---\n%s", wantRaw, gotRaw)
	}
}

// licenseRenameKeys rewrites object keys through the map, leaving keys it does
// not know (the obligations, already snake_case) and the elective-obligations
// map's SPDX keys alone.
func licenseRenameKeys(v any, at string, rename map[string]string) any {
	switch n := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(n))
		for k, val := range n {
			name := k
			if to, ok := rename[k]; ok {
				name = to
			}
			if at == "" && name == "elective_obligations" {
				out[name] = val
				continue
			}
			out[name] = licenseRenameKeys(val, at+"/"+name, rename)
		}
		return out
	case []any:
		out := make([]any, 0, len(n))
		for _, e := range n {
			out = append(out, licenseRenameKeys(e, at+"[]", rename))
		}
		return out
	default:
		return v
	}
}

// TestLicenseWireNamesCoverEveryProjectedField is what makes the map above a
// decision rather than a snapshot.
//
// Every exported field of every projected domain type must have a wire name, and
// the view must publish it under exactly that name. A field added to
// LicenseFileEntry tomorrow fails here until somebody decides what it is called
// on the wire — which is the whole point of having a view.
func TestLicenseWireNamesCoverEveryProjectedField(t *testing.T) {
	for _, pair := range licenseDomainTypes() {
		t.Run(pair.name, func(t *testing.T) {
			names := licenseWireNames[pair.name]
			if names == nil {
				t.Fatalf("no wire names recorded for %s", pair.name)
			}
			published := map[string]bool{}
			for i := 0; i < pair.view.NumField(); i++ {
				f := pair.view.Field(i)
				tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
				published[tag] = true
			}
			for i := 0; i < pair.domain.NumField(); i++ {
				f := pair.domain.Field(i)
				if !f.IsExported() {
					continue
				}
				wire, named := names[f.Name]
				if !named {
					t.Errorf("%s.%s has no wire name: a field added to the domain must be given one "+
						"deliberately, or left off this surface deliberately", pair.name, f.Name)
					continue
				}
				if !published[wire] {
					t.Errorf("%s.%s is named %q but the view publishes no such key", pair.name, f.Name, wire)
				}
			}
			// And nothing named that the domain no longer has.
			domainFields := map[string]bool{}
			for i := 0; i < pair.domain.NumField(); i++ {
				domainFields[pair.domain.Field(i).Name] = true
			}
			for goName := range names {
				if !domainFields[goName] {
					t.Errorf("%s.%s is named on the wire but the domain type has no such field", pair.name, goName)
				}
			}
		})
	}
}
