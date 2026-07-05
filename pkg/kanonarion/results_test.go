package kanonarion_test

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	directivedomain "github.com/eitanity/kanonarion/internal/directive/domain"
	exampledomain "github.com/eitanity/kanonarion/internal/example/domain"
	extractdomain "github.com/eitanity/kanonarion/internal/extract/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fipsdomain "github.com/eitanity/kanonarion/internal/fips/domain"
	godebugdomain "github.com/eitanity/kanonarion/internal/godebug/domain"
	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"
	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
	sbomdomain "github.com/eitanity/kanonarion/internal/sbom/domain"
	vendordomain "github.com/eitanity/kanonarion/internal/vendortree/domain"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"

	"github.com/eitanity/kanonarion/pkg/kanonarion"
)

// The compile-time assignments below are the drift guard required by
// §2.1: each façade result type must be a *type alias* to the internal
// serialized record, not a distinct copy. A bidirectional assignment compiles
// only when the two names denote the identical type; if the façade ever forked a
// type (e.g. a struct copy that could silently drift from its JSON projection),
// these stop compiling.
var (
	_ kanonarion.ModuleCoordinate     = fetchdomain.ModuleCoordinate{}
	_ fetchdomain.ModuleCoordinate    = kanonarion.ModuleCoordinate{}
	_ kanonarion.FactRecord           = fetchdomain.FactRecord{}
	_ fetchdomain.FactRecord          = kanonarion.FactRecord{}
	_ kanonarion.WalkRecord           = walkdomain.WalkRecord{}
	_ walkdomain.WalkRecord           = kanonarion.WalkRecord{}
	_ kanonarion.LicenseRecord        = licensedomain.LicenseRecord{}
	_ licensedomain.LicenseRecord     = kanonarion.LicenseRecord{}
	_ kanonarion.InterfaceRecord      = ifacedomain.InterfaceRecord{}
	_ ifacedomain.InterfaceRecord     = kanonarion.InterfaceRecord{}
	_ kanonarion.CallGraphRecord      = callgraphdomain.CallGraphRecord{}
	_ callgraphdomain.CallGraphRecord = kanonarion.CallGraphRecord{}
	_ kanonarion.ExampleRecord        = exampledomain.ExampleRecord{}
	_ exampledomain.ExampleRecord     = kanonarion.ExampleRecord{}
	_ kanonarion.ExtractionRun        = extractdomain.ExtractionRun{}
	_ extractdomain.ExtractionRun     = kanonarion.ExtractionRun{}
	_ kanonarion.VulnerabilityRecord  = vulndomain.VulnerabilityRecord{}
	_ vulndomain.VulnerabilityRecord  = kanonarion.VulnerabilityRecord{}
	_ kanonarion.WalkScanRun          = vulndomain.WalkScanRun{}
	_ vulndomain.WalkScanRun          = kanonarion.WalkScanRun{}
	_ kanonarion.SBOMRecord           = sbomdomain.SBOMRecord{}
	_ sbomdomain.SBOMRecord           = kanonarion.SBOMRecord{}
	_ kanonarion.Component            = sbomdomain.Component{}
	_ sbomdomain.Component            = kanonarion.Component{}
	_ kanonarion.DirectiveRecord      = directivedomain.Record{}
	_ directivedomain.Record          = kanonarion.DirectiveRecord{}
	_ kanonarion.GoDebugRecord        = godebugdomain.Record{}
	_ godebugdomain.Record            = kanonarion.GoDebugRecord{}
	_ kanonarion.VendorRecord         = vendordomain.Record{}
	_ vendordomain.Record             = kanonarion.VendorRecord{}
	_ kanonarion.FIPSRecord           = fipsdomain.Record{}
	_ fipsdomain.Record               = kanonarion.FIPSRecord{}
)

// resultAlias pairs a graduated result alias's FAÇADE name with a zero value
// of the type, so reflection-based guards can iterate them. The explicit name
// is needed because reflection only sees the underlying type's name, and the
// four supply-chain-gap records all alias a type named "Record" in their
// respective domain packages — reflect names would collide as baseline keys.
// The bidirectional alias-identity assertions above pin each name to the
// right underlying type, so the label cannot drift from the alias it tags.
type resultAlias struct {
	name string
	v    any
}

// resultTypes is the full set of graduated result aliases, instantiated
// as zero values so reflection-based guards can iterate them.
func resultTypes() []resultAlias {
	return []resultAlias{
		{"ModuleCoordinate", kanonarion.ModuleCoordinate{}},
		{"FactRecord", kanonarion.FactRecord{}},
		{"WalkRecord", kanonarion.WalkRecord{}},
		{"LicenseRecord", kanonarion.LicenseRecord{}},
		{"InterfaceRecord", kanonarion.InterfaceRecord{}},
		{"CallGraphRecord", kanonarion.CallGraphRecord{}},
		{"ExampleRecord", kanonarion.ExampleRecord{}},
		{"ExtractionRun", kanonarion.ExtractionRun{}},
		{"VulnerabilityRecord", kanonarion.VulnerabilityRecord{}},
		{"WalkScanRun", kanonarion.WalkScanRun{}},
		{"SBOMRecord", kanonarion.SBOMRecord{}},
		{"Component", kanonarion.Component{}},
		{"DirectiveRecord", kanonarion.DirectiveRecord{}},
		{"GoDebugRecord", kanonarion.GoDebugRecord{}},
		{"VendorRecord", kanonarion.VendorRecord{}},
		{"FIPSRecord", kanonarion.FIPSRecord{}},
	}
}

// TestResultTypes_NoHasherReachable extends the §3 guard to every
// result alias: a graduated result type must be read-shaped, never a *Hasher.
// Type aliases re-export the underlying type's name, so a leaked hasher surfaces
// in the reflected type name.
func TestResultTypes_NoHasherReachable(t *testing.T) {
	t.Parallel()

	for _, entry := range resultTypes() {
		if name := reflect.TypeOf(entry.v).String(); strings.Contains(name, "Hasher") {
			t.Errorf("façade result type %q names a Hasher; hashers must stay internal", name)
		}
	}
}

// TestResultTypes_TableNamesUnique guards the resultTypes table itself: every
// façade name must appear exactly once, or a baseline lookup would silently
// check the wrong type (the collision risk the explicit names exist to solve).
func TestResultTypes_TableNamesUnique(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool, len(resultTypes()))
	for _, entry := range resultTypes() {
		if seen[entry.name] {
			t.Errorf("resultTypes lists %q twice; baseline keys must be unique", entry.name)
		}
		seen[entry.name] = true
	}
}

// allowedResultMethods is the golden method set every result alias exposes at
// the v0 freeze (§2.1: result types graduate "read-shaped — exported
// fields, no behavior, no hashers"). The methods present are read-shape plumbing,
// not domain behaviour: JSON/text marshalers (MarshalJSON/UnmarshalJSON/
// MarshalText/UnmarshalText), pure accessors (Coordinate, String,
// IsPseudoVersion, ExtractCommitPrefix), and in-place determinism helpers
// (Sort/SortFiles/SortExamples). A result type GAINING any method not recorded
// here is the regression this guards — most importantly a leaked *Hasher or
// other business behaviour. Adding a method here must be a conscious decision
// that the new method is still read-shape plumbing, never a hasher (which
// behaviourMethodMarkers rejects outright regardless of this list).
var allowedResultMethods = map[string][]string{
	"ModuleCoordinate":    {"ExtractCommitPrefix", "IsLocal", "IsPseudoVersion", "MarshalJSON", "MarshalText", "String", "UnmarshalJSON", "UnmarshalText"},
	"FactRecord":          {"Coordinate"},
	"WalkRecord":          {},
	"LicenseRecord":       {"SortFiles"},
	"InterfaceRecord":     {"Sort"},
	"CallGraphRecord":     {"Sort"},
	"ExampleRecord":       {"SortExamples"},
	"ExtractionRun":       {"MarshalJSON", "UnmarshalJSON"},
	"VulnerabilityRecord": {"UnmarshalJSON"},
	"WalkScanRun":         {},
	"SBOMRecord":          {},
	"Component":           {},
	"DirectiveRecord":     {},
	"GoDebugRecord":       {},
	"VendorRecord":        {},
	"FIPSRecord":          {},
}

// behaviourMethodMarkers are substrings whose presence in a method name betrays
// domain behaviour leaking onto a read-shaped result type — above all a hasher,
// the §3 exemplar that must stay internal. A method matching one of
// these fails the guard even if it is added to allowedResultMethods, so the
// baseline cannot be widened to admit a hasher by mistake.
var behaviourMethodMarkers = []string{
	"Hash", "Hasher", "Digest", "Merkle", "Proof",
	"Sign", "Anchor", "Compute", "Verify",
}

// allowedResultFields is the golden exported-field set of every result alias at
// the v0 freeze. §4 makes field ADDITION the only compatible growth
// path for a result type (a minor); removing, renaming, or retyping a field is
// breaking. This guard tolerates new fields (they are not in the map, and are
// ignored) but fails when a baselined field disappears — the breaking change the
// bidirectional alias-identity assertions above do NOT catch, because a zero
// value T{} still compiles after a field is removed from the underlying record.
var allowedResultFields = map[string][]string{
	"ModuleCoordinate":    {"Path", "Version"},
	"FactRecord":          {"ContentHash", "ContentLocation", "Ecosystem", "FetchedAt", "GitCommitHash", "GitRef", "GitURL", "GoModHash", "GoModLocation", "ModuleHash", "ModulePath", "ModuleVersion", "PipelineVersion", "Retracted", "SchemaVersion", "VerificationDetail", "VerificationStatus"},
	"WalkRecord":          {"CompletedAt", "ContentHash", "Depth", "Ecosystem", "Graph", "ID", "Operator", "OverallStatus", "PerNodeResults", "PipelineVersion", "PolicyHash", "PolicyVersion", "SchemaVersion", "Scope", "StageDepths", "StartedAt", "Target"},
	"LicenseRecord":       {"ContentHash", "Coordinate", "CopyrightStatus", "Ecosystem", "EffectiveSet", "Expression", "ExtractedAt", "FailureDetail", "LicenseFiles", "OverallStatus", "PackageLicenses", "PipelineVersion", "PrimaryConfidence", "PrimarySPDX", "Provenance", "SchemaVersion"},
	"InterfaceRecord":     {"ContentHash", "Coordinate", "Ecosystem", "ExtractedAt", "FailureDetail", "OverallStatus", "Packages", "PipelineVersion", "SchemaVersion"},
	"CallGraphRecord":     {"Algorithm", "ContentHash", "Coordinate", "Ecosystem", "EdgeCount", "Edges", "ExclusionList", "ExclusionReason", "ExtractedAt", "FailureDetail", "NodeCount", "Nodes", "OverallStatus", "PipelineVersion", "SchemaVersion"},
	"ExampleRecord":       {"ContentHash", "Coordinate", "Ecosystem", "Examples", "ExtractedAt", "FailureDetail", "OverallStatus", "ParseFailures", "PipelineVersion", "SchemaVersion"},
	"ExtractionRun":       {"CompletedAt", "ContentHash", "Ecosystem", "ID", "Operator", "OverallStatus", "PerModuleResults", "PipelineVersions", "RequestedStages", "SchemaVersion", "StartedAt", "WalkID"},
	"VulnerabilityRecord": {"ContentHash", "Coordinate", "DatabaseSnapshot", "Ecosystem", "ErrorDetail", "Findings", "OverallStatus", "PipelineVersion", "ScannedAt", "UnscannableReason", "WalkID"},
	"WalkScanRun":         {"CompletedAt", "ContentHash", "ID", "Operator", "OverallStatus", "PerModuleResults", "PipelineVersion", "Snapshot", "StartedAt", "WalkID"},
	"SBOMRecord":          {"Content", "ContentHash", "Ecosystem", "Format", "GeneratedAt", "ID", "LicensesIncomplete", "Operator", "PipelineVersion", "WalkID", "WalkScanRunID"},
	"Component":           {"Copyright", "License", "Module"},
	"DirectiveRecord":     {"CompletedAt", "ContentHash", "Directives", "Ecosystem", "ExtractedAt", "ID", "PipelineVersion", "ProjectModulePath", "ResolvedVersions", "SchemaVersion", "StartedAt"},
	"GoDebugRecord":       {"ContentHash", "Ecosystem", "ExtractedAt", "PipelineVersion", "ProjectModulePath", "SchemaVersion", "Settings", "TaxonomyVersion"},
	"VendorRecord":        {"ContentHash", "Ecosystem", "ExtractedAt", "Findings", "Modules", "OverallStatus", "PipelineVersion", "ProjectModulePath", "SchemaVersion", "VendorDir", "VendorOnly"},
	"FIPSRecord":          {"CatalogueVersion", "Caveat", "ComplianceAssessment", "ContentHash", "Ecosystem", "ExtractedAt", "FIPSModeStaticallyEnabled", "Findings", "PipelineVersion", "ProjectModulePath", "SchemaVersion", "ToolchainCapable", "ToolchainRaw", "ToolchainVariant"},
}

// resultMethodViolations is the pure checker behind
// TestResultTypes_NoBehaviourOrHasherLeak, factored out so
// TestResultMethodChecker can exercise it against synthetic method sets without
// a real type that leaks a hasher. It reports, for one result type, every method
// that is a behaviour/hasher leak (name marker) or is absent from the type's
// golden baseline (a newly gained method).
func resultMethodViolations(typeName string, methods []string) []string {
	allowed := make(map[string]bool, len(allowedResultMethods[typeName]))
	for _, m := range allowedResultMethods[typeName] {
		allowed[m] = true
	}
	var out []string
	for _, m := range methods {
		for _, marker := range behaviourMethodMarkers {
			if strings.Contains(m, marker) {
				out = append(out, fmt.Sprintf("%s.%s names domain behaviour (%q); result types are read-shaped — hashers and behaviour stay internal", typeName, m, marker))
				break
			}
		}
		if !allowed[m] {
			out = append(out, fmt.Sprintf("%s gained method %s; result types must not grow behaviour — if this is read-shape plumbing add it to allowedResultMethods, else keep it internal", typeName, m))
		}
	}
	return out
}

// TestResultTypes_NoBehaviourOrHasherLeak enforces the §2.1/§3
// read-shaped invariant on every graduated result alias: no *Hasher and no
// behaviour beyond the read-shape plumbing frozen in allowedResultMethods. It
// fails if a result type gains any method (the regression the ticket targets)
// and, harder, if any method name reads like a hasher. It also fails on a stale
// baseline entry so allowedResultMethods cannot drift from reality.
func TestResultTypes_NoBehaviourOrHasherLeak(t *testing.T) {
	t.Parallel()

	for _, entry := range resultTypes() {
		name := entry.name
		if _, known := allowedResultMethods[name]; !known {
			t.Errorf("result type %q has no allowedResultMethods baseline — add one recording its read-shape methods", name)
			continue
		}
		ptr := reflect.PointerTo(reflect.TypeOf(entry.v))
		present := make(map[string]bool, ptr.NumMethod())
		methods := make([]string, 0, ptr.NumMethod())
		for i := 0; i < ptr.NumMethod(); i++ {
			m := ptr.Method(i).Name
			present[m] = true
			methods = append(methods, m)
		}
		for _, msg := range resultMethodViolations(name, methods) {
			t.Error(msg)
		}
		for _, want := range allowedResultMethods[name] {
			if !present[want] {
				t.Errorf("%s no longer has baselined method %s — remove the stale entry from allowedResultMethods", name, want)
			}
		}
	}
}

// TestResultMethodChecker is the regression guard for the leak checker itself:
// it proves resultMethodViolations accepts the frozen read-shape methods,
// rejects a newly gained method, and rejects a hasher-named method even were the
// baseline widened. Without a working checker this fails, so the leak guard
// cannot silently become a no-op.
func TestResultMethodChecker(t *testing.T) {
	t.Parallel()

	// The frozen ModuleCoordinate set is clean.
	if got := resultMethodViolations("ModuleCoordinate", allowedResultMethods["ModuleCoordinate"]); len(got) != 0 {
		t.Errorf("checker flagged the frozen read-shape surface: %v", got)
	}
	// A gained, innocuously named method is rejected as new behaviour.
	got := resultMethodViolations("FactRecord", []string{"Coordinate", "Recompute"})
	if !containsSubstr(got, "gained method Recompute") {
		t.Errorf("checker did not reject a gained method: %v", got)
	}
	// A hasher is rejected by name even though it was added to the baseline.
	got = resultMethodViolations("SBOMRecord", []string{"MerkleRoot"})
	if !containsSubstr(got, "names domain behaviour") {
		t.Errorf("checker did not reject a hasher-named method: %v", got)
	}
}

func containsSubstr(msgs []string, sub string) bool {
	for _, m := range msgs {
		if strings.Contains(m, sub) {
			return true
		}
	}
	return false
}

// TestResultTypes_FieldAddOnlyGrowth asserts §4's result-type growth
// policy: field ADDITION is the only compatible change. New fields are tolerated
// (consumers must not assume field exhaustiveness), but a baselined field that
// disappears is a breaking removal/rename and fails here. Positional construction
// — the other way a field-add breaks consumers — is forbidden by the same policy
// and rejected by `go vet`'s composites analyser in `make lint`, since these
// structs are imported across the boundary.
func TestResultTypes_FieldAddOnlyGrowth(t *testing.T) {
	t.Parallel()

	for _, entry := range resultTypes() {
		typ := reflect.TypeOf(entry.v)
		name := entry.name
		baseline, known := allowedResultFields[name]
		if !known {
			t.Errorf("result type %q has no allowedResultFields baseline — record its exported fields", name)
			continue
		}
		present := make(map[string]bool, typ.NumField())
		for i := 0; i < typ.NumField(); i++ {
			if f := typ.Field(i); f.IsExported() {
				present[f.Name] = true
			}
		}
		missing := make([]string, 0)
		for _, want := range baseline {
			if !present[want] {
				missing = append(missing, want)
			}
		}
		sort.Strings(missing)
		for _, f := range missing {
			t.Errorf("%s lost field %s — removing/renaming a result-type field is breaking; only adding fields is compatible", name, f)
		}
	}
}

// TestResultTypes_ReadShaped asserts every result alias is a struct exposing at
// least one exported field. "Read-shaped" (§2.1) means consumers read
// the data off exported fields; a result type with no exported field would be
// opaque and unusable across the boundary.
func TestResultTypes_ReadShaped(t *testing.T) {
	t.Parallel()

	for _, entry := range resultTypes() {
		typ := reflect.TypeOf(entry.v)
		if typ.Kind() != reflect.Struct {
			t.Errorf("result type %q is %s, want struct", typ, typ.Kind())
			continue
		}
		var exported int
		for i := 0; i < typ.NumField(); i++ {
			if typ.Field(i).IsExported() {
				exported++
			}
		}
		if exported == 0 {
			t.Errorf("result type %q exposes no exported fields; cannot be read across the boundary", typ)
		}
	}
}
