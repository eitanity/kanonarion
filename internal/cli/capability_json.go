package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/eitanity/kanonarion/internal/coordinate"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	capdomain "github.com/eitanity/kanonarion/internal/capability/domain"
)

func encodeJSON(stdout io.Writer, v any) error {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return nil
}

type capabilityFindingJSON struct {
	Capability string `json:"capability"`
	// CapslockCategory is the capslock name the capability maps onto; the map
	// is many-to-one.
	CapslockCategory  string `json:"capslock_category"`
	WeakestConfidence string `json:"weakest_confidence"`
	// Basis is what the path established: "use", "linkage_only" or
	// "callee_body_fact". Emitted on every entry in both arrays so a consumer
	// that merges them cannot lose the distinction.
	Basis string `json:"basis"`
	// BasisNote is the one-line reason, empty for "use".
	BasisNote    string `json:"basis_note,omitempty"`
	Reach        string `json:"reach"`
	CallerKind   string `json:"caller_kind"`
	ClassifiedBy string `json:"classified_by"`
	// Suppressed is what text hides unless --show-suppressed is given.
	Suppressed   bool     `json:"suppressed"`
	PlumbingOnly bool     `json:"plumbing_only"`
	SinkPackage  string   `json:"sink_package"`
	SinkSymbol   string   `json:"sink_symbol"`
	Path         []string `json:"path"`
}

type capabilityRowJSON struct {
	CallerKind       string `json:"caller_kind"`
	Capability       string `json:"capability"`
	CapslockCategory string `json:"capslock_category"`
	Reach            string `json:"reach"`
	Callee           string `json:"callee"`
	Caller           string `json:"caller"`
	BodyFact         bool   `json:"body_fact"`
	ClassifiedBy     string `json:"classified_by"`
	Confidence       string `json:"confidence"`
	Suppressed       bool   `json:"suppressed"`
	PlumbingOnly     bool   `json:"plumbing_only"`
}

type sensitiveCallJSON struct {
	Callee           string   `json:"callee"`
	Capability       string   `json:"capability"`
	CapslockCategory string   `json:"capslock_category"`
	CallerKinds      []string `json:"caller_kinds"`
	Callers          int      `json:"callers"`
}

type coLocationJSON struct {
	Function   string   `json:"function"`
	CallerKind string   `json:"caller_kind"`
	Collection []string `json:"collection"`
	Egress     []string `json:"egress"`
}

type initReachJSON struct {
	Init            string `json:"init"`
	CallerKind      string `json:"caller_kind"`
	Depth           int    `json:"depth"`
	CollectionDepth int    `json:"collection_depth"`
	EgressDepth     int    `json:"egress_depth"`
	Collection      string `json:"collection"`
	Egress          string `json:"egress"`
}

type initReachDepthChangeJSON struct {
	Init       string `json:"init"`
	Collection string `json:"collection"`
	Egress     string `json:"egress"`
	FromDepth  int    `json:"from_depth"`
	ToDepth    int    `json:"to_depth"`
}

type packageDefaultJSON struct {
	Package string `json:"package"`
	Callees int    `json:"callees"`
}

type capabilityReportJSON struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	// TestRoots is "excluded" or "included": which root set produced the
	// answer. It is always populated, so a consumer cannot mistake an unstated
	// axis for a missing one.
	TestRoots string `json:"test_roots"`
	// Frame is the build frame the record read was extracted under, in
	// callgraph-show's shape; absent for a record that states none.
	Frame        *frameJSON              `json:"frame,omitempty"`
	Partial      bool                    `json:"partial"`
	Caveat       string                  `json:"caveat,omitempty"`
	Capabilities []string                `json:"capabilities"`
	Findings     []capabilityFindingJSON `json:"findings"`
	// Observations are paths that reach a classified node but establish
	// something weaker than a capability of this module. Always present (empty
	// array when there are none) so its absence cannot be read as "none found".
	Observations        []capabilityFindingJSON `json:"observations"`
	RowCount            int                     `json:"row_count"`
	SensitiveCalls      []sensitiveCallJSON     `json:"sensitive_calls"`
	CollectsAndEgresses []coLocationJSON        `json:"collects_and_egresses"`
	InitReachesBoth     []initReachJSON         `json:"init_reaches_both"`
	Unanalyzed          []string                `json:"unanalyzed"`
	UnanalyzedCallees   int                     `json:"unanalyzed_callees"`
	PackageDefaults     []packageDefaultJSON    `json:"package_defaults"`
	// SetAside names the stored call graph generations the reads behind this
	// document left out because this build cannot reproduce them.
	SetAside []setAsideJSON `json:"set_aside,omitempty"`
}

type capabilityDiffJSON struct {
	From     capabilityReportJSON `json:"from"`
	To       capabilityReportJSON `json:"to"`
	ParityOK bool                 `json:"parity_ok"`
	Caveat   string               `json:"caveat,omitempty"`
	// Added, Removed and Common are the capability set, in the current
	// vocabulary.
	Added                      []string            `json:"added"`
	Removed                    []string            `json:"removed"`
	Common                     []string            `json:"common"`
	FromRows                   int                 `json:"from_rows"`
	ToRows                     int                 `json:"to_rows"`
	RowsAdded                  []capabilityRowJSON `json:"rows_added"`
	RowsRemoved                []capabilityRowJSON `json:"rows_removed"`
	SensitiveCallsAdded        []sensitiveCallJSON `json:"sensitive_calls_added"`
	SensitiveCallsRemoved      []sensitiveCallJSON `json:"sensitive_calls_removed"`
	CollectsAndEgressesAdded   []coLocationJSON    `json:"collects_and_egresses_added"`
	CollectsAndEgressesRemoved []coLocationJSON    `json:"collects_and_egresses_removed"`
	InitReachesBothAdded       []initReachJSON     `json:"init_reaches_both_added"`
	InitReachesBothRemoved     []initReachJSON     `json:"init_reaches_both_removed"`
	// InitReachesBothDepthChanged is a fact both versions hold at different
	// depths: a change, not an add and a remove.
	InitReachesBothDepthChanged []initReachDepthChangeJSON `json:"init_reaches_both_depth_changed"`
	UnanalyzedAdded             []string                   `json:"unanalyzed_added"`
	UnanalyzedRemoved           []string                   `json:"unanalyzed_removed"`
	// SetAside names the stored call graph generations the reads behind this
	// document left out because this build cannot reproduce them.
	SetAside []setAsideJSON `json:"set_aside,omitempty"`
}

func capabilityReportToJSON(coord coordinate.ModuleCoordinate, r capdomain.CapabilityReport, scope cgdomain.RootScope) capabilityReportJSON {
	defaults := make([]packageDefaultJSON, 0, len(r.PackageDefaults))
	for _, d := range r.PackageDefaults {
		defaults = append(defaults, packageDefaultJSON{Package: d.Package, Callees: d.Callees})
	}
	return capabilityReportJSON{
		Module:              coord.Path(),
		Version:             coord.Version(),
		TestRoots:           capabilityRootScopeJSON(scope),
		Partial:             r.Partial,
		Caveat:              r.Caveat,
		Capabilities:        capsToStrings(r.Capabilities()),
		Findings:            capabilityFindingsToJSON(r.Findings),
		Observations:        capabilityFindingsToJSON(r.Observations),
		RowCount:            len(r.Rows),
		SensitiveCalls:      sensitiveCallsToJSON(r.SensitiveCalls),
		CollectsAndEgresses: coLocationsToJSON(r.CollectsAndEgresses),
		InitReachesBoth:     initReachesToJSON(r.InitReachesBoth),
		Unanalyzed:          nonNil(r.Unanalyzed),
		UnanalyzedCallees:   r.UnanalyzedCallees,
		PackageDefaults:     defaults,
	}
}

func capabilityFindingsToJSON(fs []capdomain.CapabilityFinding) []capabilityFindingJSON {
	out := make([]capabilityFindingJSON, 0, len(fs))
	for _, f := range fs {
		out = append(out, capabilityFindingJSON{
			Capability:        string(f.Capability),
			CapslockCategory:  f.Capability.CapslockCategory(),
			WeakestConfidence: string(f.WeakestConfidence),
			Basis:             string(f.Basis),
			BasisNote:         f.Basis.Explanation(),
			Reach:             string(f.Reach),
			CallerKind:        string(f.CallerKind),
			ClassifiedBy:      string(f.ClassifiedBy),
			Suppressed:        f.Suppressed(),
			PlumbingOnly:      f.PlumbingOnly,
			SinkPackage:       f.SinkPackage,
			SinkSymbol:        f.SinkSymbol,
			Path:              f.Path,
		})
	}
	return out
}

func capabilityRowsToJSON(rows []capdomain.WitnessRow) []capabilityRowJSON {
	out := make([]capabilityRowJSON, 0, len(rows))
	for _, r := range rows {
		out = append(out, capabilityRowJSON{
			CallerKind:       string(r.CallerKind),
			Capability:       string(r.Capability),
			CapslockCategory: r.Capability.CapslockCategory(),
			Reach:            string(r.Reach),
			Callee:           r.Callee,
			Caller:           r.Caller,
			BodyFact:         r.BodyFact,
			ClassifiedBy:     string(r.ClassifiedBy),
			Confidence:       string(r.Confidence),
			Suppressed:       r.Suppressed,
			PlumbingOnly:     r.PlumbingOnly,
		})
	}
	return out
}

func sensitiveCallsToJSON(calls []capdomain.SensitiveCall) []sensitiveCallJSON {
	out := make([]sensitiveCallJSON, 0, len(calls))
	for _, c := range calls {
		kinds := make([]string, 0, len(c.CallerKinds))
		for _, k := range c.CallerKinds {
			kinds = append(kinds, string(k))
		}
		out = append(out, sensitiveCallJSON{
			Callee: c.Callee, Capability: string(c.Capability),
			CapslockCategory: c.Capability.CapslockCategory(), CallerKinds: kinds, Callers: c.Callers,
		})
	}
	return out
}

func coLocationsToJSON(cs []capdomain.CoLocation) []coLocationJSON {
	out := make([]coLocationJSON, 0, len(cs))
	for _, c := range cs {
		out = append(out, coLocationJSON{
			Function: c.Function, CallerKind: string(c.CallerKind), Collection: c.Collection, Egress: c.Egress,
		})
	}
	return out
}

func initReachesToJSON(rs []capdomain.InitReach) []initReachJSON {
	out := make([]initReachJSON, 0, len(rs))
	for _, r := range rs {
		out = append(out, initReachJSON{
			Init: r.Init, CallerKind: string(r.CallerKind), Depth: r.Depth,
			CollectionDepth: r.CollectionDepth, EgressDepth: r.EgressDepth,
			Collection: r.Collection, Egress: r.Egress,
		})
	}
	return out
}

func depthChangesToJSON(cs []capdomain.InitReachDepthChange) []initReachDepthChangeJSON {
	out := make([]initReachDepthChangeJSON, 0, len(cs))
	for _, c := range cs {
		out = append(out, initReachDepthChangeJSON{
			Init: c.To.Init, Collection: c.To.Collection, Egress: c.To.Egress,
			FromDepth: c.From.Depth, ToDepth: c.To.Depth,
		})
	}
	return out
}

// nonNil keeps an empty list an array in JSON, so absence never reads as
// "not computed".
func nonNil(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

func capabilityDiffToJSON(from, to coordinate.ModuleCoordinate, fromReport, toReport capdomain.CapabilityReport, diff capdomain.CapabilityDiff, scope cgdomain.RootScope) capabilityDiffJSON {
	return capabilityDiffJSON{
		From:                        capabilityReportToJSON(from, fromReport, scope),
		To:                          capabilityReportToJSON(to, toReport, scope),
		ParityOK:                    diff.ParityOK,
		Caveat:                      diff.Caveat,
		Added:                       capsToStrings(diff.Added),
		Removed:                     capsToStrings(diff.Removed),
		Common:                      capsToStrings(diff.Common),
		FromRows:                    diff.FromRows,
		ToRows:                      diff.ToRows,
		RowsAdded:                   capabilityRowsToJSON(diff.RowsAdded),
		RowsRemoved:                 capabilityRowsToJSON(diff.RowsRemoved),
		SensitiveCallsAdded:         sensitiveCallsToJSON(diff.SensitiveAdded),
		SensitiveCallsRemoved:       sensitiveCallsToJSON(diff.SensitiveRemoved),
		CollectsAndEgressesAdded:    coLocationsToJSON(diff.CollectsAndEgressesAdded),
		CollectsAndEgressesRemoved:  coLocationsToJSON(diff.CollectsAndEgressesRemoved),
		InitReachesBothAdded:        initReachesToJSON(diff.InitReachesBothAdded),
		InitReachesBothRemoved:      initReachesToJSON(diff.InitReachesBothRemoved),
		InitReachesBothDepthChanged: depthChangesToJSON(diff.InitReachesBothDepthChanged),
		UnanalyzedAdded:             nonNil(diff.UnanalyzedAdded),
		UnanalyzedRemoved:           nonNil(diff.UnanalyzedRemoved),
	}
}

func capsToStrings(caps []capdomain.Capability) []string {
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		out = append(out, string(c))
	}
	return out
}
