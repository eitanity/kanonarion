package cli

import (
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// scanRunDiffDocument is what `vuln-scan-diff --json` answers with.
//
// The command used to EMBED vuldomain.ScanRunDiff, which carries no json tags,
// so seven of the domain type's Go field names WERE the wire contract and a
// rename there — an ordinary refactor, invisible to anything that reads the
// tree — would have changed keys a consumer parses. The three delta element
// types below it published their own field names on the same terms.
//
// The projection is TOTAL, on the model licenseDocument sets: no domain struct
// is reachable from this type, every field states its wire name explicitly at
// every depth, and TestCLIViewsAreTotalProjections refuses a field that reopens
// the link. Two kinds of type still travel as they are, and neither publishes a
// Go identifier: a named string (a status, a rung, an analyser) is a value, and
// a type that marshals itself — coordinate.ModuleCoordinate, time.Time,
// vuldomain.DatabaseSnapshot — decides its own wire form.
//
// The VALUES are the diff's, unconverted. Nothing is reformatted, rounded,
// re-ordered or normalised on the way through, and a nil slice stays null while
// an empty one stays [] — those are different answers, and the delta lists are
// nil exactly when the diff holds none.
type scanRunDiffDocument struct {
	RunA scanRunJSON `json:"run_a"`
	RunB scanRunJSON `json:"run_b"`

	NewFindings         []scanFindingDeltaJSON       `json:"new_findings"`
	ResolvedFindings    []scanFindingDeltaJSON       `json:"resolved_findings"`
	WithdrawnFindings   []scanFindingDeltaJSON       `json:"withdrawn_findings"`
	ReachabilityChanges []scanReachabilityChangeJSON `json:"reachability_changes"`
	UnresolvedFindings  []scanUnresolvedFindingJSON  `json:"unresolved_findings"`
}

// scanRunJSON is one of the two runs the diff compares.
type scanRunJSON struct {
	ID       string                     `json:"id"`
	WalkID   string                     `json:"walk_id"`
	Snapshot vuldomain.DatabaseSnapshot `json:"snapshot"`
	// PerModuleResults maps a coordinate to the content hash of the
	// vulnerability record recorded for it. Its KEYS are coordinates — data the
	// run carries, not names this view chose.
	PerModuleResults map[coordinate.ModuleCoordinate]string `json:"per_module_results"`
	StartedAt        time.Time                              `json:"started_at"`
	CompletedAt      time.Time                              `json:"completed_at"`
	OverallStatus    vuldomain.WalkScanStatus               `json:"overall_status"`
	CoverageStatus   vuldomain.CoverageStatus               `json:"coverage_status"`
	FindingsStatus   vuldomain.FindingsStatus               `json:"findings_status"`
	Counts           scanRunCountsJSON                      `json:"counts"`
	PipelineVersion  string                                 `json:"pipeline_version"`
	Operator         string                                 `json:"operator"`
	ContentHash      string                                 `json:"content_hash"`
}

// scanRunCountsJSON is the population a run's verdict was measured over.
type scanRunCountsJSON struct {
	Total       int `json:"total"`
	Analysed    int `json:"analysed"`
	Affected    int `json:"affected"`
	Unscannable int `json:"unscannable"`
	Failed      int `json:"failed"`
}

// scanFindingDeltaJSON is one finding that appeared, disappeared or was
// withdrawn, with the coordinate it was recorded against.
//
// It publishes no route root: a delta carries no analysis frame, and the frame
// is what decides whether a route is closure-rooted, so the key is left off
// rather than computed against a guessed one. The missing key is the true
// statement — this producer does not derive it.
type scanFindingDeltaJSON struct {
	Coordinate coordinate.ModuleCoordinate `json:"coordinate"`
	Finding    scanFindingJSON             `json:"finding"`
}

// scanReachabilityChangeJSON is one finding whose reachability moved between the
// runs, with the rung behind the answer the LATER run gives.
type scanReachabilityChangeJSON struct {
	Coordinate   coordinate.ModuleCoordinate `json:"coordinate"`
	Finding      scanFindingJSON             `json:"finding"`
	WasReachable bool                        `json:"was_reachable"`
	IsReachable  bool                        `json:"is_reachable"`
}

// scanUnresolvedFindingJSON is one would-be green verdict withheld because the
// two runs analysed the module at unequal call-graph fidelity.
type scanUnresolvedFindingJSON struct {
	Coordinate coordinate.ModuleCoordinate `json:"coordinate"`
	Finding    scanFindingJSON             `json:"finding"`
	Kind       string                      `json:"kind"`
	Reason     string                      `json:"reason"`
}

// scanFindingJSON is one stored finding with its derived reachability rung.
//
// Soundness is emitted on every finding, positive and negative alike: "not
// stated" on a reachable finding is a statement, and it is a different statement
// from the key being missing. SoundnessReason is omitted when there is none,
// because NegativeSoundness returns a reason exactly when it returns a rung.
type scanFindingJSON struct {
	ID                     string                          `json:"id"`
	Aliases                []string                        `json:"aliases,omitzero"`
	Summary                string                          `json:"summary"`
	Details                string                          `json:"details,omitzero"`
	AffectedRange          string                          `json:"affected_range"`
	FixedIn                string                          `json:"fixed_in,omitzero"`
	Severity               *scanSeverityJSON               `json:"severity,omitzero"`
	AffectedSymbols        []string                        `json:"affected_symbols,omitzero"`
	Reachable              *scanReachabilityJSON           `json:"reachable,omitzero"`
	AdvisoryNamesNoSymbols bool                            `json:"advisory_names_no_symbols,omitzero"`
	ReachabilityNote       string                          `json:"reachability_note,omitzero"`
	References             []scanAdvisoryReferenceJSON     `json:"references,omitzero"`
	PublishedAt            time.Time                       `json:"published_at"`
	ModifiedAt             time.Time                       `json:"modified_at"`
	WithdrawnAt            time.Time                       `json:"withdrawn_at,omitzero"`
	Soundness              vuldomain.ReachabilitySoundness `json:"soundness"`
	SoundnessReason        string                          `json:"soundness_reason,omitempty"`
}

// scanSeverityJSON is the advisory's severity as it stated it.
type scanSeverityJSON struct {
	Vector string  `json:"vector,omitzero"`
	Score  float64 `json:"score,omitzero"`
	Label  string  `json:"label,omitzero"`
}

// scanAdvisoryReferenceJSON is one advisory link, type and URL kept as a pair.
type scanAdvisoryReferenceJSON struct {
	Type string `json:"type,omitzero"`
	URL  string `json:"url"`
}

// scanReachabilityJSON is one reachability answer with the routes behind it and
// the instrument that produced it.
type scanReachabilityJSON struct {
	IsReachable bool                             `json:"is_reachable"`
	Confidence  vuldomain.ReachabilityConfidence `json:"confidence"`
	Routes      []scanRouteJSON                  `json:"routes,omitzero"`
	DerivedBy   scanDerivationJSON               `json:"derived_by,omitzero"`
}

// scanRouteJSON is one path from an entry point to the vulnerable symbol, entry
// point first.
type scanRouteJSON []scanRouteFrameJSON

// scanRouteFrameJSON is one hop on a route.
type scanRouteFrameJSON struct {
	ModulePath    string `json:"module_path,omitzero"`
	ModuleVersion string `json:"module_version,omitzero"`
	Package       string `json:"package,omitzero"`
	Receiver      string `json:"receiver,omitzero"`
	Symbol        string `json:"symbol,omitzero"`
}

// scanDerivationJSON states the instrument, how well it could see, and the
// analysis frame the answer was reached in.
type scanDerivationJSON struct {
	Analyser vuldomain.ReachabilityAnalyser `json:"analyser,omitzero"`
	Fidelity string                         `json:"fidelity,omitzero"`
	Rooting  vuldomain.Rooting              `json:"rooting,omitzero"`
}

// newScanRunDiffDocument projects a diff onto the view.
//
// Field-by-field assignment rather than a conversion or a copy helper: the point
// of the view is that adding a field to a domain type does not add a key to the
// wire, and only an explicit assignment has that property.
func newScanRunDiffDocument(d vuldomain.ScanRunDiff) scanRunDiffDocument {
	return scanRunDiffDocument{
		RunA:                scanRunJSONOf(d.RunA),
		RunB:                scanRunJSONOf(d.RunB),
		NewFindings:         scanFindingDeltasJSONOf(d.NewFindings),
		ResolvedFindings:    scanFindingDeltasJSONOf(d.ResolvedFindings),
		WithdrawnFindings:   scanFindingDeltasJSONOf(d.WithdrawnFindings),
		ReachabilityChanges: scanReachabilityChangesJSONOf(d.ReachabilityChanges),
		UnresolvedFindings:  scanUnresolvedFindingsJSONOf(d.UnresolvedFindings),
	}
}

func scanRunJSONOf(r vuldomain.WalkScanRun) scanRunJSON {
	return scanRunJSON{
		ID:               r.ID,
		WalkID:           r.WalkID,
		Snapshot:         r.Snapshot,
		PerModuleResults: r.PerModuleResults,
		StartedAt:        r.StartedAt,
		CompletedAt:      r.CompletedAt,
		OverallStatus:    r.OverallStatus,
		CoverageStatus:   r.CoverageStatus,
		FindingsStatus:   r.FindingsStatus,
		Counts: scanRunCountsJSON{
			Total:       r.Counts.Total,
			Analysed:    r.Counts.Analysed,
			Affected:    r.Counts.Affected,
			Unscannable: r.Counts.Unscannable,
			Failed:      r.Counts.Failed,
		},
		PipelineVersion: r.PipelineVersion,
		Operator:        r.Operator,
		ContentHash:     r.ContentHash,
	}
}

// The projections below all share one shape, and the nil test each opens with is
// why none is folded into a generic helper's happy path: a nil slice marshals to
// null and an empty one to [], those are different answers on this surface, and
// the projection must not turn one into the other on the way through.

func scanFindingDeltasJSONOf(in []vuldomain.FindingDelta) []scanFindingDeltaJSON {
	if in == nil {
		return nil
	}
	out := make([]scanFindingDeltaJSON, 0, len(in))
	for _, d := range in {
		out = append(out, scanFindingDeltaJSON{
			Coordinate: d.Coordinate,
			Finding:    scanFindingJSONOf(d.Finding),
		})
	}
	return out
}

func scanReachabilityChangesJSONOf(in []vuldomain.ReachabilityChange) []scanReachabilityChangeJSON {
	if in == nil {
		return nil
	}
	out := make([]scanReachabilityChangeJSON, 0, len(in))
	for _, c := range in {
		out = append(out, scanReachabilityChangeJSON{
			Coordinate:   c.Coordinate,
			Finding:      scanFindingJSONOf(c.Finding),
			WasReachable: c.WasReachable,
			IsReachable:  c.IsReachable,
		})
	}
	return out
}

func scanUnresolvedFindingsJSONOf(in []vuldomain.UnresolvedFinding) []scanUnresolvedFindingJSON {
	if in == nil {
		return nil
	}
	out := make([]scanUnresolvedFindingJSON, 0, len(in))
	for _, u := range in {
		out = append(out, scanUnresolvedFindingJSON{
			Coordinate: u.Coordinate,
			Finding:    scanFindingJSONOf(u.Finding),
			Kind:       u.Kind,
			Reason:     u.Reason,
		})
	}
	return out
}

// scanFindingJSONOf projects one finding and derives its rung.
func scanFindingJSONOf(f vuldomain.VulnerabilityFinding) scanFindingJSON {
	soundness, reason := vuldomain.NegativeSoundness(f)
	return scanFindingJSON{
		ID:                     f.ID,
		Aliases:                f.Aliases,
		Summary:                f.Summary,
		Details:                f.Details,
		AffectedRange:          f.AffectedRange,
		FixedIn:                f.FixedIn,
		Severity:               scanSeverityJSONOf(f.Severity),
		AffectedSymbols:        f.AffectedSymbols,
		Reachable:              scanReachabilityJSONOf(f.Reachable),
		AdvisoryNamesNoSymbols: f.AdvisoryNamesNoSymbols,
		ReachabilityNote:       f.ReachabilityNote,
		References:             scanAdvisoryReferencesJSONOf(f.References),
		PublishedAt:            f.PublishedAt,
		ModifiedAt:             f.ModifiedAt,
		WithdrawnAt:            f.WithdrawnAt,
		Soundness:              soundness,
		SoundnessReason:        reason,
	}
}

func scanSeverityJSONOf(s *vuldomain.Severity) *scanSeverityJSON {
	if s == nil {
		return nil
	}
	return &scanSeverityJSON{Vector: s.Vector, Score: s.Score, Label: s.Label}
}

func scanAdvisoryReferencesJSONOf(in []vuldomain.AdvisoryReference) []scanAdvisoryReferenceJSON {
	if in == nil {
		return nil
	}
	out := make([]scanAdvisoryReferenceJSON, 0, len(in))
	for _, r := range in {
		out = append(out, scanAdvisoryReferenceJSON{Type: r.Type, URL: r.URL})
	}
	return out
}

func scanReachabilityJSONOf(r *vuldomain.ReachabilityResult) *scanReachabilityJSON {
	if r == nil {
		return nil
	}
	return &scanReachabilityJSON{
		IsReachable: r.IsReachable,
		Confidence:  r.Confidence,
		Routes:      scanRoutesJSONOf(r.Routes),
		DerivedBy: scanDerivationJSON{
			Analyser: r.DerivedBy.Analyser,
			Fidelity: r.DerivedBy.Fidelity,
			Rooting:  r.DerivedBy.Rooting,
		},
	}
}

func scanRoutesJSONOf(in []vuldomain.ReachabilityRoute) []scanRouteJSON {
	if in == nil {
		return nil
	}
	out := make([]scanRouteJSON, 0, len(in))
	for _, route := range in {
		out = append(out, scanRouteJSONOf(route))
	}
	return out
}

func scanRouteJSONOf(in vuldomain.ReachabilityRoute) scanRouteJSON {
	if in == nil {
		return nil
	}
	out := make(scanRouteJSON, 0, len(in))
	for _, f := range in {
		out = append(out, scanRouteFrameJSON{
			ModulePath:    f.ModulePath,
			ModuleVersion: f.ModuleVersion,
			Package:       f.Package,
			Receiver:      f.Receiver,
			Symbol:        f.Symbol,
		})
	}
	return out
}
