package cli

import (
	"encoding/json"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// The guard on the boundary `vuln-scan-diff --json` now has.
//
// The command used to embed vuldomain.ScanRunDiff and, through it, the three
// delta types below it — so the Go field names of four domain structs were the
// wire contract, and a rename anywhere in that tree was a silent break of a
// published surface. These tests hold the boundary from two sides: no Go field
// name reaches the document at any depth, and the values behind the new names
// are the ones the old contract published and nothing else.

// scanDiffWireNames is the wire spelling of every domain field this surface
// renamed, keyed by the type it belongs to.
//
// Written out rather than derived from the Go name by a rule, because a rule is
// a second implementation of the rename and would agree with a mistake made the
// same way twice. Only the untagged types appear: everything under a finding
// already stated its own wire name and travels unchanged.
var scanDiffWireNames = map[string]map[string]string{
	"ScanRunDiff": {
		"RunA":                "run_a",
		"RunB":                "run_b",
		"NewFindings":         "new_findings",
		"ResolvedFindings":    "resolved_findings",
		"WithdrawnFindings":   "withdrawn_findings",
		"ReachabilityChanges": "reachability_changes",
		"UnresolvedFindings":  "unresolved_findings",
	},
	"FindingDelta": {
		"Coordinate": "coordinate",
		"Finding":    "finding",
	},
	"ReachabilityChange": {
		"Coordinate":   "coordinate",
		"Finding":      "finding",
		"WasReachable": "was_reachable",
		"IsReachable":  "is_reachable",
	},
	"UnresolvedFinding": {
		"Coordinate": "coordinate",
		"Finding":    "finding",
		"Kind":       "kind",
		"Reason":     "reason",
	},
}

// scanRunForWire is one side of the diff, every field set to something
// distinguishable so a value that travelled to the wrong key is visible rather
// than hidden behind two zero values that happen to match.
func scanRunForWire(id string, affected int) vuldomain.WalkScanRun {
	return vuldomain.WalkScanRun{
		ID:       id,
		WalkID:   "01WALKFORWIRE0000000000000",
		Snapshot: vulntest.MustSealOver("vuln.go.dev", "2026-08-14T16:22:54Z", time.Date(2026, 8, 15, 8, 54, 1, 0, time.UTC), []byte("fixture advisories")),
		PerModuleResults: map[coordinate.ModuleCoordinate]string{
			coordinatetest.MustNew("golang.org/x/crypto", "v0.31.0"): "sha256:aa",
			coordinatetest.MustNew("github.com/lib/pq", "v1.10.5"):   "sha256:bb",
		},
		StartedAt:       time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC),
		CompletedAt:     time.Date(2026, 8, 20, 1, 5, 0, 0, time.UTC),
		OverallStatus:   vuldomain.WalkStatusAffected,
		CoverageStatus:  vuldomain.CoveragePartial,
		FindingsStatus:  vuldomain.FindingsAffected,
		Counts:          vuldomain.WalkScanCounts{Total: 12, Analysed: 11, Affected: affected, Unscannable: 1, Failed: 0},
		PipelineVersion: "3.1.0",
		Operator:        "wire-fixture",
		ContentHash:     "sha256:" + id,
	}
}

// scanFindingsForWire covers the states the projection has to carry apart: a
// finding with everything set, one with the nil arms (no aliases, no severity,
// no reachability answer, no references), and one with the EMPTY arms beside
// them — null and [] are different answers, and normalising one to the other is
// a value change.
func scanFindingsForWire() []vuldomain.VulnerabilityFinding {
	derived := vuldomain.ReachabilityDerivation{
		Analyser: vuldomain.AnalyserGovulncheck,
		Fidelity: "source",
		Rooting:  vuldomain.TargetRootedAt(coordinatetest.MustNew("example.com/app", "local")),
	}
	return []vuldomain.VulnerabilityFinding{
		{
			ID:              "GO-2026-0001",
			Aliases:         []string{"CVE-2026-1", "GHSA-aaaa"},
			Summary:         "everything set",
			Details:         "the long form",
			AffectedRange:   "< v0.32.0",
			FixedIn:         "v0.32.0",
			Severity:        &vuldomain.Severity{Vector: "CVSS:3.1/AV:N", Score: 7.5, Label: "HIGH"},
			AffectedSymbols: []string{"golang.org/x/crypto/ssh.Dial", "golang.org/x/crypto/ssh.Handshake"},
			Reachable: &vuldomain.ReachabilityResult{
				IsReachable: true,
				Confidence:  vuldomain.ConfidenceHigh,
				Routes: []vuldomain.ReachabilityRoute{
					{
						{ModulePath: "example.com/app", Package: "example.com/app/cmd", Symbol: "main"},
						{ModulePath: "golang.org/x/crypto", ModuleVersion: "v0.31.0",
							Package: "golang.org/x/crypto/ssh", Receiver: "Client", Symbol: "Dial"},
					},
					// An empty route beside a populated one: a route the analyser
					// reported with no hops is not a route it did not report.
					{},
				},
				DerivedBy: derived,
			},
			References: []vuldomain.AdvisoryReference{
				{Type: "FIX", URL: "https://example.com/fix"},
				{URL: "https://example.com/web"},
			},
			PublishedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			ModifiedAt:  time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC),
			WithdrawnAt: time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC),
		},
		{
			// The nil arms, and the negative that earns a rung.
			ID:              "GO-2026-0002",
			Summary:         "the negative",
			AffectedRange:   "< v1.10.6",
			AffectedSymbols: []string{"github.com/lib/pq.Open"},
			Reachable: &vuldomain.ReachabilityResult{
				IsReachable: false,
				Confidence:  vuldomain.ConfidenceHigh,
				DerivedBy:   derived,
			},
			PublishedAt: time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC),
			ModifiedAt:  time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC),
		},
		{
			// The empty arms, and no reachability answer at all.
			ID:                     "GO-2026-0003",
			Aliases:                []string{},
			Summary:                "never analysed",
			AffectedRange:          "< v2.0.0",
			AffectedSymbols:        []string{},
			References:             []vuldomain.AdvisoryReference{},
			AdvisoryNamesNoSymbols: true,
			ReachabilityNote:       "call graph could not be loaded",
			PublishedAt:            time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC),
			ModifiedAt:             time.Date(2026, 7, 8, 9, 10, 11, 0, time.UTC),
		},
	}
}

// scanRunDiffForWire is a diff whose every delta list is populated, so the
// measurement below is of the whole document rather than of the two runs at the
// top of it.
func scanRunDiffForWire() vuldomain.ScanRunDiff {
	findings := scanFindingsForWire()
	crypto := coordinatetest.MustNew("golang.org/x/crypto", "v0.31.0")
	pq := coordinatetest.MustNew("github.com/lib/pq", "v1.10.5")
	return vuldomain.ScanRunDiff{
		RunA: scanRunForWire("vscan-A", 3),
		RunB: scanRunForWire("vscan-B", 5),
		NewFindings: []vuldomain.FindingDelta{
			{Coordinate: crypto, Finding: findings[0]},
			{Coordinate: pq, Finding: findings[1]},
		},
		ResolvedFindings: []vuldomain.FindingDelta{
			{Coordinate: pq, Finding: findings[2]},
		},
		WithdrawnFindings: []vuldomain.FindingDelta{
			{Coordinate: crypto, Finding: findings[0]},
		},
		ReachabilityChanges: []vuldomain.ReachabilityChange{
			{Coordinate: crypto, Finding: findings[0], WasReachable: false, IsReachable: true},
			{Coordinate: pq, Finding: findings[1], WasReachable: true, IsReachable: false},
		},
		UnresolvedFindings: []vuldomain.UnresolvedFinding{
			{Coordinate: pq, Finding: findings[2], Kind: vuldomain.UnresolvedKindResolved,
				Reason: "completeness level differs: before=BUILT_WITH_BODIES after=METADATA_ONLY"},
		},
	}
}

// scanDiffKeyPaths walks a decoded document and returns every object key with
// the path it sits at, so a measurement of this surface is of the WHOLE document
// rather than of its top level.
//
// per_module_results is skipped as a container of keys: its members are module
// coordinates, which are data the run carries, not names this view chose.
func scanDiffKeyPaths(v any, at string, into map[string]string) {
	switch n := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(n))
		for k := range n {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := at + "/" + k
			into[p] = k
			if k == "per_module_results" {
				continue
			}
			scanDiffKeyPaths(n[k], p, into)
		}
	case []any:
		for _, e := range n {
			scanDiffKeyPaths(e, at+"[]", into)
		}
	}
}

// TestScanDiffJSONPublishesNoGoFieldNameAtAnyDepth is the measurement, taken
// over the whole document rather than its top level.
//
// Half a rename is not a smaller version of this fix: snake_case at the top with
// Go identifiers underneath makes a consumer carry two conventions through one
// payload, which is worse than the uniform PascalCase it replaced.
func TestScanDiffJSONPublishesNoGoFieldNameAtAnyDepth(t *testing.T) {
	out, err := json.Marshal(newScanRunDiffDocument(scanRunDiffForWire()))
	if err != nil {
		t.Fatalf("marshalling the scan diff document: %v", err)
	}
	var doc any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("vuln-scan-diff --json does not decode: %v\n%s", err, out)
	}
	paths := map[string]string{}
	scanDiffKeyPaths(doc, "", paths)

	snake := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	var bad []string
	for p, key := range paths {
		if !snake.MatchString(key) {
			bad = append(bad, p)
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Errorf("vuln-scan-diff --json publishes %d key(s) that are not snake_case:\n  %s\n"+
			"a Go field name on the wire, at any depth, means a domain rename breaks this surface silently:\n%s",
			len(bad), strings.Join(bad, "\n  "), out)
	}
	if len(paths) < 40 {
		t.Errorf("the fixture reaches only %d key(s); it is not exercising the nested types this test "+
			"exists to measure", len(paths))
	}
}

// TestScanDiffViewRenamesKeysAndChangesNoValue is the other half: the rename
// moved names and nothing else, everywhere.
//
// The proof is a whole-document comparison against the shape this command used
// to publish — the domain diff embedded, with the three delta lists shadowed so
// each finding carried its rung. That reference is rendered, every key in it is
// rewritten through the map above, and the result must equal the document the
// command writes today. Nothing is compared field by field and nothing is
// skipped: a value converted, reordered, dropped, invented, or a nil slice
// normalised to [] at any depth fails here — as does a field added to one of the
// embedded domain types and not carried onto the view.
func TestScanDiffViewRenamesKeysAndChangesNoValue(t *testing.T) {
	diff := scanRunDiffForWire()

	oldRaw, err := json.Marshal(wasScanDiffPublished(diff))
	if err != nil {
		t.Fatal(err)
	}

	// One flat rename, because no Go field name on this surface maps to two
	// different wire names — asserted rather than assumed.
	rename := map[string]string{}
	for typ, fields := range scanDiffWireNames {
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
	renamed := scanDiffRenameKeys(oldDoc, rename)

	newRaw, err := json.Marshal(newScanRunDiffDocument(diff))
	if err != nil {
		t.Fatal(err)
	}
	var newDoc any
	if err := json.Unmarshal(newRaw, &newDoc); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(renamed, newDoc) {
		gotRaw, _ := json.MarshalIndent(newDoc, "", "  ")
		wantRaw, _ := json.MarshalIndent(renamed, "", "  ")
		t.Errorf("the document is not the old one with its keys renamed — a value changed somewhere:\n"+
			"--- the old document, keys renamed ---\n%s\n--- what the command writes ---\n%s", wantRaw, gotRaw)
	}
}

// wasScanDiffPublished reproduces exactly what `vuln-scan-diff --json` emitted
// before the view existed: the domain diff embedded, with each delta list
// shadowed so its findings carried the derived rung.
func wasScanDiffPublished(d vuldomain.ScanRunDiff) any {
	type wasFindingDelta struct {
		vuldomain.FindingDelta
		Finding vulnFindingRungJSON
	}
	type wasReachabilityChange struct {
		vuldomain.ReachabilityChange
		Finding vulnFindingRungJSON
	}
	type wasUnresolvedFinding struct {
		vuldomain.UnresolvedFinding
		Finding vulnFindingRungJSON
	}
	type wasPublished struct {
		vuldomain.ScanRunDiff
		NewFindings         []wasFindingDelta       `json:"NewFindings"`
		ResolvedFindings    []wasFindingDelta       `json:"ResolvedFindings"`
		WithdrawnFindings   []wasFindingDelta       `json:"WithdrawnFindings"`
		ReachabilityChanges []wasReachabilityChange `json:"ReachabilityChanges"`
		UnresolvedFindings  []wasUnresolvedFinding  `json:"UnresolvedFindings"`
	}

	was := wasPublished{ScanRunDiff: d}
	for _, x := range d.NewFindings {
		was.NewFindings = append(was.NewFindings,
			wasFindingDelta{FindingDelta: x, Finding: toVulnFindingRungJSON(x.Finding)})
	}
	for _, x := range d.ResolvedFindings {
		was.ResolvedFindings = append(was.ResolvedFindings,
			wasFindingDelta{FindingDelta: x, Finding: toVulnFindingRungJSON(x.Finding)})
	}
	for _, x := range d.WithdrawnFindings {
		was.WithdrawnFindings = append(was.WithdrawnFindings,
			wasFindingDelta{FindingDelta: x, Finding: toVulnFindingRungJSON(x.Finding)})
	}
	for _, x := range d.ReachabilityChanges {
		was.ReachabilityChanges = append(was.ReachabilityChanges,
			wasReachabilityChange{ReachabilityChange: x, Finding: toVulnFindingRungJSON(x.Finding)})
	}
	for _, x := range d.UnresolvedFindings {
		was.UnresolvedFindings = append(was.UnresolvedFindings,
			wasUnresolvedFinding{UnresolvedFinding: x, Finding: toVulnFindingRungJSON(x.Finding)})
	}
	return was
}

// scanDiffRenameKeys rewrites object keys through the map, leaving keys it does
// not know — everything under a finding, which already stated its own wire name
// — and the per-module-results map's coordinate keys alone.
func scanDiffRenameKeys(v any, rename map[string]string) any {
	switch n := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(n))
		for k, val := range n {
			name := k
			if to, ok := rename[k]; ok {
				name = to
			}
			if name == "per_module_results" {
				out[name] = val
				continue
			}
			out[name] = scanDiffRenameKeys(val, rename)
		}
		return out
	case []any:
		out := make([]any, 0, len(n))
		for _, e := range n {
			out = append(out, scanDiffRenameKeys(e, rename))
		}
		return out
	default:
		return v
	}
}
