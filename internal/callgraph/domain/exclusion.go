package domain

import (
	"sort"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// NormaliseExclusions returns a sorted, de-duplicated copy of the configured
// callgraph.exclude list with blank entries dropped. Callers store the result
// on the record so the exclusion policy is reproducible and hashes
// deterministically regardless of config-file ordering. A nil or all-blank
// input yields nil (an absent policy, not an empty-but-present one).
func NormaliseExclusions(exclude []string) []string {
	if len(exclude) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(exclude))
	out := make([]string, 0, len(exclude))
	for _, e := range exclude {
		if e == "" {
			continue
		}
		if _, dup := seen[e]; dup {
			continue
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

// IsModuleExcluded reports whether modulePath is excluded from call-graph
// analysis by the given exclude list. Matching is by exact module path; the
// list is operator-supplied module paths (see budgets rationale).
func IsModuleExcluded(modulePath string, exclude []string) bool {
	for _, e := range exclude {
		if e != "" && e == modulePath {
			return true
		}
	}
	return false
}

// NewExcludedRecord builds the CallGraphRecord persisted for a module that was
// skipped because it is listed in callgraph.exclude. It has no nodes or edges;
// the caller still sets ExtractedAt, PipelineVersion, and the content hash.
// exclusionList must already be normalised (see NormaliseExclusions).
func NewExcludedRecord(coord coordinate.ModuleCoordinate, algorithm CallGraphAlgorithm, exclusionList []string) CallGraphRecord {
	return CallGraphRecord{
		SchemaVersion:   CallGraphSchemaVersion,
		Ecosystem:       fetchdomain.EcosystemGo,
		Coordinate:      coord,
		Algorithm:       algorithm,
		OverallStatus:   CallGraphStatusExcludedByConfig,
		ExclusionReason: ExclusionReasonConfig,
		ExclusionList:   exclusionList,
		ExtractedAt:     time.Time{},
	}
}
