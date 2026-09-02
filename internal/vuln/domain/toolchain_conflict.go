package domain

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// ToolchainConflict is two vulnerability records for one coordinate that state
// different Go toolchains.
//
// Which files build constraints select, which stdlib is linked, and which
// symbols a source-mode analysis can reach are all the toolchain's, so two
// toolchains produced two verdicts about two builds. There is no ladder between
// them: picking by recency or by call-graph completeness would answer a question
// the caller did not ask, and the verdict would say nothing about which build it
// described.
//
// It mirrors iface's InterfaceConflict and callgraph's CallGraphConflict,
// including reporting the content hashes of the records carrying each value.
type ToolchainConflict struct {
	// Coordinate is the module the disagreeing records describe.
	Coordinate coordinate.ModuleCoordinate
	// Values are the distinct toolchains recorded, sorted for a stable report.
	Values []string
	// ContentHashes name the records carrying each of Values, in the same order.
	ContentHashes []string
}

// Error renders the conflict as a message. ToolchainConflict satisfies error so
// the store can return it directly.
func (c ToolchainConflict) Error() string {
	return fmt.Sprintf(
		"conflicting vulnerability records for %s: two Go toolchains scanned it (%v; records %v). "+
			"A scan's reachable set is the toolchain's, so neither answer supersedes the other — "+
			"re-scan under the toolchain you are using:\n  kanonarion vuln-scan-rescan",
		c.Coordinate, c.Values, c.ContentHashes)
}

// findToolchainConflict reports two toolchains that reached DIFFERENT verdicts
// for one coordinate, or nil.
//
// The verdict difference is the disagreement; the toolchain is what explains it.
// Two toolchains that reached the same verdict reached the same answer, and
// refusing on the label alone would refuse reads this dimension has nothing to
// say about — measured on the call-graph ledger, that mistake made 18 of 30
// refusals byte-identical results.
//
// A record that states NO toolchain takes no part. That is a DELIBERATE
// EXCEPTION to the rule that an absent value is not a dimension value: no stored
// vulnerability record carries any toolchain marker, there is nothing to ladder
// a pre-field row to, and assigning the reading host's would be fabrication. So
// it ladders below a record that names one rather than competing with it.
func findToolchainConflict(records []VulnerabilityRecord) *ToolchainConflict {
	if len(records) < 2 {
		return nil
	}
	seen := map[string]string{}    // toolchain -> content hash of a record stating it
	verdict := map[string]string{} // toolchain -> the verdict it reached
	for _, r := range records {
		v := string(r.Toolchain)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; !ok {
			seen[v], verdict[v] = r.ContentHash, verdictDigest(r)
		}
	}
	if len(seen) < 2 || sameVerdicts(verdict) {
		return nil
	}
	values := make([]string, 0, len(seen))
	for v := range seen {
		values = append(values, v)
	}
	sort.Strings(values)
	hashes := make([]string, 0, len(values))
	for _, v := range values {
		hashes = append(hashes, seen[v])
	}
	return &ToolchainConflict{Coordinate: records[0].Coordinate, Values: values, ContentHashes: hashes}
}

// verdictDigest is what a record CLAIMS about the module's vulnerability state,
// with the provenance of the measurement left out.
//
// It is never persisted and is not a second seal: the content hash cannot answer
// "do these two agree", because it also covers when the scan ran and which walk
// asked. What remains here is the answer itself — the axes, the reasons, and each
// finding's identity, remediation and reachability.
func verdictDigest(r VulnerabilityRecord) string {
	parts := []string{
		string(r.OverallStatus), string(r.CoverageStatus), string(r.FindingsStatus),
		string(r.UnscanReason), r.UnscannableReason,
	}
	ids := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		reach := "unrecorded"
		if f.Reachable != nil {
			reach = strconv.FormatBool(f.Reachable.IsReachable) + "/" + string(f.Reachable.Confidence)
		}
		ids = append(ids, f.ID+"|"+f.FixedIn+"|"+reach)
	}
	sort.Strings(ids)
	return strings.Join(append(parts, ids...), "\x00")
}

// sameVerdicts reports whether every toolchain in the group reached the same
// answer, in which case there is nothing to choose between them.
func sameVerdicts(byToolchain map[string]string) bool {
	var first string
	// An all-equal check, so the map order cannot reach the answer. The empty
	// string is safe as the "nothing seen yet" marker because verdictDigest
	// joins at least five fields and so never returns one.
	for _, v := range byToolchain {
		if first == "" {
			first = v
			continue
		}
		if v != first {
			return false
		}
	}
	return true
}
