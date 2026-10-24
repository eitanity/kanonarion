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
	// NewestWalkID is the walk named by the newest of the disagreeing records,
	// empty when that record names none. It is the pin the refusal offers.
	NewestWalkID string
}

// Error renders the conflict as a message. ToolchainConflict satisfies error so
// the store can return it directly.
func (c ToolchainConflict) Error() string {
	// No re-scan line: a re-scan appends a record and leaves the other
	// toolchain's standing, so the pair the refusal fired on is unchanged.
	// Naming one build is what resolves it, and the pins name builds.
	coord := c.Coordinate.String()
	lines := make([]string, 0, 3)
	if c.NewestWalkID != "" {
		lines = append(lines, "kanonarion vuln-show "+coord+" --walk-id "+c.NewestWalkID)
	}
	lines = append(lines,
		"kanonarion vuln-show "+coord+" --gomod ./go.mod",
		"kanonarion vuln-show "+coord+" --history")
	return fmt.Sprintf(
		"conflicting vulnerability records for %s: two Go toolchains scanned it (%v; records %v). "+
			"A scan's reachable set is the toolchain's, so neither answer supersedes the other, and no "+
			"re-scan settles it: a re-scan appends a record and the other toolchain's stays. Name the build you mean — "+
			"the walk of the newest record, or the newest project walk for your go.mod, run from the "+
			"project — and the last line lists every record with the walk it was measured in:\n  %s",
		c.Coordinate, c.Values, c.ContentHashes, strings.Join(lines, "\n  "))
}

// findToolchainConflict reports two toolchains that reached DIFFERENT verdicts
// for one coordinate against the SAME advisory-database snapshot, or nil.
//
// The comparison is confined to the snapshot of the record the ladder would
// serve. Records on other snapshots were measured against other advisory sets,
// so their verdicts differ for that reason and say nothing about the toolchain.
// Within the snapshot each toolchain is represented by its best record under
// servesBefore, so the answer does not depend on the order rows arrive in.
//
// Two toolchains that reached the same verdict reached the same answer, and
// refusing on the label alone would refuse reads this dimension has nothing to
// say about — measured on the call-graph ledger, that mistake made 18 of 30
// refusals byte-identical results.
//
// A record that analysed nothing and reported nothing takes no part either: a
// failed or unscannable scan makes no claim about the module, so it cannot
// contradict one that does. One that did report a finding still claims it.
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
	served := best(records).DatabaseSnapshot
	rep := map[string]VulnerabilityRecord{} // toolchain -> its best record on the served snapshot
	var (
		newest    VulnerabilityRecord
		hasNewest bool
	)
	for _, r := range records {
		v := string(r.Toolchain)
		if v == "" || !sameSnapshot(r.DatabaseSnapshot, served) || !claimsAVerdict(r) {
			continue
		}
		if cur, ok := rep[v]; !ok || servesBefore(r, cur) {
			rep[v] = r
		}
		if !hasNewest || newerScan(r, newest) {
			newest, hasNewest = r, true
		}
	}
	verdict := make(map[string]string, len(rep))
	for v, r := range rep {
		verdict[v] = verdictDigest(r)
	}
	if len(rep) < 2 || sameVerdicts(verdict) {
		return nil
	}
	values := make([]string, 0, len(rep))
	for v := range rep {
		values = append(values, v)
	}
	sort.Strings(values)
	hashes := make([]string, 0, len(values))
	for _, v := range values {
		hashes = append(hashes, rep[v].ContentHash)
	}
	return &ToolchainConflict{Coordinate: records[0].Coordinate, Values: values, ContentHashes: hashes, NewestWalkID: newest.WalkID}
}

// claimsAVerdict reports whether a record says anything about the module: it
// was analysed, or it reported an advisory whatever its coverage.
func claimsAVerdict(r VulnerabilityRecord) bool {
	coverage, findings := RecordAxes(r)
	return coverage == CoverageAnalysed || reportsAdvisory(findings)
}

// sameSnapshot reports whether two records were measured against one advisory
// set: the same source and version, and the same content hash when both carry
// one. The retrieval instant is not identity: a re-download, or one instant
// stored at two precisions, is still one set, and a conflict across it is real.
func sameSnapshot(a, b DatabaseSnapshot) bool {
	if a.Source() != b.Source() || a.Version() != b.Version() {
		return false
	}
	return a.ContentHash() == "" || b.ContentHash() == "" || a.ContentHash() == b.ContentHash()
}

// newerScan orders records by scan time, the content hash breaking a tie so the
// pick does not depend on row order.
func newerScan(a, b VulnerabilityRecord) bool {
	if !a.ScannedAt.Equal(b.ScannedAt) {
		return a.ScannedAt.After(b.ScannedAt)
	}
	return a.ContentHash < b.ContentHash
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
