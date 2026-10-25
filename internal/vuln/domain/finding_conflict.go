package domain

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/recordstamp"
)

// ErrVulnConflict is the sentinel every vulnerability-record disagreement
// wraps. It is declared here rather than only in ports because readers call
// composition directly, so the domain's own conflict types must carry it.
var ErrVulnConflict = errors.New("conflicting vulnerability records")

// FindingConflict is two or more analysed records that answer one question —
// one coordinate, pipeline, advisory snapshot, frame and toolchain — and report
// different advisories.
//
// Which advisories match a module version is the database's answer, so two
// records of one snapshot that differ in it cannot both be right, and recency
// is no reason to prefer either.
type FindingConflict struct {
	// Coordinate is the module the disagreeing records describe.
	Coordinate coordinate.ModuleCoordinate
	// ContentHashes name one record per distinct finding set, ordered by the set.
	ContentHashes []string
	// ScannedAt is when each of ContentHashes was scanned.
	ScannedAt []time.Time
	// Only lists, per entry of ContentHashes, the advisories that record reports
	// and another lacks.
	Only [][]string
	// members is every record of the disputed group, for the findings index,
	// which lists them all so a by-advisory read reaches the module.
	members []VulnerabilityRecord
}

// Error renders the conflict as a message naming the records and the read that
// lists them.
func (c FindingConflict) Error() string {
	parts := make([]string, 0, len(c.ContentHashes))
	for i, h := range c.ContentHashes {
		// The scan time is how a text --history row is matched to the record.
		rec := fmt.Sprintf("record %s (scanned %s)", h, recordstamp.Format(c.ScannedAt[i]))
		if len(c.Only[i]) == 0 {
			parts = append(parts, rec+" reports nothing another lacks")
			continue
		}
		parts = append(parts, fmt.Sprintf("%s reports %v, which another lacks", rec, c.Only[i]))
	}
	return fmt.Sprintf(
		"conflicting vulnerability records for %s: %d analysed records of one advisory snapshot, frame, toolchain and pipeline "+
			"report different advisories (%s). Neither supersedes the other, and no re-scan settles it: a re-scan appends a "+
			"record and these stay. Every record is listed by:\n  kanonarion vuln-show %s --history",
		c.Coordinate, len(c.ContentHashes), strings.Join(parts, "; "), c.Coordinate)
}

// Unwrap makes errors.Is(err, ErrVulnConflict) hold, which is how the CLI maps
// the refusal to its exit code.
func (c FindingConflict) Unwrap() error { return ErrVulnConflict }

// findFindingConflict reports the served record's group disagreeing on its
// finding-ID set, or nil.
//
// Only the served group is compared: a disagreement under an older snapshot is
// history the ladder already does not serve. A member must be analysed and
// report an advisory, as the served record must — a failed or unscannable scan
// makes no claim, and a bare all-clear is outranked by rung 1, not disputed.
// Completeness is not part of the group: it bears on reachability, not on which
// advisories match.
func findFindingConflict(records []VulnerabilityRecord) *FindingConflict {
	if len(records) < 2 {
		return nil
	}
	served := best(records)
	if !claimsFindings(served) {
		return nil
	}
	rep := map[string]VulnerabilityRecord{} // finding-ID set -> its best record
	ids := map[string][]string{}
	var members []VulnerabilityRecord
	for _, r := range records {
		if !claimsFindings(r) || !sameQuestion(r, served) {
			continue
		}
		members = append(members, r)
		set := findingIDs(r)
		key := strings.Join(set, "\x00")
		if cur, ok := rep[key]; !ok || servesBefore(r, cur) {
			rep[key], ids[key] = r, set
		}
	}
	if len(rep) < 2 {
		return nil
	}
	keys := make([]string, 0, len(rep))
	for k := range rep {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	common := map[string]int{}
	for _, k := range keys {
		for _, id := range ids[k] {
			common[id]++
		}
	}
	c := &FindingConflict{Coordinate: served.Coordinate, members: members}
	for _, k := range keys {
		var only []string
		for _, id := range ids[k] {
			if common[id] < len(keys) {
				only = append(only, id)
			}
		}
		c.ContentHashes = append(c.ContentHashes, rep[k].ContentHash)
		c.ScannedAt = append(c.ScannedAt, rep[k].ScannedAt)
		c.Only = append(c.Only, only)
	}
	return c
}

// claimsFindings reports whether a record is an analysis that reported an
// advisory, the only kind that can dispute another's finding set.
func claimsFindings(r VulnerabilityRecord) bool {
	coverage, findings := RecordAxes(r)
	return coverage == CoverageAnalysed && reportsAdvisory(findings)
}

// sameQuestion reports whether two records answer one question: one pipeline,
// advisory snapshot, frame and toolchain.
func sameQuestion(a, b VulnerabilityRecord) bool {
	return a.PipelineVersion == b.PipelineVersion &&
		sameSnapshot(a.DatabaseSnapshot, b.DatabaseSnapshot) &&
		RecordRooting(a) == RecordRooting(b) &&
		a.Toolchain == b.Toolchain
}

// findingIDs is the sorted, deduplicated set of advisory IDs a record reports.
func findingIDs(r VulnerabilityRecord) []string {
	seen := make(map[string]bool, len(r.Findings))
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		if !seen[f.ID] {
			seen[f.ID] = true
			out = append(out, f.ID)
		}
	}
	sort.Strings(out)
	return out
}

// compositionRefusal is the disagreement composition must not resolve by
// picking, or nil. Toolchains are checked first: two toolchains are two builds,
// and only within one build can two finding sets dispute each other.
func compositionRefusal(records []VulnerabilityRecord) error {
	if c := findToolchainConflict(records); c != nil {
		return *c
	}
	if c := findFindingConflict(records); c != nil {
		return *c
	}
	return nil
}

// IndexedAt returns the records whose findings the findings index of one frame
// lists: the one ComposeForIndex serves, or every member of a disputed group.
// Indexing the whole dispute is what lets a by-advisory read reach the module
// and refuse there, rather than answer "no modules affected".
func IndexedAt(records []VulnerabilityRecord, rooting Rooting) ([]VulnerabilityRecord, bool, error) {
	rec, ok, err := ComposeForIndex(records, rooting)
	if c, disputed := errors.AsType[FindingConflict](err); disputed {
		return c.members, true, nil
	}
	if !ok {
		return nil, false, err
	}
	return []VulnerabilityRecord{rec}, true, nil
}
