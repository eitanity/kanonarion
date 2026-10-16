package sqlite

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/versionorder"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// ListVulnerabilityRecordsByFindingID returns one vulnerability record per
// module version that contains a finding with the given identifier.
//
// A coordinate accumulates a record per (pipeline version, snapshot) it was ever
// scanned under, and those generations disagree — the same module version is
// Affected under one snapshot and Clean under another. Reporting every
// generation gives the reader rows they cannot rank; reporting only the newest
// would let a later Clean quietly retire an earlier finding.
//
// The tie-break is therefore the finding, not the clock: a record that reports
// the module as Affected outranks one that does not, and only among equals does
// the newest scan win.
//
// Clean is the right label for a module where the advisory was never found. It
// is not a label a finding may quietly decay into: once a finding exists,
// turning it into anything else needs a stated reason — the advisory was
// withdrawn, the module moved out of the affected range, the reachability
// verdict was corrected. The store has no way to record such a reason yet, so
// this ranking is a guard rather than a model: it keeps an unexplained Clean
// from displacing a finding until reasoned transitions exist.
//
// The guard is not hypothetical. In a working store, seven (advisory, module,
// snapshot) triples — identical inputs, no new evidence — were reported Clean by
// exactly one pipeline generation and Affected by every other. Ranking by
// recency alone would have let that generation retract seven real findings.
//
// Superseded generations are not lost — vuln-show --history exists to show them,
// and does.
//
// An empty walkID answers across the store. When walkID is set the answer is
// restricted to the modules a scan run of that walk covered, and "most recent"
// is taken within that walk.
//
// The walk constraint goes through walk_scan_run_modules rather than the
// walk_id column on vulnerability_records: since schema v5 that column is
// provenance for the last walk that triggered the scan, so a record shared by
// two walks names only one of them and filtering on it would drop the other
// walk's module. ListVulnerabilityRecordsForModuleInWalk takes the same route.
//
// Each row is the generation the index row describes and never a sibling at its
// key: unscoped, the record the index was composed from (domain.ComposeForIndex);
// walk-scoped, the generation the walk's run named. Either way a record that
// does not carry the advisory is not listed, so after a Go upgrade the older
// toolchain's record is not reported for an advisory only the newer one found.
//
// An unknown walkID is an error rather than an empty result: "no modules are
// affected by this CVE" is the wrong answer to give for a walk that was never
// scanned.
func (s *Store) ListVulnerabilityRecordsByFindingID(ctx context.Context, findingID, walkID string) ([]domain.VulnerabilityRecord, error) {
	var (
		groups map[string][]domain.VulnerabilityRecord
		frames map[string]domain.Rooting
		bad    []ports.UnreadableRow
		err    error
	)
	if walkID == "" {
		groups, frames, bad, err = s.byFindingGenerations(ctx, findingID)
	} else {
		known, kerr := s.walkHasScanRun(ctx, walkID)
		if kerr != nil {
			return nil, kerr
		}
		if !known {
			return nil, fmt.Errorf("no vulnerability scan run for walk %s — run: kanonarion vuln-scan %s", walkID, walkID)
		}
		groups, bad, err = s.byFindingInWalk(ctx, findingID, walkID)
	}
	if err != nil {
		return nil, err
	}
	carrying := make([]domain.VulnerabilityRecord, 0, len(groups))
	for key, gens := range groups {
		if walkID == "" {
			served, ok, cerr := domain.ComposeForIndex(gens, frames[key])
			if cerr != nil {
				return nil, fmt.Errorf("composing the record the finding index describes: %w", cerr)
			}
			if !ok {
				continue
			}
			gens = []domain.VulnerabilityRecord{served}
		}
		for _, rec := range gens {
			if recordFindingIDs(rec)[findingID] {
				carrying = append(carrying, rec)
			}
		}
	}
	return onePerCoordinate(carrying), listingErr(bad)
}

// byFindingGenerations returns, per index row's key and frame, every readable
// generation at that key in that frame, and the frame itself.
func (s *Store) byFindingGenerations(ctx context.Context, findingID string) (
	map[string][]domain.VulnerabilityRecord, map[string]domain.Rooting, []ports.UnreadableRow, error,
) {
	// The index carries the analysis frame, so the join carries it too: an index
	// row an isolated scan wrote must not attach to a target-rooted record.
	const q = `
SELECT vr.serialised, fi.module_path, fi.module_version, fi.pipeline_version,
       fi.snapshot_source, fi.snapshot_version, fi.rooting
FROM vulnerability_findings_index fi
JOIN vulnerability_records vr
  ON vr.module_path      = fi.module_path
 AND vr.module_version   = fi.module_version
 AND vr.pipeline_version = fi.pipeline_version
 AND vr.snapshot_source  = fi.snapshot_source
 AND vr.snapshot_version = fi.snapshot_version
 AND vr.rooting          = fi.rooting
WHERE fi.finding_id = ?
ORDER BY julianday(vr.scanned_at) ASC, vr.rowid ASC`
	rows, err := s.db.DB().QueryContext(ctx, q, findingID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("querying records by finding id: %w", err)
	}
	defer func() { _ = rows.Close() }()

	groups := map[string][]domain.VulnerabilityRecord{}
	frames := map[string]domain.Rooting{}
	var bad []ports.UnreadableRow
	for rows.Next() {
		var (
			serialised []byte
			k          [6]string
		)
		if err := rows.Scan(&serialised, &k[0], &k[1], &k[2], &k[3], &k[4], &k[5]); err != nil {
			return nil, nil, nil, fmt.Errorf("scanning vulnerability record: %w", err)
		}
		key := strings.Join(k[:], "\x00")
		frames[key] = domain.Rooting(k[5])
		rec, unreadable := recordRow(serialised)
		if unreadable != nil {
			bad = append(bad, *unreadable)
			continue
		}
		groups[key] = append(groups[key], rec)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("iterating vulnerability records: %w", err)
	}
	return groups, frames, bad, nil
}

// byFindingInWalk returns the generations a walk's scan runs named whose key
// the index lists for the finding, one group per record.
func (s *Store) byFindingInWalk(ctx context.Context, findingID, walkID string) (
	map[string][]domain.VulnerabilityRecord, []ports.UnreadableRow, error,
) {
	// DISTINCT absorbs the duplicate rows a walk with several runs over one
	// module produces. A run that named no hash reaches every generation of
	// its key, as in ListVulnerabilityRecordsForModuleInWalk.
	const q = `
SELECT DISTINCT vr.serialised, vr.rowid
FROM vulnerability_records vr
JOIN vulnerability_findings_index fi
  ON fi.module_path      = vr.module_path
 AND fi.module_version   = vr.module_version
 AND fi.pipeline_version = vr.pipeline_version
 AND fi.snapshot_source  = vr.snapshot_source
 AND fi.snapshot_version = vr.snapshot_version
 AND fi.rooting          = vr.rooting
JOIN walk_scan_run_modules m
  ON m.module_path      = vr.module_path
 AND m.module_version   = vr.module_version
 AND m.pipeline_version = vr.pipeline_version
 AND m.snapshot_source  = vr.snapshot_source
 AND m.snapshot_version = vr.snapshot_version
 AND (m.record_content_hash = '' OR m.record_content_hash = vr.content_hash)
JOIN walk_scan_runs wsr ON wsr.id = m.walk_scan_run_id
WHERE fi.finding_id = ? AND wsr.walk_id = ?`
	rows, err := s.db.DB().QueryContext(ctx, q, findingID, walkID)
	if err != nil {
		return nil, nil, fmt.Errorf("querying records by finding id in walk %s: %w", walkID, err)
	}
	defer func() { _ = rows.Close() }()

	groups := map[string][]domain.VulnerabilityRecord{}
	var bad []ports.UnreadableRow
	for rows.Next() {
		var (
			serialised []byte
			rowID      int64
		)
		if err := rows.Scan(&serialised, &rowID); err != nil {
			return nil, nil, fmt.Errorf("scanning vulnerability record: %w", err)
		}
		rec, unreadable := recordRow(serialised)
		if unreadable != nil {
			bad = append(bad, *unreadable)
			continue
		}
		groups[fmt.Sprint(rowID)] = []domain.VulnerabilityRecord{rec}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterating vulnerability records: %w", err)
	}
	return groups, bad, nil
}

// onePerCoordinate keeps one record per module version, by byFindingRanksBefore,
// newest scan first.
func onePerCoordinate(recs []domain.VulnerabilityRecord) []domain.VulnerabilityRecord {
	best := map[string]domain.VulnerabilityRecord{}
	for _, r := range recs {
		k := r.Coordinate.Path() + "@" + r.Coordinate.Version()
		if cur, ok := best[k]; !ok || byFindingRanksBefore(r, cur) {
			best[k] = r
		}
	}
	out := make([]domain.VulnerabilityRecord, 0, len(best))
	for _, r := range best {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ScannedAt.Equal(out[j].ScannedAt) {
			return out[i].ScannedAt.After(out[j].ScannedAt)
		}
		return out[i].Coordinate.String() < out[j].Coordinate.String()
	})
	return out
}

// byFindingRanksBefore ranks two records for one coordinate: one reporting the
// advisory (Affected or Withdrawn) first, so a later all-clear cannot retire a
// finding and a newer retraction still supersedes; then an analysed verdict, so a
// failed scan never outranks a real all-clear; then the newest scan; then the
// newest pipeline, read numerically. The pipeline is a tie-break, never a filter:
// a stale answer labelled with its generation is a fact, a missing one a false
// all-clear.
func byFindingRanksBefore(a, b domain.VulnerabilityRecord) bool {
	ac, af := domain.RecordAxes(a)
	bc, bf := domain.RecordAxes(b)
	if x, y := reportsAdvisoryOrWithdrawal(af), reportsAdvisoryOrWithdrawal(bf); x != y {
		return x
	}
	if x, y := ac == domain.CoverageAnalysed, bc == domain.CoverageAnalysed; x != y {
		return x
	}
	if !a.ScannedAt.Equal(b.ScannedAt) {
		return a.ScannedAt.After(b.ScannedAt)
	}
	if c := versionorder.ComparePipelineVersions(a.PipelineVersion, b.PipelineVersion); c != 0 {
		return c > 0
	}
	return a.ContentHash < b.ContentHash
}

// reportsAdvisoryOrWithdrawal is the first ranking tier: Affected and Withdrawn.
func reportsAdvisoryOrWithdrawal(f domain.RecordFindingsStatus) bool {
	return f == domain.FindingsRecordAffected || f == domain.FindingsRecordWithdrawn
}
