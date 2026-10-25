package sqlite

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"
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
// Each row is the record vuln-show serves for the module in the index row's
// frame and pipeline, across every snapshot: unscoped, domain.ComposeForIndex;
// walk-scoped, the walk's own selection (servedInWalk). A module whose served
// record does not carry the advisory is not listed, so a row an older snapshot
// or an older toolchain left in the index answers nothing. The index is the
// lookup; the composition decides.
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
			return nil, ports.WalkNotScanned{WalkID: walkID}
		}
		groups, bad, err = s.byFindingInWalk(ctx, findingID, walkID)
	}
	if err != nil {
		return nil, err
	}
	carrying := make([]domain.VulnerabilityRecord, 0, len(groups))
	seen := map[servedQuestion]bool{}
	reads := map[servedQuestion]moduleRead{}
	for key, gens := range groups {
		for _, rec := range gens {
			q := servedQuestion{rec.Coordinate, rec.PipelineVersion, domain.RecordRooting(rec)}
			if walkID == "" {
				q.rooting = frames[key]
			}
			if seen[q] {
				continue
			}
			seen[q] = true
			served, ok, more, serr := s.servedFor(ctx, q, walkID, reads)
			bad = append(bad, more...)
			if serr != nil {
				return nil, serr
			}
			if ok && recordFindingIDs(served)[findingID] {
				carrying = append(carrying, served)
			}
		}
	}
	return onePerCoordinate(dedupeServed(carrying)), listingErr(dedupeRows(bad))
}

// ListCoordinatesByFindingID returns every module version the index lists for
// findingID, restricted to walkID's runs when set. Nothing is composed: a module
// whose served record no longer carries the advisory is still named, which is
// what a history read needs.
func (s *Store) ListCoordinatesByFindingID(ctx context.Context, findingID, walkID string) ([]coordinate.ModuleCoordinate, error) {
	q := `SELECT DISTINCT module_path, module_version FROM vulnerability_findings_index WHERE finding_id = ?`
	args := []any{findingID}
	if walkID != "" {
		known, kerr := s.walkHasScanRun(ctx, walkID)
		if kerr != nil {
			return nil, kerr
		}
		if !known {
			return nil, ports.WalkNotScanned{WalkID: walkID}
		}
		q = `
SELECT DISTINCT fi.module_path, fi.module_version
FROM vulnerability_findings_index fi
JOIN walk_scan_run_modules m
  ON m.module_path      = fi.module_path
 AND m.module_version   = fi.module_version
 AND m.pipeline_version = fi.pipeline_version
 AND m.snapshot_source  = fi.snapshot_source
 AND m.snapshot_version = fi.snapshot_version
JOIN walk_scan_runs wsr ON wsr.id = m.walk_scan_run_id
WHERE fi.finding_id = ? AND wsr.walk_id = ?`
		args = append(args, walkID)
	}
	rows, err := s.db.DB().QueryContext(ctx, q+` ORDER BY 1, 2`, args...)
	if err != nil {
		return nil, fmt.Errorf("querying modules indexed for %s: %w", findingID, err)
	}
	defer func() { _ = rows.Close() }()
	var out []coordinate.ModuleCoordinate
	for rows.Next() {
		var path, version string
		if serr := rows.Scan(&path, &version); serr != nil {
			return nil, fmt.Errorf("scanning modules indexed for %s: %w", findingID, serr)
		}
		c, cerr := coordinate.NewModuleCoordinate(path, version)
		if cerr != nil {
			return nil, fmt.Errorf("module indexed for %s: %w", findingID, cerr)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating modules indexed for %s: %w", findingID, err)
	}
	return out, nil
}

// servedQuestion is one module, pipeline and frame a by-advisory read asks
// vuln-show's question about.
type servedQuestion struct {
	coord    coordinate.ModuleCoordinate
	pipeline string
	rooting  domain.Rooting
}

// moduleRead is one module's generations at one pipeline and the rows that
// could not be read, kept so each frame of a module costs one read.
type moduleRead struct {
	recs []domain.VulnerabilityRecord
	bad  []ports.UnreadableRow
}

// servedFor is the record vuln-show serves for q across every snapshot: in the
// row's frame unscoped, and by the walk's own frame selection walk-scoped.
func (s *Store) servedFor(ctx context.Context, q servedQuestion, walkID string, reads map[servedQuestion]moduleRead) (domain.VulnerabilityRecord, bool, []ports.UnreadableRow, error) {
	key := servedQuestion{coord: q.coord, pipeline: q.pipeline}
	read, cached := reads[key]
	if !cached {
		var err error
		if walkID == "" {
			const stmt = `
SELECT serialised FROM vulnerability_records
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?
ORDER BY julianday(scanned_at) DESC, rowid DESC`
			read.recs, read.bad, err = s.queryRecordRows(ctx, "vulnerability records for module",
				selectedBy(q.coord.Path(), q.coord.Version(), filedAs{"pipeline_version", q.pipeline}), stmt,
				q.coord.Path(), q.coord.Version(), q.pipeline)
		} else {
			read.recs, read.bad, err = s.moduleInWalkRows(ctx, q.coord, q.pipeline, walkID)
		}
		if err != nil {
			return domain.VulnerabilityRecord{}, false, nil, err
		}
		reads[key] = read
	}
	recs, bad := read.recs, read.bad
	if walkID == "" {
		served, ok, cerr := domain.ComposeForIndex(recs, q.rooting)
		if cerr != nil {
			return domain.VulnerabilityRecord{}, false, bad, fmt.Errorf("composing the record vuln-show serves for %s: %w", q.coord, cerr)
		}
		return served, ok, bad, nil
	}
	served, _, _, ok, cerr := domain.ComposeInFrame(recs, walkFrame(recs, q.rooting))
	if cerr != nil {
		return domain.VulnerabilityRecord{}, false, bad, fmt.Errorf("composing the records walk %s holds for %s: %w", walkID, q.coord, cerr)
	}
	return served, ok, bad, nil
}

// walkFrame is the frame vuln-show --walk-id selects in: the one target-rooted
// frame the walk's records state, else the isolated frame. A walk whose records
// state several (a run that named no hash) is asked in the row's own frame.
func walkFrame(recs []domain.VulnerabilityRecord, row domain.Rooting) domain.Rooting {
	var target domain.Rooting
	for _, r := range recs {
		f := domain.RecordRooting(r)
		if !f.IsTargetRooted() || f == target {
			continue
		}
		if target != "" {
			return row
		}
		target = f
	}
	if target == "" {
		return domain.RootingIsolated
	}
	return target
}

// dedupeServed keeps one copy of each served record: two rows can name the same.
func dedupeServed(recs []domain.VulnerabilityRecord) []domain.VulnerabilityRecord {
	seen := map[string]bool{}
	out := recs[:0]
	for _, r := range recs {
		if !seen[r.ContentHash] {
			seen[r.ContentHash] = true
			out = append(out, r)
		}
	}
	return out
}

// dedupeRows keeps one report of each unreadable row, in a stable order: the
// index join and the module reads can both meet it.
func dedupeRows(rows []ports.UnreadableRow) []ports.UnreadableRow {
	byKey := map[string]ports.UnreadableRow{}
	for _, r := range rows {
		byKey[r.ID+"\x00"+r.ContentHash] = r
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]ports.UnreadableRow, 0, len(keys))
	for _, k := range keys {
		out = append(out, byKey[k])
	}
	return out
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
		rec, unreadable := recordRow(serialised, selectedBy(k[0], k[1],
			filedAs{"pipeline_version", k[2]}, filedAs{"snapshot_source", k[3]},
			filedAs{"snapshot_version", k[4]}, filedAs{"rooting", k[5]}))
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
SELECT DISTINCT vr.serialised, vr.rowid, vr.module_path, vr.module_version, vr.pipeline_version,
       vr.snapshot_source, vr.snapshot_version, vr.rooting
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
			k          [6]string
		)
		if err := rows.Scan(&serialised, &rowID, &k[0], &k[1], &k[2], &k[3], &k[4], &k[5]); err != nil {
			return nil, nil, fmt.Errorf("scanning vulnerability record: %w", err)
		}
		rec, unreadable := recordRow(serialised, selectedBy(k[0], k[1],
			filedAs{"pipeline_version", k[2]}, filedAs{"snapshot_source", k[3]},
			filedAs{"snapshot_version", k[4]}, filedAs{"rooting", k[5]}))
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

// reportsAdvisoryOrWithdrawal is the first ranking tier: Affected, Withdrawn and
// Inconclusive, each of which reports a matched advisory.
func reportsAdvisoryOrWithdrawal(f domain.RecordFindingsStatus) bool {
	return f == domain.FindingsRecordAffected || f == domain.FindingsRecordWithdrawn || f == domain.FindingsRecordInconclusive
}
