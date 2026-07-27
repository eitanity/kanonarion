package sqlite

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// FindingsIndexDefect names one vulnerability_findings_index row that the
// record it keys on does not support.
//
// The index exists so vuln-by-id can answer "which of my modules is affected by
// this advisory" without decoding every record. That makes an unsupported row a
// false positive on a security question, produced by the store rather than by
// the scanner — and one no content-hash check can catch, because the record it
// contradicts is internally valid and correctly sealed.
type FindingsIndexDefect struct {
	// FindingID is the advisory identifier the index row claims.
	FindingID string
	// ModulePath, ModuleVersion, PipelineVersion and Snapshot are the record key
	// the row points at — the same tuple PutVulnerabilityRecord reconciles on.
	//
	// The module is held as the two raw columns rather than as a
	// coordinate.ModuleCoordinate because this is a report about rows that are
	// already wrong: a key that no longer parses as a coordinate (the stdlib
	// pseudo-module's empty version, or a row written before a validation rule
	// existed) is precisely the kind of row worth naming, and constructing a
	// coordinate would fail on it instead of reporting it.
	ModulePath      string
	ModuleVersion   string
	PipelineVersion string
	Snapshot        domain.DatabaseSnapshot
	// Reason states which of the two failures this is: the record carries no such
	// finding, the record could not be decoded, or there is no record at all.
	Reason string
}

// String renders the defect as one line naming the row and why it is wrong.
func (d FindingsIndexDefect) String() string {
	return fmt.Sprintf("%s indexed against %s@%s (pipeline %s, snapshot %s@%s): %s",
		d.FindingID, d.ModulePath, d.ModuleVersion, d.PipelineVersion,
		d.Snapshot.Source, d.Snapshot.Version, d.Reason)
}

// Reasons a findings-index row fails to be supported by its record.
const (
	reasonFindingAbsent = "the record does not carry this finding"
	reasonNoRecord      = "no vulnerability record exists for this key"
	reasonUndecodable   = "the record could not be decoded"
)

// CheckFindingsIndex reports every findings-index row whose record does not
// support it, most-specific key order, and nil when the index is consistent.
//
// This is the check that the write path's index reconciliation exists to keep
// passing. It is deliberately a whole-table sweep rather than a per-record one:
// the defect it catches is a row that survived a write it was not part of, so
// it can only be found by asking the index what it claims and the records
// whether they agree — never by re-reading the record that was just written.
//
// A row whose record is absent entirely counts as a defect on the same terms as
// one whose record disagrees. Both put a module into an advisory's answer on
// the strength of evidence that is not there.
func (s *Store) CheckFindingsIndex(ctx context.Context) ([]FindingsIndexDefect, error) {
	// LEFT JOIN, not JOIN: an index row with no record at all is a defect this
	// check must report, and an inner join would silently drop exactly those.
	const q = `
SELECT fi.finding_id, fi.module_path, fi.module_version, fi.pipeline_version,
       fi.snapshot_source, fi.snapshot_version, vr.serialised
FROM vulnerability_findings_index fi
LEFT JOIN vulnerability_records vr
    ON vr.module_path      = fi.module_path
   AND vr.module_version   = fi.module_version
   AND vr.pipeline_version = fi.pipeline_version
   AND vr.snapshot_source  = fi.snapshot_source
   AND vr.snapshot_version = fi.snapshot_version
ORDER BY fi.module_path, fi.module_version, fi.pipeline_version,
         fi.snapshot_source, fi.snapshot_version, fi.finding_id`

	rows, err := s.db.DB().QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("querying findings index for consistency: %w", err)
	}
	defer func() { _ = rows.Close() }()

	// supported caches the identifier set of each record so a module with many
	// index rows decodes its record once rather than once per row.
	supported := make(map[string]map[string]bool)

	var defects []FindingsIndexDefect
	for rows.Next() {
		var findingID, path, version, pipeline, snapSource, snapVersion string
		var serialised []byte
		if err := rows.Scan(&findingID, &path, &version, &pipeline,
			&snapSource, &snapVersion, &serialised); err != nil {
			return nil, fmt.Errorf("scanning findings index row: %w", err)
		}

		defect := FindingsIndexDefect{
			FindingID:       findingID,
			ModulePath:      path,
			ModuleVersion:   version,
			PipelineVersion: pipeline,
			Snapshot:        domain.DatabaseSnapshot{Source: snapSource, Version: snapVersion},
		}

		if serialised == nil {
			defect.Reason = reasonNoRecord
			defects = append(defects, defect)
			continue
		}

		key := strings.Join([]string{path, version, pipeline, snapSource, snapVersion}, "\x00")
		ids, cached := supported[key]
		if !cached {
			// decodeRecord verifies the content hash, so a record that fails here is
			// already reported by every read path; the index sweep names it too
			// rather than treating an unreadable record as agreement.
			rec, derr := decodeRecord(serialised)
			if derr != nil {
				supported[key] = nil
			} else {
				ids = recordFindingIDs(rec)
				supported[key] = ids
			}
			ids = supported[key]
		}
		switch {
		case ids == nil:
			defect.Reason = reasonUndecodable
		case !ids[findingID]:
			defect.Reason = reasonFindingAbsent
		default:
			continue
		}
		defects = append(defects, defect)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating findings index rows: %w", err)
	}
	return defects, nil
}

// recordFindingIDs returns every identifier the record's findings can legally be
// indexed under: each finding's own ID plus its aliases, which is exactly the
// set PutVulnerabilityRecord inserts. A non-empty map is always returned for a
// decodable record so the caller can tell "no findings" from "could not decode".
func recordFindingIDs(rec domain.VulnerabilityRecord) map[string]bool {
	ids := make(map[string]bool)
	for _, f := range rec.Findings {
		ids[f.ID] = true
		for _, alias := range f.Aliases {
			ids[alias] = true
		}
	}
	return ids
}

// FindingsIndexDefectsError renders defects as a single error naming each one,
// for callers that want the check to fail rather than to enumerate. It returns
// nil for an empty slice so it can wrap a CheckFindingsIndex result directly.
func FindingsIndexDefectsError(defects []FindingsIndexDefect) error {
	if len(defects) == 0 {
		return nil
	}
	lines := make([]string, 0, len(defects))
	for _, d := range defects {
		lines = append(lines, d.String())
	}
	sort.Strings(lines)
	return fmt.Errorf("findings index disagrees with %d record(s):\n  %s",
		len(defects), strings.Join(lines, "\n  "))
}
