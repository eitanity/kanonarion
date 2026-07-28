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
	// Rooting is the analysis frame the row is filed under. The index is keyed on
	// it because an isolated record and a target-rooted one for the same
	// coordinate and snapshot are two answers, so a row is supported by the
	// composed record OF ITS OWN FRAME and by no other.
	Rooting domain.Rooting
	// Reason states which of the two failures this is: the record carries no such
	// finding, the record could not be decoded, or there is no record at all.
	Reason string
}

// String renders the defect as one line naming the row and why it is wrong.
func (d FindingsIndexDefect) String() string {
	return fmt.Sprintf("%s indexed against %s@%s (pipeline %s, snapshot %s@%s, rooting %s): %s",
		d.FindingID, d.ModulePath, d.ModuleVersion, d.PipelineVersion,
		d.Snapshot.Source, d.Snapshot.Version, d.Rooting, d.Reason)
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
// Since the record table became a ledger, "its record" is the COMPOSED record
// of the row's own frame rather than the single row a coordinate used to
// resolve to. A superseded generation that still carries the advisory is not
// support: the index has to agree with what a read returns, or vuln-by-id
// answers from a record no reader is served.
func (s *Store) CheckFindingsIndex(ctx context.Context) ([]FindingsIndexDefect, error) {
	const q = `
SELECT finding_id, module_path, module_version, pipeline_version,
       snapshot_source, snapshot_version, rooting
FROM vulnerability_findings_index
ORDER BY module_path, module_version, pipeline_version,
         snapshot_source, snapshot_version, rooting, finding_id`

	// The index rows are read to completion and the cursor closed BEFORE any
	// record is composed. The pool holds a single connection, so composing inside
	// the loop would issue a query against the connection this cursor is holding
	// and deadlock.
	type indexRow struct {
		findingID, path, version, pipeline, snapSource, snapVersion, rooting string
	}
	var indexRows []indexRow

	if err := func() error {
		rows, qerr := s.db.DB().QueryContext(ctx, q)
		if qerr != nil {
			return fmt.Errorf("querying findings index for consistency: %w", qerr)
		}
		defer func() {
			_ = rows.Close() //nolint:errcheck // rows.Err() checked below
		}()
		for rows.Next() {
			var r indexRow
			if serr := rows.Scan(&r.findingID, &r.path, &r.version, &r.pipeline,
				&r.snapSource, &r.snapVersion, &r.rooting); serr != nil {
				return fmt.Errorf("scanning findings index row: %w", serr)
			}
			indexRows = append(indexRows, r)
		}
		if rerr := rows.Err(); rerr != nil {
			return fmt.Errorf("iterating findings index rows: %w", rerr)
		}
		return nil
	}(); err != nil {
		return nil, err
	}

	// supported caches, per (key, frame), the identifier set the composed record
	// carries — or the reason there is none — so a module with many index rows
	// composes once rather than once per row.
	type support struct {
		ids    map[string]bool
		reason string
	}
	supported := make(map[string]support)

	var defects []FindingsIndexDefect
	for _, row := range indexRows {
		findingID, path, version := row.findingID, row.path, row.version
		pipeline, snapSource, snapVersion, rooting := row.pipeline, row.snapSource, row.snapVersion, row.rooting

		defect := FindingsIndexDefect{
			FindingID:       findingID,
			ModulePath:      path,
			ModuleVersion:   version,
			PipelineVersion: pipeline,
			Snapshot:        domain.DatabaseSnapshot{Source: snapSource, Version: snapVersion},
			Rooting:         domain.Rooting(rooting),
		}

		key := strings.Join([]string{path, version, pipeline, snapSource, snapVersion, rooting}, "\x00")
		sup, cached := supported[key]
		if !cached {
			sup.ids, sup.reason = s.composedFindingIDs(ctx, path, version, pipeline, snapSource, snapVersion, domain.Rooting(rooting))
			supported[key] = sup
		}
		switch {
		case sup.ids == nil:
			defect.Reason = sup.reason
			defects = append(defects, defect)
		case !sup.ids[findingID]:
			defect.Reason = reasonFindingAbsent
			defects = append(defects, defect)
		}
	}
	return defects, nil
}

// composedFindingIDs returns the identifiers the composed record of one key and
// frame carries, or nil plus the reason there is none.
//
// A generation that fails its content-hash check stops the whole answer rather
// than being skipped: decodeRecord verifies, so an unreadable generation is
// already reported by every read path, and treating it as agreement here would
// let the one check aimed at this defect class be the one that looks away.
func (s *Store) composedFindingIDs(
	ctx context.Context,
	path, version, pipeline, snapSource, snapVersion string,
	rooting domain.Rooting,
) (map[string]bool, string) {
	generations, err := s.listGenerations(ctx, s.db.DB(), path, version, pipeline, snapSource, snapVersion)
	if err != nil {
		return nil, reasonUndecodable
	}
	if len(generations) == 0 {
		return nil, reasonNoRecord
	}
	served, ok, cerr := domain.ComposeAt(generations, rooting)
	if cerr != nil || !ok {
		return nil, reasonNoRecord
	}
	return recordFindingIDs(served), ""
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
