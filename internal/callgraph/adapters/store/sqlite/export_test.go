package sqlite

import (
	"context"
	"fmt"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// BackfillCompletenessForTest runs migration 9's Go step against an already-open
// store, so the back-fill can be exercised directly rather than only through a
// migration that has already been applied by the time a test store opens.
func (s *Store) BackfillCompletenessForTest(ctx context.Context) error {
	tx, err := s.db.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }() //nolint:errcheck
	if err := backfillCompleteness(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing: %w", err)
	}
	return nil
}

// RetireSyntheticLocalRecordsForTest runs migration 10's Go step against an
// already-open store, so the retirement can be exercised directly rather than
// only through a migration that has already been applied by the time a test store
// opens.
func (s *Store) RetireSyntheticLocalRecordsForTest(ctx context.Context) error {
	tx, err := s.db.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }() //nolint:errcheck
	if err := retireSyntheticLocalRecords(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing: %w", err)
	}
	return nil
}

// SeedPreFieldRowForTest inserts a record the way a build that predates the
// write-leg guards would have, so a migration test can meet a row exactly as it
// exists in an upgraded store. It bypasses PutCallGraphRecord's refusals on
// purpose: those guards are what the stranded rows predate.
func (s *Store) SeedPreFieldRowForTest(ctx context.Context, r domain2.CallGraphRecord) error {
	var h domain2.CallGraphRecordHasher
	rBlob := r
	rBlob.Edges = nil
	raw, err := h.Marshal(rBlob)
	if err != nil {
		return fmt.Errorf("marshalling: %w", err)
	}
	if _, err := s.db.DB().ExecContext(ctx, `
INSERT INTO callgraph_records (module_path, module_version, pipeline_version, algorithm,
    overall_status, completeness, analysis_source, worktree_digest, node_count, edge_count,
    extracted_at, content_hash, serialised)
VALUES (?,?,?,?,?,?,'','',?,?,?,?,?)`,
		r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion, string(r.Algorithm),
		int(r.OverallStatus), string(r.Completeness), r.NodeCount, r.EdgeCount,
		r.ExtractedAt.UTC().Format(time.RFC3339), r.ContentHash, blobcodec.Encode(raw),
	); err != nil {
		return fmt.Errorf("seeding record: %w", err)
	}
	for _, e := range r.Edges {
		if _, err := s.db.DB().ExecContext(ctx, `
INSERT OR IGNORE INTO callgraph_edges (record_content_hash, from_module, from_version,
    pipeline_version, from_id, to_id, confidence, call_site_file, call_site_line,
    reflect_dispatch, is_test)
VALUES (?,?,?,?,?,?,?,?,?,0,0)`,
			r.ContentHash, r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion,
			e.FromID, e.ToID, string(e.Confidence), e.CallSite.File, e.CallSite.Line,
		); err != nil {
			return fmt.Errorf("seeding edge: %w", err)
		}
	}
	return nil
}
