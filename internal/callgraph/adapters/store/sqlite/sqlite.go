// Package sqlite implements ports.CallGraphStore using a SQLite database via
// modernc.org/sqlite (pure Go, no CGO).
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

// Store is the SQLite-backed call graph store.
type Store struct {
	db sqlitestore.DB
}

// New returns a new Store using the provided database handle.
func New(db sqlitestore.DB) *Store {
	return &Store{db: db}
}

// Migrations returns the schema migrations for the callgraph module.
func Migrations() []sqlitestore.Migration {
	return []sqlitestore.Migration{
		{Module: "callgraph", Version: 1, SQL: `CREATE TABLE IF NOT EXISTS callgraph_records (
            module_path        TEXT NOT NULL,
            module_version     TEXT NOT NULL,
            pipeline_version   TEXT NOT NULL,
            algorithm          TEXT NOT NULL,
            overall_status     INTEGER NOT NULL,
            node_count         INTEGER NOT NULL,
            edge_count         INTEGER NOT NULL,
            extracted_at       TEXT NOT NULL,
            content_hash       TEXT NOT NULL,
            serialised         BLOB NOT NULL,
            PRIMARY KEY (module_path, module_version, pipeline_version)
        );
        CREATE TABLE IF NOT EXISTS callgraph_edges (
            from_module        TEXT NOT NULL,
            from_version       TEXT NOT NULL,
            pipeline_version   TEXT NOT NULL,
            from_id            TEXT NOT NULL,
            to_id              TEXT NOT NULL,
            confidence         TEXT NOT NULL,
            PRIMARY KEY (from_module, from_version, pipeline_version, from_id, to_id)
        );
        CREATE INDEX IF NOT EXISTS callgraph_edges_to_idx
            ON callgraph_edges(to_id, pipeline_version)`},
		{Module: "callgraph", Version: 2, SQL: `CREATE INDEX IF NOT EXISTS callgraph_edges_from_idx
            ON callgraph_edges(from_id, pipeline_version)`},
		// Migration v3: add call_site_file and call_site_line to callgraph_edges so
		// edges can be fully reconstructed from the table (enabling the v2 blob format
		// that omits edges from the serialised column). Existing rows are migrated with
		// default empty/0 call-site values; they remain readable via the v1 blob path.
		{Module: "callgraph", Version: 3, SQL: `
CREATE TABLE callgraph_edges_v3 (
    from_module      TEXT    NOT NULL,
    from_version     TEXT    NOT NULL,
    pipeline_version TEXT    NOT NULL,
    from_id          TEXT    NOT NULL,
    to_id            TEXT    NOT NULL,
    confidence       TEXT    NOT NULL,
    call_site_file   TEXT    NOT NULL DEFAULT '',
    call_site_line   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (from_module, from_version, pipeline_version, from_id, to_id, call_site_file, call_site_line)
);
INSERT INTO callgraph_edges_v3 (from_module, from_version, pipeline_version, from_id, to_id, confidence)
    SELECT from_module, from_version, pipeline_version, from_id, to_id, confidence FROM callgraph_edges;
DROP TABLE callgraph_edges;
ALTER TABLE callgraph_edges_v3 RENAME TO callgraph_edges;
CREATE INDEX IF NOT EXISTS callgraph_edges_to_idx   ON callgraph_edges(to_id, pipeline_version);
CREATE INDEX IF NOT EXISTS callgraph_edges_from_idx ON callgraph_edges(from_id, pipeline_version)`},
		// Migration v4: the ecosystem field joined the canonical hash and bumped
		// the schema version, so every pre-existing blob carries a stale hash and
		// no ecosystem field — unreadable under the new schema. Purge the legacy
		// rows; they are regenerable by re-extracting.
		{Module: "callgraph", Version: 4, SQL: `DELETE FROM callgraph_records;
DELETE FROM callgraph_edges`},
		// Migration v5: per-node body-level facts (uses_unsafe_pointer,
		// is_assembly_or_linkname) joined the canonical node schema and bumped the
		// schema version. Pre-existing blobs lack these fields, so capability
		// analysis would silently under-report UNSAFE_POINTER and
		// ARBITRARY_EXECUTION over them. Purge the legacy rows; re-extraction
		// repopulates them with the new facts.
		{Module: "callgraph", Version: 5, SQL: `DELETE FROM callgraph_records;
DELETE FROM callgraph_edges`},
	}
}

// Open opens (or creates) the SQLite database at dsn and runs migrations.
// Use ":memory:" for tests.
func Open(dsn string) (*Store, error) {
	db, err := sqlitestore.Open(dsn, Migrations())
	if err != nil {
		return nil, fmt.Errorf("opening callgraph store: %w", err)
	}
	return &Store{db: db}, nil
}

// InternalDB returns the underlying sqlite.DB for testing purposes.
func (s *Store) InternalDB() sqlitestore.DB {
	return s.db
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("closing callgraph store: %w", err)
	}
	return nil
}

// PutCallGraphRecord inserts or replaces a call graph record. Idempotent on
// (module_path, module_version, pipeline_version).
//
// The serialised blob stores the full record minus the Edges slice; edges are
// stored separately in callgraph_edges so that GetCallGraphRecord can
// reconstruct the record without a second full parse of a large blob.
func (s *Store) PutCallGraphRecord(ctx context.Context, r domain2.CallGraphRecord) error {
	var h domain2.CallGraphRecordHasher
	if err := h.VerifyContentHash(r); err != nil {
		return fmt.Errorf("verifying content hash before put: %w", err)
	}

	// Store the record without the Edges slice to avoid duplicating data that
	// lives in callgraph_edges. The hash was computed over the full record, so
	// GetCallGraphRecord must reconstruct edges from the table before verifying.
	rBlob := r
	rBlob.Edges = nil
	raw, err := h.Marshal(rBlob)
	if err != nil {
		return fmt.Errorf("marshalling callgraph record: %w", err)
	}
	blob := blobcodec.Encode(raw)

	tx, err := s.db.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback() //nolint:errcheck
	}()

	const qRecord = `
INSERT INTO callgraph_records (
    module_path, module_version, pipeline_version,
    algorithm, overall_status, node_count, edge_count,
    extracted_at, content_hash, serialised
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (module_path, module_version, pipeline_version) DO UPDATE SET
    algorithm      = excluded.algorithm,
    overall_status = excluded.overall_status,
    node_count     = excluded.node_count,
    edge_count     = excluded.edge_count,
    extracted_at   = excluded.extracted_at,
    content_hash   = excluded.content_hash,
    serialised     = excluded.serialised`

	_, err = tx.ExecContext(ctx, qRecord,
		r.Coordinate.Path, r.Coordinate.Version, r.PipelineVersion,
		string(r.Algorithm), int(r.OverallStatus),
		r.NodeCount, r.EdgeCount,
		r.ExtractedAt.UTC().Format(time.RFC3339),
		r.ContentHash, blob,
	)
	if err != nil {
		return fmt.Errorf("inserting callgraph record: %w", err)
	}

	const qDel = `DELETE FROM callgraph_edges
	WHERE from_module = ? AND from_version = ? AND pipeline_version = ?`
	if _, err := tx.ExecContext(ctx, qDel, r.Coordinate.Path, r.Coordinate.Version, r.PipelineVersion); err != nil {
		return fmt.Errorf("deleting old callgraph edges: %w", err)
	}

	const qEdge = `
INSERT OR IGNORE INTO callgraph_edges (
    from_module, from_version, pipeline_version,
    from_id, to_id, confidence,
    call_site_file, call_site_line
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	stmtEdge, err := tx.PrepareContext(ctx, qEdge)
	if err != nil {
		return fmt.Errorf("preparing callgraph edge statement: %w", err)
	}
	defer func() { _ = stmtEdge.Close() }()

	for _, e := range r.Edges {
		if _, err := stmtEdge.ExecContext(ctx,
			r.Coordinate.Path, r.Coordinate.Version, r.PipelineVersion,
			e.FromID, e.ToID, string(e.Confidence),
			e.CallSite.File, e.CallSite.Line,
		); err != nil {
			return fmt.Errorf("inserting callgraph edge %s→%s: %w", e.FromID, e.ToID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing callgraph record: %w", err)
	}
	_, _ = s.db.DB().ExecContext(ctx, `PRAGMA optimize`) //nolint:errcheck
	return nil
}

// GetCallGraphRecord retrieves and tamper-checks the call graph record.
// Returns (zero, false, nil) if not found.
// Returns (zero, false, ErrCallGraphIntegrity) on hash mismatch.
func (s *Store) GetCallGraphRecord(ctx context.Context, coord fetchdomain.ModuleCoordinate, pipelineVersion string) (domain2.CallGraphRecord, bool, error) {
	const q = `SELECT serialised, content_hash FROM callgraph_records
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?`

	row := s.db.DB().QueryRowContext(ctx, q, coord.Path, coord.Version, pipelineVersion)
	var blob []byte
	var storedHash string
	if err := row.Scan(&blob, &storedHash); errors.Is(err, sql.ErrNoRows) {
		return domain2.CallGraphRecord{}, false, nil
	} else if err != nil {
		return domain2.CallGraphRecord{}, false, fmt.Errorf("querying callgraph record: %w", err)
	}

	blob, decErr := blobcodec.Decode(blob)
	if decErr != nil {
		return domain2.CallGraphRecord{}, false, fmt.Errorf("decompressing callgraph record: %w", decErr)
	}

	var h domain2.CallGraphRecordHasher
	rec, err := h.Unmarshal(blob)
	if err != nil {
		return domain2.CallGraphRecord{}, false, fmt.Errorf("unmarshalling callgraph record: %w", err)
	}

	switch rec.SchemaVersion {
	case "1":
		// v1 blobs contain edges; verify via the fast in-place blob hash.
		if verr := h.VerifyBlobHash(blob, storedHash); verr != nil {
			return domain2.CallGraphRecord{}, false, fmt.Errorf("%w: %w", ports.ErrCallGraphIntegrity, verr)
		}
		return rec, true, nil
	default:
		// v2+ blobs omit edges; reconstruct them from callgraph_edges and
		// verify the hash over the full reconstructed record.
		if rec.ContentHash != storedHash {
			return domain2.CallGraphRecord{}, false, fmt.Errorf("%w: embedded hash %q does not match stored %q",
				ports.ErrCallGraphIntegrity, rec.ContentHash, storedHash)
		}
		edges, fetchErr := s.fetchEdges(ctx, coord, pipelineVersion)
		if fetchErr != nil {
			return domain2.CallGraphRecord{}, false, fetchErr
		}
		rec.Edges = edges
		if verr := h.VerifyContentHash(rec); verr != nil {
			return domain2.CallGraphRecord{}, false, fmt.Errorf("%w: %w", ports.ErrCallGraphIntegrity, verr)
		}
		return rec, true, nil
	}
}

// fetchEdges queries callgraph_edges for all edges belonging to a record,
// returning them in canonical sort order (from_id, to_id, call_site_file, call_site_line).
func (s *Store) fetchEdges(ctx context.Context, coord fetchdomain.ModuleCoordinate, pipelineVersion string) ([]domain2.CallEdge, error) {
	const q = `SELECT from_id, to_id, confidence, call_site_file, call_site_line
	    FROM callgraph_edges
	    WHERE from_module = ? AND from_version = ? AND pipeline_version = ?
	    ORDER BY from_id, to_id, call_site_file, call_site_line`

	rows, err := s.db.DB().QueryContext(ctx, q, coord.Path, coord.Version, pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("fetching callgraph edges: %w", err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck
	}()

	var edges []domain2.CallEdge
	for rows.Next() {
		var e domain2.CallEdge
		var conf string
		if serr := rows.Scan(&e.FromID, &e.ToID, &conf, &e.CallSite.File, &e.CallSite.Line); serr != nil {
			return nil, fmt.Errorf("scanning callgraph edge: %w", serr)
		}
		e.Confidence = domain2.EdgeConfidence(conf)
		edges = append(edges, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating callgraph edges: %w", err)
	}
	return edges, nil
}

// ListCallGraphRecords returns summaries matching the filter, ordered by
// extracted_at descending.
func (s *Store) ListCallGraphRecords(ctx context.Context, filter ports.CallGraphFilter) ([]ports.CallGraphSummary, error) {
	q := `SELECT module_path, module_version, pipeline_version,
	             algorithm, overall_status, node_count, edge_count,
	             extracted_at, content_hash
	      FROM callgraph_records`
	var args []any
	var where []string

	if filter.ModulePath != "" {
		where = append(where, "module_path = ?")
		args = append(args, filter.ModulePath)
	}
	if filter.PipelineVersion != "" {
		where = append(where, "pipeline_version = ?")
		args = append(args, filter.PipelineVersion)
	}

	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}

	q += " ORDER BY extracted_at DESC"

	if filter.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, filter.Limit)
		if filter.Offset > 0 {
			q += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	} else if filter.Offset > 0 {
		// SQLite requires LIMIT when using OFFSET; -1 means unlimited.
		q += " LIMIT -1 OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.DB().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing callgraph records: %w", err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck
	}()

	var out []ports.CallGraphSummary
	for rows.Next() {
		var sum ports.CallGraphSummary
		var extractedAt string
		var status int
		var algo string
		if serr := rows.Scan(
			&sum.ModulePath, &sum.ModuleVersion, &sum.PipelineVersion,
			&algo, &status, &sum.NodeCount, &sum.EdgeCount,
			&extractedAt, &sum.ContentHash,
		); serr != nil {
			return nil, fmt.Errorf("scanning callgraph summary: %w", serr)
		}
		t, perr := time.Parse(time.RFC3339, extractedAt)
		if perr != nil {
			return nil, fmt.Errorf("parsing extracted_at %q: %w", extractedAt, perr)
		}
		sum.ExtractedAt = t.UTC()
		sum.OverallStatus = domain2.CallGraphStatus(status)
		sum.Algorithm = domain2.CallGraphAlgorithm(algo)
		out = append(out, sum)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating callgraph summaries: %w", err)
	}
	return out, nil
}

// FindCallers returns all edges where the callee matches symbolID.
func (s *Store) FindCallers(ctx context.Context, symbolID string, pipelineVersion string) ([]ports.CallEdgeRef, error) {
	const q = `SELECT DISTINCT from_module, from_version, pipeline_version,
	                   from_id, to_id, confidence
	            FROM callgraph_edges
	            WHERE to_id = ? AND pipeline_version = ?
	            ORDER BY from_module, from_version, from_id`
	return s.queryEdges(ctx, q, symbolID, pipelineVersion)
}

// FindCallees returns all edges where the caller matches symbolID.
func (s *Store) FindCallees(ctx context.Context, symbolID string, pipelineVersion string) ([]ports.CallEdgeRef, error) {
	const q = `SELECT DISTINCT from_module, from_version, pipeline_version,
	                   from_id, to_id, confidence
	            FROM callgraph_edges
	            WHERE from_id = ? AND pipeline_version = ?
	            ORDER BY from_module, from_version, to_id`
	return s.queryEdges(ctx, q, symbolID, pipelineVersion)
}

func (s *Store) queryEdges(ctx context.Context, q, symbolID, pipelineVersion string) ([]ports.CallEdgeRef, error) {
	rows, err := s.db.DB().QueryContext(ctx, q, symbolID, pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("querying callgraph edges: %w", err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck
	}()

	var out []ports.CallEdgeRef
	for rows.Next() {
		var ref ports.CallEdgeRef
		var conf string
		if serr := rows.Scan(
			&ref.ModulePath, &ref.ModuleVersion, &ref.PipelineVersion,
			&ref.FromID, &ref.ToID, &conf,
		); serr != nil {
			return nil, fmt.Errorf("scanning callgraph edge ref: %w", serr)
		}
		ref.Confidence = domain2.EdgeConfidence(conf)
		out = append(out, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating callgraph edge refs: %w", err)
	}
	return out, nil
}

// Ensure Store implements ports.CallGraphStore at compile time.
var _ ports.CallGraphStore = (*Store)(nil)
