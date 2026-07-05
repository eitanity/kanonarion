// Package sqlite implements ports.WalkStore using a SQLite database via
// modernc.org/sqlite (pure Go, no CGO). The schema is versioned through a
// schema_migrations table shared with the fetch fact store when they use the
// same database file.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
	"github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// Store is the SQLite-backed walk store.
type Store struct {
	db sqlitestore.DB
}

// New returns a new Store using the provided database handle.
func New(db sqlitestore.DB) *Store {
	return &Store{db: db}
}

// Migrations returns the schema migrations for the walk module.
func Migrations() []sqlitestore.Migration {
	return []sqlitestore.Migration{
		{Module: "walk", Version: 1, SQL: `CREATE TABLE IF NOT EXISTS walks (
            id               TEXT PRIMARY KEY,
            target_path      TEXT NOT NULL,
            target_version   TEXT NOT NULL,
            started_at       TEXT NOT NULL,
            completed_at     TEXT NOT NULL,
            overall_status   INTEGER NOT NULL,
            pipeline_version TEXT NOT NULL,
            operator         TEXT NOT NULL,
            content_hash     TEXT NOT NULL,
            node_count       INTEGER NOT NULL DEFAULT 0,
            failure_count    INTEGER NOT NULL DEFAULT 0,
            serialised       BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS walks_target_idx    ON walks(target_path, target_version);
        CREATE INDEX IF NOT EXISTS walks_started_at_idx ON walks(started_at);
        CREATE INDEX IF NOT EXISTS walks_status_idx    ON walks(overall_status)`},
		{Module: "walk", Version: 2, SQL: `ALTER TABLE walks ADD COLUMN scope TEXT NOT NULL DEFAULT 'production';
        CREATE INDEX IF NOT EXISTS walks_scope_idx ON walks(scope)`},
		{Module: "walk", Version: 3, SQL: `ALTER TABLE walks ADD COLUMN depth TEXT NOT NULL DEFAULT '';
        CREATE INDEX IF NOT EXISTS walks_depth_idx ON walks(depth)`},
		// The ecosystem field joined the canonical hash and bumped the schema
		// version, so every row written before this migration carries a stale
		// hash and a blob with no ecosystem field — unreadable under the new
		// schema. Purge them; they are regenerable by re-walking.
		{Module: "walk", Version: 4, SQL: `DELETE FROM walks`},
	}
}

// Open opens (or creates) the SQLite database at dsn and runs migrations.
// Use ":memory:" for tests.
func Open(dsn string) (*Store, error) {
	db, err := sqlitestore.Open(dsn, Migrations())
	if err != nil {
		return nil, fmt.Errorf("opening walk store: %w", err)
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
		return fmt.Errorf("closing walk store: %w", err)
	}
	return nil
}

// PutWalk inserts or replaces a walk record. Verifies the ContentHash before
// storage. Idempotent on ID.
func (s *Store) PutWalk(ctx context.Context, rec domain.WalkRecord) error {
	var h domain.WalkRecordHasher
	if err := h.VerifyContentHash(rec); err != nil {
		return fmt.Errorf("verifying content hash before put: %w", err)
	}

	raw, err := h.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshalling walk record: %w", err)
	}
	blob := blobcodec.Encode(raw)

	nodeCount, failureCount := summariseCounts(rec)

	scope := string(rec.Scope)
	if scope == "" {
		scope = string(domain.WalkScopeCode)
	}

	// Store depth as "" for full walks (matches the DEFAULT and omitempty convention).
	depth := string(rec.Depth)
	if depth == string(domain.WalkDepthFull) {
		depth = ""
	}

	const q = `
INSERT INTO walks (
    id, target_path, target_version,
    started_at, completed_at, overall_status,
    pipeline_version, operator, content_hash,
    node_count, failure_count, scope, depth, serialised
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET
    target_path      = excluded.target_path,
    target_version   = excluded.target_version,
    started_at       = excluded.started_at,
    completed_at     = excluded.completed_at,
    overall_status   = excluded.overall_status,
    pipeline_version = excluded.pipeline_version,
    operator         = excluded.operator,
    content_hash     = excluded.content_hash,
    node_count       = excluded.node_count,
    failure_count    = excluded.failure_count,
    scope            = excluded.scope,
    depth            = excluded.depth,
    serialised       = excluded.serialised`

	_, err = s.db.DB().ExecContext(ctx, q,
		rec.ID, rec.Target.Path, rec.Target.Version,
		rec.StartedAt.UTC().Format(time.RFC3339),
		rec.CompletedAt.UTC().Format(time.RFC3339),
		int(rec.OverallStatus),
		rec.PipelineVersion, rec.Operator, rec.ContentHash,
		nodeCount, failureCount, scope, depth, blob,
	)
	if err != nil {
		return fmt.Errorf("inserting walk record: %w", err)
	}
	return nil
}

// GetWalk retrieves a walk record by ID. Returns ErrWalkNotFound if absent.
// Returns ErrWalkIntegrity if the stored hash does not verify.
func (s *Store) GetWalk(ctx context.Context, id string) (domain.WalkRecord, error) {
	const q = `SELECT serialised, content_hash FROM walks WHERE id = ?`
	row := s.db.DB().QueryRowContext(ctx, q, id)

	var blob []byte
	var storedHash string
	if err := row.Scan(&blob, &storedHash); errors.Is(err, sql.ErrNoRows) {
		return domain.WalkRecord{}, walkports.ErrWalkNotFound
	} else if err != nil {
		return domain.WalkRecord{}, fmt.Errorf("querying walk record: %w", err)
	}

	blob, decErr := blobcodec.Decode(blob)
	if decErr != nil {
		return domain.WalkRecord{}, fmt.Errorf("decompressing walk record: %w", decErr)
	}
	var h domain.WalkRecordHasher
	rec, err := h.Unmarshal(blob)
	if err != nil {
		return domain.WalkRecord{}, fmt.Errorf("unmarshalling walk record: %w", err)
	}

	if verr := h.VerifyContentHash(rec); verr != nil {
		return domain.WalkRecord{}, fmt.Errorf("%w: %w", walkports.ErrWalkIntegrity, verr)
	}
	return rec, nil
}

// ListWalks returns summaries ordered by started_at descending.
func (s *Store) ListWalks(ctx context.Context, filter walkports.WalkFilter) ([]walkports.WalkSummary, error) {
	q, args := buildListQuery(filter)
	rows, err := s.db.DB().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing walks: %w", err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck // rows.Err() checked below
	}()

	var summaries []walkports.WalkSummary
	for rows.Next() {
		var sum walkports.WalkSummary
		var startedAt, completedAt, scope, depth string
		var status int
		if serr := rows.Scan(
			&sum.ID,
			&sum.Target.Path, &sum.Target.Version,
			&startedAt, &completedAt,
			&status,
			&sum.NodeCount, &sum.FailureCount,
			&scope, &depth,
		); serr != nil {
			return nil, fmt.Errorf("scanning walk summary: %w", serr)
		}
		t1, perr := time.Parse(time.RFC3339, startedAt)
		if perr != nil {
			return nil, fmt.Errorf("parsing started_at %q: %w", startedAt, perr)
		}
		t2, perr := time.Parse(time.RFC3339, completedAt)
		if perr != nil {
			return nil, fmt.Errorf("parsing completed_at %q: %w", completedAt, perr)
		}
		sum.StartedAt = t1.UTC()
		sum.CompletedAt = t2.UTC()
		sum.OverallStatus = domain.WalkStatus(status)
		sum.Scope = domain.WalkScope(scope)
		if sum.Scope == "" {
			sum.Scope = domain.WalkScopeCode
		}
		sum.Depth = domain.WalkDepth(depth)
		if sum.Depth == "" {
			sum.Depth = domain.WalkDepthFull
		}
		summaries = append(summaries, sum)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating walk summaries: %w", err)
	}
	return summaries, nil
}

func buildListQuery(f walkports.WalkFilter) (string, []any) {
	var q string
	if f.LatestOnly {
		q = `SELECT id, target_path, target_version, started_at, completed_at,
	             overall_status, node_count, failure_count, scope, depth
	      FROM walks w1
	      WHERE started_at = (
	          SELECT MAX(started_at) FROM walks w2
	          WHERE w2.target_path = w1.target_path AND w2.target_version = w1.target_version
	          AND w2.scope = w1.scope
	      )`
	} else {
		q = `SELECT id, target_path, target_version, started_at, completed_at,
	             overall_status, node_count, failure_count, scope, depth
	      FROM walks`
	}
	var conditions []string
	var args []any

	if f.Target != nil {
		conditions = append(conditions, "target_path = ? AND target_version = ?")
		args = append(args, f.Target.Path, f.Target.Version)
	}
	if f.Since != nil {
		conditions = append(conditions, "started_at >= ?")
		args = append(args, f.Since.UTC().Format(time.RFC3339))
	}
	if f.Until != nil {
		conditions = append(conditions, "started_at <= ?")
		args = append(args, f.Until.UTC().Format(time.RFC3339))
	}
	if f.OverallStatus != nil {
		conditions = append(conditions, "overall_status = ?")
		args = append(args, int(*f.OverallStatus))
	}
	if f.Scope != nil {
		conditions = append(conditions, "scope = ?")
		args = append(args, string(*f.Scope))
	}
	if f.Depth != nil {
		// Full walks are stored as "" in the DB (omitempty convention).
		d := string(*f.Depth)
		if d == string(domain.WalkDepthFull) {
			d = ""
		}
		conditions = append(conditions, "depth = ?")
		args = append(args, d)
	}

	for i, c := range conditions {
		if i == 0 && !f.LatestOnly {
			q += " WHERE " + c
		} else {
			q += " AND " + c
		}
	}
	q += " ORDER BY started_at DESC"
	if f.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, f.Limit)
		if f.Offset > 0 {
			q += " OFFSET ?"
			args = append(args, f.Offset)
		}
	} else if f.Offset > 0 {
		q += " LIMIT -1 OFFSET ?"
		args = append(args, f.Offset)
	}
	return q, args
}

// summariseCounts returns the total node count and failure count for a record.
func summariseCounts(rec domain.WalkRecord) (nodeCount, failureCount int) {
	nodeCount = len(rec.PerNodeResults)
	for _, nr := range rec.PerNodeResults {
		if nr.Status != domain.NodeSucceeded {
			failureCount++
		}
	}
	return nodeCount, failureCount
}

// Ensure Store implements ports.WalkStore at compile time.
var _ walkports.WalkStore = (*Store)(nil)
