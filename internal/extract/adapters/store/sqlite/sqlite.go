package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/extract/domain"
	"github.com/eitanity/kanonarion/internal/extract/ports"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

type Store struct {
	db     sqlitestore.DB
	hasher domain.ExtractionRunHasher
}

// New returns a new Store using the provided database handle.
func New(db sqlitestore.DB) *Store {
	return &Store{db: db, hasher: domain.ExtractionRunHasher{}}
}

// Migrations returns the schema migrations for the extraction module.
func Migrations() []sqlitestore.Migration {
	return []sqlitestore.Migration{
		{
			Module:  "extraction",
			Version: 1,
			SQL: `CREATE TABLE IF NOT EXISTS extraction_runs (
                id              TEXT PRIMARY KEY,
                walk_id         TEXT NOT NULL,
                target_path     TEXT NOT NULL,
                target_version  TEXT NOT NULL,
                started_at      TEXT NOT NULL,
                completed_at    TEXT NOT NULL,
                overall_status  INTEGER NOT NULL,
                content_hash    TEXT NOT NULL,
                raw_record      BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_extraction_walk_id ON extraction_runs(walk_id);
            CREATE INDEX IF NOT EXISTS idx_extraction_started_at ON extraction_runs(started_at);`,
		},
		// Migration v2: the ecosystem field joined the canonical hash and bumped
		// the schema version, so every pre-existing blob carries a stale hash and
		// no ecosystem field — unreadable under the new schema. Purge the legacy
		// rows; they are regenerable by re-running extraction.
		{
			Module:  "extraction",
			Version: 2,
			SQL:     `DELETE FROM extraction_runs`,
		},
	}
}

func Open(dsn string) (*Store, error) {
	db, err := sqlitestore.Open(dsn, Migrations())
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}
	return &Store{db: db, hasher: domain.ExtractionRunHasher{}}, nil
}

func (s *Store) PutExtractionRun(ctx context.Context, run domain.ExtractionRun) error {
	if err := s.hasher.VerifyContentHash(run); err != nil {
		return fmt.Errorf("verifying integrity: %w", err)
	}

	data, err := s.hasher.Marshal(run)
	if err != nil {
		return fmt.Errorf("marshalling for storage: %w", err)
	}

	_, err = s.db.DB().ExecContext(ctx,
		`INSERT INTO extraction_runs (
			id, walk_id, target_path, target_version, started_at, completed_at, 
			overall_status, content_hash, raw_record
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			completed_at=excluded.completed_at,
			overall_status=excluded.overall_status,
			raw_record=excluded.raw_record`,
		run.ID, run.WalkID, "", "", // We don't have target at hand, but it's in raw_record.
		// Actually let's try to get it if we want to filter by target.
		run.StartedAt.UTC().Format(time.RFC3339),
		run.CompletedAt.UTC().Format(time.RFC3339),
		int(run.OverallStatus),
		run.ContentHash,
		data,
	)
	if err != nil {
		return fmt.Errorf("inserting extraction run: %w", err)
	}
	return nil
}

func (s *Store) GetExtractionRun(ctx context.Context, id string) (domain.ExtractionRun, error) {
	var data []byte
	err := s.db.DB().QueryRowContext(ctx,
		`SELECT raw_record FROM extraction_runs WHERE id = ?`, id,
	).Scan(&data)

	if errors.Is(err, sql.ErrNoRows) {
		return domain.ExtractionRun{}, ports.ErrExtractionRunNotFound
	}
	if err != nil {
		return domain.ExtractionRun{}, fmt.Errorf("querying extraction run: %w", err)
	}

	run, err := s.hasher.Unmarshal(data)
	if err != nil {
		return domain.ExtractionRun{}, fmt.Errorf("unmarshalling extraction run: %w", err)
	}

	if err := s.hasher.VerifyContentHash(run); err != nil {
		return domain.ExtractionRun{}, fmt.Errorf("%w: %w", ports.ErrExtractionRunIntegrity, err)
	}

	return run, nil
}

func (s *Store) ListExtractionRuns(ctx context.Context, filter ports.ExtractionRunFilter) ([]ports.ExtractionRunSummary, error) {
	query, args := buildListQuery(filter)
	rows, err := s.db.DB().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing extraction runs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var summaries []ports.ExtractionRunSummary
	for rows.Next() {
		var row struct {
			ID            string
			WalkID        string
			StartedAt     string
			CompletedAt   string
			OverallStatus int
			RawRecord     []byte
		}

		if err := rows.Scan(&row.ID, &row.WalkID, &row.StartedAt, &row.CompletedAt, &row.OverallStatus, &row.RawRecord); err != nil {
			return nil, fmt.Errorf("scanning summary: %w", err)
		}

		sTime, _ := time.Parse(time.RFC3339, row.StartedAt)
		cTime, _ := time.Parse(time.RFC3339, row.CompletedAt)

		summary := ports.ExtractionRunSummary{
			ID:            row.ID,
			WalkID:        row.WalkID,
			StartedAt:     sTime,
			CompletedAt:   cTime,
			OverallStatus: domain.ExtractionRunStatus(row.OverallStatus),
		}

		// Unmarshal data to get module count
		run, err := s.hasher.Unmarshal(row.RawRecord)
		if err == nil {
			summary.ModuleCount = len(run.PerModuleResults)
		}

		summaries = append(summaries, summary)
	}
	return summaries, nil
}

func buildListQuery(f ports.ExtractionRunFilter) (string, []any) {
	var sb strings.Builder
	sb.WriteString(`SELECT id, walk_id, started_at, completed_at, overall_status, raw_record FROM extraction_runs`)

	var where []string
	var args []any

	if f.WalkID != "" {
		where = append(where, "walk_id = ?")
		args = append(args, f.WalkID)
	}
	if f.Since != nil {
		where = append(where, "started_at >= ?")
		args = append(args, f.Since.UTC().Format(time.RFC3339))
	}
	if f.Until != nil {
		where = append(where, "started_at <= ?")
		args = append(args, f.Until.UTC().Format(time.RFC3339))
	}
	if f.OverallStatus != nil {
		where = append(where, "overall_status = ?")
		args = append(args, int(*f.OverallStatus))
	}
	if len(f.IDs) > 0 {
		placeholders := make([]string, len(f.IDs))
		for i := range f.IDs {
			placeholders[i] = "?"
			args = append(args, f.IDs[i])
		}
		where = append(where, fmt.Sprintf("id IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(where) > 0 {
		sb.WriteString(" WHERE ")
		sb.WriteString(strings.Join(where, " AND "))
	}

	sb.WriteString(" ORDER BY started_at DESC")

	if f.Limit > 0 {
		sb.WriteString(" LIMIT ?")
		args = append(args, f.Limit)
	}
	if f.Offset > 0 {
		sb.WriteString(" OFFSET ?")
		args = append(args, f.Offset)
	}

	return sb.String(), args
}

// (already handled by replacing Open above)
