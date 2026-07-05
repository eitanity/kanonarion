// Package sqlite implements ports.LicenseStore using a SQLite database via
// modernc.org/sqlite (pure Go, no CGO). The schema is versioned through a
// schema_migrations table shared with other contexts when using the same DB.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	domain2 "github.com/eitanity/kanonarion/internal/license/domain"
	"github.com/eitanity/kanonarion/internal/license/ports"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

// Store is the SQLite-backed license store.
type Store struct {
	db sqlitestore.DB
}

// New returns a new Store using the provided database handle.
func New(db sqlitestore.DB) *Store {
	return &Store{db: db}
}

// Migrations returns the schema migrations for the license module.
func Migrations() []sqlitestore.Migration {
	return []sqlitestore.Migration{
		{Module: "license", Version: 1, SQL: `CREATE TABLE IF NOT EXISTS licence_records (
            module_path      TEXT NOT NULL,
            module_version   TEXT NOT NULL,
            pipeline_version TEXT NOT NULL,
            primary_spdx     TEXT NOT NULL DEFAULT '',
            overall_status   INTEGER NOT NULL,
            extracted_at     TEXT NOT NULL,
            content_hash     TEXT NOT NULL,
            serialised       BLOB NOT NULL,
            PRIMARY KEY (module_path, module_version, pipeline_version)
        );
        CREATE INDEX IF NOT EXISTS licence_records_spdx_idx
            ON licence_records(primary_spdx);
        CREATE INDEX IF NOT EXISTS licence_records_status_idx
            ON licence_records(overall_status)`},
		{Module: "license", Version: 2, SQL: `ALTER TABLE licence_records
            ADD COLUMN copyright_status INTEGER NOT NULL DEFAULT 0;
        CREATE INDEX IF NOT EXISTS licence_records_copyright_status_idx
            ON licence_records(copyright_status)`},
		{Module: "license", Version: 3, SQL: `ALTER TABLE licence_records
            ADD COLUMN provenance_confidence INTEGER NOT NULL DEFAULT 0;
        CREATE INDEX IF NOT EXISTS licence_records_provenance_confidence_idx
            ON licence_records(provenance_confidence)`},
		{Module: "license", Version: 4, SQL: `ALTER TABLE licence_records
            ADD COLUMN spdx_expression TEXT NOT NULL DEFAULT ''`},
		// Migration v5: the ecosystem field joined the canonical hash and bumped
		// the schema version, so every pre-existing blob carries a stale hash and
		// no ecosystem field — unreadable under the new schema. Purge the legacy
		// rows; they are regenerable by re-extracting.
		{Module: "license", Version: 5, SQL: `DELETE FROM licence_records`},
	}
}

// Open opens (or creates) the SQLite database at dsn and runs migrations.
// Use ":memory:" for tests.
func Open(dsn string) (*Store, error) {
	db, err := sqlitestore.Open(dsn, Migrations())
	if err != nil {
		return nil, fmt.Errorf("opening license store: %w", err)
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
		return fmt.Errorf("closing license store: %w", err)
	}
	return nil
}

// PutLicenceRecord inserts or replaces a license record. Idempotent on
// (module_path, module_version, pipeline_version). Verifies the ContentHash
// before storage.
func (s *Store) PutLicenseRecord(ctx context.Context, r domain2.LicenseRecord) error {
	var h domain2.LicenseRecordHasher
	if err := h.VerifyContentHash(r); err != nil {
		return fmt.Errorf("verifying content hash before put: %w", err)
	}

	raw, err := h.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshalling license record: %w", err)
	}
	blob := blobcodec.Encode(raw)

	const q = `
INSERT INTO licence_records (
    module_path, module_version, pipeline_version,
    primary_spdx, spdx_expression, overall_status, copyright_status, provenance_confidence,
    extracted_at, content_hash, serialised
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (module_path, module_version, pipeline_version) DO UPDATE SET
    primary_spdx             = excluded.primary_spdx,
    spdx_expression          = excluded.spdx_expression,
    overall_status           = excluded.overall_status,
    copyright_status         = excluded.copyright_status,
    provenance_confidence    = excluded.provenance_confidence,
    extracted_at             = excluded.extracted_at,
    content_hash             = excluded.content_hash,
    serialised               = excluded.serialised`

	_, err = s.db.DB().ExecContext(ctx, q,
		r.Coordinate.Path, r.Coordinate.Version, r.PipelineVersion,
		r.PrimarySPDX, r.Expression, int(r.OverallStatus), int(r.CopyrightStatus), int(r.Provenance.Confidence),
		r.ExtractedAt.UTC().Format(time.RFC3339),
		r.ContentHash, blob,
	)
	if err != nil {
		return fmt.Errorf("inserting license record: %w", err)
	}
	return nil
}

// GetLicenceRecord retrieves and tamper-checks the license record for the
// given coordinate and pipeline version. Returns (zero, false, nil) if not
// found. Returns (zero, false, ErrLicenceIntegrity) on hash mismatch.
func (s *Store) GetLicenseRecord(ctx context.Context, coord fetchdomain.ModuleCoordinate, pipelineVersion string) (domain2.LicenseRecord, bool, error) {
	const q = `SELECT serialised, content_hash FROM licence_records
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?`

	row := s.db.DB().QueryRowContext(ctx, q, coord.Path, coord.Version, pipelineVersion)
	var blob []byte
	var storedHash string
	if err := row.Scan(&blob, &storedHash); errors.Is(err, sql.ErrNoRows) {
		return domain2.LicenseRecord{}, false, nil
	} else if err != nil {
		return domain2.LicenseRecord{}, false, fmt.Errorf("querying license record: %w", err)
	}

	blob, decErr := blobcodec.Decode(blob)
	if decErr != nil {
		return domain2.LicenseRecord{}, false, fmt.Errorf("decompressing license record: %w", decErr)
	}
	var h domain2.LicenseRecordHasher
	rec, err := h.Unmarshal(blob)
	if err != nil {
		return domain2.LicenseRecord{}, false, fmt.Errorf("unmarshalling license record: %w", err)
	}

	if verr := h.VerifyContentHash(rec); verr != nil {
		return domain2.LicenseRecord{}, false, fmt.Errorf("%w: %w", ports.ErrLicenceIntegrity, verr)
	}
	return rec, true, nil
}

// ListLicenseRecords returns summaries matching the filter, ordered by
// extracted_at descending.
func (s *Store) ListLicenseRecords(ctx context.Context, filter ports.LicenseFilter) ([]ports.LicenseSummary, error) {
	q, args := buildListQuery(filter)
	rows, err := s.db.DB().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing license records: %w", err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck // rows.Err() checked below
	}()

	var out []ports.LicenseSummary
	for rows.Next() {
		var sum ports.LicenseSummary
		var extractedAt string
		var status int
		if serr := rows.Scan(
			&sum.ModulePath, &sum.ModuleVersion, &sum.PipelineVersion,
			&sum.PrimarySPDX, &sum.Expression, &status, &extractedAt, &sum.ContentHash,
		); serr != nil {
			return nil, fmt.Errorf("scanning license summary: %w", serr)
		}
		t, perr := time.Parse(time.RFC3339, extractedAt)
		if perr != nil {
			return nil, fmt.Errorf("parsing extracted_at %q: %w", extractedAt, perr)
		}
		sum.ExtractedAt = t.UTC()
		sum.OverallStatus = domain2.LicenseStatus(status)
		out = append(out, sum)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating license summaries: %w", err)
	}
	return out, nil
}

func buildListQuery(f ports.LicenseFilter) (string, []any) {
	q := `SELECT module_path, module_version, pipeline_version,
	             primary_spdx, spdx_expression, overall_status, extracted_at, content_hash
	      FROM licence_records`
	var conds []string
	var args []any

	if f.SPDX != "" {
		conds = append(conds, "primary_spdx = ?")
		args = append(args, f.SPDX)
	}
	if f.Status != nil {
		conds = append(conds, "overall_status = ?")
		args = append(args, int(*f.Status))
	}

	for i, c := range conds {
		if i == 0 {
			q += " WHERE " + c
		} else {
			q += " AND " + c
		}
	}
	q += " ORDER BY extracted_at DESC"
	if f.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, f.Limit)
		if f.Offset > 0 {
			q += " OFFSET ?"
			args = append(args, f.Offset)
		}
	} else if f.Offset > 0 {
		// SQLite requires LIMIT when using OFFSET.
		q += " LIMIT -1 OFFSET ?"
		args = append(args, f.Offset)
	}
	return q, args
}

// Ensure Store implements ports.LicenseStore at compile time.
var _ ports.LicenseStore = (*Store)(nil)
