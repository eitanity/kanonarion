// Package sqlite implements ports.ExampleStore using a SQLite database via
// modernc.org/sqlite (pure Go, no CGO). The schema is versioned through the
// schema_migrations table shared with other contexts when using the same DB.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	domain2 "github.com/eitanity/kanonarion/internal/example/domain"
	"github.com/eitanity/kanonarion/internal/example/ports"

	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

// Store is the SQLite-backed example store.
type Store struct {
	db sqlitestore.DB
}

// New returns a new Store using the provided database handle.
func New(db sqlitestore.DB) *Store {
	return &Store{db: db}
}

// Migrations returns the schema migrations for the example module.
func Migrations() []sqlitestore.Migration {
	return []sqlitestore.Migration{
		{Module: "example", Version: 1, SQL: `CREATE TABLE IF NOT EXISTS example_records (
            module_path        TEXT NOT NULL,
            module_version     TEXT NOT NULL,
            pipeline_version   TEXT NOT NULL,
            overall_status     INTEGER NOT NULL,
            example_count      INTEGER NOT NULL,
            extracted_at       TEXT NOT NULL,
            content_hash       TEXT NOT NULL,
            serialised         BLOB NOT NULL,
            PRIMARY KEY (module_path, module_version, pipeline_version)
        );
        CREATE TABLE IF NOT EXISTS example_index (
            module_path        TEXT NOT NULL,
            module_version     TEXT NOT NULL,
            pipeline_version   TEXT NOT NULL,
            package_path       TEXT NOT NULL,
            associated_symbol  TEXT NOT NULL,
            example_name       TEXT NOT NULL,
            validates          INTEGER NOT NULL,
            PRIMARY KEY (module_path, module_version, pipeline_version,
                         package_path, associated_symbol, example_name)
        );
        CREATE INDEX IF NOT EXISTS example_index_symbol_idx
            ON example_index(module_path, associated_symbol)`},
		// Migration v2: the ecosystem field joined the canonical hash and bumped
		// the schema version, so every pre-existing blob carries a stale hash and
		// no ecosystem field — unreadable under the new schema. Purge the legacy
		// rows; they are regenerable by re-extracting.
		{Module: "example", Version: 2, SQL: `DELETE FROM example_records;
DELETE FROM example_index`},
	}
}

// Open opens (or creates) the SQLite database at dsn and runs migrations.
// Use ":memory:" for tests.
func Open(dsn string) (*Store, error) {
	db, err := sqlitestore.Open(dsn, Migrations())
	if err != nil {
		return nil, fmt.Errorf("opening example store: %w", err)
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
		return fmt.Errorf("closing example store: %w", err)
	}
	return nil
}

// PutExampleRecord inserts or replaces an example record. Idempotent on
// (module_path, module_version, pipeline_version). Verifies the ContentHash
// before storage.
func (s *Store) PutExampleRecord(ctx context.Context, r domain2.ExampleRecord) error {
	var h domain2.ExampleRecordHasher
	if err := h.VerifyContentHash(r); err != nil {
		return fmt.Errorf("verifying content hash before put: %w", err)
	}

	raw, err := h.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshalling example record: %w", err)
	}
	blob := blobcodec.Encode(raw)

	tx, err := s.db.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback() //nolint:errcheck // rollback after commit is a no-op
	}()

	const qRecord = `
INSERT INTO example_records (
    module_path, module_version, pipeline_version,
    overall_status, example_count,
    extracted_at, content_hash, serialised
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (module_path, module_version, pipeline_version) DO UPDATE SET
    overall_status = excluded.overall_status,
    example_count  = excluded.example_count,
    extracted_at   = excluded.extracted_at,
    content_hash   = excluded.content_hash,
    serialised     = excluded.serialised`

	_, err = tx.ExecContext(ctx, qRecord,
		r.Coordinate.Path, r.Coordinate.Version, r.PipelineVersion,
		int(r.OverallStatus), len(r.Examples),
		r.ExtractedAt.UTC().Format(time.RFC3339),
		r.ContentHash, blob,
	)
	if err != nil {
		return fmt.Errorf("inserting example record: %w", err)
	}

	// Rebuild the index rows: delete old entries, insert new ones.
	const qDel = `DELETE FROM example_index
	WHERE module_path = ? AND module_version = ? AND pipeline_version = ?`
	if _, err := tx.ExecContext(ctx, qDel, r.Coordinate.Path, r.Coordinate.Version, r.PipelineVersion); err != nil {
		return fmt.Errorf("deleting old example index: %w", err)
	}

	const qIdx = `
INSERT INTO example_index (
    module_path, module_version, pipeline_version,
    package_path, associated_symbol, example_name, validates
) VALUES (?, ?, ?, ?, ?, ?, ?)`

	// Deduplicate before inserting. Platform-specific test files (e.g.
	// connect_test.go and connect_windows_test.go) can both declare the same
	// example function in the same package; only one variant builds on any
	// given OS but both are present in the module zip.
	seenIdx := make(map[string]bool, len(r.Examples))
	for _, e := range r.Examples {
		key := e.Package + "\x00" + e.AssociatedSymbol + "\x00" + e.Name
		if seenIdx[key] {
			continue
		}
		seenIdx[key] = true
		validates := 0
		if e.Validates {
			validates = 1
		}
		if _, err := tx.ExecContext(ctx, qIdx,
			r.Coordinate.Path, r.Coordinate.Version, r.PipelineVersion,
			e.Package, e.AssociatedSymbol, e.Name, validates,
		); err != nil {
			return fmt.Errorf("inserting example index row %s: %w", e.Name, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing example record: %w", err)
	}
	return nil
}

// GetExampleRecord retrieves and tamper-checks the example record for the
// given coordinate and pipeline version. Returns (zero, false, nil) if not
// found. Returns (zero, false, ErrExampleIntegrity) on hash mismatch.
func (s *Store) GetExampleRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (domain2.ExampleRecord, bool, error) {
	const q = `SELECT serialised, content_hash FROM example_records
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?`

	row := s.db.DB().QueryRowContext(ctx, q, coord.Path, coord.Version, pipelineVersion)
	var blob []byte
	var storedHash string
	if err := row.Scan(&blob, &storedHash); errors.Is(err, sql.ErrNoRows) {
		return domain2.ExampleRecord{}, false, nil
	} else if err != nil {
		return domain2.ExampleRecord{}, false, fmt.Errorf("querying example record: %w", err)
	}

	blob, decErr := blobcodec.Decode(blob)
	if decErr != nil {
		return domain2.ExampleRecord{}, false, fmt.Errorf("decompressing example record: %w", decErr)
	}
	var h domain2.ExampleRecordHasher
	rec, err := h.Unmarshal(blob)
	if err != nil {
		return domain2.ExampleRecord{}, false, fmt.Errorf("unmarshalling example record: %w", err)
	}

	if verr := h.VerifyContentHash(rec); verr != nil {
		return domain2.ExampleRecord{}, false, fmt.Errorf("%w: %w", ports.ErrExampleIntegrity, verr)
	}
	return rec, true, nil
}

// ListExampleRecords returns summaries matching the filter, ordered by
// extracted_at descending.
func (s *Store) ListExampleRecords(ctx context.Context, filter ports.ExampleFilter) ([]ports.ExampleSummary, error) {
	q := `SELECT module_path, module_version, pipeline_version,
	             overall_status, example_count, extracted_at, content_hash
	      FROM example_records
	      ORDER BY extracted_at DESC`
	var args []any

	if filter.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, filter.Limit)
		if filter.Offset > 0 {
			q += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	} else if filter.Offset > 0 {
		// SQLite requires LIMIT if OFFSET is used. Use a large number.
		q += " LIMIT -1 OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.DB().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing example records: %w", err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck // rows.Err() checked below
	}()

	var out []ports.ExampleSummary
	for rows.Next() {
		var sum ports.ExampleSummary
		var extractedAt string
		var status int
		if serr := rows.Scan(
			&sum.ModulePath, &sum.ModuleVersion, &sum.PipelineVersion,
			&status, &sum.ExampleCount, &extractedAt, &sum.ContentHash,
		); serr != nil {
			return nil, fmt.Errorf("scanning example summary: %w", serr)
		}
		t, perr := time.Parse(time.RFC3339, extractedAt)
		if perr != nil {
			return nil, fmt.Errorf("parsing extracted_at %q: %w", extractedAt, perr)
		}
		sum.ExtractedAt = t.UTC()
		sum.OverallStatus = domain2.ExampleStatus(status)
		out = append(out, sum)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating example summaries: %w", err)
	}
	return out, nil
}

// FindBySymbol returns index entries for all examples associated with the
// given symbol across all stored modules, filtered by pipeline version.
// The symbol may be qualified with a package name (e.g. "modfile.File") or
// unqualified (e.g. "File"); both forms are matched against the stored
// associated_symbol column which holds unqualified names like "File" or
// "Client.Do".
func (s *Store) FindBySymbol(ctx context.Context, symbol string, pipelineVersion string) ([]ports.ExampleRef, error) {
	// If the caller passes a package-qualified name like "modfile.File" or
	// "modfile.File.Method", strip the leading package segment so we search
	// for the unqualified form stored in the index.
	lookup := symbol
	if idx := strings.Index(symbol, "."); idx >= 0 {
		// Check whether the first segment looks like a package name (all
		// lowercase). If so, drop it.
		pkg := symbol[:idx]
		rest := symbol[idx+1:]
		if pkg != "" && strings.ToLower(pkg) == pkg {
			lookup = rest
		}
	}

	const q = `SELECT module_path, module_version, pipeline_version,
	                   package_path, associated_symbol, example_name, validates
	            FROM example_index
	            WHERE associated_symbol = ? AND pipeline_version = ?
	            ORDER BY module_path, module_version, example_name`

	rows, err := s.db.DB().QueryContext(ctx, q, lookup, pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("querying example index for %q: %w", symbol, err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck // rows.Err() checked below
	}()

	var out []ports.ExampleRef
	for rows.Next() {
		var ref ports.ExampleRef
		var validates int
		if serr := rows.Scan(
			&ref.ModulePath, &ref.ModuleVersion, &ref.PipelineVersion,
			&ref.Package, &ref.AssociatedSymbol, &ref.ExampleName, &validates,
		); serr != nil {
			return nil, fmt.Errorf("scanning example ref: %w", serr)
		}
		ref.Validates = validates != 0
		out = append(out, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating example refs: %w", err)
	}
	return out, nil
}

// FindBySymbolInModule returns index entries for examples associated with the
// given symbol within a specific module@version. Applies the same
// package-qualification stripping as FindBySymbol.
func (s *Store) FindBySymbolInModule(ctx context.Context, coord coordinate.ModuleCoordinate, symbol string, pipelineVersion string) ([]ports.ExampleRef, error) {
	lookup := symbol
	if idx := strings.Index(symbol, "."); idx >= 0 {
		pkg := symbol[:idx]
		rest := symbol[idx+1:]
		if pkg != "" && strings.ToLower(pkg) == pkg {
			lookup = rest
		}
	}

	const q = `SELECT module_path, module_version, pipeline_version,
	                   package_path, associated_symbol, example_name, validates
	            FROM example_index
	            WHERE module_path = ? AND module_version = ?
	              AND associated_symbol = ? AND pipeline_version = ?
	            ORDER BY example_name`

	rows, err := s.db.DB().QueryContext(ctx, q, coord.Path, coord.Version, lookup, pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("querying example index for %q in %s: %w", symbol, coord, err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck
	}()

	var out []ports.ExampleRef
	for rows.Next() {
		var ref ports.ExampleRef
		var validates int
		if serr := rows.Scan(
			&ref.ModulePath, &ref.ModuleVersion, &ref.PipelineVersion,
			&ref.Package, &ref.AssociatedSymbol, &ref.ExampleName, &validates,
		); serr != nil {
			return nil, fmt.Errorf("scanning example ref: %w", serr)
		}
		ref.Validates = validates != 0
		out = append(out, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating example refs: %w", err)
	}
	return out, nil
}

// Ensure Store implements ports.ExampleStore at compile time.
var _ ports.ExampleStore = (*Store)(nil)
