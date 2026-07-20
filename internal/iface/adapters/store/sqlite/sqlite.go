// Package sqlite implements ports.InterfaceStore using a SQLite database via
// modernc.org/sqlite (pure Go, no CGO). The schema is versioned through the
// schema_migrations table shared with other contexts when using the same DB.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"

	domain2 "github.com/eitanity/kanonarion/internal/iface/domain"
	"github.com/eitanity/kanonarion/internal/iface/ports"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

// Store is the SQLite-backed interface store.
type Store struct {
	db sqlitestore.DB
}

// New returns a new Store using the provided database handle.
func New(db sqlitestore.DB) *Store {
	return &Store{db: db}
}

// Migrations returns the schema migrations for the iface module.
func Migrations() []sqlitestore.Migration {
	return []sqlitestore.Migration{
		{Module: "iface", Version: 1, SQL: `CREATE TABLE IF NOT EXISTS interface_records (
            module_path        TEXT NOT NULL,
            module_version     TEXT NOT NULL,
            pipeline_version   TEXT NOT NULL,
            overall_status     INTEGER NOT NULL,
            package_count      INTEGER NOT NULL,
            extracted_at       TEXT NOT NULL,
            content_hash       TEXT NOT NULL,
            serialised         BLOB NOT NULL,
            PRIMARY KEY (module_path, module_version, pipeline_version)
        );
        CREATE TABLE IF NOT EXISTS interface_symbols (
            module_path        TEXT NOT NULL,
            module_version     TEXT NOT NULL,
            pipeline_version   TEXT NOT NULL,
            package_path       TEXT NOT NULL,
            symbol_kind        TEXT NOT NULL,
            symbol_name        TEXT NOT NULL,
            parent_type        TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (module_path, module_version, pipeline_version,
                         package_path, symbol_kind, symbol_name, parent_type)
        );
        CREATE INDEX IF NOT EXISTS interface_symbols_lookup_idx
            ON interface_symbols(module_path, module_version, symbol_name)`},
		{Module: "iface", Version: 2, SQL: `ALTER TABLE interface_symbols ADD COLUMN signature TEXT NOT NULL DEFAULT ''`},
		// Migration v3: the ecosystem field joined the canonical hash and bumped
		// the schema version, so every pre-existing blob carries a stale hash and
		// no ecosystem field — unreadable under the new schema. Purge the legacy
		// rows; they are regenerable by re-extracting.
		{Module: "iface", Version: 3, SQL: `DELETE FROM interface_records;
DELETE FROM interface_symbols`},
	}
}

// Open opens (or creates) the SQLite database at dsn and runs migrations.
// Use ":memory:" for tests.
func Open(dsn string) (*Store, error) {
	db, err := sqlitestore.Open(dsn, Migrations())
	if err != nil {
		return nil, fmt.Errorf("opening iface store: %w", err)
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
		return fmt.Errorf("closing iface store: %w", err)
	}
	return nil
}

// PutInterfaceRecord inserts or replaces an interface record. Idempotent on
// (module_path, module_version, pipeline_version).
func (s *Store) PutInterfaceRecord(ctx context.Context, r domain2.InterfaceRecord) error {
	var h domain2.InterfaceRecordHasher
	if err := h.VerifyContentHash(r); err != nil {
		return fmt.Errorf("verifying content hash before put: %w", err)
	}

	raw, err := h.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshalling interface record: %w", err)
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
INSERT INTO interface_records (
    module_path, module_version, pipeline_version,
    overall_status, package_count,
    extracted_at, content_hash, serialised
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (module_path, module_version, pipeline_version) DO UPDATE SET
    overall_status = excluded.overall_status,
    package_count  = excluded.package_count,
    extracted_at   = excluded.extracted_at,
    content_hash   = excluded.content_hash,
    serialised     = excluded.serialised`

	_, err = tx.ExecContext(ctx, qRecord,
		r.Coordinate.Path, r.Coordinate.Version, r.PipelineVersion,
		int(r.OverallStatus), len(r.Packages),
		r.ExtractedAt.UTC().Format(time.RFC3339),
		r.ContentHash, blob,
	)
	if err != nil {
		return fmt.Errorf("inserting interface record: %w", err)
	}

	const qDel = `DELETE FROM interface_symbols
	WHERE module_path = ? AND module_version = ? AND pipeline_version = ?`
	if _, err := tx.ExecContext(ctx, qDel, r.Coordinate.Path, r.Coordinate.Version, r.PipelineVersion); err != nil {
		return fmt.Errorf("deleting old interface symbols: %w", err)
	}

	const qSym = `
INSERT OR IGNORE INTO interface_symbols (
    module_path, module_version, pipeline_version,
    package_path, symbol_kind, symbol_name, parent_type, signature
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	stmtSym, err := tx.PrepareContext(ctx, qSym)
	if err != nil {
		return fmt.Errorf("preparing interface symbol statement: %w", err)
	}
	defer func() { _ = stmtSym.Close() }()

	for _, pkg := range r.Packages {
		for _, t := range pkg.Types {
			if _, err := stmtSym.ExecContext(ctx,
				r.Coordinate.Path, r.Coordinate.Version, r.PipelineVersion,
				pkg.ImportPath, "type", t.Name, "", t.Signature,
			); err != nil {
				return fmt.Errorf("inserting type symbol %s: %w", t.Name, err)
			}
			for _, m := range t.Methods {
				if _, err := stmtSym.ExecContext(ctx,
					r.Coordinate.Path, r.Coordinate.Version, r.PipelineVersion,
					pkg.ImportPath, "method", m.Name, t.Name, m.Signature,
				); err != nil {
					return fmt.Errorf("inserting method symbol %s.%s: %w", t.Name, m.Name, err)
				}
			}
		}
		for _, f := range pkg.Funcs {
			if _, err := stmtSym.ExecContext(ctx,
				r.Coordinate.Path, r.Coordinate.Version, r.PipelineVersion,
				pkg.ImportPath, "func", f.Name, "", f.Signature,
			); err != nil {
				return fmt.Errorf("inserting func symbol %s: %w", f.Name, err)
			}
		}
		for _, c := range pkg.Consts {
			if _, err := stmtSym.ExecContext(ctx,
				r.Coordinate.Path, r.Coordinate.Version, r.PipelineVersion,
				pkg.ImportPath, "const", c.Name, "", c.Type,
			); err != nil {
				return fmt.Errorf("inserting const symbol %s: %w", c.Name, err)
			}
		}
		for _, v := range pkg.Vars {
			if _, err := stmtSym.ExecContext(ctx,
				r.Coordinate.Path, r.Coordinate.Version, r.PipelineVersion,
				pkg.ImportPath, "var", v.Name, "", v.Type,
			); err != nil {
				return fmt.Errorf("inserting var symbol %s: %w", v.Name, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing interface record: %w", err)
	}
	_, _ = s.db.DB().ExecContext(ctx, `PRAGMA optimize`) //nolint:errcheck
	return nil
}

// GetInterfaceRecord retrieves and tamper-checks the interface record.
// Returns (zero, false, nil) if not found.
// Returns (zero, false, ErrInterfaceIntegrity) on hash mismatch.
func (s *Store) GetInterfaceRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (domain2.InterfaceRecord, bool, error) {
	const q = `SELECT serialised, content_hash FROM interface_records
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?`

	row := s.db.DB().QueryRowContext(ctx, q, coord.Path, coord.Version, pipelineVersion)
	var blob []byte
	var storedHash string
	if err := row.Scan(&blob, &storedHash); errors.Is(err, sql.ErrNoRows) {
		return domain2.InterfaceRecord{}, false, nil
	} else if err != nil {
		return domain2.InterfaceRecord{}, false, fmt.Errorf("querying interface record: %w", err)
	}

	blob, decErr := blobcodec.Decode(blob)
	if decErr != nil {
		return domain2.InterfaceRecord{}, false, fmt.Errorf("decompressing interface record: %w", decErr)
	}
	var h domain2.InterfaceRecordHasher
	if verr := h.VerifyBlobHash(blob, storedHash); verr != nil {
		return domain2.InterfaceRecord{}, false, fmt.Errorf("%w: %w", ports.ErrInterfaceIntegrity, verr)
	}
	rec, err := h.Unmarshal(blob)
	if err != nil {
		return domain2.InterfaceRecord{}, false, fmt.Errorf("unmarshalling interface record: %w", err)
	}
	return rec, true, nil
}

// ListInterfaceRecords returns summaries matching the filter, ordered by
// extracted_at descending.
func (s *Store) ListInterfaceRecords(ctx context.Context, filter ports.InterfaceFilter) ([]ports.InterfaceSummary, error) {
	q := `SELECT module_path, module_version, pipeline_version,
	             overall_status, package_count, extracted_at, content_hash
	      FROM interface_records
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
		return nil, fmt.Errorf("listing interface records: %w", err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck
	}()

	var out []ports.InterfaceSummary
	for rows.Next() {
		var sum ports.InterfaceSummary
		var extractedAt string
		var status int
		if serr := rows.Scan(
			&sum.ModulePath, &sum.ModuleVersion, &sum.PipelineVersion,
			&status, &sum.PackageCount, &extractedAt, &sum.ContentHash,
		); serr != nil {
			return nil, fmt.Errorf("scanning interface summary: %w", serr)
		}
		t, perr := time.Parse(time.RFC3339, extractedAt)
		if perr != nil {
			return nil, fmt.Errorf("parsing extracted_at %q: %w", extractedAt, perr)
		}
		sum.ExtractedAt = t.UTC()
		sum.OverallStatus = domain2.InterfaceStatus(status)
		out = append(out, sum)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating interface summaries: %w", err)
	}
	return out, nil
}

// FindSymbol returns index entries for all packages that export a symbol with
// the given name across all stored modules.
func (s *Store) FindSymbol(ctx context.Context, symbolName string, pipelineVersion string) ([]ports.SymbolRef, error) {
	const q = `SELECT module_path, module_version, pipeline_version,
	                   package_path, symbol_kind, symbol_name, parent_type, signature
	            FROM interface_symbols
	            WHERE symbol_name = ? AND pipeline_version = ?
	            ORDER BY module_path, module_version, package_path`

	rows, err := s.db.DB().QueryContext(ctx, q, symbolName, pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("querying interface symbols for %q: %w", symbolName, err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck
	}()

	var out []ports.SymbolRef
	for rows.Next() {
		var ref ports.SymbolRef
		if serr := rows.Scan(
			&ref.ModulePath, &ref.ModuleVersion, &ref.PipelineVersion,
			&ref.PackagePath, &ref.SymbolKind, &ref.SymbolName, &ref.ParentType, &ref.Signature,
		); serr != nil {
			return nil, fmt.Errorf("scanning symbol ref: %w", serr)
		}
		out = append(out, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating symbol refs: %w", err)
	}
	return out, nil
}

// Ensure Store implements ports.InterfaceStore at compile time.
var _ ports.InterfaceStore = (*Store)(nil)
