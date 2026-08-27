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

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/adapters/recordseal"

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
		// Migration v4: the ledger, and the satellite rekey that comes with it.
		//
		// Both tables are rebuilt because both primary keys change. A key of
		// (path, version, pipeline) made every re-extraction overwrite its
		// predecessor. For a public API that is the most costly kind of
		// overwriting: an API is close to a deterministic function of the
		// artefact's bytes, so two records that disagree are evidence of
		// non-determinism in the extractor — and the store destroyed the earlier
		// one every time, absorbing exactly the signal worth surfacing.
		//
		// The record key adds the time of measurement and the record's own content
		// hash, so every extraction that passes is its own row. ON CONFLICT DO
		// NOTHING covers the one collision left: the byte-identical record written
		// twice, which is the same measurement rather than a second one.
		//
		// The artefact identity is NOT a key column, for the reason measured on the
		// licence and example conversions and re-measured here. It lives inside the
		// compressed record blob, migrations are SQL-only and SQLite cannot
		// decompress zstd, so a column added here could only be back-filled with
		// the empty string. Measured read-only on the maintainer's store, 181 of
		// the 1,850 rows already carry a real "zip:h1:..." identity in their blob,
		// so that back-fill would state in a key column that 181 records describe
		// no artefact when they name one. Nothing is lost by leaving it out: the
		// identity is inside the hashed shape, so records describing different
		// artefacts already carry different content hashes.
		//
		// THE SATELLITE REKEY, at the scale this ticket exists to reach.
		// interface_symbols was keyed on the COORDINATE and holds 3,437,655 rows,
		// two orders of magnitude past the example_index rekey that established the
		// pattern. Once a coordinate holds several records that key no longer says
		// which record a symbol belongs to, so a Partial extraction's symbols and a
		// complete one's collide on one row — which is precisely the distinction
		// the composition ladder is built on. The children are therefore rekeyed
		// onto the PARENT RECORD's identity, its content hash, unique per row
		// because extracted_at is inside the hashed shape.
		//
		// The back-fill is a join on the coordinate, which is exact here and only
		// here: measured read-only on the maintainer's store before the change, no
		// (path, version, pipeline) group held more than one interface_records row
		// (0 of 1,850) and no interface_symbols row failed to match one (0 of
		// 3,437,655). Every child has exactly one candidate parent and the join is
		// total — the property that stops being true the moment this migration
		// lands, which is why the rekey has to happen in the same step.
		//
		// The coordinate columns stay on the satellite as denormalised copies. They
		// are no longer identity — record_content_hash alone is — but every symbol
		// query answers with a coordinate, and joining 3.4M rows back to their
		// parents to render a result would be far more expensive than carrying
		// them.
		{Module: "iface", Version: 4, SQL: `
            CREATE TABLE interface_records_ledger (
                module_path        TEXT NOT NULL,
                module_version     TEXT NOT NULL,
                pipeline_version   TEXT NOT NULL,
                overall_status     INTEGER NOT NULL,
                package_count      INTEGER NOT NULL,
                extracted_at       TEXT NOT NULL,
                content_hash       TEXT NOT NULL,
                serialised         BLOB NOT NULL,
                PRIMARY KEY (module_path, module_version, pipeline_version, extracted_at, content_hash)
            );

            INSERT INTO interface_records_ledger (
                module_path, module_version, pipeline_version,
                overall_status, package_count, extracted_at, content_hash, serialised
            )
            SELECT
                module_path, module_version, pipeline_version,
                overall_status, package_count, extracted_at, content_hash, serialised
            FROM interface_records;

            CREATE TABLE interface_symbols_ledger (
                record_content_hash TEXT NOT NULL,
                module_path         TEXT NOT NULL,
                module_version      TEXT NOT NULL,
                pipeline_version    TEXT NOT NULL,
                package_path        TEXT NOT NULL,
                symbol_kind         TEXT NOT NULL,
                symbol_name         TEXT NOT NULL,
                parent_type         TEXT NOT NULL DEFAULT '',
                signature           TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (record_content_hash, package_path, symbol_kind, symbol_name, parent_type)
            );

            INSERT INTO interface_symbols_ledger (
                record_content_hash,
                module_path, module_version, pipeline_version,
                package_path, symbol_kind, symbol_name, parent_type, signature
            )
            SELECT
                r.content_hash,
                s.module_path, s.module_version, s.pipeline_version,
                s.package_path, s.symbol_kind, s.symbol_name, s.parent_type, s.signature
            FROM interface_symbols s
            JOIN interface_records r
              ON r.module_path      = s.module_path
             AND r.module_version   = s.module_version
             AND r.pipeline_version = s.pipeline_version;

            DROP TABLE interface_symbols;
            DROP TABLE interface_records;
            ALTER TABLE interface_records_ledger RENAME TO interface_records;
            ALTER TABLE interface_symbols_ledger RENAME TO interface_symbols;

            CREATE INDEX IF NOT EXISTS interface_symbols_lookup_idx
                ON interface_symbols(module_path, module_version, symbol_name);
            CREATE INDEX IF NOT EXISTS interface_symbols_name_pipeline_idx
                ON interface_symbols(symbol_name, pipeline_version);
            CREATE INDEX IF NOT EXISTS interface_records_generation_idx
                ON interface_records(module_path, module_version, pipeline_version, extracted_at)`},
	}
}

// Open opens (or creates) the SQLite database at dsn and runs migrations.
// Use ":memory:" for tests.
func Open(dsn string) (*Store, error) {
	db, err := sqlitestore.Open(dsn, Migrations(), sqlitestore.IntentCreate)
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

// PutInterfaceRecord appends an extraction to the ledger, together with the
// symbol rows belonging to it.
//
// It never updates. The record key carries the time of measurement and the
// record's own content hash, so two distinct extractions are always two rows; the
// symbol rows carry the parent record's content hash, so each generation's
// symbols are its own. The only collision left is the same record written twice,
// which the conflict clauses make a no-op because it is one measurement rather
// than two — and it must not be an error, or a retried write would fail a run
// that had already succeeded.
//
// The symbol rows are appended, never deleted. Deleting the previous
// generation's symbols is what an overwriting store had to do; here it would
// strand the earlier record with no API to resolve, which is the orphaning this
// conversion exists to prevent.
func (s *Store) PutInterfaceRecord(ctx context.Context, r domain2.InterfaceRecord) error {
	// A record whose coordinate is the zero value would key a row on the empty
	// path at the empty version, which every later read treats as a genuine
	// measurement of a module that does not exist.
	if r.Coordinate.IsZero() {
		return coordinate.ErrZeroCoordinate
	}
	// Every record this store holds is produced by an extraction that read a
	// fetched artefact, so one that cannot name which artefact is a fault in the
	// stage, not a legacy row. It matters more than the coordinate guard above:
	// composition reads the identity to decide which records describe the same
	// bytes, so a zero identity does not merely record nothing — it groups
	// together every record that also recorded nothing.
	//
	// The read leg deliberately does NOT refuse it. Records written before the
	// field existed carry an empty one legitimately, and refusing on read would
	// make every one of them unreadable. They are read, never rewritten, so the
	// write-leg refusal costs them nothing.
	if r.ArtefactIdentity == "" {
		return fmt.Errorf("interface record for %s names no artefact: %w", r.Coordinate, fetchdomain.ErrZeroIdentity)
	}
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
ON CONFLICT (module_path, module_version, pipeline_version, extracted_at, content_hash)
DO NOTHING`

	_, err = tx.ExecContext(ctx, qRecord,
		r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion,
		int(r.OverallStatus), len(r.Packages),
		r.ExtractedAt.UTC().Format(time.RFC3339),
		r.ContentHash, blob,
	)
	if err != nil {
		return fmt.Errorf("inserting interface record: %w", err)
	}

	const qSym = `
INSERT OR IGNORE INTO interface_symbols (
    record_content_hash,
    module_path, module_version, pipeline_version,
    package_path, symbol_kind, symbol_name, parent_type, signature
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	stmtSym, err := tx.PrepareContext(ctx, qSym)
	if err != nil {
		return fmt.Errorf("preparing interface symbol statement: %w", err)
	}
	defer func() { _ = stmtSym.Close() }()

	for _, pkg := range r.Packages {
		for _, t := range pkg.Types {
			if _, err := stmtSym.ExecContext(ctx,
				r.ContentHash,
				r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion,
				pkg.ImportPath, "type", t.Name, "", t.Signature,
			); err != nil {
				return fmt.Errorf("inserting type symbol %s: %w", t.Name, err)
			}
			for _, m := range t.Methods {
				if _, err := stmtSym.ExecContext(ctx,
					r.ContentHash,
					r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion,
					pkg.ImportPath, "method", m.Name, t.Name, m.Signature,
				); err != nil {
					return fmt.Errorf("inserting method symbol %s.%s: %w", t.Name, m.Name, err)
				}
			}
		}
		for _, f := range pkg.Funcs {
			if _, err := stmtSym.ExecContext(ctx,
				r.ContentHash,
				r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion,
				pkg.ImportPath, "func", f.Name, "", f.Signature,
			); err != nil {
				return fmt.Errorf("inserting func symbol %s: %w", f.Name, err)
			}
		}
		for _, c := range pkg.Consts {
			if _, err := stmtSym.ExecContext(ctx,
				r.ContentHash,
				r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion,
				pkg.ImportPath, "const", c.Name, "", c.Type,
			); err != nil {
				return fmt.Errorf("inserting const symbol %s: %w", c.Name, err)
			}
		}
		for _, v := range pkg.Vars {
			if _, err := stmtSym.ExecContext(ctx,
				r.ContentHash,
				r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion,
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

// GetInterfaceRecord returns the composed interface answer for the coordinate
// and pipeline version. Returns (zero, false, nil) when the ledger holds none.
//
// Composition serves a complete extraction over a Partial one, then the most
// recent. Recency alone never wins: a Partial record appended after a complete
// one missed at least one package to a parse failure, so it is a weaker
// measurement of the same API rather than a newer answer. See domain.Compose for
// the ladder and for the disagreements it refuses to resolve by picking.
//
// A stored record that fails its integrity check is still ErrInterfaceIntegrity,
// and it stops the read rather than being skipped: dropping it would serve a
// composition computed over fewer records than the ledger holds and report it as
// the whole answer.
func (s *Store) GetInterfaceRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (domain2.InterfaceRecord, bool, error) {
	records, err := s.ListInterfaceRecordsFor(ctx, coord, pipelineVersion)
	if err != nil {
		return domain2.InterfaceRecord{}, false, err
	}
	if len(records) == 0 {
		return domain2.InterfaceRecord{}, false, nil
	}
	composed, err := domain2.Compose(records)
	if err != nil {
		return domain2.InterfaceRecord{}, false, fmt.Errorf("%w: %w", ports.ErrInterfaceConflict, err)
	}
	return composed, true, nil
}

// ListInterfaceRecordsFor returns every generation the ledger holds for one
// coordinate and pipeline version, in the order they were appended.
//
// This is what makes the ledger observable, and for this domain it is also what
// makes a reported non-determination examinable: the two records that disagree
// are both still here, each naming the artefact it was computed from.
//
// The secondary sort is the row id, not the content hash. extracted_at persists
// at second precision — that is the precision the canonical hash covers — and
// two extractions within one second carry the same timestamp. The ledger is
// append-only, so insertion order is the sequence it actually has, and
// composition relies on it for local coordinates.
func (s *Store) ListInterfaceRecordsFor(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) ([]domain2.InterfaceRecord, error) {
	// The zero coordinate names no module, so this is a question about nothing.
	// Answering it with absence would report "no record here" for a module that
	// was never asked about — see coordinate.ErrZeroCoordinate.
	if coord.IsZero() {
		return nil, coordinate.ErrZeroCoordinate
	}
	const q = `SELECT serialised, content_hash FROM interface_records
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?
ORDER BY extracted_at ASC, rowid ASC`

	rows, err := s.db.DB().QueryContext(ctx, q, coord.Path(), coord.Version(), pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("querying interface records: %w", err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck // rows.Err() checked below
	}()

	var out []domain2.InterfaceRecord
	for rows.Next() {
		var blob []byte
		var storedHash string
		if serr := rows.Scan(&blob, &storedHash); serr != nil {
			return nil, fmt.Errorf("scanning interface record: %w", serr)
		}
		rec, rerr := decodeRecord(blob, storedHash)
		if rerr != nil {
			return nil, rerr
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating interface records: %w", err)
	}
	return out, nil
}

// decodeRecord turns one stored blob into a verified record. A row that cannot
// be decoded, verified or parsed is an error rather than an absence.
//
// Verification is recordseal.VerifyBlob rather than a re-marshal: this store has
// verified the stored bytes against the seal they carry from the start, which is
// why it never suffered the generation-drift bug the licence store did.
func decodeRecord(blob []byte, storedHash string) (domain2.InterfaceRecord, error) {
	raw, decErr := blobcodec.Decode(blob)
	if decErr != nil {
		return domain2.InterfaceRecord{}, fmt.Errorf("decompressing interface record: %w", decErr)
	}
	if verr := recordseal.VerifyBlob(raw, storedHash); verr != nil {
		return domain2.InterfaceRecord{}, fmt.Errorf("%w: %w", ports.ErrInterfaceIntegrity, verr)
	}
	var h domain2.InterfaceRecordHasher
	rec, err := h.Unmarshal(raw)
	if err != nil {
		return domain2.InterfaceRecord{}, fmt.Errorf("unmarshalling interface record: %w", err)
	}
	return rec, nil
}

// servedContentHash returns the content hash of the record composition serves for
// one coordinate and pipeline version, and whether the ledger holds any.
//
// It is how the satellite is resolved. Symbol rows are keyed on the parent
// record's content hash, so "does this module export X" is answered by first
// deciding which record answers "what does this module export", then taking that
// record's symbols. Taking the newest rows for the coordinate instead would be
// wrong in exactly the case the ladder exists for: composition can serve an
// OLDER record than the newest, and then a Partial extraction's symbols would be
// read as though they were the complete answer's.
//
// The single-generation case — every module in the store today — is answered
// from the column without decoding a blob, which matters at 3.4M symbol rows.
func (s *Store) servedContentHash(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (string, bool, error) {
	const q = `SELECT content_hash FROM interface_records
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?
LIMIT 2`
	rows, err := s.db.DB().QueryContext(ctx, q, coord.Path(), coord.Version(), pipelineVersion)
	if err != nil {
		return "", false, fmt.Errorf("querying interface generations for %s: %w", coord, err)
	}
	var hashes []string
	for rows.Next() {
		var h string
		if serr := rows.Scan(&h); serr != nil {
			_ = rows.Close() //nolint:errcheck // returning the scan error
			return "", false, fmt.Errorf("scanning interface generation hash: %w", serr)
		}
		hashes = append(hashes, h)
	}
	if cerr := rows.Err(); cerr != nil {
		_ = rows.Close() //nolint:errcheck // returning the iteration error
		return "", false, fmt.Errorf("iterating interface generations: %w", cerr)
	}
	if cerr := rows.Close(); cerr != nil {
		return "", false, fmt.Errorf("closing interface generation rows: %w", cerr)
	}

	switch len(hashes) {
	case 0:
		return "", false, nil
	case 1:
		return hashes[0], true, nil
	default:
		served, found, gerr := s.GetInterfaceRecord(ctx, coord, pipelineVersion)
		if gerr != nil {
			return "", false, gerr
		}
		return served.ContentHash, found, nil
	}
}

// ListInterfaceRecords returns one summary per module, pipeline version pair —
// the generation composition serves — ordered by extracted_at descending.
//
// One summary per module, not one per row. The ledger holds a row per
// extraction, so listing rows would show a re-extracted module once per
// generation, and an operator reading the list has no way to tell a second
// generation from a second module.
//
// Limit and offset are applied AFTER the collapse, so they count modules rather
// than rows. Applying them in SQL would let a module with three generations
// consume three places of a --limit 50, and the page an operator sees would
// depend on how many times each module happened to be re-extracted.
func (s *Store) ListInterfaceRecords(ctx context.Context, filter ports.InterfaceFilter) ([]ports.InterfaceSummary, error) {
	// No LIMIT or OFFSET here: paging happens after the collapse, on modules
	// rather than rows.
	const q = `SELECT module_path, module_version, pipeline_version,
	             overall_status, package_count, extracted_at, content_hash
	      FROM interface_records
	      ORDER BY extracted_at DESC, rowid DESC`

	rows, err := s.db.DB().QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("listing interface records: %w", err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck
	}()

	type generationKey struct{ path, version, pipeline string }
	var order []generationKey
	counts := map[generationKey]int{}
	first := map[generationKey]ports.InterfaceSummary{}

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

		k := generationKey{sum.ModulePath, sum.ModuleVersion, sum.PipelineVersion}
		if counts[k] == 0 {
			order = append(order, k)
			first[k] = sum
		}
		counts[k]++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating interface summaries: %w", err)
	}

	out := make([]ports.InterfaceSummary, 0, len(order))
	for _, k := range order {
		if counts[k] == 1 {
			// The overwhelming majority: one generation, so the columns already
			// describe the served record and no blob is decoded to learn it.
			out = append(out, first[k])
			continue
		}
		coord, cerr := coordinate.NewModuleCoordinate(k.path, k.version)
		if cerr != nil {
			return nil, fmt.Errorf("interface record %s@%s names no module: %w", k.path, k.version, cerr)
		}
		served, found, gerr := s.GetInterfaceRecord(ctx, coord, k.pipeline)
		if errors.Is(gerr, ports.ErrInterfaceConflict) {
			// Reported on the row, not raised as the list's error: see the comment
			// on InterfaceSummary.Conflict.
			out = append(out, ports.InterfaceSummary{
				ModulePath:      k.path,
				ModuleVersion:   k.version,
				PipelineVersion: k.pipeline,
				Conflict:        gerr,
			})
			continue
		}
		if gerr != nil {
			return nil, gerr
		}
		if !found {
			continue
		}
		out = append(out, ports.InterfaceSummary{
			ModulePath:      k.path,
			ModuleVersion:   k.version,
			PipelineVersion: k.pipeline,
			OverallStatus:   served.OverallStatus,
			PackageCount:    len(served.Packages),
			ExtractedAt:     served.ExtractedAt.UTC(),
			ContentHash:     served.ContentHash,
		})
	}

	return page(out, filter.Limit, filter.Offset), nil
}

// page applies the caller's limit and offset to the collapsed list.
func page(sums []ports.InterfaceSummary, limit, offset int) []ports.InterfaceSummary {
	if offset > 0 {
		if offset >= len(sums) {
			return nil
		}
		sums = sums[offset:]
	}
	if limit > 0 && limit < len(sums) {
		sums = sums[:limit]
	}
	return sums
}

// FindSymbol returns index entries for all packages that export a symbol with
// the given name, restricted to the modules in scope (see ports.InterfaceStore).
//
// The scope filter runs over the scanned rows rather than as a SQL predicate: a
// build's version set is a list of pairs, so expressing it in the WHERE clause
// costs one bound parameter per module, and a full-depth walk holds thousands.
func (s *Store) FindSymbol(ctx context.Context, symbolName string, pipelineVersion string, scope coordinate.ModuleSet) ([]ports.SymbolRef, error) {
	const q = `SELECT record_content_hash, module_path, module_version, pipeline_version,
	                   package_path, symbol_kind, symbol_name, parent_type, signature
	            FROM interface_symbols
	            WHERE symbol_name = ? AND pipeline_version = ?
	            ORDER BY module_path, module_version, package_path`

	rows, err := s.db.DB().QueryContext(ctx, q, symbolName, pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("querying interface symbols for %q: %w", symbolName, err)
	}
	candidates, err := scanSymbols(rows)
	if err != nil {
		return nil, err
	}

	inScope := candidates[:0]
	for _, c := range candidates {
		if !scope.ContainsPathVersion(c.ref.ModulePath, c.ref.ModuleVersion) {
			continue
		}
		inScope = append(inScope, c)
	}
	return s.servedSymbols(ctx, inScope, pipelineVersion)
}

// candidateSymbol is one symbol row together with the record it belongs to.
type candidateSymbol struct {
	recordHash string
	ref        ports.SymbolRef
}

// scanSymbols drains a symbol query into candidate rows.
func scanSymbols(rows *sql.Rows) (_ []candidateSymbol, retErr error) {
	defer func() {
		if cerr := rows.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("closing interface symbol rows: %w", cerr)
		}
	}()
	var out []candidateSymbol
	for rows.Next() {
		var c candidateSymbol
		if serr := rows.Scan(
			&c.recordHash,
			&c.ref.ModulePath, &c.ref.ModuleVersion, &c.ref.PipelineVersion,
			&c.ref.PackagePath, &c.ref.SymbolKind, &c.ref.SymbolName, &c.ref.ParentType, &c.ref.Signature,
		); serr != nil {
			return nil, fmt.Errorf("scanning symbol ref: %w", serr)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating symbol refs: %w", err)
	}
	return out, nil
}

// servedSymbols keeps the candidate rows that belong to the record composition
// serves for their module, and drops the rest.
//
// This is the read half of the satellite rekey. Without it a module holding two
// generations returns each symbol once per generation, and — worse — a Partial
// extraction's symbols would be indistinguishable from a complete one's, which
// is the distinction the whole composition ladder is built on.
//
// A module whose records are in conflict is omitted from the result and reported
// alongside it, rather than failing the whole query: a symbol lookup spans every
// module in the store, so one disputed module must not delete every correct
// answer. Callers get the refs AND a non-nil error, so nothing is dropped
// silently.
func (s *Store) servedSymbols(ctx context.Context, candidates []candidateSymbol, pipelineVersion string) ([]ports.SymbolRef, error) {
	type moduleKey struct{ path, version string }
	served := map[moduleKey]string{}
	var conflicts []error

	out := make([]ports.SymbolRef, 0, len(candidates))
	for _, c := range candidates {
		k := moduleKey{c.ref.ModulePath, c.ref.ModuleVersion}
		hash, resolved := served[k]
		if !resolved {
			coord, cerr := coordinate.NewModuleCoordinate(k.path, k.version)
			if cerr != nil {
				return nil, fmt.Errorf("interface symbol row %s@%s names no module: %w", k.path, k.version, cerr)
			}
			h, found, herr := s.servedContentHash(ctx, coord, pipelineVersion)
			switch {
			case errors.Is(herr, ports.ErrInterfaceConflict):
				conflicts = append(conflicts, herr)
				h = ""
			case herr != nil:
				return nil, herr
			case !found:
				// A symbol row whose parent record is not in the ledger. The write
				// path inserts both in one transaction and neither is ever deleted,
				// so this cannot arise from a completed write; reporting it is the
				// only way it does not become a silently short answer.
				return nil, fmt.Errorf("interface symbol row for %s@%s at pipeline %s has no record in the ledger",
					k.path, k.version, pipelineVersion)
			}
			hash = h
			served[k] = h
		}
		if hash == "" || c.recordHash != hash {
			continue
		}
		out = append(out, c.ref)
	}
	if len(conflicts) > 0 {
		return out, fmt.Errorf("%w: %d module(s) omitted: %w",
			ports.ErrInterfaceConflict, len(conflicts), errors.Join(conflicts...))
	}
	return out, nil
}

// Ensure Store implements ports.InterfaceStore and the optional history read at
// compile time.
var (
	_ ports.InterfaceStore        = (*Store)(nil)
	_ ports.InterfaceRecordLister = (*Store)(nil)
)
