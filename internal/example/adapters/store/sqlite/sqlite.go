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

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
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
		// Migration v3: the ledger, and the satellite rekey that comes with it.
		//
		// Both tables are rebuilt because both primary keys change. A key of
		// (path, version, pipeline) made every re-extraction overwrite its
		// predecessor, so the store could not say what it previously held — and an
		// example extraction legitimately changes for one artefact when a parse
		// failure clears: a toolchain that can now build a package, a loader
		// failure that has gone away. The earlier answer was destroyed each time,
		// which is precisely the evidence an investigation into a changed answer
		// needs to read.
		//
		// The record key adds the time of measurement and the record's own content
		// hash, so every extraction that passes is its own row. ON CONFLICT DO
		// NOTHING covers the one collision left: the byte-identical record written
		// twice, which is the same measurement rather than a second one.
		//
		// The artefact identity is NOT a key column, for the reason measured on the
		// licence conversion and re-measured here. It lives inside the compressed
		// record blob, migrations are SQL-only and SQLite cannot decompress zstd,
		// so a column added here could only be back-filled with the empty string.
		// Measured read-only on the maintainer's store, 177 of the 1,847 rows
		// already carry a real "zip:h1:..." identity in their blob, so that
		// back-fill would state in a key column that 177 records describe no
		// artefact when they name one — and the next extraction of those modules,
		// keying on the true identity, would land in a different composition group
		// from the record it is meant to be compared against. Nothing is lost by
		// leaving it out: the identity is inside the hashed shape, so records
		// describing different artefacts already carry different content hashes.
		//
		// THE SATELLITE REKEY is the half this conversion exists to establish.
		// example_index was keyed on the COORDINATE. Once a coordinate holds
		// several records that key no longer says which record a child belongs to,
		// so children of two generations collide on one row and a reader cannot
		// tell a partial extraction's examples from a clean one's. The children are
		// therefore rekeyed onto the PARENT RECORD's identity — its content hash —
		// which is unique per row because extracted_at is inside the hashed shape.
		//
		// The back-fill is a join on the coordinate, which is exact here and only
		// here: measured read-only on the maintainer's store before the change, no
		// (path, version, pipeline) group held more than one example_records row
		// (0 of 1,847) and no example_index row failed to match one (0 of 23,209).
		// So every child has exactly one candidate parent and the join is
		// total — the property that stops being true the moment this migration
		// lands, which is why the rekey has to happen in the same step.
		//
		// The coordinate columns stay on the satellite as denormalised copies. They
		// are no longer identity — record_content_hash alone is — but every symbol
		// query answers with a coordinate, and reading it from the child avoids
		// joining 23,209 rows back to their parents to render a result.
		{Module: "example", Version: 3, SQL: `
            CREATE TABLE example_records_ledger (
                module_path        TEXT NOT NULL,
                module_version     TEXT NOT NULL,
                pipeline_version   TEXT NOT NULL,
                overall_status     INTEGER NOT NULL,
                example_count      INTEGER NOT NULL,
                extracted_at       TEXT NOT NULL,
                content_hash       TEXT NOT NULL,
                serialised         BLOB NOT NULL,
                PRIMARY KEY (module_path, module_version, pipeline_version, extracted_at, content_hash)
            );

            INSERT INTO example_records_ledger (
                module_path, module_version, pipeline_version,
                overall_status, example_count, extracted_at, content_hash, serialised
            )
            SELECT
                module_path, module_version, pipeline_version,
                overall_status, example_count, extracted_at, content_hash, serialised
            FROM example_records;

            CREATE TABLE example_index_ledger (
                record_content_hash TEXT NOT NULL,
                module_path         TEXT NOT NULL,
                module_version      TEXT NOT NULL,
                pipeline_version    TEXT NOT NULL,
                package_path        TEXT NOT NULL,
                associated_symbol   TEXT NOT NULL,
                example_name        TEXT NOT NULL,
                validates           INTEGER NOT NULL,
                PRIMARY KEY (record_content_hash, package_path, associated_symbol, example_name)
            );

            INSERT INTO example_index_ledger (
                record_content_hash,
                module_path, module_version, pipeline_version,
                package_path, associated_symbol, example_name, validates
            )
            SELECT
                r.content_hash,
                i.module_path, i.module_version, i.pipeline_version,
                i.package_path, i.associated_symbol, i.example_name, i.validates
            FROM example_index i
            JOIN example_records r
              ON r.module_path      = i.module_path
             AND r.module_version   = i.module_version
             AND r.pipeline_version = i.pipeline_version;

            DROP TABLE example_index;
            DROP TABLE example_records;
            ALTER TABLE example_records_ledger RENAME TO example_records;
            ALTER TABLE example_index_ledger RENAME TO example_index;

            CREATE INDEX IF NOT EXISTS example_index_symbol_idx
                ON example_index(module_path, associated_symbol);
            CREATE INDEX IF NOT EXISTS example_index_symbol_pipeline_idx
                ON example_index(associated_symbol, pipeline_version);
            CREATE INDEX IF NOT EXISTS example_records_generation_idx
                ON example_records(module_path, module_version, pipeline_version, extracted_at)`},
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

// PutExampleRecord appends an extraction to the ledger, together with the index
// rows belonging to it.
//
// It never updates. The record key carries the time of measurement and the
// record's own content hash, so two distinct extractions are always two rows; the
// index rows carry the parent record's content hash, so each generation's
// children are its own. The only collision left is the same record written twice,
// which the conflict clauses make a no-op because it is one measurement rather
// than two — and it must not be an error, or a retried write would fail a run
// that had already succeeded.
//
// The index rows are appended, never deleted. Deleting the previous generation's
// children is what an overwriting store had to do; here it would strand the
// earlier record with no examples to resolve, which is the orphaning this
// conversion exists to prevent.
func (s *Store) PutExampleRecord(ctx context.Context, r domain2.ExampleRecord) error {
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
		return fmt.Errorf("example record for %s names no artefact: %w", r.Coordinate, fetchdomain.ErrZeroIdentity)
	}
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
ON CONFLICT (module_path, module_version, pipeline_version, extracted_at, content_hash)
DO NOTHING`

	_, err = tx.ExecContext(ctx, qRecord,
		r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion,
		int(r.OverallStatus), len(r.Examples),
		r.ExtractedAt.UTC().Format(time.RFC3339),
		r.ContentHash, blob,
	)
	if err != nil {
		return fmt.Errorf("inserting example record: %w", err)
	}

	const qIdx = `
INSERT INTO example_index (
    record_content_hash,
    module_path, module_version, pipeline_version,
    package_path, associated_symbol, example_name, validates
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (record_content_hash, package_path, associated_symbol, example_name)
DO NOTHING`

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
			r.ContentHash,
			r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion,
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

// GetExampleRecord returns the composed example answer for the coordinate and
// pipeline version. Returns (zero, false, nil) when the ledger holds none.
//
// Composition serves a completed extraction over a failed one, then the fewest
// parse failures, then the most recent. Recency alone never wins: an extraction
// that regresses to more parse failures must not displace a cleaner earlier one
// merely by running later. See domain.Compose for the ladder and for the
// disagreement it refuses to resolve by picking.
//
// A stored record that fails its integrity check is still ErrExampleIntegrity,
// and it stops the read rather than being skipped: dropping it would serve a
// composition computed over fewer records than the ledger holds and report it as
// the whole answer.
func (s *Store) GetExampleRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (domain2.ExampleRecord, bool, error) {
	records, err := s.ListExampleRecordsFor(ctx, coord, pipelineVersion)
	if err != nil {
		return domain2.ExampleRecord{}, false, err
	}
	if len(records) == 0 {
		return domain2.ExampleRecord{}, false, nil
	}
	composed, err := domain2.Compose(records)
	if err != nil {
		return domain2.ExampleRecord{}, false, fmt.Errorf("%w: %w", ports.ErrExampleConflict, err)
	}
	return composed, true, nil
}

// ListExampleRecordsFor returns every generation the ledger holds for one
// coordinate and pipeline version, in the order they were appended.
//
// This is what makes the ledger observable: the earlier extraction is still
// here, naming the artefact it was computed from, after a later one has changed
// the served answer.
//
// The secondary sort is the row id, not the content hash. extracted_at persists
// at second precision — that is the precision the canonical hash covers, so
// widening the column would put the stored hashes and the stored time out of
// step — and two extractions within one second carry the same timestamp. The
// ledger is append-only, so insertion order is the sequence it actually has, and
// composition relies on it for local coordinates.
func (s *Store) ListExampleRecordsFor(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) ([]domain2.ExampleRecord, error) {
	// The zero coordinate names no module, so this is a question about nothing.
	// Answering it with absence would report "no record here" for a module that
	// was never asked about — see coordinate.ErrZeroCoordinate.
	if coord.IsZero() {
		return nil, coordinate.ErrZeroCoordinate
	}
	const q = `SELECT serialised FROM example_records
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?
ORDER BY extracted_at ASC, rowid ASC`

	rows, err := s.db.DB().QueryContext(ctx, q, coord.Path(), coord.Version(), pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("querying example records: %w", err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck // rows.Err() checked below
	}()

	var out []domain2.ExampleRecord
	for rows.Next() {
		var blob []byte
		if serr := rows.Scan(&blob); serr != nil {
			return nil, fmt.Errorf("scanning example record: %w", serr)
		}
		rec, rerr := decodeRecord(blob)
		if rerr != nil {
			return nil, rerr
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating example records: %w", err)
	}
	return out, nil
}

// decodeRecord turns one stored blob into a verified record. A row that cannot
// be decoded, parsed or verified is an error rather than an absence.
func decodeRecord(blob []byte) (domain2.ExampleRecord, error) {
	raw, decErr := blobcodec.Decode(blob)
	if decErr != nil {
		return domain2.ExampleRecord{}, fmt.Errorf("decompressing example record: %w", decErr)
	}
	var h domain2.ExampleRecordHasher
	rec, err := h.Unmarshal(raw)
	if err != nil {
		return domain2.ExampleRecord{}, fmt.Errorf("unmarshalling example record: %w", err)
	}
	if verr := h.VerifyContentHash(rec); verr != nil {
		// A record this build cannot reproduce is not necessarily one that has
		// been altered. recordseal decides which, on the stored bytes alone.
		return domain2.ExampleRecord{}, fmt.Errorf("%w: %w",
			ports.ErrExampleIntegrity, recordseal.Classify(raw, rec.ContentHash, verr))
	}
	return rec, nil
}

// servedContentHash returns the content hash of the record composition serves
// for one coordinate and pipeline version, and whether the ledger holds any.
//
// It is how the satellite is resolved. Index rows are keyed on the parent
// record's content hash, so "which examples does this module have" is answered
// by first deciding which record answers "what did we find", then taking that
// record's children. Taking the newest rows for the coordinate instead would be
// wrong in exactly the case the ladder exists for: composition can serve an
// OLDER record than the newest, and then the newest generation's children are
// not the ones a reader wants.
//
// The single-generation case — every module in the store today — is answered
// from the column without decoding a blob.
func (s *Store) servedContentHash(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (string, bool, error) {
	const q = `SELECT content_hash FROM example_records
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?
LIMIT 2`
	rows, err := s.db.DB().QueryContext(ctx, q, coord.Path(), coord.Version(), pipelineVersion)
	if err != nil {
		return "", false, fmt.Errorf("querying example generations for %s: %w", coord, err)
	}
	var hashes []string
	for rows.Next() {
		var h string
		if serr := rows.Scan(&h); serr != nil {
			_ = rows.Close() //nolint:errcheck // returning the scan error
			return "", false, fmt.Errorf("scanning example generation hash: %w", serr)
		}
		hashes = append(hashes, h)
	}
	if cerr := rows.Err(); cerr != nil {
		_ = rows.Close() //nolint:errcheck // returning the iteration error
		return "", false, fmt.Errorf("iterating example generations: %w", cerr)
	}
	if cerr := rows.Close(); cerr != nil {
		return "", false, fmt.Errorf("closing example generation rows: %w", cerr)
	}

	switch len(hashes) {
	case 0:
		return "", false, nil
	case 1:
		return hashes[0], true, nil
	default:
		served, found, gerr := s.GetExampleRecord(ctx, coord, pipelineVersion)
		if gerr != nil {
			return "", false, gerr
		}
		return served.ContentHash, found, nil
	}
}

// ListExampleRecords returns one summary per module, pipeline version pair —
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
func (s *Store) ListExampleRecords(ctx context.Context, filter ports.ExampleFilter) ([]ports.ExampleSummary, error) {
	// No LIMIT or OFFSET here: paging happens after the collapse, on modules
	// rather than rows.
	const q = `SELECT module_path, module_version, pipeline_version,
	             overall_status, example_count, extracted_at, content_hash
	      FROM example_records
	      ORDER BY extracted_at DESC, rowid DESC`

	rows, err := s.db.DB().QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("listing example records: %w", err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck // rows.Err() checked below
	}()

	type generationKey struct{ path, version, pipeline string }
	var order []generationKey
	counts := map[generationKey]int{}
	first := map[generationKey]ports.ExampleSummary{}

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

		k := generationKey{sum.ModulePath, sum.ModuleVersion, sum.PipelineVersion}
		if counts[k] == 0 {
			order = append(order, k)
			first[k] = sum
		}
		counts[k]++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating example summaries: %w", err)
	}

	out := make([]ports.ExampleSummary, 0, len(order))
	for _, k := range order {
		if counts[k] == 1 {
			// The overwhelming majority: one generation, so the columns already
			// describe the served record and no blob is decoded to learn it.
			out = append(out, first[k])
			continue
		}
		coord, cerr := coordinate.NewModuleCoordinate(k.path, k.version)
		if cerr != nil {
			return nil, fmt.Errorf("example record %s@%s names no module: %w", k.path, k.version, cerr)
		}
		served, found, gerr := s.GetExampleRecord(ctx, coord, k.pipeline)
		if errors.Is(gerr, ports.ErrExampleConflict) {
			// Reported on the row, not raised as the list's error: see the comment
			// on ExampleSummary.Conflict.
			out = append(out, ports.ExampleSummary{
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
		out = append(out, ports.ExampleSummary{
			ModulePath:      k.path,
			ModuleVersion:   k.version,
			PipelineVersion: k.pipeline,
			OverallStatus:   served.OverallStatus,
			ExampleCount:    len(served.Examples),
			ExtractedAt:     served.ExtractedAt.UTC(),
			ContentHash:     served.ContentHash,
		})
	}

	return page(out, filter.Limit, filter.Offset), nil
}

// page applies the caller's limit and offset to the collapsed list.
func page(sums []ports.ExampleSummary, limit, offset int) []ports.ExampleSummary {
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

// FindBySymbol returns index entries for all examples associated with the
// given symbol, filtered by pipeline version and restricted to the modules in
// scope (the zero ModuleSet imposes no restriction, matching every stored
// version — see ports.ExampleStore).
// The symbol may be qualified with a package name (e.g. "modfile.File") or
// unqualified (e.g. "File"); both forms are matched against the stored
// associated_symbol column which holds unqualified names like "File" or
// "Client.Do".
func (s *Store) FindBySymbol(ctx context.Context, symbol string, pipelineVersion string, scope coordinate.ModuleSet) ([]ports.ExampleRef, error) {
	const q = `SELECT record_content_hash, module_path, module_version, pipeline_version,
	                   package_path, associated_symbol, example_name, validates
	            FROM example_index
	            WHERE associated_symbol = ? AND pipeline_version = ?
	            ORDER BY module_path, module_version, example_name`

	rows, err := s.db.DB().QueryContext(ctx, q, unqualify(symbol), pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("querying example index for %q: %w", symbol, err)
	}
	candidates, err := scanRefs(rows)
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
	return s.servedRefs(ctx, inScope, pipelineVersion)
}

// candidateRef is one index row together with the record it belongs to.
type candidateRef struct {
	recordHash string
	ref        ports.ExampleRef
}

// scanRefs drains an index query into candidate rows.
func scanRefs(rows *sql.Rows) (_ []candidateRef, retErr error) {
	defer func() {
		if cerr := rows.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("closing example index rows: %w", cerr)
		}
	}()
	var out []candidateRef
	for rows.Next() {
		var c candidateRef
		var validates int
		if serr := rows.Scan(
			&c.recordHash,
			&c.ref.ModulePath, &c.ref.ModuleVersion, &c.ref.PipelineVersion,
			&c.ref.Package, &c.ref.AssociatedSymbol, &c.ref.ExampleName, &validates,
		); serr != nil {
			return nil, fmt.Errorf("scanning example ref: %w", serr)
		}
		c.ref.Validates = validates != 0
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating example refs: %w", err)
	}
	return out, nil
}

// servedRefs keeps the candidate rows that belong to the record composition
// serves for their module, and drops the rest.
//
// This is the read half of the satellite rekey. Without it a module holding two
// generations returns each of its examples once per generation — the duplicate
// listing the ledger would otherwise reintroduce — and, worse, a partial
// extraction's examples would be indistinguishable from a clean one's.
//
// A module whose records are in conflict is omitted from the result and reported
// alongside it, rather than failing the whole query: one disputed module must not
// delete the answers for every other module. Callers get the refs AND a non-nil
// error, so nothing is dropped silently.
func (s *Store) servedRefs(ctx context.Context, candidates []candidateRef, pipelineVersion string) ([]ports.ExampleRef, error) {
	type moduleKey struct{ path, version string }
	served := map[moduleKey]string{}
	var conflicts []error

	out := make([]ports.ExampleRef, 0, len(candidates))
	for _, c := range candidates {
		k := moduleKey{c.ref.ModulePath, c.ref.ModuleVersion}
		hash, resolved := served[k]
		if !resolved {
			coord, cerr := coordinate.NewModuleCoordinate(k.path, k.version)
			if cerr != nil {
				return nil, fmt.Errorf("example index row %s@%s names no module: %w", k.path, k.version, cerr)
			}
			h, found, herr := s.servedContentHash(ctx, coord, pipelineVersion)
			switch {
			case errors.Is(herr, ports.ErrExampleConflict):
				conflicts = append(conflicts, herr)
				h = ""
			case herr != nil:
				return nil, herr
			case !found:
				// An index row whose parent record is not in the ledger. The write
				// path inserts both in one transaction and neither is ever deleted,
				// so this cannot arise from a completed write; reporting it is the
				// only way it does not become a silently short answer.
				return nil, fmt.Errorf("example index row for %s@%s at pipeline %s has no record in the ledger",
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
			ports.ErrExampleConflict, len(conflicts), errors.Join(conflicts...))
	}
	return out, nil
}

// unqualify strips a leading package segment from a symbol, so a caller may pass
// either "modfile.File" or "File" and match the unqualified form the index
// stores.
func unqualify(symbol string) string {
	before, after, ok := strings.Cut(symbol, ".")
	if !ok {
		return symbol
	}
	// Check whether the first segment looks like a package name (all
	// lowercase). If so, drop it.
	pkg := before
	if pkg != "" && strings.ToLower(pkg) == pkg {
		return after
	}
	return symbol
}

// FindBySymbolInModule returns index entries for examples associated with the
// given symbol within a specific module@version. Applies the same
// package-qualification stripping as FindBySymbol.
func (s *Store) FindBySymbolInModule(ctx context.Context, coord coordinate.ModuleCoordinate, symbol string, pipelineVersion string) ([]ports.ExampleRef, error) {
	// The zero coordinate names no module, so this is a question about nothing.
	// Answering it with absence would report "no record here" for a module that
	// was never asked about — see coordinate.ErrZeroCoordinate.
	if coord.IsZero() {
		return nil, coordinate.ErrZeroCoordinate
	}

	const q = `SELECT record_content_hash, module_path, module_version, pipeline_version,
	                   package_path, associated_symbol, example_name, validates
	            FROM example_index
	            WHERE module_path = ? AND module_version = ?
	              AND associated_symbol = ? AND pipeline_version = ?
	            ORDER BY example_name`

	rows, err := s.db.DB().QueryContext(ctx, q, coord.Path(), coord.Version(), unqualify(symbol), pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("querying example index for %q in %s: %w", symbol, coord, err)
	}
	candidates, err := scanRefs(rows)
	if err != nil {
		return nil, err
	}
	return s.servedRefs(ctx, candidates, pipelineVersion)
}

// Ensure Store implements ports.ExampleStore and the optional history read at
// compile time.
var (
	_ ports.ExampleStore        = (*Store)(nil)
	_ ports.ExampleRecordLister = (*Store)(nil)
)
