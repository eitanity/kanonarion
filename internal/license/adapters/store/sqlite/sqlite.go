// Package sqlite implements ports.LicenseStore using a SQLite database via
// modernc.org/sqlite (pure Go, no CGO). The schema is versioned through a
// schema_migrations table shared with other contexts when using the same DB.
package sqlite

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/adapters/recordseal"

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
		// Migration v6: the pipeline 1.0.0 generation cannot verify itself. Two
		// fields were added to canonicalFileEntry without omitempty and without a
		// purge, so every 1.0.0 record carrying at least one licence file gained
		// two keys in its canonical JSON and its stored hash stopped describing
		// its contents. Measured on the maintainer's store through the store's own
		// read path: 643 rows at 1.0.0, of which 638 fail with ErrLicenceIntegrity
		// and 5 verify — exactly the five that carry no licence file and so emit no
		// canonicalFileEntry at all.
		//
		// Purged rather than rehashed. The hash is the evidence; recomputing it
		// over the current shape would manufacture a seal for a measurement nobody
		// re-made. Nothing is lost: every one of the 643 coordinates also holds a
		// row at 1.1.0, measured as an EXCEPT of the two generations returning 0,
		// so no module loses its only licence record. They are regenerable by
		// re-extracting in any case.
		//
		// Scoped to 1.0.0 rather than "everything that is not current". The claim
		// backing this delete is a measurement of one generation, and a predicate
		// that outlives the measurement would silently purge a future generation
		// nobody has examined.
		{Module: "license", Version: 6, SQL: `DELETE FROM licence_records WHERE pipeline_version = '1.0.0'`},
		// Migration v7: the ledger. The table is rebuilt because its primary key
		// changes. A key of (path, version, pipeline) makes every re-extraction
		// overwrite its predecessor, so the store cannot say what it previously
		// held — and a licence answer legitimately changes for one artefact. A
		// relicensing, a corrected detection or a classifier improvement all
		// destroyed the earlier finding, which is the one downstream fact with
		// legal weight and the one an audit asks about by date.
		//
		// The new key adds the time of measurement and the record's own content
		// hash, so every extraction that passes is its own row.
		//
		// The artefact identity is NOT a key column, unlike the fetch ledger's
		// module_hash. It is not merely redundant there — it is unavailable. The
		// identity lives inside the compressed record blob, migrations are SQL-only
		// and SQLite cannot decompress zstd, so a column added here could only be
		// back-filled with the empty string. Measured on the maintainer's store,
		// 176 of the 2,206 surviving rows already carry a real zip identity in
		// their blob, so that back-fill would state, in a key column, that 176
		// records describe no artefact when they name one. A later extraction of
		// those modules would then key on the true identity, and the two records
		// describing one artefact would land in different composition groups — a
		// ledger that cannot reconcile its own rows, which is the failure the epic
		// calls a leak rather than a ledger.
		//
		// Nothing is lost by leaving it out, because the identity is inside the
		// hashed shape: two records describing different artefacts necessarily
		// carry different content hashes, so the key already separates them, and
		// composition reads the identity from the record it has already decoded and
		// verified.
		//
		// ON CONFLICT DO NOTHING covers the one remaining collision: the
		// byte-identical record written twice. That is the same measurement, not a
		// second one, so dropping it discards no evidence — and it must not be an
		// error, or a retried write would fail a run that had already succeeded.
		//
		// Existing rows carry in as the first generation with no purge. Measured
		// through the store's own read path after migration 6, all 2,206 of them
		// still verify their content hashes, and no (coordinate, pipeline,
		// extracted_at, content_hash) key holds more than one row, so the rebuild
		// loses none of them.
		{Module: "license", Version: 7, SQL: `
            CREATE TABLE licence_records_ledger (
                module_path           TEXT NOT NULL,
                module_version        TEXT NOT NULL,
                pipeline_version      TEXT NOT NULL,
                primary_spdx          TEXT NOT NULL DEFAULT '',
                spdx_expression       TEXT NOT NULL DEFAULT '',
                overall_status        INTEGER NOT NULL,
                copyright_status      INTEGER NOT NULL DEFAULT 0,
                provenance_confidence INTEGER NOT NULL DEFAULT 0,
                extracted_at          TEXT NOT NULL,
                content_hash          TEXT NOT NULL,
                serialised            BLOB NOT NULL,
                PRIMARY KEY (module_path, module_version, pipeline_version, extracted_at, content_hash)
            );

            INSERT INTO licence_records_ledger (
                module_path, module_version, pipeline_version,
                primary_spdx, spdx_expression, overall_status, copyright_status,
                provenance_confidence, extracted_at, content_hash, serialised
            )
            SELECT
                module_path, module_version, pipeline_version,
                primary_spdx, spdx_expression, overall_status, copyright_status,
                provenance_confidence, extracted_at, content_hash, serialised
            FROM licence_records;

            DROP TABLE licence_records;
            ALTER TABLE licence_records_ledger RENAME TO licence_records;

            CREATE INDEX IF NOT EXISTS licence_records_spdx_idx
                ON licence_records(primary_spdx);
            CREATE INDEX IF NOT EXISTS licence_records_status_idx
                ON licence_records(overall_status);
            CREATE INDEX IF NOT EXISTS licence_records_copyright_status_idx
                ON licence_records(copyright_status);
            CREATE INDEX IF NOT EXISTS licence_records_provenance_confidence_idx
                ON licence_records(provenance_confidence);
            CREATE INDEX IF NOT EXISTS licence_records_generation_idx
                ON licence_records(module_path, module_version, pipeline_version, extracted_at)`},
	}
}

// Open opens (or creates) the SQLite database at dsn and runs migrations.
// Use ":memory:" for tests.
func Open(dsn string) (*Store, error) {
	db, err := sqlitestore.Open(dsn, Migrations(), sqlitestore.IntentCreate)
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

// PutLicenseRecord appends an extraction to the ledger.
//
// It never updates. The key carries the time of measurement and the record's own
// content hash, so two distinct extractions are always two rows. The only
// collision left is the same record written twice, which the conflict clause
// makes a no-op because it is one measurement rather than two.
//
// This is the property the whole conversion turns on. A licence answer
// legitimately changes for one artefact — a relicensing, a corrected detection, a
// classifier improvement — and an overwriting store destroyed the earlier finding
// every time, leaving "what did we believe in March, and on what evidence" with
// no evidence to read.
func (s *Store) PutLicenseRecord(ctx context.Context, r domain2.LicenseRecord) error {
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
		return fmt.Errorf("licence record for %s names no artefact: %w", r.Coordinate, fetchdomain.ErrZeroIdentity)
	}
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
ON CONFLICT (module_path, module_version, pipeline_version, extracted_at, content_hash)
DO NOTHING`

	_, err = s.db.DB().ExecContext(ctx, q,
		r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion,
		r.PrimarySPDX, r.Expression, int(r.OverallStatus), int(r.CopyrightStatus), int(r.Provenance.Confidence),
		r.ExtractedAt.UTC().Format(time.RFC3339),
		r.ContentHash, blob,
	)
	if err != nil {
		return fmt.Errorf("inserting license record: %w", err)
	}
	return nil
}

// GetLicenseRecord returns the composed licence answer for the coordinate and
// pipeline version. Returns (zero, false, nil) when the ledger holds none.
//
// Composition serves the highest-confidence extraction, then the most recent.
// Recency alone never wins: a classifier regression or a partial read must not
// displace a confident earlier detection merely by running later. See
// domain.Compose for the ladder and for the disagreements it refuses to resolve
// by picking.
//
// A stored record that fails its integrity check is still ErrLicenceIntegrity,
// and it stops the read rather than being skipped: dropping it would serve a
// composition computed over fewer records than the ledger holds and report it as
// the whole answer.
func (s *Store) GetLicenseRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (domain2.LicenseRecord, bool, error) {
	records, err := s.ListLicenseRecordsFor(ctx, coord, pipelineVersion)
	if err != nil {
		return domain2.LicenseRecord{}, false, err
	}
	if len(records) == 0 {
		return domain2.LicenseRecord{}, false, nil
	}
	composed, err := domain2.Compose(records)
	if err != nil {
		return domain2.LicenseRecord{}, false, fmt.Errorf("%w: %w", ports.ErrLicenceConflict, err)
	}
	return composed, true, nil
}

// ListLicenseRecordsFor returns every generation the ledger holds for one
// coordinate and pipeline version, in the order they were appended.
//
// This is what makes the ledger observable: the earlier finding is still here,
// naming the artefact it was computed from, after a later extraction has changed
// the served answer.
//
// The secondary sort is the row id, not the content hash. extracted_at persists
// at second precision — that is the precision the canonical hash covers, so
// widening the column would put the stored hashes and the stored time out of
// step — and two extractions within one second carry the same timestamp. The
// ledger is append-only, so insertion order is the sequence it actually has, and
// composition relies on it for local coordinates.
func (s *Store) ListLicenseRecordsFor(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) ([]domain2.LicenseRecord, error) {
	// The zero coordinate names no module, so this is a question about nothing.
	// Answering it with absence would report "no record here" for a module that
	// was never asked about — see coordinate.ErrZeroCoordinate.
	if coord.IsZero() {
		return nil, coordinate.ErrZeroCoordinate
	}
	const q = `SELECT serialised FROM licence_records
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?
ORDER BY extracted_at ASC, rowid ASC`

	rows, err := s.db.DB().QueryContext(ctx, q, coord.Path(), coord.Version(), pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("querying license records: %w", err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck // rows.Err() checked below
	}()

	var out []domain2.LicenseRecord
	for rows.Next() {
		var blob []byte
		if serr := rows.Scan(&blob); serr != nil {
			return nil, fmt.Errorf("scanning license record: %w", serr)
		}
		rec, rerr := decodeRecord(blob)
		if rerr != nil {
			return nil, rerr
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating license records: %w", err)
	}
	return out, nil
}

// decodeRecord turns one stored blob into a verified record. A row that cannot
// be decoded, parsed or verified is an error rather than an absence.
func decodeRecord(blob []byte) (domain2.LicenseRecord, error) {
	raw, decErr := blobcodec.Decode(blob)
	if decErr != nil {
		return domain2.LicenseRecord{}, fmt.Errorf("decompressing license record: %w", decErr)
	}
	var h domain2.LicenseRecordHasher
	rec, err := h.Unmarshal(raw)
	if err != nil {
		return domain2.LicenseRecord{}, fmt.Errorf("unmarshalling license record: %w", err)
	}
	if verr := h.VerifyContentHash(rec); verr != nil {
		// A record this build cannot reproduce is not necessarily a record that
		// has been altered. recordseal decides which, on the stored bytes alone.
		return domain2.LicenseRecord{}, fmt.Errorf("%w: %w",
			ports.ErrLicenceIntegrity, recordseal.Classify(raw, rec.ContentHash, verr))
	}
	return rec, nil
}

// ListLicenseRecords returns one summary per module, pipeline version pair —
// the generation composition serves — ordered by extracted_at descending.
//
// One summary per module, not one per row. The ledger holds a row per
// extraction, so listing rows would show a re-extracted module once per
// generation, which is exactly the duplicate listing migration 6 removed: an
// operator reading the list has no way to tell a second generation from a second
// module. The list therefore answers the same question the composed read does.
//
// Limit and offset are applied AFTER the collapse, so they count modules rather
// than rows. Applying them in SQL would let a module with three generations
// consume three places of a --limit 50, and the page an operator sees would
// depend on how many times each module happened to be re-extracted.
func (s *Store) ListLicenseRecords(ctx context.Context, filter ports.LicenseFilter) ([]ports.LicenseSummary, error) {
	q, args := buildListQuery(filter)
	rows, err := s.db.DB().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing license records: %w", err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck // rows.Err() checked below
	}()

	type generationKey struct{ path, version, pipeline string }
	var order []generationKey
	counts := map[generationKey]int{}
	first := map[generationKey]ports.LicenseSummary{}

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

		k := generationKey{sum.ModulePath, sum.ModuleVersion, sum.PipelineVersion}
		if counts[k] == 0 {
			order = append(order, k)
			first[k] = sum
		}
		counts[k]++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating license summaries: %w", err)
	}

	out := make([]ports.LicenseSummary, 0, len(order))
	for _, k := range order {
		if counts[k] == 1 {
			// The overwhelming majority: one generation, so the columns already
			// describe the served record and no blob is decoded to learn it.
			out = append(out, first[k])
			continue
		}
		coord, cerr := coordinate.NewModuleCoordinate(k.path, k.version)
		if cerr != nil {
			return nil, fmt.Errorf("license record %s@%s names no module: %w", k.path, k.version, cerr)
		}
		// A filter narrows which ROWS are listed, but composition is defined over
		// every record describing the artefact — composing the filtered subset
		// would serve a record chosen from a ladder missing its own top.
		served, found, gerr := s.GetLicenseRecord(ctx, coord, k.pipeline)
		if errors.Is(gerr, ports.ErrLicenceConflict) {
			// Reported on the row, not raised as the list's error: see the comment
			// on LicenseSummary.Conflict.
			out = append(out, ports.LicenseSummary{
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
		out = append(out, ports.LicenseSummary{
			ModulePath:      k.path,
			ModuleVersion:   k.version,
			PipelineVersion: k.pipeline,
			PrimarySPDX:     served.PrimarySPDX,
			Expression:      served.Expression,
			OverallStatus:   served.OverallStatus,
			ExtractedAt:     served.ExtractedAt.UTC(),
			ContentHash:     served.ContentHash,
		})
	}

	return page(out, filter.Limit, filter.Offset), nil
}

// page applies the caller's limit and offset to the collapsed list.
func page(sums []ports.LicenseSummary, limit, offset int) []ports.LicenseSummary {
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

	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	// No LIMIT or OFFSET here: paging happens after the collapse, on modules
	// rather than rows.
	q += " ORDER BY extracted_at DESC, rowid DESC"
	return q, args
}

// Ensure Store implements ports.LicenseStore and the optional history read at
// compile time.
var (
	_ ports.LicenseStore        = (*Store)(nil)
	_ ports.LicenceRecordLister = (*Store)(nil)
)
