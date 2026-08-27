// Package sqlite implements ports.FactStore using a SQLite database via
// modernc.org/sqlite (pure Go, no CGO). The schema is versioned through a
// schema_migrations table.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

// fetchedAtFormat is how a measurement's time is PERSISTED: RFC3339 in UTC with
// a fixed-width nanosecond fraction, matching domain.CanonicalTimeFormat.
//
// Sub-second resolution is for forensics. A second-precision timestamp cannot
// order two measurements taken within one second, and correlating the ledger
// against the assurance log or an external trace is exactly the situation where
// that ordering is the question being asked.
//
// The fraction is FIXED WIDTH — nine digits always — because SQLite orders a
// TEXT column lexicographically and time.RFC3339Nano strips trailing zeros. With
// a variable-width fraction "…T12:00:00Z" sorts AFTER "…T12:00:00.123Z" ('Z' is
// 0x5A, '.' is 0x2E), so the ledger's own sequence would come back reversed
// within a second.
//
// Records written before sub-second measurement existed are NOT rewritten into
// this form. Their stored hashes cover a second-precision time, so rewriting the
// column would be a rehash of the whole store; the canonical encoding follows
// the value instead, and those records keep verifying untouched. The two
// generations differ in width, so a legacy row and a new row sharing one second
// would sort by width rather than by time — reachable only in the second that
// spans the upgrade, and rowid is the tiebreaker the sequence actually relies on.
const fetchedAtFormat = "2006-01-02T15:04:05.000000000Z07:00"

// Store is the SQLite-backed fact store.
type Store struct {
	db sqlitestore.DB
}

// Migrations returns the schema migrations for the fetch module.
func Migrations() []sqlitestore.Migration {
	return []sqlitestore.Migration{
		{Module: "fetch", Version: 1, SQL: `CREATE TABLE IF NOT EXISTS fetch_records (
            module_path         TEXT NOT NULL,
            module_version      TEXT NOT NULL,
            pipeline_version    TEXT NOT NULL,
            schema_version      TEXT NOT NULL,
            module_hash         TEXT NOT NULL,
            go_mod_hash         TEXT NOT NULL,
            git_url             TEXT NOT NULL DEFAULT '',
            git_ref             TEXT NOT NULL DEFAULT '',
            git_commit_hash     TEXT NOT NULL DEFAULT '',
            verification_status TEXT NOT NULL,
            verification_detail TEXT NOT NULL DEFAULT '',
            fetched_at          TEXT NOT NULL,
            content_location    TEXT NOT NULL,
            content_hash        TEXT NOT NULL,
            PRIMARY KEY (module_path, module_version, pipeline_version)
        )`},
		{Module: "fetch", Version: 2, SQL: `ALTER TABLE fetch_records ADD COLUMN retracted BOOLEAN NOT NULL DEFAULT 0`},
		{Module: "fetch", Version: 3, SQL: `ALTER TABLE fetch_records ADD COLUMN go_mod_location TEXT NOT NULL DEFAULT ''`},
		{Module: "fetch", Version: 4, SQL: `ALTER TABLE fetch_records ADD COLUMN ecosystem TEXT NOT NULL DEFAULT 'go'`},
		{Module: "fetch", Version: 5, SQL: `CREATE TABLE IF NOT EXISTS fetch_attestations (
            module_path       TEXT NOT NULL,
            module_version    TEXT NOT NULL,
            pipeline_version  TEXT NOT NULL,
            subject_kind      TEXT NOT NULL,
            subject_algorithm TEXT NOT NULL,
            subject_digest    TEXT NOT NULL,
            bundle            BLOB NOT NULL,
            signed_at         TEXT NOT NULL,
            PRIMARY KEY (module_path, module_version, pipeline_version, subject_kind, subject_digest)
        )`},
		{Module: "fetch", Version: 6, SQL: `
            ALTER TABLE fetch_records ADD COLUMN zip_sha256 TEXT NOT NULL DEFAULT '';
            ALTER TABLE fetch_records ADD COLUMN zip_sha384 TEXT NOT NULL DEFAULT '';
            ALTER TABLE fetch_records ADD COLUMN zip_sha512 TEXT NOT NULL DEFAULT '';`},
		// A record written before this column existed defaults to 0, which reads as
		// "the lookup did not fail" and so stays cache-eligible. That is the honest
		// default: those records were written by a pipeline that could not
		// distinguish the two cases, and re-verifying every one of them on the
		// strength of an absent column would invalidate the whole store.
		{Module: "fetch", Version: 7, SQL: `ALTER TABLE fetch_records ADD COLUMN sumdb_lookup_failed BOOLEAN NOT NULL DEFAULT 0`},
		// A record written before this column existed defaults to '', which reads
		// as "the mode was not recorded" rather than guessing one from the handle
		// shape. The empty value is omitted from the canonical JSON, so those
		// records verify their content hash unchanged.
		{Module: "fetch", Version: 8, SQL: `ALTER TABLE fetch_records ADD COLUMN acquisition_mode TEXT NOT NULL DEFAULT ''`},
		// The ledger migration. The table is rebuilt because its primary key
		// changes: a key of (path, version, pipeline) makes every re-measurement
		// overwrite its predecessor, which is how the store came to contradict its
		// own audit log — fifteen recorded writes for one coordinate, one surviving
		// row, and no evidence left to explain what changed.
		//
		// The new key adds the artefact hash, the time of measurement and the
		// record's own content hash, so every measurement that passes is its own
		// row.
		//
		// content_hash is a TIEBREAKER, not the key. Keying on it alone would be
		// wrong — the canonical hash covers fetched_at, so 19,537 of 19,655
		// historical writes carried a distinct one and the ledger would grow once
		// per fetch attempt rather than once per artefact. But two DIFFERENT
		// measurements can share an instant: a coarse clock, or a fixed one, gives
		// them the same fetched_at, and without the tiebreaker the second would
		// collide with the first and be lost. Losing a measurement is precisely
		// what this ticket exists to stop, so the key distinguishes them.
		//
		// ON CONFLICT DO NOTHING then covers the one remaining collision: the
		// byte-identical record written twice. That is the same measurement, not a
		// second one, so dropping it discards no evidence — and it must not be an
		// error, or a retried write would fail a run that had already succeeded.
		//
		// Existing rows carry in as the first generation. Nothing is purged: they
		// all still verify their content hashes, and they hold the only history the
		// store has. Measured on the maintainer's 6629 rows, no pair of records for
		// one coordinate disagrees on any hash they both carry, so the divergence
		// rule fires on nothing at migration.
		{Module: "fetch", Version: 9, SQL: `
            ALTER TABLE fetch_records ADD COLUMN measurement_kind TEXT NOT NULL DEFAULT '';
            ALTER TABLE fetch_records ADD COLUMN sumdb_check TEXT NOT NULL DEFAULT '';
            ALTER TABLE fetch_records ADD COLUMN sumdb_check_source TEXT NOT NULL DEFAULT '';
            ALTER TABLE fetch_records ADD COLUMN vcs_check TEXT NOT NULL DEFAULT '';
            ALTER TABLE fetch_records ADD COLUMN vcs_check_source TEXT NOT NULL DEFAULT '';

            CREATE TABLE fetch_records_ledger (
                module_path         TEXT NOT NULL,
                module_version      TEXT NOT NULL,
                pipeline_version    TEXT NOT NULL,
                schema_version      TEXT NOT NULL,
                ecosystem           TEXT NOT NULL DEFAULT 'go',
                module_hash         TEXT NOT NULL,
                go_mod_hash         TEXT NOT NULL,
                git_url             TEXT NOT NULL DEFAULT '',
                git_ref             TEXT NOT NULL DEFAULT '',
                git_commit_hash     TEXT NOT NULL DEFAULT '',
                verification_status TEXT NOT NULL,
                verification_detail TEXT NOT NULL DEFAULT '',
                fetched_at          TEXT NOT NULL,
                content_location    TEXT NOT NULL,
                go_mod_location     TEXT NOT NULL DEFAULT '',
                content_hash        TEXT NOT NULL,
                retracted           BOOLEAN NOT NULL DEFAULT 0,
                zip_sha256          TEXT NOT NULL DEFAULT '',
                zip_sha384          TEXT NOT NULL DEFAULT '',
                zip_sha512          TEXT NOT NULL DEFAULT '',
                sumdb_lookup_failed BOOLEAN NOT NULL DEFAULT 0,
                acquisition_mode    TEXT NOT NULL DEFAULT '',
                measurement_kind    TEXT NOT NULL DEFAULT '',
                sumdb_check         TEXT NOT NULL DEFAULT '',
                sumdb_check_source  TEXT NOT NULL DEFAULT '',
                vcs_check           TEXT NOT NULL DEFAULT '',
                vcs_check_source    TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (module_path, module_version, pipeline_version, module_hash, fetched_at, content_hash)
            );

            INSERT INTO fetch_records_ledger (
                module_path, module_version, pipeline_version, schema_version, ecosystem,
                module_hash, go_mod_hash, git_url, git_ref, git_commit_hash,
                verification_status, verification_detail, fetched_at,
                content_location, go_mod_location, content_hash, retracted,
                zip_sha256, zip_sha384, zip_sha512, sumdb_lookup_failed, acquisition_mode,
                measurement_kind, sumdb_check, sumdb_check_source, vcs_check, vcs_check_source
            )
            SELECT
                module_path, module_version, pipeline_version, schema_version, ecosystem,
                module_hash, go_mod_hash, git_url, git_ref, git_commit_hash,
                verification_status, verification_detail, fetched_at,
                content_location, go_mod_location, content_hash, retracted,
                zip_sha256, zip_sha384, zip_sha512, sumdb_lookup_failed, acquisition_mode,
                measurement_kind, sumdb_check, sumdb_check_source, vcs_check, vcs_check_source
            FROM fetch_records;

            DROP TABLE fetch_records;
            ALTER TABLE fetch_records_ledger RENAME TO fetch_records;

            CREATE INDEX IF NOT EXISTS idx_fetch_records_identity
                ON fetch_records (module_path, module_version, pipeline_version, module_hash, fetched_at);`},
	}
}

// New returns a new Store using the provided database handle.
func New(db sqlitestore.DB) *Store {
	return &Store{db: db}
}

// Open opens (or creates) the SQLite database at dsn and runs migrations.
// Use ":memory:" for tests.
func Open(dsn string) (*Store, error) {
	db, err := sqlitestore.Open(dsn, Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		return nil, fmt.Errorf("opening fact store: %w", err)
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
		return fmt.Errorf("closing fact store: %w", err)
	}
	return nil
}

// recordColumns is the column list every read projects, in the order scanRecord
// consumes them.
const recordColumns = `schema_version, ecosystem, module_path, module_version, pipeline_version,
       module_hash, go_mod_hash, git_url, git_ref, git_commit_hash,
       verification_status, verification_detail,
       fetched_at, content_location, go_mod_location, content_hash, retracted,
       zip_sha256, zip_sha384, zip_sha512, sumdb_lookup_failed, acquisition_mode,
       measurement_kind, sumdb_check, sumdb_check_source, vcs_check, vcs_check_source`

// PutFetchRecord appends a measurement to the ledger.
//
// It never updates. The key carries the artefact hash, the time of measurement
// and the record's own content hash, so two distinct measurements are always two
// rows even when they share an instant. The only collision left is the same
// record written twice, which the conflict clause makes a no-op because it is
// one measurement rather than two. This is the property the whole ticket turns
// on — an overwriting store destroys the evidence an investigation needs, and it
// did.
//
// It takes a SealedRecord, so a record whose content hash does not describe its
// contents cannot reach storage at all — except for the one value the type
// system cannot exclude, the zero SealedRecord, which this refuses with
// domain2.ErrUnsealedRecord rather than storing.
func (s *Store) PutFetchRecord(ctx context.Context, sealed domain2.SealedRecord) error {
	if sealed.IsZero() {
		return domain2.ErrUnsealedRecord
	}
	r := sealed.Record()
	const q = `
INSERT INTO fetch_records (
    module_path, module_version, pipeline_version,
    schema_version, ecosystem, module_hash, go_mod_hash,
    git_url, git_ref, git_commit_hash,
    verification_status, verification_detail,
    fetched_at, content_location, go_mod_location, content_hash, retracted,
    zip_sha256, zip_sha384, zip_sha512, sumdb_lookup_failed, acquisition_mode,
    measurement_kind, sumdb_check, sumdb_check_source, vcs_check, vcs_check_source
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (module_path, module_version, pipeline_version, module_hash, fetched_at, content_hash)
DO NOTHING`

	_, err := s.db.DB().ExecContext(ctx, q,
		r.ModulePath, r.ModuleVersion, r.PipelineVersion,
		r.SchemaVersion, r.Ecosystem, r.ModuleHash, r.GoModHash,
		r.GitURL, r.GitRef, r.GitCommitHash,
		r.VerificationStatus, r.VerificationDetail,
		r.FetchedAt.UTC().Format(fetchedAtFormat),
		r.ContentLocation, r.GoModLocation, r.ContentHash, r.Retracted,
		r.ZipSHA256, r.ZipSHA384, r.ZipSHA512, r.SumDBLookupFailed, r.AcquisitionMode,
		r.MeasurementKind, r.SumDBCheck, r.SumDBCheckSource, r.VCSCheck, r.VCSCheckSource,
	)
	if err != nil {
		return fmt.Errorf("appending fetch record: %w", err)
	}
	return nil
}

// GetFetchRecord returns the composed view of every measurement held for the
// coordinate and pipeline version. The bool is false when none exist.
//
// A stored record that fails to rehydrate is an ERROR, not an absence. It used
// to be reported as (zero, false, nil): a detected tamper handed back as "no
// record here", which the caller then treated as a cache miss and re-fetched,
// overwriting the very evidence that something had been tampered with. The
// loudest signal the store can produce was its quietest path.
func (s *Store) GetFetchRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (domain2.CompositeRecord, bool, error) {
	// The zero coordinate names no module, so this is a question about nothing.
	// Answering it with absence would report "no record here" for a module that
	// was never asked about — see coordinate.ErrZeroCoordinate.
	if coord.IsZero() {
		return domain2.CompositeRecord{}, false, coordinate.ErrZeroCoordinate
	}
	records, err := s.ListFetchRecords(ctx, coord, pipelineVersion)
	if err != nil {
		return domain2.CompositeRecord{}, false, err
	}
	return composeRead(coord, records)
}

// ComposeFetchRecord returns the composed view of every measurement held for the
// coordinate, whatever fetch pipeline version wrote it. The bool is false when
// none exist. It satisfies the optional ports.FactRecordComposer capability.
//
// It is GetFetchRecord without the pipeline-version predicate, and the predicate
// is what made it necessary: filtering by fetch pipeline version happens BEFORE
// domain.Compose folds the results, so it hides from the composer exactly the
// measurements the composer exists to rank. A reader outside the fetch context
// wants the artefact, and the generation of the fetch pipeline that measured it
// is not a property of the artefact.
//
// Composing across generations does not weaken the divergence guard, which is
// the one thing a wider read could plausibly break. FindDivergence fires on
// disagreement about a hash two records BOTH carry, so widening the input can
// only find MORE disagreement, never less. Measured on the maintainer's store of
// 7732 records over 5652 coordinates — 1834 of them present at more than one
// fetch pipeline version — widening the read introduces zero divergences: no
// coordinate disagrees on module_hash and none on go_mod_hash across versions.
func (s *Store) ComposeFetchRecord(ctx context.Context, coord coordinate.ModuleCoordinate) (domain2.CompositeRecord, bool, error) {
	// The zero coordinate names no module, so this is a question about nothing.
	// Answering it with absence would report "no record here" for a module that
	// was never asked about — see coordinate.ErrZeroCoordinate.
	if coord.IsZero() {
		return domain2.CompositeRecord{}, false, coordinate.ErrZeroCoordinate
	}
	records, err := s.listFetchRecords(ctx, coord, allPipelineVersions, "")
	if err != nil {
		return domain2.CompositeRecord{}, false, err
	}
	return composeRead(coord, records)
}

// composeRead folds a listed set of measurements into the record a reader gets,
// on terms shared by both reads: absence is absence, a disagreement between
// measurements is an error, and composition itself may refuse.
func composeRead(coord coordinate.ModuleCoordinate, records []domain2.FactRecord) (domain2.CompositeRecord, bool, error) {
	if len(records) == 0 {
		return domain2.CompositeRecord{}, false, nil
	}
	if d := domain2.FindDivergence(records); d != nil {
		return domain2.CompositeRecord{}, false, d
	}
	composite, err := domain2.Compose(records)
	if err != nil {
		return domain2.CompositeRecord{}, false, fmt.Errorf("composing records for %s: %w", coord, err)
	}
	return composite, true, nil
}

// pipelineScope selects whether a listing is narrowed to one fetch pipeline
// version or spans every generation of the ledger.
type pipelineScope bool

const (
	// onePipelineVersion narrows the listing to the named fetch pipeline version.
	onePipelineVersion pipelineScope = false

	// allPipelineVersions spans every fetch pipeline version, which is the scope a
	// reader outside the fetch context wants: it asks about an artefact, not about
	// a generation of the pipeline that measured one.
	allPipelineVersions pipelineScope = true
)

// ListFetchRecords returns every measurement held for the coordinate and
// pipeline version, in the order they were appended.
//
// The secondary sort is the row id, not the content hash. fetched_at persists at
// second precision, so two measurements taken within one second carry the same
// timestamp and a timestamp sort cannot order them; insertion order is what an
// append-only ledger actually has, and composition relies on it for coordinates
// whose content is not pinned. It satisfies the optional
// ports.FactRecordLister capability, which the write path needs in order to
// inherit validation legs from earlier measurements of the same artefact.
func (s *Store) ListFetchRecords(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) ([]domain2.FactRecord, error) {
	// The zero coordinate names no module, so this is a question about nothing.
	// Answering it with absence would report "no record here" for a module that
	// was never asked about — see coordinate.ErrZeroCoordinate.
	if coord.IsZero() {
		return nil, coordinate.ErrZeroCoordinate
	}
	return s.listFetchRecords(ctx, coord, onePipelineVersion, pipelineVersion)
}

// listFetchRecords is the one query and one rehydration loop both listings share.
// pipelineVersion is read only when scope is onePipelineVersion.
func (s *Store) listFetchRecords(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	scope pipelineScope,
	pipelineVersion string,
) ([]domain2.FactRecord, error) {
	q := `SELECT ` + recordColumns + `
FROM fetch_records
WHERE module_path = ? AND module_version = ?`
	args := []any{coord.Path(), coord.Version()}
	if scope == onePipelineVersion {
		q += ` AND pipeline_version = ?`
		args = append(args, pipelineVersion)
	}
	q += `
ORDER BY fetched_at ASC, rowid ASC`

	rows, err := s.db.DB().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("querying fetch records: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []domain2.FactRecord
	for rows.Next() {
		r, serr := scanRecord(rows)
		if serr != nil {
			return nil, serr
		}
		// Rehydrate verifies the whole integrity floor and fails closed. A row
		// that cannot be rehydrated stops the read rather than being skipped:
		// silently dropping it would report a tampered store as a smaller one.
		sealed, rerr := domain2.Rehydrate(r)
		if rerr != nil {
			return nil, fmt.Errorf("rehydrating stored fetch record for %s: %w", coord, rerr)
		}
		out = append(out, sealed.Record())
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating fetch records: %w", err)
	}
	return out, nil
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanRecord reads one row into a FactRecord, without verifying it.
func scanRecord(sc rowScanner) (domain2.FactRecord, error) {
	var r domain2.FactRecord
	var fetchedAt string
	err := sc.Scan(
		&r.SchemaVersion, &r.Ecosystem, &r.ModulePath, &r.ModuleVersion, &r.PipelineVersion,
		&r.ModuleHash, &r.GoModHash, &r.GitURL, &r.GitRef, &r.GitCommitHash,
		&r.VerificationStatus, &r.VerificationDetail,
		&fetchedAt, &r.ContentLocation, &r.GoModLocation, &r.ContentHash, &r.Retracted,
		&r.ZipSHA256, &r.ZipSHA384, &r.ZipSHA512, &r.SumDBLookupFailed, &r.AcquisitionMode,
		&r.MeasurementKind, &r.SumDBCheck, &r.SumDBCheckSource, &r.VCSCheck, &r.VCSCheckSource,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain2.FactRecord{}, fmt.Errorf("scanning fetch record: %w", err)
		}
		return domain2.FactRecord{}, fmt.Errorf("scanning fetch record: %w", err)
	}
	t, err := time.Parse(time.RFC3339, fetchedAt)
	if err != nil {
		return domain2.FactRecord{}, fmt.Errorf("parsing fetched_at %q: %w", fetchedAt, err)
	}
	r.FetchedAt = t.UTC()
	return r, nil
}

// PutAttestation inserts or replaces a provenance attestation. Idempotent on
// (module_path, module_version, pipeline_version, subject_kind, subject_digest).
func (s *Store) PutAttestation(ctx context.Context, r domain2.AttestationRecord) error {
	const q = `
INSERT INTO fetch_attestations (
    module_path, module_version, pipeline_version,
    subject_kind, subject_algorithm, subject_digest, bundle, signed_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (module_path, module_version, pipeline_version, subject_kind, subject_digest)
DO UPDATE SET
    subject_algorithm = excluded.subject_algorithm,
    bundle            = excluded.bundle,
    signed_at         = excluded.signed_at`

	_, err := s.db.DB().ExecContext(ctx, q,
		r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion,
		string(r.SubjectKind), r.SubjectAlgorithm, r.SubjectDigest, r.Bundle,
		r.SignedAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("inserting attestation: %w", err)
	}
	return nil
}

// ListAttestations returns all attestations for a coordinate and pipeline
// version in deterministic order.
func (s *Store) ListAttestations(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) ([]domain2.AttestationRecord, error) {
	// The zero coordinate names no module, so this is a question about nothing.
	// Answering it with absence would report "no record here" for a module that
	// was never asked about — see coordinate.ErrZeroCoordinate.
	if coord.IsZero() {
		return nil, coordinate.ErrZeroCoordinate
	}
	const q = `
SELECT subject_kind, subject_algorithm, subject_digest, bundle, signed_at
FROM fetch_attestations
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?
ORDER BY subject_kind, subject_digest`

	rows, err := s.db.DB().QueryContext(ctx, q, coord.Path(), coord.Version(), pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("querying attestations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []domain2.AttestationRecord
	for rows.Next() {
		var (
			kind, algo, digest, signedAt string
			bundle                       []byte
		)
		if err := rows.Scan(&kind, &algo, &digest, &bundle, &signedAt); err != nil {
			return nil, fmt.Errorf("scanning attestation: %w", err)
		}
		t, perr := time.Parse(time.RFC3339, signedAt)
		if perr != nil {
			return nil, fmt.Errorf("parsing signed_at %q: %w", signedAt, perr)
		}
		out = append(out, domain2.AttestationRecord{
			Coordinate:       coord,
			PipelineVersion:  pipelineVersion,
			SubjectKind:      domain2.SubjectKind(kind),
			SubjectAlgorithm: algo,
			SubjectDigest:    digest,
			Bundle:           bundle,
			SignedAt:         t.UTC(),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating attestations: %w", err)
	}
	return out, nil
}

// Ensure Store implements ports.FactStore and ports.AttestationStore at compile time.
var (
	_ ports.FactStore          = (*Store)(nil)
	_ ports.FactRecordLister   = (*Store)(nil)
	_ ports.FactRecordComposer = (*Store)(nil)
	_ ports.AttestationStore   = (*Store)(nil)
)
