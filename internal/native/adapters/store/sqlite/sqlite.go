// Package sqlite implements ports.NativeStore using the shared SQLite database.
// The native module owns its own migration series, keyed by the module
// coordinate, the pipeline fingerprint and the artefact the measurement read.
package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/native/domain"
	"github.com/eitanity/kanonarion/internal/native/ports"
)

// Store is the SQLite-backed native-component store.
type Store struct {
	db sqlitestore.DB
}

// New returns a Store using the provided shared database handle.
func New(db sqlitestore.DB) *Store { return &Store{db: db} }

// Migrations returns the schema migrations for the native module.
//
// The artefact identity is a key column rather than a detail inside the blob.
// A native-component record is a claim about specific bytes, and two records
// naming different artefacts for one pinned version is a contradiction the
// store must be able to see; keying on the coordinate alone would have the
// second measurement quietly replace the first.
func Migrations() []sqlitestore.Migration {
	return []sqlitestore.Migration{
		{Module: "native", Version: 1, SQL: `CREATE TABLE IF NOT EXISTS native_records (
            module_path          TEXT NOT NULL,
            module_version       TEXT NOT NULL,
            pipeline_fingerprint TEXT NOT NULL,
            artefact_identity    TEXT NOT NULL,
            presence             TEXT NOT NULL,
            component_count      INTEGER NOT NULL,
            source_count         INTEGER NOT NULL,
            extracted_at         TEXT NOT NULL,
            content_hash         TEXT NOT NULL,
            serialised           BLOB NOT NULL,
            PRIMARY KEY (module_path, module_version, pipeline_fingerprint, artefact_identity)
        );
        CREATE INDEX IF NOT EXISTS native_records_presence_idx
            ON native_records(presence)`},
	}
}

// PutNativeRecord persists a record.
//
// The measurement is a function of the artefact's bytes at a fixed generation,
// so re-writing the same key writes the same answer; the update is there so a
// re-measurement refreshes the timestamp rather than being refused.
func (s *Store) PutNativeRecord(ctx context.Context, rec domain.Record) error {
	// A record whose coordinate is the zero value would key a row on the empty
	// path at the empty version, which every later read treats as a genuine
	// measurement of a module that does not exist.
	if rec.Coordinate.IsZero() {
		return coordinate.ErrZeroCoordinate
	}
	// Every record here describes bytes an extraction read. One that cannot
	// name which bytes is unfalsifiable, and it would also share a key with
	// every other record that named none.
	if rec.ArtefactIdentity == "" {
		return fmt.Errorf("native record for %s names no artefact: %w", rec.Coordinate, fetchdomain.ErrZeroIdentity)
	}
	if rec.Ecosystem != domain.EcosystemGo {
		return fmt.Errorf("%w: got %q, want %q", domain.ErrUnsupportedEcosystem, rec.Ecosystem, domain.EcosystemGo)
	}

	raw, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshalling native record: %w", err)
	}
	blob := blobcodec.Encode(raw)

	const q = `
INSERT INTO native_records (
    module_path, module_version, pipeline_fingerprint, artefact_identity,
    presence, component_count, source_count, extracted_at, content_hash, serialised
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (module_path, module_version, pipeline_fingerprint, artefact_identity) DO UPDATE SET
    presence        = excluded.presence,
    component_count = excluded.component_count,
    source_count    = excluded.source_count,
    extracted_at    = excluded.extracted_at,
    content_hash    = excluded.content_hash,
    serialised      = excluded.serialised`

	if _, err := s.db.DB().ExecContext(ctx, q,
		rec.Coordinate.Path(), rec.Coordinate.Version(), domain.PipelineFingerprint(), rec.ArtefactIdentity,
		string(rec.Presence), len(rec.Components), len(rec.Sources),
		rec.ExtractedAt.UTC().Format(time.RFC3339), rec.ContentHash, blob,
	); err != nil {
		return fmt.Errorf("inserting native record: %w", err)
	}
	return nil
}

// GetNativeRecord returns the record for a coordinate at the current pipeline
// fingerprint.
//
// Two rows for one pinned version means two measurements disagree about what
// that version's bytes are. Composition refuses rather than picking: choosing
// one would report a native component read out of an artefact the caller may
// not have, and hide that the ledger holds another.
func (s *Store) GetNativeRecord(ctx context.Context, coord coordinate.ModuleCoordinate) (domain.Record, bool, error) {
	if coord.IsZero() {
		return domain.Record{}, false, coordinate.ErrZeroCoordinate
	}

	const q = `SELECT artefact_identity, serialised FROM native_records
WHERE module_path = ? AND module_version = ? AND pipeline_fingerprint = ?
ORDER BY artefact_identity`

	rows, err := s.db.DB().QueryContext(ctx, q, coord.Path(), coord.Version(), domain.PipelineFingerprint())
	if err != nil {
		return domain.Record{}, false, fmt.Errorf("querying native record: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var (
		identities []string
		records    []domain.Record
	)
	for rows.Next() {
		var identity string
		var blob []byte
		if serr := rows.Scan(&identity, &blob); serr != nil {
			return domain.Record{}, false, fmt.Errorf("scanning native record: %w", serr)
		}
		decoded, derr := blobcodec.Decode(blob)
		if derr != nil {
			return domain.Record{}, false, fmt.Errorf("decompressing native record: %w", derr)
		}
		var rec domain.Record
		if uerr := json.Unmarshal(decoded, &rec); uerr != nil {
			return domain.Record{}, false, fmt.Errorf("unmarshalling native record: %w", uerr)
		}
		if rec.Ecosystem != domain.EcosystemGo {
			return domain.Record{}, false, fmt.Errorf("%w: got %q, want %q", domain.ErrUnsupportedEcosystem, rec.Ecosystem, domain.EcosystemGo)
		}
		identities = append(identities, identity)
		records = append(records, rec)
	}
	if rerr := rows.Err(); rerr != nil {
		return domain.Record{}, false, fmt.Errorf("reading native records: %w", rerr)
	}

	switch len(records) {
	case 0:
		return domain.Record{}, false, nil
	case 1:
		return records[0], true, nil
	default:
		return domain.Record{}, false, fmt.Errorf("%w: %s is described by %d artefacts %v",
			ports.ErrNativeConflict, coord, len(identities), identities)
	}
}

// listNativeColumns is the projection every listed row is built from. The
// serialised record is read with them: at 202 rows the whole table is under
// 80 KB, and decoding it is what lets a row name the library rather than count
// it.
const listNativeColumns = `module_path, module_version, pipeline_fingerprint, artefact_identity,
    presence, source_count, extracted_at, content_hash, serialised`

// ListNativeRecords returns summaries matching the filter.
//
// The ordering is the listing convention this store's siblings already follow:
// newest measurement first, with the row's primary key as tiebreak so the order
// is total. A page is then exactly the rows the previous page did not show, and
// two calls order the population identically.
func (s *Store) ListNativeRecords(ctx context.Context, filter ports.NativeFilter) ([]ports.NativeSummary, error) {
	q := `SELECT ` + listNativeColumns + ` FROM native_records`
	where, args := nativeListPredicate(filter)
	q += where + `
ORDER BY extracted_at DESC, module_path, module_version, pipeline_fingerprint, artefact_identity`
	// SQLite parses OFFSET only after a LIMIT, and -1 is its own spelling of
	// "no limit", so an offset with no limit still pages. Bound as parameters,
	// like every other paged listing in this store.
	if filter.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, filter.Limit)
		if filter.Offset > 0 {
			q += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	} else if filter.Offset > 0 {
		q += " LIMIT -1 OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.DB().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing native records: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []ports.NativeSummary{}
	for rows.Next() {
		sum, serr := scanNativeSummary(rows)
		if serr != nil {
			return nil, serr
		}
		out = append(out, sum)
	}
	if rerr := rows.Err(); rerr != nil {
		return nil, fmt.Errorf("reading native records: %w", rerr)
	}

	disputed, derr := s.disputedNativeCoordinates(ctx, filter)
	if derr != nil {
		return nil, derr
	}
	for i := range out {
		key := nativeDisputeKey{
			path: out[i].Coordinate.Path(), version: out[i].Coordinate.Version(),
			generation: out[i].Generation,
		}
		if n := disputed[key]; n > 1 {
			out[i].Conflict = fmt.Errorf("%w: %s at generation %s is described by %d artefacts",
				ports.ErrNativeConflict, out[i].Coordinate, out[i].Generation, n)
		}
	}
	return out, nil
}

// nativeListPredicate renders the filter's WHERE clause and its arguments.
//
// The generation restriction is the default rather than an option: a record
// taken at a superseded generation answers no query this build serves, and
// listing it unmarked alongside the servable ones would pad the count of what
// is known with rows that cannot answer.
func nativeListPredicate(filter ports.NativeFilter) (string, []any) {
	var clauses []string
	var args []any
	if !filter.AllGenerations {
		clauses = append(clauses, "pipeline_fingerprint = ?")
		args = append(args, domain.PipelineFingerprint())
	}
	if len(filter.Presence) > 0 {
		clauses = append(clauses, "presence IN ("+strings.TrimSuffix(strings.Repeat("?,", len(filter.Presence)), ",")+")")
		for _, p := range filter.Presence {
			args = append(args, p)
		}
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return "\nWHERE " + strings.Join(clauses, " AND "), args
}

// nativeSummaryScanner is the row reader ListNativeRecords scans through. It is
// an interface so the scan is one function rather than one per call site.
type nativeSummaryScanner interface {
	Scan(dest ...any) error
}

// scanNativeSummary reads one row into a summary, decoding the stored record so
// the row can name the components and the external libraries.
func scanNativeSummary(row nativeSummaryScanner) (ports.NativeSummary, error) {
	var (
		modulePath, moduleVersion, generation, identity string
		presence, extractedAt, contentHash              string
		sourceCount                                     int
		blob                                            []byte
	)
	if err := row.Scan(&modulePath, &moduleVersion, &generation, &identity,
		&presence, &sourceCount, &extractedAt, &contentHash, &blob); err != nil {
		return ports.NativeSummary{}, fmt.Errorf("scanning native record: %w", err)
	}
	decoded, derr := blobcodec.Decode(blob)
	if derr != nil {
		return ports.NativeSummary{}, fmt.Errorf("decompressing native record: %w", derr)
	}
	var rec domain.Record
	if uerr := json.Unmarshal(decoded, &rec); uerr != nil {
		return ports.NativeSummary{}, fmt.Errorf("unmarshalling native record: %w", uerr)
	}
	if rec.Ecosystem != domain.EcosystemGo {
		return ports.NativeSummary{}, fmt.Errorf("%w: got %q, want %q",
			domain.ErrUnsupportedEcosystem, rec.Ecosystem, domain.EcosystemGo)
	}
	// The coordinate comes from the record rather than from the key columns, on
	// the same terms as GetNativeRecord: the record states what it describes,
	// and the columns are the index over it. A record whose coordinate does not
	// match the row it was stored under is refused rather than listed under a
	// name it does not claim.
	coord := rec.Coordinate
	if coord.Path() != modulePath || coord.Version() != moduleVersion {
		return ports.NativeSummary{}, fmt.Errorf("native record stored under %s@%s describes %s",
			modulePath, moduleVersion, coord)
	}
	// The timestamp is read from the column rather than the record: it is the
	// value the ordering was applied to, so a row that sorted here cannot then
	// report a different instant.
	taken, terr := time.Parse(time.RFC3339, extractedAt)
	if terr != nil {
		return ports.NativeSummary{}, fmt.Errorf("reading extracted_at of native record %s: %w", coord, terr)
	}
	components := rec.Components
	if components == nil {
		components = []domain.Component{}
	}
	return ports.NativeSummary{
		Coordinate:       coord,
		Generation:       generation,
		ArtefactIdentity: identity,
		Presence:         domain.Presence(presence),
		Components:       components,
		SourceCount:      sourceCount,
		LinkedExternal:   domain.ExternalLibraryNames(rec.LinkedLibraries),
		ExtractedAt:      taken,
		ContentHash:      contentHash,
	}, nil
}

// nativeDisputeKey identifies the records that must agree: one coordinate at
// one generation.
type nativeDisputeKey struct{ path, version, generation string }

// disputedNativeCoordinates counts the records held per coordinate per
// generation, for the coordinates holding more than one.
//
// It is a second query over the same corpus rather than a window function on
// the first, because the first is paged: a coordinate whose two records
// straddle a page boundary must still be marked on the page that shows one of
// them. It reads three indexed columns and no blob.
func (s *Store) disputedNativeCoordinates(ctx context.Context, filter ports.NativeFilter) (map[nativeDisputeKey]int, error) {
	q := `SELECT module_path, module_version, pipeline_fingerprint, COUNT(*)
FROM native_records`
	// The presence restriction is deliberately dropped: two records for one
	// coordinate may disagree about the presence itself, and counting only the
	// rows that matched the filter would report such a pair as undisputed.
	where, args := nativeListPredicate(ports.NativeFilter{AllGenerations: filter.AllGenerations})
	q += where + `
GROUP BY module_path, module_version, pipeline_fingerprint
HAVING COUNT(*) > 1`

	rows, err := s.db.DB().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("counting native records per coordinate: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := map[nativeDisputeKey]int{}
	for rows.Next() {
		var key nativeDisputeKey
		var n int
		if serr := rows.Scan(&key.path, &key.version, &key.generation, &n); serr != nil {
			return nil, fmt.Errorf("scanning native record count: %w", serr)
		}
		out[key] = n
	}
	if rerr := rows.Err(); rerr != nil {
		return nil, fmt.Errorf("reading native record counts: %w", rerr)
	}
	return out, nil
}

// Store satisfies the optional survey capability as well as the store itself.
var _ ports.NativeRecordLister = (*Store)(nil)
