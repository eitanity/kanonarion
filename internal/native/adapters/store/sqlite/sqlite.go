// Package sqlite implements ports.NativeStore using the shared SQLite database.
// The native module owns its own migration series, keyed by the module
// coordinate, the pipeline fingerprint and the artefact the measurement read.
package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
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
