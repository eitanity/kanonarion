// Package sqlite implements ports.CallGraphStore using a SQLite database via
// modernc.org/sqlite (pure Go, no CGO).
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
	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"

	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

// syntheticLocalVersion is the module version `kanonarion local` used to write
// working trees under, before it was retired for coordinate.LocalVersion. It
// survives only so migration 10 can name the rows it strands; nothing writes it.
const syntheticLocalVersion = "v0.0.0"

// Store is the SQLite-backed call graph store.
type Store struct {
	db sqlitestore.DB
}

// New returns a new Store using the provided database handle.
func New(db sqlitestore.DB) *Store {
	return &Store{db: db}
}

// Migrations returns the schema migrations for the callgraph module.
func Migrations() []sqlitestore.Migration {
	return []sqlitestore.Migration{
		{Module: "callgraph", Version: 1, SQL: `CREATE TABLE IF NOT EXISTS callgraph_records (
            module_path        TEXT NOT NULL,
            module_version     TEXT NOT NULL,
            pipeline_version   TEXT NOT NULL,
            algorithm          TEXT NOT NULL,
            overall_status     INTEGER NOT NULL,
            node_count         INTEGER NOT NULL,
            edge_count         INTEGER NOT NULL,
            extracted_at       TEXT NOT NULL,
            content_hash       TEXT NOT NULL,
            serialised         BLOB NOT NULL,
            PRIMARY KEY (module_path, module_version, pipeline_version)
        );
        CREATE TABLE IF NOT EXISTS callgraph_edges (
            from_module        TEXT NOT NULL,
            from_version       TEXT NOT NULL,
            pipeline_version   TEXT NOT NULL,
            from_id            TEXT NOT NULL,
            to_id              TEXT NOT NULL,
            confidence         TEXT NOT NULL,
            PRIMARY KEY (from_module, from_version, pipeline_version, from_id, to_id)
        );
        CREATE INDEX IF NOT EXISTS callgraph_edges_to_idx
            ON callgraph_edges(to_id, pipeline_version)`},
		{Module: "callgraph", Version: 2, SQL: `CREATE INDEX IF NOT EXISTS callgraph_edges_from_idx
            ON callgraph_edges(from_id, pipeline_version)`},
		// Migration v3: add call_site_file and call_site_line to callgraph_edges so
		// edges can be fully reconstructed from the table (enabling the v2 blob format
		// that omits edges from the serialised column). Existing rows are migrated with
		// default empty/0 call-site values; they remain readable via the v1 blob path.
		{Module: "callgraph", Version: 3, SQL: `
CREATE TABLE callgraph_edges_v3 (
    from_module      TEXT    NOT NULL,
    from_version     TEXT    NOT NULL,
    pipeline_version TEXT    NOT NULL,
    from_id          TEXT    NOT NULL,
    to_id            TEXT    NOT NULL,
    confidence       TEXT    NOT NULL,
    call_site_file   TEXT    NOT NULL DEFAULT '',
    call_site_line   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (from_module, from_version, pipeline_version, from_id, to_id, call_site_file, call_site_line)
);
INSERT INTO callgraph_edges_v3 (from_module, from_version, pipeline_version, from_id, to_id, confidence)
    SELECT from_module, from_version, pipeline_version, from_id, to_id, confidence FROM callgraph_edges;
DROP TABLE callgraph_edges;
ALTER TABLE callgraph_edges_v3 RENAME TO callgraph_edges;
CREATE INDEX IF NOT EXISTS callgraph_edges_to_idx   ON callgraph_edges(to_id, pipeline_version);
CREATE INDEX IF NOT EXISTS callgraph_edges_from_idx ON callgraph_edges(from_id, pipeline_version)`},
		// Migration v4: the ecosystem field joined the canonical hash and bumped
		// the schema version, so every pre-existing blob carries a stale hash and
		// no ecosystem field — unreadable under the new schema. Purge the legacy
		// rows; they are regenerable by re-extracting.
		{Module: "callgraph", Version: 4, SQL: `DELETE FROM callgraph_records;
DELETE FROM callgraph_edges`},
		// Migration v5: per-node body-level facts (uses_unsafe_pointer,
		// is_assembly_or_linkname) joined the canonical node schema and bumped the
		// schema version. Pre-existing blobs lack these fields, so capability
		// analysis would silently under-report UNSAFE_POINTER and
		// ARBITRARY_EXECUTION over them. Purge the legacy rows; re-extraction
		// repopulates them with the new facts.
		{Module: "callgraph", Version: 5, SQL: `DELETE FROM callgraph_records;
DELETE FROM callgraph_edges`},
		// Migration v6: the edge confidence vocabulary was redesigned
		// (DynamicDispatch -> CHA-overapprox, Reflection folded into Unknown) and
		// the per-edge reflect_dispatch attribute joined the canonical edge hash,
		// bumping the schema version. Pre-existing blobs carry stale hashes and the
		// old vocabulary, so purge the legacy rows — they are regenerable by
		// re-extracting — and add the reflect_dispatch column for new records.
		{Module: "callgraph", Version: 6, SQL: `DELETE FROM callgraph_records;
DELETE FROM callgraph_edges;
ALTER TABLE callgraph_edges ADD COLUMN reflect_dispatch INTEGER NOT NULL DEFAULT 0`},
		// Migration v7: _test.go declarations became graph nodes and the
		// interface/implementer relation joined the record, bumping the schema
		// version. Pre-existing rows carry stale hashes, and — the reason a purge
		// rather than a backfill is right — they were produced by an analysis that
		// never looked at test files, so leaving them in place would answer test
		// scope questions from a measurement that did not make one. The is_test
		// column lets an edge query exclude the test surface in SQL rather than
		// reconstructing node roles per row.
		{Module: "callgraph", Version: 7, SQL: `DELETE FROM callgraph_records;
DELETE FROM callgraph_edges;
ALTER TABLE callgraph_edges ADD COLUMN is_test INTEGER NOT NULL DEFAULT 0`},
		// Migration v8: callgraph_records becomes an append-only ledger and
		// callgraph_edges is rekeyed onto the parent record. Both tables are rebuilt
		// because both keys change.
		//
		// WHY THIS ONE DOES NOT PURGE, WHEN FOUR OF THE SEVEN ABOVE DO.
		//
		// Each of those purges is individually well argued — migration 7's is a good
		// example: test declarations became nodes, so the pre-existing rows "were
		// produced by an analysis that never looked at test files, so leaving them in
		// place would answer test scope questions from a measurement that did not
		// make one." The individual arguments are right. The aggregate is the
		// problem: a table cannot be an append-only ledger and also have its entire
		// history deleted on every analyser shape change, and the analyser is the
		// component that changes shape most.
		//
		// The resolution is that the mechanism the purges exist for is ALREADY here
		// and is not a purge. GetCallGraphRecord gates on SchemaVersion: a record
		// written at an older canonical shape decodes with every later field at its
		// zero value, cannot be told apart from one whose analysis genuinely found
		// nothing, and is therefore treated as not-found and re-derived. That gate
		// makes a shape bump self-enforcing without deleting the evidence, exactly as
		// the vulnerability records gate stale generations out of reads by pipeline
		// version rather than removing them. So from here: a shape change bumps
		// CallGraphSchemaVersion and the gate keeps the stale generation out of every
		// answer, while the row survives for a history read. Superseded rows cost
		// disk; deleted rows cost the ledger its reason to exist.
		//
		// THE PARENT KEY. extracted_at and the record's own content hash join it, so
		// two distinct extractions are always two rows and the same record written
		// twice is one. The artefact identity is deliberately NOT a key column: it
		// could only be back-filled '', which would state in a key column that rows
		// describe no artefact when they name one, and it is inside the hashed shape
		// already, so records describing different artefacts carry different content
		// hashes.
		//
		// THE SATELLITE. Edges were keyed on the coordinate, so under an append-only
		// parent every generation's edges would collide on one row and a
		// METADATA_ONLY graph's edges would be indistinguishable from a
		// BUILT_WITH_BODIES one's — the distinction the whole composition ladder is
		// built on. They are rekeyed onto record_content_hash, unique per row because
		// extracted_at is inside the hashed shape. The back-fill joins on the
		// coordinate, which is exact here and only here: measured read-only on the
		// maintainer's store before the change, no (path, version, pipeline) group
		// held more than one callgraph_records row. That property stops being true
		// the moment this migration lands, which is why the rekey happens in the same
		// step. The coordinate columns stay on the satellite as denormalised copies:
		// they are no longer identity, but every edge query answers with a
		// coordinate, and joining millions of rows back to their parents to render a
		// result would cost far more than carrying them.
		//
		// THE NEW COLUMNS. completeness drives composition and analysis_source is the
		// dimension composition must never pick across, so both are readable without
		// decoding a blob; worktree_digest is what distinguishes two checkouts of one
		// module path. All three are back-filled '' — the honest value for a record
		// written before the field existed, and the one the record's own decoded
		// shape already carries.
		{Module: "callgraph", Version: 8, SQL: `
CREATE TABLE callgraph_records_ledger (
    module_path        TEXT NOT NULL,
    module_version     TEXT NOT NULL,
    pipeline_version   TEXT NOT NULL,
    algorithm          TEXT NOT NULL,
    overall_status     INTEGER NOT NULL,
    completeness       TEXT NOT NULL DEFAULT '',
    analysis_source    TEXT NOT NULL DEFAULT '',
    worktree_digest    TEXT NOT NULL DEFAULT '',
    node_count         INTEGER NOT NULL,
    edge_count         INTEGER NOT NULL,
    extracted_at       TEXT NOT NULL,
    content_hash       TEXT NOT NULL,
    serialised         BLOB NOT NULL,
    PRIMARY KEY (module_path, module_version, pipeline_version, extracted_at, content_hash)
);

INSERT INTO callgraph_records_ledger (
    module_path, module_version, pipeline_version,
    algorithm, overall_status, node_count, edge_count,
    extracted_at, content_hash, serialised
)
SELECT
    module_path, module_version, pipeline_version,
    algorithm, overall_status, node_count, edge_count,
    extracted_at, content_hash, serialised
FROM callgraph_records;

CREATE TABLE callgraph_edges_ledger (
    record_content_hash TEXT    NOT NULL,
    from_module         TEXT    NOT NULL,
    from_version        TEXT    NOT NULL,
    pipeline_version    TEXT    NOT NULL,
    from_id             TEXT    NOT NULL,
    to_id               TEXT    NOT NULL,
    confidence          TEXT    NOT NULL,
    call_site_file      TEXT    NOT NULL DEFAULT '',
    call_site_line      INTEGER NOT NULL DEFAULT 0,
    reflect_dispatch    INTEGER NOT NULL DEFAULT 0,
    is_test             INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (record_content_hash, from_id, to_id, call_site_file, call_site_line)
);

INSERT INTO callgraph_edges_ledger (
    record_content_hash,
    from_module, from_version, pipeline_version,
    from_id, to_id, confidence, call_site_file, call_site_line,
    reflect_dispatch, is_test
)
SELECT
    r.content_hash,
    e.from_module, e.from_version, e.pipeline_version,
    e.from_id, e.to_id, e.confidence, e.call_site_file, e.call_site_line,
    e.reflect_dispatch, e.is_test
FROM callgraph_edges e
JOIN callgraph_records r
  ON r.module_path      = e.from_module
 AND r.module_version   = e.from_version
 AND r.pipeline_version = e.pipeline_version;

DROP TABLE callgraph_edges;
DROP TABLE callgraph_records;
ALTER TABLE callgraph_records_ledger RENAME TO callgraph_records;
ALTER TABLE callgraph_edges_ledger   RENAME TO callgraph_edges;

CREATE INDEX IF NOT EXISTS callgraph_edges_to_idx   ON callgraph_edges(to_id, pipeline_version);
CREATE INDEX IF NOT EXISTS callgraph_edges_from_idx ON callgraph_edges(from_id, pipeline_version);
CREATE INDEX IF NOT EXISTS callgraph_records_generation_idx
    ON callgraph_records(module_path, module_version, pipeline_version, extracted_at)`},
		// Migration v9: back-fill the completeness column migration 8 left empty.
		//
		// Migration 8 added three columns and back-filled all three with ''. That is
		// correct for analysis_source and worktree_digest — those facts were never
		// recorded, and '' is the honest "not recorded" value the decoded record also
		// carries. It is WRONG for completeness, and the difference is the whole
		// point: completeness has been inside the serialised record since schema v8,
		// so a row whose column says '' while its own blob says BUILT_WITH_BODIES is a
		// denormalised copy that contradicts what it copies.
		//
		// Measured on the maintainer's store when this was found: 234 rows carried an
		// empty column while their records stated 189 BUILT_WITH_BODIES, 41
		// METADATA_ONLY, 3 FAILED and 1 TYPE_ONLY. Nothing read the column into a
		// wrong answer — composition reads the decoded record, not the column — but a
		// column that has to be distrusted is worse than no column, because the next
		// reader will not know to distrust it.
		//
		// SQLite cannot do this: the value is inside a zstd-compressed blob. This is
		// the caller that brings back sqlitestore.Migration.Fn, which was previously
		// removed for having none — reintroduced together with its use, in one change,
		// which is the condition its own doc comment sets.
		{Module: "callgraph", Version: 9, Fn: backfillCompleteness},
		// Migration v10: retire the working-tree records stranded at the synthetic
		// "v0.0.0" coordinate.
		//
		// `kanonarion local` used to store a working tree at <path>@v0.0.0. That
		// version was retired because it states something untrue — v0.0.0 names a
		// published release, and nothing published the tree — and local ingests now
		// write at coordinate.LocalVersion instead.
		//
		// Retiring the label left the old rows behind, and that is a defect rather
		// than untidiness. Before the change, each `local` run OVERWROTE the v0.0.0
		// row, so it tracked the tree. Now nothing writes that coordinate ever again:
		// the row is frozen at whatever the tree looked like on the last run before
		// the upgrade, it can never be superseded, and an unscoped caller/callee query
		// spans every stored coordinate — so it answers alongside the live @local
		// record forever. Measured on the maintainer's store: every symbol in the
		// project reported TWICE, and the stale half named a test that had since been
		// deleted. Any user who had ever run `kanonarion local` inherits this on
		// upgrade.
		//
		// WHY THIS PURGE, WHEN MIGRATION 8 ARGUES AGAINST PURGING. Migration 8's
		// argument is about ANALYSER SHAPE CHANGES: a superseded generation of the
		// same question, which the SchemaVersion read gate already keeps out of every
		// answer while leaving the evidence in place. These rows are a different
		// thing. They are not a weaker answer to the same question — they are a
		// correct measurement filed under a name that misdescribes it, at a coordinate
		// no producer will ever write again, actively serving stale answers with no
		// read gate that can recognise them. And they are regenerable in one command:
		// `kanonarion local` reproduces the measurement at the coordinate that is true
		// of it.
		//
		// THE DISCRIMINATOR IS NARROW, BECAUSE v0.0.0 IS LEGAL SEMVER. A genuinely
		// fetched module at v0.0.0 must not be touched. The test is: version is
		// exactly "v0.0.0", AND the record names no artefact, AND it names no analysis
		// source. A fetched record always names the artefact it read — the store now
		// refuses one that does not — and a working-tree record written since the
		// change names its source and lives at @local. Measured before writing this:
		// of 240 rows, exactly 3 satisfy it, and they are exactly the three local
		// ingests. The artefact identity lives inside the compressed blob, which is
		// why this needs a Go step.
		{Module: "callgraph", Version: 10, Fn: retireSyntheticLocalRecords},
		// Migration v11: add the failure_cause column.
		//
		// The cause axis says whether a failed extraction is a statement about the
		// module or about the run that tried to analyse it, and the cache gate reads
		// it — see domain.RecordIsCacheable. It lives inside the serialised record
		// like every other fact; this column is the denormalised copy, on the same
		// terms completeness and analysis_source are, so the population can be
		// counted without decompressing a blob per row.
		//
		// NO BACK-FILL AND NO PURGE, and the two have different reasons.
		//
		// No back-fill because '' is the true value. No record written before this
		// migration states a cause — the axis did not exist — and the decoded record
		// carries exactly the same empty value. This is the opposite of migration 9's
		// situation, where the column contradicted a fact the blob already held.
		// Inventing a cause here would be exactly the collapse the axis exists to
		// prevent: an unattributed failure asserted to be the module's fault.
		//
		// No purge because the record shape did not move. The field is omitzero in
		// the canonical encoding, so a record that states no cause marshals to the
		// bytes it always did and verifies against the content hash it was written
		// with. CallGraphSchemaVersion is unchanged and so is PipelineVersion, so the
		// read gate lets every existing generation through and they keep answering.
		//
		// What DOES change for the existing rows is cache eligibility, and only for
		// the failures among them: a record that failed and states no cause is
		// re-attempted once, because "no cause recorded" is not evidence the module
		// was at fault. Measured read-only on the maintainer's store before writing
		// this: of 264 rows, 46 are failures (5 at FAILED completeness, 41 at
		// METADATA_ONLY) and 218 carry a graph and are untouched by the rule.
		{Module: "callgraph", Version: 11, SQL: `
ALTER TABLE callgraph_records ADD COLUMN failure_cause TEXT NOT NULL DEFAULT ''`},
		// Migration v12: edges gain a kind, so a function value taken can be told
		// from a function called. Existing rows back-fill '' — the zero value,
		// which reads as a call, and which is the truth about every edge written
		// before reference extraction existed: nothing recorded a reference, so
		// nothing stored is one.
		//
		// No purge, and no schema-version bump above it. The kind is omitted from
		// the sealed shape when empty, so every stored record still re-marshals to
		// the bytes it was sealed over; and the one thing an old record would
		// otherwise say falsely — that an empty callers answer is a measured
		// absence — is closed by CallGraphRecord.ReferenceScope, which reads
		// "not measured" on every record written before it and downgrades the
		// verdict rather than deleting the evidence.
		{Module: "callgraph", Version: 12, SQL: `
ALTER TABLE callgraph_edges ADD COLUMN kind TEXT NOT NULL DEFAULT ''`},
	}
}

// retireSyntheticLocalRecords deletes the working-tree records stranded at the
// synthetic "v0.0.0" coordinate, and the edge rows belonging to them.
//
// Rows are drained fully before any DELETE is issued: the store runs on a single
// connection, so writing while the SELECT's result set is still open deadlocks.
//
// A row that cannot be decoded is an error rather than a skip. Guessing whether
// an unreadable row is one of these is exactly the judgement this migration must
// not make on its own.
func retireSyntheticLocalRecords(tx *sql.Tx) error {
	rows, err := tx.Query(
		`SELECT content_hash, serialised FROM callgraph_records WHERE module_version = ?`,
		syntheticLocalVersion)
	if err != nil {
		return fmt.Errorf("selecting synthetic-local records: %w", err)
	}
	type candidate struct {
		hash string
		blob []byte
	}
	var found []candidate
	for rows.Next() {
		var c candidate
		if serr := rows.Scan(&c.hash, &c.blob); serr != nil {
			_ = rows.Close() //nolint:errcheck // returning the scan error
			return fmt.Errorf("scanning synthetic-local record: %w", serr)
		}
		found = append(found, c)
	}
	if cerr := rows.Err(); cerr != nil {
		_ = rows.Close() //nolint:errcheck // returning the iteration error
		return fmt.Errorf("iterating synthetic-local records: %w", cerr)
	}
	if cerr := rows.Close(); cerr != nil {
		return fmt.Errorf("closing synthetic-local rows: %w", cerr)
	}

	var h domain2.CallGraphRecordHasher
	for _, c := range found {
		raw, derr := blobcodec.Decode(c.blob)
		if derr != nil {
			return fmt.Errorf("decompressing record %s: %w", c.hash, derr)
		}
		rec, uerr := h.Unmarshal(raw)
		if uerr != nil {
			return fmt.Errorf("unmarshalling record %s: %w", c.hash, uerr)
		}
		if rec.ArtefactIdentity != "" || rec.AnalysisSource != domain2.AnalysisSourceUnrecorded {
			// A genuinely fetched module that happens to sit at v0.0.0, or a record
			// written since the source field existed. Not ours to remove.
			continue
		}
		if _, eerr := tx.Exec(`DELETE FROM callgraph_edges WHERE record_content_hash = ?`, c.hash); eerr != nil {
			return fmt.Errorf("deleting edges for stranded record %s: %w", c.hash, eerr)
		}
		if _, rerr := tx.Exec(`DELETE FROM callgraph_records WHERE content_hash = ?`, c.hash); rerr != nil {
			return fmt.Errorf("deleting stranded record %s: %w", c.hash, rerr)
		}
	}
	return nil
}

// backfillCompleteness populates callgraph_records.completeness from each row's
// own serialised record.
//
// Rows are drained fully before any UPDATE is issued. The store runs on a single
// connection, so writing while the SELECT's result set is still open deadlocks.
//
// A row that cannot be decoded is an error rather than a skip. The migration runs
// inside the caller's transaction, so failing rolls back the schema change it
// accompanies — leaving a store whose column disagrees with its rows for the
// second time is the outcome worth refusing.
func backfillCompleteness(tx *sql.Tx) error {
	rows, err := tx.Query(`SELECT rowid, serialised FROM callgraph_records WHERE completeness = ''`)
	if err != nil {
		return fmt.Errorf("selecting rows to back-fill: %w", err)
	}
	type pending struct {
		rowID int64
		blob  []byte
	}
	var todo []pending
	for rows.Next() {
		var p pending
		if serr := rows.Scan(&p.rowID, &p.blob); serr != nil {
			_ = rows.Close() //nolint:errcheck // returning the scan error
			return fmt.Errorf("scanning row to back-fill: %w", serr)
		}
		todo = append(todo, p)
	}
	if cerr := rows.Err(); cerr != nil {
		_ = rows.Close() //nolint:errcheck // returning the iteration error
		return fmt.Errorf("iterating rows to back-fill: %w", cerr)
	}
	if cerr := rows.Close(); cerr != nil {
		return fmt.Errorf("closing back-fill rows: %w", cerr)
	}

	var h domain2.CallGraphRecordHasher
	for _, p := range todo {
		raw, derr := blobcodec.Decode(p.blob)
		if derr != nil {
			return fmt.Errorf("decompressing record %d: %w", p.rowID, derr)
		}
		rec, uerr := h.Unmarshal(raw)
		if uerr != nil {
			return fmt.Errorf("unmarshalling record %d: %w", p.rowID, uerr)
		}
		if rec.Completeness == domain2.CompletenessUnknown {
			// The record genuinely records no level — written before the field, or by
			// a path that makes no fidelity claim. '' is already correct for it.
			continue
		}
		if _, uerr := tx.Exec(`UPDATE callgraph_records SET completeness = ? WHERE rowid = ?`,
			string(rec.Completeness), p.rowID); uerr != nil {
			return fmt.Errorf("back-filling completeness for record %d: %w", p.rowID, uerr)
		}
	}
	return nil
}

// Open opens (or creates) the SQLite database at dsn and runs migrations.
// Use ":memory:" for tests.
func Open(dsn string) (*Store, error) {
	db, err := sqlitestore.Open(dsn, Migrations())
	if err != nil {
		return nil, fmt.Errorf("opening callgraph store: %w", err)
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
		return fmt.Errorf("closing callgraph store: %w", err)
	}
	return nil
}

// PutCallGraphRecord appends an extraction to the ledger, together with the edge
// rows belonging to it.
//
// It never updates. The record key carries the time of measurement and the
// record's own content hash, so two distinct extractions are always two rows;
// the edge rows carry the parent record's content hash, so each generation's
// edges are its own. The only collision left is the same record written twice,
// which the conflict clauses make a no-op because it is one measurement rather
// than two — and it must not be an error, or a retried write would fail a run
// that had already succeeded.
//
// The edge rows are appended, never deleted. Deleting the previous generation's
// edges is what an overwriting store had to do; here it would strand the earlier
// record with no graph to reconstruct — and since the content hash is verified
// over the reconstructed record, that earlier record would then fail its own
// integrity check. That is the orphaning this conversion exists to prevent.
//
// The serialised blob stores the full record minus the Edges slice; edges are
// stored separately in callgraph_edges so that GetCallGraphRecord can
// reconstruct the record without a second full parse of a large blob.
func (s *Store) PutCallGraphRecord(ctx context.Context, r domain2.CallGraphRecord) error {
	// A record whose coordinate is the zero value would key a row on the empty
	// path at the empty version, which every later read treats as a genuine
	// measurement of a module that does not exist.
	if r.Coordinate.IsZero() {
		return coordinate.ErrZeroCoordinate
	}
	// A record produced by analysing a fetched artefact must name which artefact,
	// because composition reads the identity to decide which records describe the
	// same bytes: a zero identity does not merely record nothing, it groups
	// together every record that also recorded nothing.
	//
	// A worktree record is exempt, and that exemption is the point rather than a
	// loophole. Nothing was fetched, so there is no artefact identity to name —
	// inapplicable, not missing — and WorktreeDigest is what identifies it
	// instead. The refusal is therefore written against what the record says it
	// analysed, not against the field being empty.
	//
	// The read leg deliberately does NOT refuse either. Records written before the
	// field existed carry an empty identity legitimately, and refusing on read
	// would make every one of them unreadable. They are read, never rewritten, so
	// the write-leg refusal costs them nothing.
	if r.AnalysisSource != domain2.AnalysisSourceWorktree && r.ArtefactIdentity == "" {
		return fmt.Errorf("call graph record for %s names no artefact: %w", r.Coordinate, fetchdomain.ErrZeroIdentity)
	}
	if r.AnalysisSource == domain2.AnalysisSourceWorktree && r.WorktreeDigest == "" {
		return fmt.Errorf("worktree call graph record for %s identifies no tree: %w",
			r.Coordinate, ports.ErrUnidentifiedWorktree)
	}
	var h domain2.CallGraphRecordHasher
	if err := h.VerifyContentHash(r); err != nil {
		return fmt.Errorf("verifying content hash before put: %w", err)
	}

	// Store the record without the Edges slice to avoid duplicating data that
	// lives in callgraph_edges. The hash was computed over the full record, so
	// GetCallGraphRecord must reconstruct edges from the table before verifying.
	rBlob := r
	rBlob.Edges = nil
	raw, err := h.Marshal(rBlob)
	if err != nil {
		return fmt.Errorf("marshalling callgraph record: %w", err)
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
INSERT INTO callgraph_records (
    module_path, module_version, pipeline_version,
    algorithm, overall_status, completeness, analysis_source, worktree_digest,
    failure_cause,
    node_count, edge_count,
    extracted_at, content_hash, serialised
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (module_path, module_version, pipeline_version, extracted_at, content_hash)
DO NOTHING`

	_, err = tx.ExecContext(ctx, qRecord,
		r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion,
		string(r.Algorithm), int(r.OverallStatus),
		string(r.Completeness), string(r.AnalysisSource), r.WorktreeDigest,
		string(r.FailureCause),
		r.NodeCount, r.EdgeCount,
		r.ExtractedAt.UTC().Format(time.RFC3339),
		r.ContentHash, blob,
	)
	if err != nil {
		return fmt.Errorf("inserting callgraph record: %w", err)
	}

	const qEdge = `
INSERT OR IGNORE INTO callgraph_edges (
    record_content_hash,
    from_module, from_version, pipeline_version,
    from_id, to_id, confidence,
    call_site_file, call_site_line, reflect_dispatch, is_test, kind
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	stmtEdge, err := tx.PrepareContext(ctx, qEdge)
	if err != nil {
		return fmt.Errorf("preparing callgraph edge statement: %w", err)
	}
	defer func() { _ = stmtEdge.Close() }()

	// An edge is test-scope when either end is: a production function calling a
	// test fake, and a test calling production code, are both part of the test
	// surface a query may want to set aside. The role is denormalised onto the
	// edge because the edge queries are answered from this table alone — they
	// never load the record the node roles live in.
	testNode := make(map[string]bool, len(r.Nodes))
	for _, n := range r.Nodes {
		if n.IsTest {
			testNode[n.ID] = true
		}
	}

	for _, e := range r.Edges {
		if _, err := stmtEdge.ExecContext(ctx,
			r.ContentHash,
			r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion,
			e.FromID, e.ToID, string(e.Confidence),
			e.CallSite.File, e.CallSite.Line, e.ReflectDispatch,
			testNode[e.FromID] || testNode[e.ToID],
			string(e.Kind),
		); err != nil {
			return fmt.Errorf("inserting callgraph edge %s→%s: %w", e.FromID, e.ToID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing callgraph record: %w", err)
	}
	_, _ = s.db.DB().ExecContext(ctx, `PRAGMA optimize`) //nolint:errcheck
	return nil
}

// GetCallGraphRecord returns the composed call graph answer for the coordinate
// and pipeline version. Returns (zero, false, nil) when the ledger holds none.
//
// Composition serves the highest completeness, then the most recent. Recency
// alone never wins: a METADATA_ONLY record appended after a BUILT_WITH_BODIES
// one analysed less of the same module, so it is a weaker measurement rather
// than a newer answer. The analysis source is not on that ladder at all — see
// domain.Compose for the dimension rule and for the disagreements composition
// refuses to resolve by picking.
//
// A stored record that fails its integrity check is still ErrCallGraphIntegrity,
// and it stops the read rather than being skipped: dropping it would serve a
// composition computed over fewer records than the ledger holds and report it as
// the whole answer.
func (s *Store) GetCallGraphRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (domain2.CallGraphRecord, bool, error) {
	return s.composeFor(ctx, coord, pipelineVersion, domain2.ComposeRequest{})
}

// GetCallGraphRecordFrom answers the same question as GetCallGraphRecord but
// restricted to records built from one kind of source.
//
// It exists because the source is a dimension: a graph built from a published
// module zip and one built from a working tree describe different bytes, so
// "which does the caller want" is a real question the coordinate cannot answer.
// GetCallGraphRecord applies a stated default (see domain.Compose); this is how
// a caller asks for the other one.
func (s *Store) GetCallGraphRecordFrom(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string, source domain2.AnalysisSource) (domain2.CallGraphRecord, bool, error) {
	return s.composeFor(ctx, coord, pipelineVersion, domain2.ComposeRequest{Source: source})
}

func (s *Store) composeFor(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string, req domain2.ComposeRequest) (domain2.CallGraphRecord, bool, error) {
	// A working tree's generations are a SEQUENCE, so composition serves the last
	// one and needs none of the others — see domain.Compose. Loading N generations
	// to return the Nth is pure waste, and it is unbounded waste: `kanonarion
	// local` appends a generation on every run, forever, and each one costs a full
	// blob decode plus a reconstruction of its entire edge set. Measured before
	// this path existed, on a 115k-edge project: every additional generation added
	// ~0.45s to EVERY callers/callees/implementers query, permanently.
	//
	// Reading only the newest row makes that O(1) in the depth of the history. It
	// is exactly equivalent, not an approximation: the sequence rule's "last" is by
	// insertion order, which is what this query returns.
	if latest, ok, err := s.latestWorktreeGeneration(ctx, coord, pipelineVersion, req); ok || err != nil {
		return latest, ok, err
	}

	records, err := s.ListCallGraphRecordsFor(ctx, coord, pipelineVersion)
	if err != nil {
		return domain2.CallGraphRecord{}, false, err
	}
	if len(records) == 0 {
		return domain2.CallGraphRecord{}, false, nil
	}
	composed, err := domain2.Compose(records, req)
	if errors.Is(err, domain2.ErrNoRecordsToCompose) {
		// The ledger holds generations, but none from the source the caller asked
		// for. That is an absence of an answer to THIS question, not an error.
		return domain2.CallGraphRecord{}, false, nil
	}
	if err != nil {
		return domain2.CallGraphRecord{}, false, fmt.Errorf("%w: %w", ports.ErrCallGraphConflict, err)
	}
	return composed, true, nil
}

// latestWorktreeGeneration answers a compose request from the newest row alone,
// when the coordinate's generations are a working-tree sequence.
//
// It reports ok=false when the fast path does not apply, and the caller falls
// back to composing the full history. It applies only when BOTH hold:
//
//   - the coordinate is local — nothing else stores a working tree; and
//   - no generation at that coordinate came from a module zip.
//
// The second condition is the one that is easy to miss. A local coordinate can
// legitimately hold a zip-sourced record too (a walk over a local-path replace
// target fetches and analyses one), and then the answer is decided by the source
// dimension and the completeness ladder rather than by the sequence — so the fast
// path must stand aside. Both conditions are decided from COLUMNS, without
// decoding anything.
//
// A request that explicitly names the module-zip source also stands aside: it is
// asking the other question.
func (s *Store) latestWorktreeGeneration(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string, req domain2.ComposeRequest) (domain2.CallGraphRecord, bool, error) {
	if !coord.IsLocal() || req.Source == domain2.AnalysisSourceModuleZip {
		return domain2.CallGraphRecord{}, false, nil
	}
	const qSources = `SELECT DISTINCT analysis_source FROM callgraph_records
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?`
	rows, err := s.db.DB().QueryContext(ctx, qSources, coord.Path(), coord.Version(), pipelineVersion)
	if err != nil {
		return domain2.CallGraphRecord{}, false, fmt.Errorf("querying analysis sources for %s: %w", coord, err)
	}
	var sources []string
	for rows.Next() {
		var src string
		if serr := rows.Scan(&src); serr != nil {
			_ = rows.Close() //nolint:errcheck // returning the scan error
			return domain2.CallGraphRecord{}, false, fmt.Errorf("scanning analysis source: %w", serr)
		}
		sources = append(sources, src)
	}
	if cerr := rows.Err(); cerr != nil {
		_ = rows.Close() //nolint:errcheck // returning the iteration error
		return domain2.CallGraphRecord{}, false, fmt.Errorf("iterating analysis sources: %w", cerr)
	}
	if cerr := rows.Close(); cerr != nil {
		return domain2.CallGraphRecord{}, false, fmt.Errorf("closing analysis source rows: %w", cerr)
	}
	if len(sources) == 0 {
		return domain2.CallGraphRecord{}, false, nil
	}
	for _, src := range sources {
		if domain2.AnalysisSource(src) == domain2.AnalysisSourceModuleZip {
			return domain2.CallGraphRecord{}, false, nil
		}
	}

	// "Last" is by insertion order, because extracted_at persists at second
	// precision and two runs within one second share it.
	const qLatest = `SELECT serialised, content_hash FROM callgraph_records
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?
ORDER BY extracted_at DESC, rowid DESC
LIMIT 1`
	var blob []byte
	var storedHash string
	if serr := s.db.DB().QueryRowContext(ctx, qLatest,
		coord.Path(), coord.Version(), pipelineVersion).Scan(&blob, &storedHash); errors.Is(serr, sql.ErrNoRows) {
		return domain2.CallGraphRecord{}, false, nil
	} else if serr != nil {
		return domain2.CallGraphRecord{}, false, fmt.Errorf("querying latest generation for %s: %w", coord, serr)
	}
	rec, ok, derr := s.decodeRecord(ctx, blob, storedHash)
	if derr != nil {
		return domain2.CallGraphRecord{}, false, derr
	}
	if !ok {
		// The newest generation was written at an older canonical shape. Fall back
		// to the full read, which skips it and may find an older readable one.
		return domain2.CallGraphRecord{}, false, nil
	}
	return rec, true, nil
}

// ListCallGraphRecordsFor returns every generation the ledger holds for one
// coordinate and pipeline version, in the order they were appended, each with
// its own edges reconstructed and its content hash verified.
//
// This is what makes the ledger observable, and for this domain it is also what
// makes a reported non-determination examinable: the two records that disagree
// are both still here, each naming the artefact or the working tree it was
// computed from.
//
// The secondary sort is the row id, not the content hash. extracted_at persists
// at second precision — that is the precision the canonical hash covers — and
// two extractions within one second carry the same timestamp. The ledger is
// append-only, so insertion order is the sequence it actually has, and
// composition relies on it for a mutating working tree.
func (s *Store) ListCallGraphRecordsFor(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) ([]domain2.CallGraphRecord, error) {
	// The zero coordinate names no module, so this is a question about nothing.
	// Answering it with absence would report "no record here" for a module that
	// was never asked about — see coordinate.ErrZeroCoordinate.
	if coord.IsZero() {
		return nil, coordinate.ErrZeroCoordinate
	}
	const q = `SELECT serialised, content_hash FROM callgraph_records
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?
ORDER BY extracted_at ASC, rowid ASC`

	rows, err := s.db.DB().QueryContext(ctx, q, coord.Path(), coord.Version(), pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("querying callgraph records: %w", err)
	}
	type stored struct {
		blob []byte
		hash string
	}
	var raw []stored
	for rows.Next() {
		var st stored
		if serr := rows.Scan(&st.blob, &st.hash); serr != nil {
			_ = rows.Close() //nolint:errcheck // returning the scan error
			return nil, fmt.Errorf("scanning callgraph record: %w", serr)
		}
		raw = append(raw, st)
	}
	if cerr := rows.Err(); cerr != nil {
		_ = rows.Close() //nolint:errcheck // returning the iteration error
		return nil, fmt.Errorf("iterating callgraph records: %w", cerr)
	}
	if cerr := rows.Close(); cerr != nil {
		return nil, fmt.Errorf("closing callgraph record rows: %w", cerr)
	}

	// The edge fetch runs after the record rows are drained, not inside the loop:
	// the store is opened on a single connection, so a second query issued while
	// the first result set is still open deadlocks.
	out := make([]domain2.CallGraphRecord, 0, len(raw))
	for _, st := range raw {
		rec, ok, derr := s.decodeRecord(ctx, st.blob, st.hash)
		if derr != nil {
			return nil, derr
		}
		if !ok {
			// Written at an older canonical shape. Skipped for composition rather
			// than reported: see decodeRecord.
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}

// decodeRecord turns one stored row into a verified record, reconstructing its
// edges from the satellite. The bool is false when the row was written at an
// older canonical shape.
//
// The schema version is part of a record's identity, not just a hint about how
// to verify it. A record written at an older schema decodes with every later
// field at its zero value, and the caller cannot tell "absent because the
// analysed code has none" from "absent because this record predates the field".
// Skipping it routes the caller down the path it already has for a missing
// record — re-extraction — which is what makes a schema bump self-enforcing
// rather than a claim in a comment.
//
// This gate is also why the ledger does not need a purge on every analyser shape
// change: the stale generation stays in the table, readable as history, and
// answers nothing.
func (s *Store) decodeRecord(ctx context.Context, blob []byte, storedHash string) (domain2.CallGraphRecord, bool, error) {
	raw, decErr := blobcodec.Decode(blob)
	if decErr != nil {
		return domain2.CallGraphRecord{}, false, fmt.Errorf("decompressing callgraph record: %w", decErr)
	}

	var h domain2.CallGraphRecordHasher
	rec, err := h.Unmarshal(raw)
	if err != nil {
		return domain2.CallGraphRecord{}, false, fmt.Errorf("unmarshalling callgraph record: %w", err)
	}
	if rec.SchemaVersion != domain2.CallGraphSchemaVersion {
		return domain2.CallGraphRecord{}, false, nil
	}

	// Current-schema blobs omit edges; reconstruct them from callgraph_edges and
	// verify the hash over the full reconstructed record.
	if rec.ContentHash != storedHash {
		return domain2.CallGraphRecord{}, false, fmt.Errorf("%w: embedded hash %q does not match stored %q",
			ports.ErrCallGraphIntegrity, rec.ContentHash, storedHash)
	}
	edges, fetchErr := s.fetchEdges(ctx, storedHash)
	if fetchErr != nil {
		return domain2.CallGraphRecord{}, false, fetchErr
	}
	rec.Edges = edges
	if verr := h.VerifyContentHash(rec); verr != nil {
		return domain2.CallGraphRecord{}, false, fmt.Errorf("%w: %w", ports.ErrCallGraphIntegrity, verr)
	}
	return rec, true, nil
}

// fetchEdges queries callgraph_edges for the edges belonging to ONE record,
// addressed by that record's content hash, in canonical sort order (from_id,
// to_id, call_site_file, call_site_line).
//
// Addressed by the parent record rather than by the coordinate: under an
// append-only parent a coordinate names every generation at once, so a
// coordinate-keyed fetch would hand a record the union of its own edges and
// every other generation's — and the hash verification over the reconstructed
// record would then fail on a record nothing had tampered with.
func (s *Store) fetchEdges(ctx context.Context, recordContentHash string) ([]domain2.CallEdge, error) {
	const q = `SELECT from_id, to_id, confidence, call_site_file, call_site_line, reflect_dispatch, kind
	    FROM callgraph_edges
	    WHERE record_content_hash = ?
	    ORDER BY from_id, to_id, call_site_file, call_site_line`

	rows, err := s.db.DB().QueryContext(ctx, q, recordContentHash)
	if err != nil {
		return nil, fmt.Errorf("fetching callgraph edges: %w", err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck
	}()

	var edges []domain2.CallEdge
	for rows.Next() {
		var e domain2.CallEdge
		var conf, kind string
		var reflectDispatch bool
		if serr := rows.Scan(&e.FromID, &e.ToID, &conf, &e.CallSite.File, &e.CallSite.Line, &reflectDispatch, &kind); serr != nil {
			return nil, fmt.Errorf("scanning callgraph edge: %w", serr)
		}
		e.Kind = domain2.EdgeKind(kind)
		// Normalise any legacy vocabulary lingering in the table; a stored
		// Reflection string also implies the reflect origin.
		e.Confidence, e.ReflectDispatch = domain2.MigrateConfidence(conf)
		e.ReflectDispatch = e.ReflectDispatch || reflectDispatch
		edges = append(edges, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating callgraph edges: %w", err)
	}
	return edges, nil
}

// ListCallGraphRecords returns one summary per module, pipeline version pair —
// the generation composition serves — ordered by extracted_at descending.
//
// One summary per module, not one per row. The ledger holds a row per
// extraction, so listing rows would show a re-analysed module once per
// generation, and an operator reading the list has no way to tell a second
// generation from a second module.
//
// Limit and offset are applied AFTER the collapse, so they count modules rather
// than rows. Applying them in SQL would let a module with three generations
// consume three places of a --limit 50, and the page an operator sees would
// depend on how many times each module happened to be re-analysed.
func (s *Store) ListCallGraphRecords(ctx context.Context, filter ports.CallGraphFilter) ([]ports.CallGraphSummary, error) {
	// No LIMIT or OFFSET here: paging happens after the collapse, on modules
	// rather than rows.
	q := `SELECT module_path, module_version, pipeline_version,
	             algorithm, overall_status, completeness, analysis_source,
	             node_count, edge_count,
	             extracted_at, content_hash
	      FROM callgraph_records`
	var args []any
	var where []string

	if filter.ModulePath != "" {
		where = append(where, "module_path = ?")
		args = append(args, filter.ModulePath)
	}
	if filter.PipelineVersion != "" {
		where = append(where, "pipeline_version = ?")
		args = append(args, filter.PipelineVersion)
	}
	if filter.AnalysisSource != domain2.AnalysisSourceUnrecorded {
		where = append(where, "analysis_source = ?")
		args = append(args, string(filter.AnalysisSource))
	}

	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY extracted_at DESC, rowid DESC"

	rows, err := s.db.DB().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing callgraph records: %w", err)
	}

	type generationKey struct{ path, version, pipeline string }
	var order []generationKey
	counts := map[generationKey]int{}
	first := map[generationKey]ports.CallGraphSummary{}

	for rows.Next() {
		var sum ports.CallGraphSummary
		var extractedAt string
		var status int
		var algo, completeness, source string
		if serr := rows.Scan(
			&sum.ModulePath, &sum.ModuleVersion, &sum.PipelineVersion,
			&algo, &status, &completeness, &source, &sum.NodeCount, &sum.EdgeCount,
			&extractedAt, &sum.ContentHash,
		); serr != nil {
			_ = rows.Close() //nolint:errcheck // returning the scan error
			return nil, fmt.Errorf("scanning callgraph summary: %w", serr)
		}
		t, perr := time.Parse(time.RFC3339, extractedAt)
		if perr != nil {
			_ = rows.Close() //nolint:errcheck // returning the parse error
			return nil, fmt.Errorf("parsing extracted_at %q: %w", extractedAt, perr)
		}
		sum.ExtractedAt = t.UTC()
		sum.OverallStatus = domain2.CallGraphStatus(status)
		sum.Algorithm = domain2.CallGraphAlgorithm(algo)
		sum.Completeness = domain2.CompletenessLevel(completeness)
		sum.AnalysisSource = domain2.AnalysisSource(source)

		k := generationKey{sum.ModulePath, sum.ModuleVersion, sum.PipelineVersion}
		if counts[k] == 0 {
			order = append(order, k)
			first[k] = sum
		}
		counts[k]++
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close() //nolint:errcheck // returning the iteration error
		return nil, fmt.Errorf("iterating callgraph summaries: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("closing callgraph summary rows: %w", err)
	}

	out := make([]ports.CallGraphSummary, 0, len(order))
	for _, k := range order {
		if counts[k] == 1 {
			// The overwhelming majority: one generation, so the columns already
			// describe the served record and no blob is decoded to learn it.
			out = append(out, first[k])
			continue
		}
		coord, cerr := coordinate.NewModuleCoordinate(k.path, k.version)
		if cerr != nil {
			return nil, fmt.Errorf("callgraph record %s@%s names no module: %w", k.path, k.version, cerr)
		}
		served, found, gerr := s.GetCallGraphRecord(ctx, coord, k.pipeline)
		if errors.Is(gerr, ports.ErrCallGraphConflict) {
			// Reported on the row, not raised as the list's error: see the comment
			// on CallGraphSummary.Conflict.
			out = append(out, ports.CallGraphSummary{
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
		out = append(out, ports.CallGraphSummary{
			ModulePath:      k.path,
			ModuleVersion:   k.version,
			PipelineVersion: k.pipeline,
			Algorithm:       served.Algorithm,
			OverallStatus:   served.OverallStatus,
			Completeness:    served.Completeness,
			AnalysisSource:  served.AnalysisSource,
			NodeCount:       served.NodeCount,
			EdgeCount:       served.EdgeCount,
			ExtractedAt:     served.ExtractedAt.UTC(),
			ContentHash:     served.ContentHash,
		})
	}

	return pageSummaries(out, filter.Limit, filter.Offset), nil
}

// pageSummaries applies the caller's limit and offset to the collapsed list.
func pageSummaries(sums []ports.CallGraphSummary, limit, offset int) []ports.CallGraphSummary {
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

// servedContentHash returns the content hash of the record composition serves for
// one coordinate and pipeline version, and whether the ledger holds any.
//
// It is how the satellite is resolved. Edge rows are keyed on the parent
// record's content hash, so "who calls X" is answered by first deciding which
// record answers "what is this module's graph", then taking that record's edges.
// Taking the newest rows for the coordinate instead would be wrong in exactly
// the case the ladder exists for: composition can serve an OLDER record than the
// newest, and then a METADATA_ONLY analysis's edges would be read as though they
// were the complete answer's.
//
// The single-generation case — every module in the store today — is answered
// from the column without decoding a blob, which matters at millions of edge
// rows.
func (s *Store) servedContentHash(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (string, bool, error) {
	const q = `SELECT content_hash FROM callgraph_records
WHERE module_path = ? AND module_version = ? AND pipeline_version = ?
LIMIT 2`
	rows, err := s.db.DB().QueryContext(ctx, q, coord.Path(), coord.Version(), pipelineVersion)
	if err != nil {
		return "", false, fmt.Errorf("querying callgraph generations for %s: %w", coord, err)
	}
	var hashes []string
	for rows.Next() {
		var h string
		if serr := rows.Scan(&h); serr != nil {
			_ = rows.Close() //nolint:errcheck // returning the scan error
			return "", false, fmt.Errorf("scanning callgraph generation hash: %w", serr)
		}
		hashes = append(hashes, h)
	}
	if cerr := rows.Err(); cerr != nil {
		_ = rows.Close() //nolint:errcheck // returning the iteration error
		return "", false, fmt.Errorf("iterating callgraph generations: %w", cerr)
	}
	if cerr := rows.Close(); cerr != nil {
		return "", false, fmt.Errorf("closing callgraph generation rows: %w", cerr)
	}

	switch len(hashes) {
	case 0:
		return "", false, nil
	case 1:
		return hashes[0], true, nil
	default:
		served, found, gerr := s.GetCallGraphRecord(ctx, coord, pipelineVersion)
		if gerr != nil {
			return "", false, gerr
		}
		return served.ContentHash, found, nil
	}
}

// FindCallers returns all edges where the callee matches symbolID, restricted
// to edges owned by a module in scope (see ports.CallGraphStore).
func (s *Store) FindCallers(ctx context.Context, symbolID string, pipelineVersion string, scope coordinate.ModuleSet, opts ports.EdgeQueryOptions) ([]ports.CallEdgeRef, error) {
	q := `SELECT DISTINCT record_content_hash, from_module, from_version, pipeline_version,
	                   from_id, to_id, confidence, is_test, kind
	            FROM callgraph_edges
	            WHERE to_id = ? AND pipeline_version = ?`
	if opts.ExcludeTests {
		q += ` AND is_test = 0`
	}
	q += ` ORDER BY from_module, from_version, from_id`
	return s.queryEdges(ctx, q, symbolID, pipelineVersion, scope)
}

// FindCallees returns all edges where the caller matches symbolID, restricted
// to edges owned by a module in scope (see ports.CallGraphStore).
func (s *Store) FindCallees(ctx context.Context, symbolID string, pipelineVersion string, scope coordinate.ModuleSet, opts ports.EdgeQueryOptions) ([]ports.CallEdgeRef, error) {
	q := `SELECT DISTINCT record_content_hash, from_module, from_version, pipeline_version,
	                   from_id, to_id, confidence, is_test, kind
	            FROM callgraph_edges
	            WHERE from_id = ? AND pipeline_version = ?`
	if opts.ExcludeTests {
		q += ` AND is_test = 0`
	}
	q += ` ORDER BY from_module, from_version, to_id`
	return s.queryEdges(ctx, q, symbolID, pipelineVersion, scope)
}

// queryEdges runs an edge query and drops rows whose owning module is outside
// scope. The filter is applied here rather than in SQL because a build's version
// set is a list of pairs, not a range: expressing it as a WHERE clause means one
// bound parameter per module, and a full-depth walk can hold thousands. Both
// queries are already driven by an index on the symbol ID, so the rows reaching
// this loop are the matches for one symbol — a set small enough that filtering
// in Go costs nothing the parameter list would not cost more of.
func (s *Store) queryEdges(ctx context.Context, q, symbolID, pipelineVersion string, scope coordinate.ModuleSet) ([]ports.CallEdgeRef, error) {
	rows, err := s.db.DB().QueryContext(ctx, q, symbolID, pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("querying callgraph edges: %w", err)
	}

	var candidates []edgeCandidate
	for rows.Next() {
		var c edgeCandidate
		var conf, kind string
		if serr := rows.Scan(
			&c.recordHash,
			&c.ref.ModulePath, &c.ref.ModuleVersion, &c.ref.PipelineVersion,
			&c.ref.FromID, &c.ref.ToID, &conf, &c.ref.IsTest, &kind,
		); serr != nil {
			_ = rows.Close() //nolint:errcheck // returning the scan error
			return nil, fmt.Errorf("scanning callgraph edge ref: %w", serr)
		}
		if !scope.ContainsPathVersion(c.ref.ModulePath, c.ref.ModuleVersion) {
			continue
		}
		// Normalise any legacy vocabulary lingering in the table so query
		// consumers only ever see the current confidence tags.
		c.ref.Confidence, _ = domain2.MigrateConfidence(conf)
		c.ref.Kind = domain2.EdgeKind(kind)
		candidates = append(candidates, c)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close() //nolint:errcheck // returning the iteration error
		return nil, fmt.Errorf("iterating callgraph edge refs: %w", err)
	}
	// Drained and closed before resolving the served generation: the store runs on
	// a single connection, so issuing the resolution query while this result set
	// is still open deadlocks.
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("closing callgraph edge rows: %w", err)
	}

	return s.servedEdges(ctx, candidates, pipelineVersion)
}

// edgeCandidate is one edge row together with the record it belongs to.
type edgeCandidate struct {
	recordHash string
	ref        ports.CallEdgeRef
}

// servedEdges keeps the candidate rows belonging to the record composition
// serves for their module, and drops the rest.
//
// This is the read half of the satellite rekey. Without it a module holding two
// generations returns each edge once per generation, and — worse — a
// METADATA_ONLY analysis's edges would be indistinguishable from a
// BUILT_WITH_BODIES one's, which is the distinction the whole composition ladder
// is built on.
//
// A module whose records are in conflict is omitted from the result and reported
// alongside it, rather than failing the whole query: a caller/callee lookup spans
// every module in the store, so one disputed module must not delete every correct
// answer. Callers get the refs AND a non-nil error, so nothing is dropped
// silently.
func (s *Store) servedEdges(ctx context.Context, candidates []edgeCandidate, pipelineVersion string) ([]ports.CallEdgeRef, error) {
	type moduleKey struct{ path, version string }
	served := map[moduleKey]string{}
	var conflicts []error

	out := make([]ports.CallEdgeRef, 0, len(candidates))
	for _, c := range candidates {
		k := moduleKey{c.ref.ModulePath, c.ref.ModuleVersion}
		hash, resolved := served[k]
		if !resolved {
			coord, cerr := coordinate.NewModuleCoordinate(k.path, k.version)
			if cerr != nil {
				return nil, fmt.Errorf("callgraph edge row %s@%s names no module: %w", k.path, k.version, cerr)
			}
			h, found, herr := s.servedContentHash(ctx, coord, pipelineVersion)
			switch {
			case errors.Is(herr, ports.ErrCallGraphConflict):
				conflicts = append(conflicts, herr)
				h = ""
			case herr != nil:
				return nil, herr
			case !found:
				// An edge row whose parent record is not in the ledger. The write path
				// inserts both in one transaction and neither is ever deleted, so this
				// cannot arise from a completed write; reporting it is the only way it
				// does not become a silently short answer.
				return nil, fmt.Errorf("callgraph edge row for %s@%s at pipeline %s has no record in the ledger",
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
			ports.ErrCallGraphConflict, len(conflicts), errors.Join(conflicts...))
	}
	return out, nil
}

// Ensure Store implements ports.CallGraphStore and the optional ledger reads at
// compile time.
var (
	_ ports.CallGraphStore        = (*Store)(nil)
	_ ports.CallGraphRecordLister = (*Store)(nil)
	_ ports.CallGraphSourceReader = (*Store)(nil)
)
