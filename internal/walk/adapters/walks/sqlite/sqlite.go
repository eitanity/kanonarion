// Package sqlite implements ports.WalkStore using a SQLite database via
// modernc.org/sqlite (pure Go, no CGO). The schema is versioned through a
// schema_migrations table shared with the fetch fact store when they use the
// same database file.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
	"github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// Store is the SQLite-backed walk store.
type Store struct {
	db sqlitestore.DB
}

// New returns a new Store using the provided database handle.
func New(db sqlitestore.DB) *Store {
	return &Store{db: db}
}

// Migrations returns the schema migrations for the walk module.
func Migrations() []sqlitestore.Migration {
	return []sqlitestore.Migration{
		{Module: "walk", Version: 1, SQL: `CREATE TABLE IF NOT EXISTS walks (
            id               TEXT PRIMARY KEY,
            target_path      TEXT NOT NULL,
            target_version   TEXT NOT NULL,
            started_at       TEXT NOT NULL,
            completed_at     TEXT NOT NULL,
            overall_status   INTEGER NOT NULL,
            pipeline_version TEXT NOT NULL,
            operator         TEXT NOT NULL,
            content_hash     TEXT NOT NULL,
            node_count       INTEGER NOT NULL DEFAULT 0,
            failure_count    INTEGER NOT NULL DEFAULT 0,
            serialised       BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS walks_target_idx    ON walks(target_path, target_version);
        CREATE INDEX IF NOT EXISTS walks_started_at_idx ON walks(started_at);
        CREATE INDEX IF NOT EXISTS walks_status_idx    ON walks(overall_status)`},
		{Module: "walk", Version: 2, SQL: `ALTER TABLE walks ADD COLUMN scope TEXT NOT NULL DEFAULT 'production';
        CREATE INDEX IF NOT EXISTS walks_scope_idx ON walks(scope)`},
		{Module: "walk", Version: 3, SQL: `ALTER TABLE walks ADD COLUMN depth TEXT NOT NULL DEFAULT '';
        CREATE INDEX IF NOT EXISTS walks_depth_idx ON walks(depth)`},
		// The ecosystem field joined the canonical hash and bumped the schema
		// version, so every row written before this migration carries a stale
		// hash and a blob with no ecosystem field — unreadable under the new
		// schema. Purge them; they are regenerable by re-walking.
		{Module: "walk", Version: 4, SQL: `DELETE FROM walks`},
		// Walk records embed the fetch record per node and hash its canonical JSON
		// into the walk's own content hash. That embedded shape became the composed
		// fetch record at pipeline 1.10.0, so every stored walk record's bytes
		// predate a shape this build can no longer produce. There is deliberately no
		// mixed-shape read path: a record is purged rather than served through a
		// second decoder, because a store that answers in two shapes cannot say
		// which one a given hash was computed over.
		{Module: "walk", Version: 5, SQL: `DELETE FROM walks`},
		// The project directory a walk was taken from. It is provenance, not
		// identity: it is outside the walk's content hash and outside the
		// serialised blob, so it needs a column of its own and no purge — every
		// stored row still hashes to exactly what it did, and simply reports the
		// empty directory that rows written before this column mean.
		{Module: "walk", Version: 6, SQL: `ALTER TABLE walks ADD COLUMN project_dir TEXT NOT NULL DEFAULT ''`},
		// The identity of the analysis a walk performed, as distinct from the seal
		// over the record. Like project_dir it is outside the content hash and
		// outside the serialised blob, so it needs a column of its own and no
		// purge: every stored row still hashes to exactly what it did, and simply
		// reports the empty identity that rows written before this column mean.
		//
		// Empty is not a match. The reuse lookup filters on a non-empty identity,
		// so the pre-existing rows are never served as a reusable walk — they are
		// re-walked once, which writes their identity, and are reusable from then
		// on. Back-filling was rejected: the identity is a function of the record,
		// so filling it would mean decompressing and rehashing every stored walk
		// during a migration to save one re-walk per project.
		{Module: "walk", Version: 7, SQL: `ALTER TABLE walks ADD COLUMN identity_hash TEXT NOT NULL DEFAULT '';
        CREATE INDEX IF NOT EXISTS walks_identity_idx ON walks(identity_hash, target_path, target_version, scope)`},
		// The target platform a walk resolved for. It lives inside the sealed blob
		// as part of the graph's build environment, so this is a projection of
		// already-sealed data and not a record-shape change: no purge, no pipeline
		// bump, every stored row still hashes to exactly what it did.
		//
		// Unlike identity_hash this IS back-filled. The value is already in the
		// blob, so filling it costs one decompression per row against a table that
		// holds one row per walk, and leaving it empty would make every stored walk
		// permanently invisible to a platform-filtered lookup — the reads this
		// column exists for. A row whose record carries no build environment
		// back-fills to empty strings, which mean the frame was never recorded.
		{Module: "walk", Version: 8, SQL: `ALTER TABLE walks ADD COLUMN goos TEXT NOT NULL DEFAULT '';
        ALTER TABLE walks ADD COLUMN goarch TEXT NOT NULL DEFAULT '';
        CREATE INDEX IF NOT EXISTS walks_platform_idx ON walks(target_path, target_version, scope, goos, goarch)`,
			Fn: backfillBuildEnv},
		// The toolchain that resolved the walk. Like goos/goarch it lives inside
		// the sealed blob as part of the graph's build environment, so this is a
		// projection of already-sealed data: no purge, no pipeline bump, every
		// stored row still hashes to exactly what it did.
		//
		// It is back-filled for the reason goos/goarch are. The value is already
		// in the blob, and without it every stored walk is invisible to a
		// toolchain-filtered lookup — so a read would fall through to recency and
		// answer about whichever standard library happened to be newest, which is
		// the read this column exists to make impossible. A row whose record
		// carries no build environment back-fills to the empty string, which means
		// the toolchain was never recorded.
		{Module: "walk", Version: 9, SQL: `ALTER TABLE walks ADD COLUMN go_version TEXT NOT NULL DEFAULT '';
        CREATE INDEX IF NOT EXISTS walks_toolchain_idx ON walks(target_path, target_version, scope, go_version)`,
			Fn: backfillGoVersion},
	}
}

// backfillGoVersion fills the go_version column of migration 9 from each stored
// walk's own record, on the same terms as backfillBuildEnv: the blob is decoded
// but not re-verified, so a row whose seal no longer verifies is still projected
// honestly, and a row that cannot be decoded at all is left at the empty
// toolchain rather than failing the migration.
func backfillGoVersion(tx *sql.Tx) error {
	envs, err := scanWalkBuildEnvs(tx)
	if err != nil {
		return err
	}
	for _, e := range envs {
		if e.env.GoVersion == "" {
			continue
		}
		if _, err := tx.Exec(`UPDATE walks SET go_version = ? WHERE id = ?`, e.env.GoVersion, e.id); err != nil {
			return fmt.Errorf("back-filling toolchain for walk %s: %w", e.id, err)
		}
	}
	return nil
}

// walkBuildEnv is one stored row's id and the build environment read out of its
// record.
type walkBuildEnv struct {
	id  string
	env domain.BuildEnv
}

// scanWalkBuildEnvs reads the build environment of every stored walk. It exists
// so a projection migration states only what it projects: the two rules below
// are the same for all of them.
//
// It decodes the blob rather than re-verifying it, so a row whose seal no longer
// verifies is still projected honestly instead of being silently dropped from
// every read the new column serves. A row that cannot be decoded at all is
// skipped rather than failing the migration: the alternative is a store that
// refuses to open because one historical row is unreadable, and an unreadable
// row's build environment is genuinely unrecorded as far as a column can say.
func scanWalkBuildEnvs(tx *sql.Tx) ([]walkBuildEnv, error) {
	rows, err := tx.Query(`SELECT id, serialised FROM walks`)
	if err != nil {
		return nil, fmt.Errorf("reading walks for build-environment back-fill: %w", err)
	}
	var envs []walkBuildEnv
	for rows.Next() {
		var id string
		var blob []byte
		if err := rows.Scan(&id, &blob); err != nil {
			_ = rows.Close() //nolint:errcheck // returning the scan error
			return nil, fmt.Errorf("scanning walk row for build-environment back-fill: %w", err)
		}
		raw, decErr := blobcodec.Decode(blob)
		if decErr != nil {
			continue
		}
		var h domain.WalkRecordHasher
		rec, uErr := h.Unmarshal(raw)
		if uErr != nil {
			continue
		}
		envs = append(envs, walkBuildEnv{id: id, env: rec.Graph.BuildEnv})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close() //nolint:errcheck // returning the iteration error
		return nil, fmt.Errorf("iterating walks for build-environment back-fill: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("closing walk rows after build-environment back-fill: %w", err)
	}
	return envs, nil
}

// backfillBuildEnv fills the goos/goarch columns of migration 8 from each
// stored walk's own record. See scanWalkBuildEnvs for the two rules it reads
// under: the blob is decoded but not re-verified, and a row that cannot be
// decoded is left at the empty frame rather than failing the migration.
func backfillBuildEnv(tx *sql.Tx) error {
	envs, err := scanWalkBuildEnvs(tx)
	if err != nil {
		return err
	}
	for _, e := range envs {
		if e.env.IsZero() {
			continue
		}
		if _, err := tx.Exec(`UPDATE walks SET goos = ?, goarch = ? WHERE id = ?`, e.env.GOOS, e.env.GOARCH, e.id); err != nil {
			return fmt.Errorf("back-filling build environment for walk %s: %w", e.id, err)
		}
	}
	return nil
}

// Open opens (or creates) the SQLite database at dsn and runs migrations.
// Use ":memory:" for tests.
func Open(dsn string) (*Store, error) {
	db, err := sqlitestore.Open(dsn, Migrations())
	if err != nil {
		return nil, fmt.Errorf("opening walk store: %w", err)
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
		return fmt.Errorf("closing walk store: %w", err)
	}
	return nil
}

// PutWalk inserts or replaces a walk record. Verifies the ContentHash before
// storage. Idempotent on ID.
func (s *Store) PutWalk(ctx context.Context, rec domain.WalkRecord) error {
	// A record whose coordinate is the zero value would key a row on the empty
	// path at the empty version, which every later read treats as a genuine
	// measurement of a module that does not exist.
	if rec.Graph.Target.IsZero() {
		return coordinate.ErrZeroCoordinate
	}
	var h domain.WalkRecordHasher
	if err := h.VerifyContentHash(rec); err != nil {
		return fmt.Errorf("verifying content hash before put: %w", err)
	}

	raw, err := h.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshalling walk record: %w", err)
	}
	blob := blobcodec.Encode(raw)

	nodeCount, failureCount := summariseCounts(rec)

	scope := string(rec.Scope)
	if scope == "" {
		scope = string(domain.WalkScopeCode)
	}

	// Store depth as "" for full walks (matches the DEFAULT and omitempty convention).
	depth := string(rec.Depth)
	if depth == string(domain.WalkDepthFull) {
		depth = ""
	}

	const q = `
INSERT INTO walks (
    id, target_path, target_version,
    started_at, completed_at, overall_status,
    pipeline_version, operator, content_hash,
    node_count, failure_count, scope, depth, project_dir, identity_hash,
    goos, goarch, go_version, serialised
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET
    target_path      = excluded.target_path,
    target_version   = excluded.target_version,
    started_at       = excluded.started_at,
    completed_at     = excluded.completed_at,
    overall_status   = excluded.overall_status,
    pipeline_version = excluded.pipeline_version,
    operator         = excluded.operator,
    content_hash     = excluded.content_hash,
    node_count       = excluded.node_count,
    failure_count    = excluded.failure_count,
    scope            = excluded.scope,
    depth            = excluded.depth,
    project_dir      = excluded.project_dir,
    identity_hash    = excluded.identity_hash,
    goos             = excluded.goos,
    goarch           = excluded.goarch,
    go_version       = excluded.go_version,
    serialised       = excluded.serialised`

	_, err = s.db.DB().ExecContext(ctx, q,
		rec.ID, rec.Target.Path(), rec.Target.Version(),
		rec.StartedAt.UTC().Format(time.RFC3339),
		rec.CompletedAt.UTC().Format(time.RFC3339),
		int(rec.OverallStatus),
		rec.PipelineVersion, rec.Operator, rec.ContentHash,
		nodeCount, failureCount, scope, depth, rec.ProjectDir, rec.IdentityHash,
		// Projected from the sealed record, never from the running process: a
		// column that reported the host would answer for a cross-compiled walk in
		// a frame that walk never resolved.
		rec.Graph.BuildEnv.GOOS, rec.Graph.BuildEnv.GOARCH, rec.Graph.BuildEnv.GoVersion, blob,
	)
	if err != nil {
		return fmt.Errorf("inserting walk record: %w", err)
	}
	return nil
}

// PresentWalks reports, for each id in walkIDs, whether this store still holds
// a walk under it. Every id asked about is a key of the result, so a caller
// never has to read absence out of a missing map entry.
//
// It exists so a reader of something that REFERENCES a walk — a stored scan run
// — can state whether the reference resolves without loading the walk itself.
// The record is a compressed blob of the whole graph; presence is a primary-key
// probe, so a listing of a hundred runs costs one indexed read rather than a
// hundred decompressions.
//
// Presence is not readability: a row that is here but no longer decodes still
// answers true. That is the honest split — this method answers "is the subject
// still in the store", and GetWalk answers "can it be read back".
func (s *Store) PresentWalks(ctx context.Context, walkIDs []string) (map[string]bool, error) {
	present := make(map[string]bool, len(walkIDs))
	for _, id := range walkIDs {
		present[id] = false
	}
	if len(present) == 0 {
		return present, nil
	}

	// SQLite caps a statement's bound parameters (999 by default), so the probe
	// is chunked. The chunk size is well under the cap and the query is a
	// primary-key lookup, so the chunking is invisible in the cost.
	const chunk = 400
	ids := make([]string, 0, len(present))
	for id := range present {
		ids = append(ids, id)
	}
	for start := 0; start < len(ids); start += chunk {
		end := min(start+chunk, len(ids))
		batch := ids[start:end]
		args := make([]any, len(batch))
		placeholders := make([]string, len(batch))
		for i, id := range batch {
			args[i] = id
			placeholders[i] = "?"
		}
		q := `SELECT id FROM walks WHERE id IN (` + strings.Join(placeholders, ",") + `)`
		rows, err := s.db.DB().QueryContext(ctx, q, args...)
		if err != nil {
			return nil, fmt.Errorf("querying walk presence: %w", err)
		}
		if err := scanPresentIDs(rows, present); err != nil {
			return nil, err
		}
	}
	return present, nil
}

// scanPresentIDs marks every id the rows report as present. It closes rows.
func scanPresentIDs(rows *sql.Rows, present map[string]bool) (retErr error) {
	defer func() {
		if cerr := rows.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("closing walk presence rows: %w", cerr)
		}
	}()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("scanning walk presence row: %w", err)
		}
		present[id] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterating walk presence rows: %w", err)
	}
	return nil
}

// GetWalk retrieves a walk record by ID. Returns ErrWalkNotFound if absent.
// Returns ErrWalkIntegrity if the stored hash does not verify.
func (s *Store) GetWalk(ctx context.Context, id string) (domain.WalkRecord, error) {
	const q = `SELECT serialised, content_hash, project_dir, identity_hash FROM walks WHERE id = ?`
	row := s.db.DB().QueryRowContext(ctx, q, id)

	var blob []byte
	var storedHash string
	var projectDir string
	var identityHash string
	if err := row.Scan(&blob, &storedHash, &projectDir, &identityHash); errors.Is(err, sql.ErrNoRows) {
		return domain.WalkRecord{}, walkports.ErrWalkNotFound
	} else if err != nil {
		return domain.WalkRecord{}, fmt.Errorf("querying walk record: %w", err)
	}

	blob, decErr := blobcodec.Decode(blob)
	if decErr != nil {
		return domain.WalkRecord{}, fmt.Errorf("decompressing walk record: %w", decErr)
	}
	var h domain.WalkRecordHasher
	rec, err := h.Unmarshal(blob)
	if err != nil {
		return domain.WalkRecord{}, fmt.Errorf("unmarshalling walk record: %w", err)
	}

	if verr := h.VerifyContentHash(rec); verr != nil {
		return domain.WalkRecord{}, fmt.Errorf("%w: %w", walkports.ErrWalkIntegrity, verr)
	}
	// The project directory rides beside the sealed blob, not inside it: the
	// canonical form the hash covers has no such field, so a column that differs
	// between two checkouts of one project cannot make their walks differ. It is
	// restored after the verification it plays no part in.
	rec.ProjectDir = projectDir
	// The identity rides beside the sealed blob for the same reason the project
	// directory does: it is derived from the record rather than part of it, so
	// the canonical form the hash covers has no such field. Restored after the
	// verification it plays no part in.
	rec.IdentityHash = identityHash
	return rec, nil
}

// ListWalks returns summaries ordered by started_at descending.
func (s *Store) ListWalks(ctx context.Context, filter walkports.WalkFilter) ([]walkports.WalkSummary, error) {
	q, args := buildListQuery(filter)
	rows, err := s.db.DB().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing walks: %w", err)
	}
	defer func() {
		_ = rows.Close() //nolint:errcheck // rows.Err() checked below
	}()

	var summaries []walkports.WalkSummary
	for rows.Next() {
		var sum walkports.WalkSummary
		var startedAt, completedAt, scope, depth string
		var targetPath, targetVersion string
		var status int
		if serr := rows.Scan(
			&sum.ID,
			&targetPath, &targetVersion,
			&startedAt, &completedAt,
			&status,
			&sum.NodeCount, &sum.FailureCount,
			&scope, &depth, &sum.IdentityHash,
			&sum.GOOS, &sum.GOARCH, &sum.GoVersion,
		); serr != nil {
			return nil, fmt.Errorf("scanning walk summary: %w", serr)
		}
		t1, perr := time.Parse(time.RFC3339, startedAt)
		if perr != nil {
			return nil, fmt.Errorf("parsing started_at %q: %w", startedAt, perr)
		}
		t2, perr := time.Parse(time.RFC3339, completedAt)
		if perr != nil {
			return nil, fmt.Errorf("parsing completed_at %q: %w", completedAt, perr)
		}
		// The row's two module columns are put back together through the
		// constructor rather than written straight into the summary: a stored pair
		// that is not a coordinate is a corrupt row, and a listing that renders it
		// as a module is how it would go unnoticed.
		target, cErr := coordinate.NewModuleCoordinate(targetPath, targetVersion)
		if cErr != nil {
			return nil, fmt.Errorf("walk summary %s names no target module (%s@%s): %w", sum.ID, targetPath, targetVersion, cErr)
		}
		sum.Target = target
		sum.StartedAt = t1.UTC()
		sum.CompletedAt = t2.UTC()
		sum.OverallStatus = domain.WalkStatus(status)
		sum.Scope = domain.WalkScope(scope)
		if sum.Scope == "" {
			sum.Scope = domain.WalkScopeCode
		}
		sum.Depth = domain.WalkDepth(depth)
		if sum.Depth == "" {
			sum.Depth = domain.WalkDepthFull
		}
		summaries = append(summaries, sum)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating walk summaries: %w", err)
	}
	return summaries, nil
}

func buildListQuery(f walkports.WalkFilter) (string, []any) {
	var q string
	if f.LatestOnly {
		q = `SELECT id, target_path, target_version, started_at, completed_at,
	             overall_status, node_count, failure_count, scope, depth, identity_hash,
	             goos, goarch, go_version
	      FROM walks w1
	      WHERE started_at = (
	          SELECT MAX(started_at) FROM walks w2
	          WHERE w2.target_path = w1.target_path AND w2.target_version = w1.target_version
	          AND w2.scope = w1.scope
	          AND w2.goos = w1.goos AND w2.goarch = w1.goarch
	          AND w2.go_version = w1.go_version
	      )`
	} else {
		q = `SELECT id, target_path, target_version, started_at, completed_at,
	             overall_status, node_count, failure_count, scope, depth, identity_hash,
	             goos, goarch, go_version
	      FROM walks`
	}
	var conditions []string
	var args []any

	if f.Target != nil {
		conditions = append(conditions, "target_path = ? AND target_version = ?")
		args = append(args, f.Target.Path(), f.Target.Version())
	}
	if f.Since != nil {
		conditions = append(conditions, "started_at >= ?")
		args = append(args, f.Since.UTC().Format(time.RFC3339))
	}
	if f.Until != nil {
		conditions = append(conditions, "started_at <= ?")
		args = append(args, f.Until.UTC().Format(time.RFC3339))
	}
	if f.OverallStatus != nil {
		conditions = append(conditions, "overall_status = ?")
		args = append(args, int(*f.OverallStatus))
	}
	if f.Scope != nil {
		conditions = append(conditions, "scope = ?")
		args = append(args, string(*f.Scope))
	}
	if f.IdentityHash != nil {
		conditions = append(conditions, "identity_hash = ?")
		args = append(args, *f.IdentityHash)
	}
	if f.BuildEnv != nil {
		// One clause, both axes, matched exactly. An empty component is not
		// widened to "any": that is what a nil filter is for, and widening here
		// would hand a platform-filtered caller a frame-unrecorded walk.
		conditions = append(conditions, "goos = ? AND goarch = ?")
		args = append(args, f.BuildEnv.GOOS, f.BuildEnv.GOARCH)
	}
	if f.Toolchain != nil {
		// Matched exactly, for the reason BuildEnv is: the empty string names the
		// walks that recorded no toolchain, and widening it to "any" here would
		// hand a caller asking about one standard library a walk that links
		// another. A caller that wants any toolchain leaves the field nil.
		conditions = append(conditions, "go_version = ?")
		args = append(args, *f.Toolchain)
	}
	if f.Depth != nil {
		// Full walks are stored as "" in the DB (omitempty convention).
		d := string(*f.Depth)
		if d == string(domain.WalkDepthFull) {
			d = ""
		}
		conditions = append(conditions, "depth = ?")
		args = append(args, d)
	}

	for i, c := range conditions {
		if i == 0 && !f.LatestOnly {
			q += " WHERE " + c
		} else {
			q += " AND " + c
		}
	}
	// id breaks the tie. started_at is a second-resolution timestamp and two
	// walks can share it; without a tiebreak the row order within a second is
	// whatever the query plan produced, and a page boundary falling inside one
	// can repeat a row or drop it.
	q += " ORDER BY started_at DESC, id DESC"
	if f.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, f.Limit)
		if f.Offset > 0 {
			q += " OFFSET ?"
			args = append(args, f.Offset)
		}
	} else if f.Offset > 0 {
		q += " LIMIT -1 OFFSET ?"
		args = append(args, f.Offset)
	}
	return q, args
}

// summariseCounts returns the total node count and failure count for a record.
func summariseCounts(rec domain.WalkRecord) (nodeCount, failureCount int) {
	nodeCount = len(rec.PerNodeResults)
	for _, nr := range rec.PerNodeResults {
		if nr.Status != domain.NodeSucceeded {
			failureCount++
		}
	}
	return nodeCount, failureCount
}

// Ensure Store implements ports.WalkStore at compile time.
var _ walkports.WalkStore = (*Store)(nil)
