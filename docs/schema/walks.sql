-- walks.sql - canonical schema for the walk record store.
--
-- Walk records are write-once, append-only facts. A record is persisted exactly
-- once per walk execution and never mutated. The primary key is the walk ID (a
-- ULID), which encodes monotonic creation time.
--
-- Design: the full record is stored as a canonical-JSON BLOB (column "serialised")
-- so that the content hash can be re-verified on read. Structured columns are
-- denormalised projections used only for indexed queries; the BLOB is the source
-- of truth. JSON-BLOB storage is used rather than normalised tables so the
-- record round-trips byte-for-byte and its content hash can be re-verified on
-- read.

CREATE TABLE IF NOT EXISTS walks (
    -- id is a ULID generated at walk execution time. It encodes creation time
    -- monotonically and is the canonical stable identifier for a walk record.
    id               TEXT PRIMARY KEY,

    -- target_path and target_version identify the root module of the walk.
    -- Indexed together to support per-target history queries.
    target_path      TEXT NOT NULL,
    target_version   TEXT NOT NULL,

    -- started_at and completed_at are RFC3339 UTC strings. They are indexed
    -- to support time-range filtering in ListWalks.
    started_at       TEXT NOT NULL,
    completed_at     TEXT NOT NULL,

    -- overall_status is the integer representation of WalkStatus:
    --   0 = WalkSucceeded, 1 = WalkPartial, 2 = WalkFailed, 3 = WalkCancelled
    overall_status   INTEGER NOT NULL,

    -- pipeline_version and operator are the pipeline version string and the
    -- operator identifier at walk time.
    pipeline_version TEXT NOT NULL,
    operator         TEXT NOT NULL,

    -- content_hash is the integrity hash of the canonical JSON (sha256:hex).
    -- Verified on every read. A mismatch is treated as an integrity failure.
    content_hash     TEXT NOT NULL,

    -- node_count and failure_count are denormalised summaries for list views.
    -- They are computed from PerNodeResults at write time and stored to avoid
    -- deserialising the full BLOB for summary queries.
    node_count       INTEGER NOT NULL DEFAULT 0,
    failure_count    INTEGER NOT NULL DEFAULT 0,

    -- serialised is the canonical JSON representation of the full WalkRecord.
    -- It is the output of WalkRecordHasher.Marshal and includes all graph nodes,
    -- edges, per-node results, and the content hash itself.
    serialised       BLOB NOT NULL
);

-- walks_target_idx supports queries filtered by target module.
CREATE INDEX IF NOT EXISTS walks_target_idx    ON walks(target_path, target_version);

-- walks_started_at_idx supports time-range and ordered-history queries.
CREATE INDEX IF NOT EXISTS walks_started_at_idx ON walks(started_at);

-- walks_status_idx supports filtering by overall status.
CREATE INDEX IF NOT EXISTS walks_status_idx    ON walks(overall_status);
