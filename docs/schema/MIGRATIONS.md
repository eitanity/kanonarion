# Output & Config Schema Migrations

Kanonarion versions schemas **per registered unit** (per-module fact records,
per-stage pipeline versions, the config schema), not via a single global
envelope. This file is the human-readable migration log; it complements the
output-schema stability contract and the store-migration policy.

## Compatibility contract

- Adding a field or a new optional top-level output **section** is a
  non-breaking, additive change. Consumers MUST ignore unknown fields.
- Removing/renaming a field, changing a type, or changing an exit-code meaning
  is breaking and requires a version bump + an entry here.

## Config schema

### v1 → v2

**Additive, backward-compatible.** v2 adds four unified supply-chain
governance blocks to `config.yaml`:

- `directive_policy` - replace/exclude classification outcomes
- `godebug_policy` - red/amber/green tier outcomes
- `vendor_policy` - drift/inconsistency outcomes + `vendor_only`
- `fips_policy` - `required` + `on_deviation`

Migration for existing configs: **none required.** A `version: "1"` file with
no governance blocks continues to load; absent blocks resolve to the default
governance posture (`DefaultConfig`), and an unset outcome resolves to an
implicit allow. To adopt v2 explicitly, set `version: "2"` and add any blocks
you wish to override.

## JSON output sections

The following top-level `--json` sections are introduced **additively** by the
supply-chain governance work on top of the shared corpus groundwork. Consumers
pinned to the prior shape are unaffected (unknown-section rule above):

| Section      | Status                |
|--------------|-----------------------|
| `directives` | reserved              |
| `godebug`    | reserved              |
| `vendor`     | reserved              |
| `fips`       | reserved              |

## Vulnerability record: pipeline `v14` → `v15`

**Additive.** Two changes to `VulnerabilityRecord`'s stored shape, both of which
alter the canonical bytes it hashes over, hence the pipeline bump:

- `coverage_status` (`Analysed` / `Unscannable` / `Failed`) and
  `findings_status` (`Affected` / `Clean`) join the collapsed `overall_status`,
  whose four values answered two different questions. `overall_status` keeps its
  existing values, so a consumer that reads only the summary word is unaffected;
  a consumer that wants a findings fact must read `findings_status`. See
  [`docs/cli/vuln.md`](../cli/vuln.md) for the mapping.
- `database_snapshot.content_hash` is now populated. It was already part of the
  record's shape and empty on every record ever written.

Migration for existing stores: **none required by the consumer.** Store
migration 11 back-fills the axis columns from `overall_status`; the projection is exact, so no verdict changes.
Records at `v14` and earlier are kept and still answer queries — their blobs
carry no axes, and readers derive them from `overall_status` on read. New scans
write `v15`.

## Vulnerability record: pipeline `v15` → `v16`

**Additive, and hash-transparent.** `VulnerabilityFinding` gains `withdrawn_at`,
the OSV top-level `withdrawn` timestamp, so a retracted advisory stops being
reported as a finding against the module it names.

The field carries `omitzero`, so it is absent from the encoding exactly when it is
zero, and a `v15` record's hash recomputes identically under this generation. The
bump records that the *verdict* changed, not the bytes: `overall_status` and
`findings_status` gain a fifth/third value, `Withdrawn`, for a module whose every
matched advisory has been retracted. A mixture stays `Affected` — one live advisory
decides the axis, and the retracted ones remain visible per finding.

Migration for existing stores: **none.** No store migration and no purge; existing
records verify unchanged. Their `withdrawn_at` is absent, which reads as "the
generation that wrote this never asked", not as "confirmed live" — re-scan to get a
retraction verdict for a coordinate scanned before `v16`. New scans write `v16`.

Consumer impact: `audit --json` gains `vuln_withdrawn` (`vuln_findings` keeps its
existing meaning, retracted advisories included), `context` gains
`findings[].withdrawn_at`, `reachability` gains a `withdrawn` verdict with
`withdrawn_at`, `vuln-scan-diff` gains a `WithdrawnFindings` bucket, and a
CycloneDX SBOM marks a retracted advisory `analysis.state: false_positive` with no
`ratings` block.

## Staleness ledger: new store module `staleness`, migration 1

**Additive; a new table, no existing record shape changes.**
`staleness_records` caches what a module proxy said about a module **path**: the
latest version at that path, its publication time, the result of the
newer-major probe, and the time of the lookup. The whole store's migration count
goes `v71` -> `v72`.

It owns a **new module series** rather than joining `fetch`. A fetch record is a
sealed, hashed custody fact about a specific version that was acquired; a
staleness row is a mutable, expiring cache of an upstream claim about a path. The
two have different keys (path versus coordinate), different lifetimes, and
different truth conditions, and an overwritable row does not belong in a table
where every other row can be verified. A separate module also keeps the two
version numbers independent, so a ledger change never forces a `fetch` migration.

Rows carry **no content hash and no pipeline version**: there is nothing in them
to verify. What qualifies a row is `looked_up_at`, and every consumer states it.

Migration for existing stores: **none required by the consumer.** The table is
created empty and fills on the next `latest` or `audit`. A row is written only on
a **successful** lookup — a failed one is not a cacheable fact. An *absent* major
path is not a failure: it is a definitive answer, it bounds the probe, and it is
recorded (`major_probe_from` set, `newer_major_path` empty). `major_probe_from`
of `0` means the probe never ran, which is a different answer from "ran and found
none" and is never rendered as one.

Serving is governed by the `staleness.ttl` config key (default `1h`; `0`
disables). `--fresh` on `latest`/`audit` bypasses the read and still records.

## Walk store: module `walk`, migration 6

**Additive; a new column, no record shape change and no pipeline bump.** `walks`
gains `project_dir`: the working-tree directory a walk rooted at a local project
was taken from. A scan by walk id reads it back so it can reach the same analysis
surface the original run did - notably a project's `vendor/` tree, which is
otherwise unreachable without the directory. The whole store's migration count
goes `v72` -> `v73`.

The column sits **outside** the walk's sealed shape: `canonicalWalkRecord` does
not carry it, so it is neither hashed nor serialised into the stored blob. That
is deliberate. The path is machine-local, and admitting it to the hash would make
two walks of one project taken from two checkouts two different walks, for every
record that ever names a walk hash. Because the sealed bytes are untouched, no
`PipelineVersion` bump is owed and no purge is needed: every stored walk still
verifies against the hash it was written with.

Migration for existing stores: **none required.** Existing rows default to the
empty directory, which is also what a walk of a published coordinate records -
that module has no project root. Consumers must read the empty value as "no
project directory", never as "unrecorded": a scan finding it empty behaves
exactly as it did before the column existed. The directory is provenance, not an
oracle - a checkout that has moved or lost its `vendor/` tree degrades the scan
to the fetched surface with the reason logged, and never makes a stored walk
unscannable.

Every project-rooted walk now populates it, the `local` driver's included. The
walk request carries two values with two meanings: the directory the walk was
taken from (recorded, always) and the directory whose Go toolchain is the
authority for the module set (resolution, unchanged). They used to be one field,
which made recording where a walk happened indistinguishable from handing the
toolchain the last word on what it contains, so a driver walk that wanted the
internal resolver had to record no root at all. **Resolution behaviour is
unchanged**, and no bump or migration is owed: the change populates an existing
column on a path that previously left it empty, and the column is outside the
seal.

## Walk store: module `walk`, migration 7

**Additive; a new column, no record shape change and no pipeline bump.** `walks`
gains `identity_hash`: a name for the ANALYSIS a walk performed, as opposed to
`content_hash`, which seals the RECORD. The whole store's migration count goes
`v73` -> `v74`.

The two answer different questions and both are needed. `content_hash` covers
everything the record says, so a stored row cannot be altered without detection
— which means it covers the walk id, `started_at`, `completed_at`,
`graph.resolved_at` and the per-node fetch durations. Two runs of an unchanged
checkout differ in every one of those, so they produced two content hashes and,
with them, two walk ids; every record keyed on a walk id (licences,
vulnerability verdicts, SBOMs) became unreachable from the next run, and a full
re-scan followed because the cache key was fresh by construction rather than
because anything had changed.

`identity_hash` covers the target, scope, depth, ecosystem, both pipeline
versions, the policy version and hash, the stage depths, the build environment,
the resolved graph (every node with its coordinate, resolution source, digests,
stdlib custody and replace origin, plus every edge), each node's status and
error, and the overall status. It deliberately excludes the walk id, the three
timestamps, per-node `duration_ms` and `from_cache`, the operator, and the
composed fetch record — the last because that record carries `first_fetched_at`,
`latest_fetched_at`, `measurement_count` and per-leg dates, all of which move
when the ledger re-measures bytes that never changed. What the identity keeps
from a fetch is the **artefact identity** (the `h1` hash), which is precisely
"these bytes".

The column sits **outside** the sealed shape, like `project_dir`:
`canonicalWalkRecord` does not carry it, so it is neither hashed nor serialised
into the stored blob. Admitting a derived value to the seal would make the seal
cover a function of itself and would stop every previously-written walk from
verifying. A reader that distrusts a stored identity recomputes it from the
record it came with, which costs one hash.

Migration for existing stores: **none required, and no purge.** Existing rows
default to the empty identity. **Empty is an ABSENT identity, never a matching
one** — the reuse lookup filters on a non-empty value, so a pre-existing row is
never served as a reusable walk. Such a project is re-walked once, which writes
its identity, and is reusable from then on. Back-filling was rejected: the
identity is a function of the record, so filling it would mean decompressing and
rehashing every stored walk during a migration to save one re-walk per project.

Nothing verifies `identity_hash` on read and no stored hash is ever compared
across the old and new styles: an old-style walk has no identity at all, so the
comparison cannot arise. Reads of existing walks are unchanged in every respect.

## Vendor record: schema `3` → `4`, pipeline `0.2.0` → `0.3.0`

**Record shape change and a finding-set change; no store migration.** Vendor
records are keyed `(project_module_path, pipeline_version)`, so the bump is the
migration: `0.2.0` rows stay where they are and are never served for a `0.3.0`
request.

Two changes. Each `VendoredModule` records the **package count** from
`vendor/modules.txt` — the package lines under its heading — and the record
carries a **scope statement** naming every module in the tree the report does
not describe, with the reason. The content hash covers the package count, so an
unchanged tree hashes differently from its `0.2.0` record.

The behaviour that forced the bump: a module `modules.txt` lists with no package
under it no longer reports `missing_from_vendor`. No package of the build
imports it, so `go mod vendor` correctly vendors no directory — the old finding
described the toolchain's normal output as drift.

## SBOM: pipeline `0.5.0` → `0.6.0`

**Document bytes change; no store migration.** SBOM records are cached on
`(walk id, scan run id, format, pipeline version)`, so the bump is what stops a
`0.5.0` document being served for a `0.6.0` request. A document generated over a
project-rooted walk whose project carries a `vendor/` tree now carries the
vendor scope annotation. The SBOM record is hashed over the document bytes, not
over a canonical struct, so there is no sealed shape to migrate.

## Audit log (`audit.jsonl`)

Append-only JSONL; **no schema migration** is ever required to add an event
type. Every line carries an `event_type` discriminator. The
fact-record line keeps its historical flat layout with `event_type:
"fact_record_written"` added additively; all other events use the generic
`{event_type, timestamp, payload}` envelope. Recognised event types are the
closed set in `internal/audit`.
