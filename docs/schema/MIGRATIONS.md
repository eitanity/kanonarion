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

### Additive within v2 - `copyright_declarations`

**Additive, backward-compatible, no version bump.** `config.yaml` gains an
optional top-level `copyright_declarations` section: per module path (optionally
`path@version`), the copyright line a human read upstream, who declared it, when,
and the basis they cite. It exists so `notice` can publish an attribution
document for a module whose archive carries no copyright statement.

All four fields (`copyright`, `declared_by`, `declared_on`, `basis`) are
required; an incomplete entry is refused at config load, naming the coordinate.
`declared_on` is an ISO 8601 date.

Migration for existing configs: **none required.** An absent section resolves to
no declarations and every existing refusal and document is unchanged.

`store config show --json` gains a matching `copyright_declarations` object under
the same additive rule (consumers ignore unknown fields). No store table and no
store migration: a human-supplied copyright is an operator assertion, not a
measurement, so it lives in configuration rather than in the measurement ledger.

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

## `audit`, `context` and `latest` --json: the per-module envelope

**Breaking output-shape change; no store migration, no record or pipeline bump.**
Nothing stored changes.

Each command answered with a bare JSON array of module rows. An array has nowhere
to put a fact about the RUN, so the facts printed on stderr — which dependency
scope resolved the rows, how many modules, the flag that narrows it, and for
`context` which build the vulnerability answers were read in — reached a `--json`
consumer nowhere.

**The new shape.** One JSON object at every form and count, rows in `modules`:

```
{ "dependency_scope": {...}|null, "module_count": N, "narrow_with": "--exclude-tests",
  "rooting": {...}|null,          // context only
  "modules": [ ...the rows, unchanged... ] }
```

The rows themselves are unchanged.

## Call graph records: why a generation exists, no migration and no bump

A `CallGraphRecord` gains `derived_by`: which reuse gate governed the run that
appended the generation (`worktree` or `ledger`) and whether that run asked the
gate (`consulted`) or forced past it (`bypassed`).

**No migration, no purge, no pipeline bump, no schema-version bump.**
`derived_by` is `omitzero` and absent from every earlier record, so stored hashes
still verify.

`callgraph_records` is append-only and `--force` appending an identical
measurement is correct; what was missing was the record being able to say so. One
coordinate held thirteen generations of one analysis — same digest, same 13,861
nodes and 186,221 edges — with nothing separating a deliberate re-measurement
from a reuse gate that failed to fire.

## Interface record: pipeline `0.5.0` → `0.6.0`

**Record shape change; no store migration.** The bump is also a repair: a
coordinate whose `0.5.0` generations disagree about the API is not served, and
re-extracting at `0.5.0` only appends another disagreeing generation.

Extraction walked `testdata` subtrees as packages, and handed `go/doc` every
in-frame file of a directory even when two declared the same identifier —
resolved in map iteration order, so each run could differ.
`golang.org/x/tools@v0.49.0` is held nine times at `0.5.0` with nine distinct
APIs from one zip.

Two changes:

- **`testdata` subtrees are no longer packages.** The go tool ignores them, so
  what they hold is not part of any module's API. `golang.org/x/tools` drops
  from 471 packages to 214, all 257 under a `testdata` path.
- **A duplicate identifier in one directory is resolved deterministically**
  rather than by map order.

Migration: **none.** Reads key on the pipeline version.

## Interface record: pipeline `0.4.0` → `0.5.0`

**Record shape change; no store migration.** The bump is also the only repair
available for coordinates the defect had already spoiled.

Extraction parsed every non-test `.go` file in a package directory and evaluated
no build constraints, so a package with mutually exclusive build-tag variants
handed `go/doc` several declarations of one symbol — resolved in map iteration
order. Two extractions of one zip could disagree, and the winner described no
build that exists. Extraction now evaluates build constraints with `go/build`.

Three fields follow into the record:

- **`build_frame`** — the configuration measured (`goos`, `goarch`,
  `cgo_enabled`). An API measured at linux/amd64 and one at windows/386 are
  different facts and must not collide on one coordinate.
- **`out_of_frame`** — marks a package directory whose files are all for other
  configurations.
- **`variant_symbols`** — symbols that differ across configurations.

Migration: **none.** Reads key on the pipeline version, so `0.4.0` records are
not served.

## Interface record: pipeline `0.3.0` → `0.4.0`

**Record shape change; no store migration.** Interface records are keyed
`(module_path, module_version, pipeline_version)`, so the bump is the migration:
`0.3.0` rows stay and are never served for a `0.4.0` request. Cost is one
re-extraction per module on its next `interface` run — 472 records at the time,
each answering not-found until re-extracted, naming the command that produces it.

Two extraction reads changed:

- **A constant group carries its declared type to every member.** A spec with no
  expression list repeats the previous spec's type — what makes an `iota`
  enumeration work. Reading each spec alone left every member but the first with
  no type: 9 of 11 constants on `github.com/golang-jwt/jwt/v4@v4.5.1`.
- A constant's type is the whole of its signature in `interface-diff`, so a
  `0.3.0` record cannot see a grouped constant's type change and a `0.4.0` can.

## Vulnerability record: pipeline `v24` → `v25`

**Content change on three fields; not hash-transparent.**

On a finding whose matched advisory entry names no symbols for the module path:

- `affected_symbols` is now empty. It previously held whatever the `govulncheck`
  trace terminated at, which the advisory never named. Those symbols are still
  available as the last hop of each route under `reachable.routes`.
- `reachable.is_reachable` and `reachable.confidence` now read `false` /
  `Unknown` instead of `true` / `High`.
- The routes are unchanged.

Migration: **none, and no purge.** Reads key on the pipeline version, so `v24`
rows are simply not served for a `v25` question. The three fields sit inside the
hashed canonical shape, so they cannot be corrected in place — re-sealing would
stamp a `v24` record with a conclusion that generation did not reach.

**Cost: every stored vulnerability record is superseded until re-scanned.**


## Vulnerability record: pipeline `v23` → `v24`

**No shape change; not hash-transparent.** One record was built from two advisory
databases and named only one.

`govulncheck` was handed the pinned snapshot, while the coordinate-match route
queried `https://vuln.go.dev` live. An advisory published after the snapshot
therefore entered the record, stamped not-reachable at high confidence by an
analysis that never saw it. Both routes now read the pinned snapshot, and a scan
that cannot read it fails rather than falling back to the live database.

Migration: **none, and no purge.** Reads key on the pipeline version, and the
change lives inside the serialised record rather than in a column. It could not
be a migration in any case: which findings came from the live service was never
recorded.

**Consumer impact.** A scan whose snapshot lags live reports fewer findings, and
only the ones its stated database can produce. A scan whose snapshot agrees with
live is unchanged.

## Licence records: what each licence covers, no migration and no bump

**No migration, no schema-version bump, no pipeline bump.** A licence record now
says what each identified licence GOVERNS — the module's own code, documentation
it ships, or third-party material it carries — and a licence that does not govern
the code no longer enters the expression, holds the primary, or contributes
obligations.

Coverage is derived from `LicenseFiles` at extraction and on every
deserialisation, never stored, and outside the canonical shape the hash covers.
All 1,828 stored records still pass `VerifyContentHash`.

**No re-extraction needed.** The licence surfaces compose the same reading over a
record already in the ledger, so existing records answer correctly today. Of
1,828 records, 19 carry a conjunction and **4 change identity**; the other 1,809
do not move.

**Reads that change.** `license --json` gains `coverage` on every `license_files`
entry, always emitted. `effective_set`, `package_licenses` and `content_hash` are
unchanged for every record. `license-list --limit 0 --json` pays a decode per
record for the identity — 0.03s to 0.08s over 1,828 records.

**What is corrected is the identity, never what gets looked at.** `notice` still
reproduces every licence text in the archive, and `license-compat` still
evaluates every identifier in it.

## Licence record: pipeline `1.2.0` → `1.3.0`

**No shape change; not hash-transparent.** The expression was inferred from a
confidence delta between two text matches; it is now read from the licence file's
prose.

A compound file is read down an ordered ladder:

- **election** — a disjunctive `SPDX-License-Identifier:` line, or wording such
  as "under the terms of either licence";
- **split** — the file names what each grant covers. Checked **before** bundling,
  because a split names several copyright holders and would otherwise look like
  a bundle;
- **bundled grant** — a later text behind its own dated copyright notice or a
  `Files: <glob>` stanza. The module's own grant is the one that comes **first**
  in the file, not the one with the largest span;
- **unstated** — every grant applies, and the record says the reading was
  conservative.

Migration: **none.** Reads key on the pipeline version.

## Vulnerability record: pipeline `v22` → `v23`

**No shape change; not hash-transparent.** A finding's fixed version could name a
release later than the one that actually carried the fix.

`govulncheck` emits a finding message per level — module, package, and symbol
where it can trace a call. The parse kept only the symbol level, so an advisory it
could not trace to a symbol reached the record by coordinate match instead,
carrying that route's fixed version: the advisory's single highest, across all
branches. On a backported advisory that named an unreleased toolchain when a point
release already had the fix.

`fixedForVersion` now selects the fixed bound of the interval containing the
version in hand. A version inside an interval with no fixed bound reports no fix
rather than borrowing another branch's, and a non-SEMVER range selects nothing.

A **dual-module advisory** — listed under both `stdlib` and `golang.org/x/net`
with different ranges — answers each coordinate from its own block, and is stored
as two records. They are not merged.

Migration: **none, and no purge.** Reads key on the pipeline version.

## Vulnerability record: pipeline `v19` → `v20`

**Additive in shape, not hash-transparent.**
`VulnerabilityFinding.references` was on the sealed shape from the start and no
producer ever wrote it — 0 of 2,548 stored records carried one. It is now
populated with the advisory's own links.

The field was `[]string` and is now a list of objects:
`[{"type": "FIX", "url": "https://..."}]`. The type separates a `FIX` commit from
a `WEB` mention, which a flattened URL list loses.

Both producing routes populate it from an advisory each already had in hand, so
no scan does extra work.

Migration: **none.** Reads key on the pipeline version.

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
migration 11 back-fills the axis columns from `overall_status`; the projection is exact, so no answer changes.
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
retraction answer for a coordinate scanned before `v16`. New scans write `v16`.

Consumer impact: `audit --json` gains `vuln_withdrawn` (`vuln_findings` keeps its
existing meaning, retracted advisories included), `context` gains
`findings[].withdrawn_at`, `reachability` gains a `withdrawn` verdict with
`withdrawn_at`, `vuln-scan-diff` gains a `WithdrawnFindings` bucket, and a
CycloneDX SBOM marks a retracted advisory `analysis.state: false_positive` with no
`ratings` block.

## Staleness ledger: new store module `staleness`, migration 1

Creates `staleness_records`: what a module proxy said about a module **path** —
the latest version there, its publication time, the newer-major probe result, and
the time of the lookup. Store `v71` -> `v72`.

Additive: a new table, no existing record shape changes.

It owns a **new module series** rather than joining `fetch`. A fetch record is a
sealed custody fact about a version that was acquired; a staleness row is a
mutable, expiring cache of an upstream claim about a path. Different keys,
lifetimes and truth conditions.

Rows carry **no content hash and no pipeline version** — there is nothing in them
to verify. What qualifies a row is `looked_up_at`, and every consumer states it.

## Staleness ledger: module `staleness`, migration 2

Adds four columns to `staleness_records` for a `+incompatible` pin whose OWN
major was republished at `/vN`. Store `v78` -> `v79`.

Additive: no record shape change, no pipeline bump — this table carries neither
a content hash nor a pipeline version.

A republication is a different fact from a newer major line: the major NUMBER is
unchanged and only the path moved. Sharing the `newer_major_*` columns reported
it as a major upgrade, and a pin with both — `github.com/go-chi/chi@v3.3.4+incompatible`
has `/v3@v3.3.5` and `/v5@v5.3.1` — could hold only the higher.

| Column | Meaning |
|---|---|
| `republication_asked` | `1` when the question was put. Only for a `+incompatible` pin on a bare path, so `0` means "does not apply", not "asked, no". |
| `republication_path` | The `/vN` path that resolved. Empty with `asked = 1` is a recorded negative. |
| `republication_version` | The newest version at that path. |

## Staleness ledger: module `staleness`, migration 3

Adds two columns to `staleness_records` for a module's own **deprecation
notice** — the `// Deprecated:` comment on its `go.mod` `module` directive.
Store `v79` -> `v80`.

Additive: no record shape change, no pipeline bump.

It is a fourth fact, not a variant of the others: the successor a notice names is
often at a path the `/vN` walk cannot reach (`google.golang.org/protobuf`
succeeds `github.com/golang/protobuf`), while a module with a newer major is
usually not deprecated.

| Column | Meaning |
|---|---|
| `deprecation_checked` | `1` when the question was ANSWERED. `0` means "not established", not "not deprecated". |
| `deprecation_notice` | The notice verbatim. Empty with `checked = 1` is a recorded negative. |

## Walk store: module `walk`, migration 6

Adds `walks.project_dir`: the working-tree directory a walk rooted at a local
project was taken from. A scan by walk id reads it back to reach the same
analysis surface the original run did — notably a project's `vendor/` tree.
Store `v72` -> `v73`.

Additive: no record shape change, no pipeline bump, no purge.

The column sits **outside** the walk's sealed shape, so it is neither hashed nor
serialised into the blob. The path is machine-local, and admitting it to the hash
would make two walks of one project from two checkouts two different walks.

**No back-fill:** existing rows default to empty, which is correct — a walk taken
before this does not record where it ran.

## Walk store: module `walk`, migration 7

Adds `walks.identity_hash`: a name for the ANALYSIS a walk performed, as opposed
to `content_hash`, which seals the RECORD. Store `v73` -> `v74`.

Additive: no record shape change, no pipeline bump.

Both are needed. `content_hash` covers everything the record says, including the
walk id and the timestamps — so two runs of an unchanged checkout produced two
content hashes and two walk ids, and every record keyed on a walk id (licences,
vulnerability answers, SBOMs) became unreachable from the next run.

`identity_hash` covers the target, scope, depth, ecosystem, both pipeline
versions, the policy, the build environment, the resolved graph and each node's
status. It excludes the walk id, the timestamps, per-node `duration_ms` and
`from_cache`, the operator, and the composed fetch record.

## Call graph record: pipeline `0.4.1` → `0.5.0`

**Behaviour change in what gets analysed; no record shape change, no schema bump,
no store migration.** Records are keyed `(module, version, pipeline_version)`, so
the bump is the migration: `0.4.1` rows stay, become unreachable, and are never
served for a `0.5.0` request. Cost is one re-extraction per coordinate on its
next `callgraph` run.

The analyser no longer takes its function set from the SSA library's
`AllFunctions`, and closes the set itself. The library derives most of that set by
enumerating runtime types, which is not reproducible: it de-duplicates types by
identity while walking them under two spellings, so meeting an alias first
consumes the entry its named twin needed and the pointer-receiver method wrapper
is never derived. Five consecutive enumerations of one program returned five
different sets.

The effect is always in one direction: a graph could be missing a wrapper and the
interface call sites it would have resolved.

## Call graph record: pipeline `0.3.0` → `0.4.1`

**Behaviour change in what gets loaded; no record shape change, no schema bump,
no store migration.** Records are keyed `(module, version, pipeline_version)`, so
the bump is the migration: `0.3.0` rows stay, become unreachable, and are never
served for a `0.4.1` request. Cost is one re-extraction per coordinate.

Four changes to what the loader is pointed at, each of which can turn an empty
graph into a real one:

- **Package membership follows the module path the analysed tree DECLARES**, not
  the coordinate it was published under. A fork republished at a new path that
  never rewrote its `module` directive matched none of its own packages.
- **The load no longer requires the artefact to ship a `go.sum`** covering its
  own module graph. A module analysed alone is a main module for the first time,
  and its published zip was never required to carry one.
- **A synthesised `go.mod` pins `go 1.17` rather than `go 1.16`**, so the module
  graph is pruned to what the build reads.
- **A load that resolves nothing records which of those it was.** Old records
  said only `no packages successfully loaded`.

The version skips `0.4.0`, consumed by an intermediate measurement.

## Vendor record: schema `4` → `5`, pipeline `0.3.0` → `0.4.0`

**Record shape change and a finding-set change; no store migration.** Vendor
records are keyed `(project_module_path, pipeline_version)` and `GetVendorRecord`
selects on the current one, so the bump is the migration: `0.3.0` rows stay
where they are, become unreachable, and are never served for a `0.4.0` request.
The cost is one re-scan per project on its next `vendor` run.

Each `VendoredModule` records the **replacement coordinate**
(`replacement_path` / `replacement_version`) `vendor/modules.txt` names for it,
and the **number of files compared** against the verified zip; the record
carries the total. The content hash covers all three.

The behaviour that forced the bump: a module is resolved through
`vendor/modules.txt`'s replace clause before the `go.sum` lookup, so a replaced
module is verified against the **replacement's** `h1` — the coordinate the build
resolves, and the only one `go.sum` attests. A `0.3.0` record reports every
replaced module as having no `go.sum` entry. That is not merely less than a
`0.4.0` record says, it is the opposite of what `go.sum` holds, so the two must
not be served for one another.

`expected_hash` on a replaced module is now the replacement's checksum, and is
absent for a filesystem replacement (`=> ../fork`), which publishes no module
and so has no checksum anywhere. A filesystem replacement is reported
`unverified` naming the path, never verified against the original coordinate's
retained `go.sum` line.

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

## Walk store: module `walk`, migration 8

Adds `walks.goos` and `walks.goarch`: the target platform a walk resolved for.
Store `v74` -> `v75`.

Additive: no record shape change, no pipeline bump, no purge. The value already
lived in the sealed blob as the graph's `BuildEnv`, so these columns are a
projection and every stored walk still verifies against its written hash.

**Back-fill: every row.** Decompresses each stored walk once and copies the frame
out of its own record. Leaving the columns empty would make every stored walk
permanently invisible to the platform-filtered lookups they exist for.

## Walk store: module `walk`, migration 9

Adds `walks.go_version`: the Go toolchain that resolved the walk, as
`go env GOVERSION` reported it in the project's directory. Store `v80` -> `v81`.

Additive: no purge, no pipeline bump, no record shape change. The value already
lived in the sealed blob as the graph's `BuildEnv`, so the column is a projection
of it and every stored walk still verifies against its written hash.

Walk selection needs it because two walks of one project, scope and platform can
differ in the toolchain that resolved them, and the toolchain pins the stdlib
node. Falling through to recency answered about whichever Go release was newest —
and since a newer patch release clears toolchain advisories, that error ran
towards reporting the toolchain clean.

**Back-fill: every row.** Decompresses each stored walk once and copies the
toolchain out of its own record. A row whose record carries no build environment
back-fills to the empty string; a row this build cannot decode is skipped rather
than failing the migration.

Note: walk migrations 4 and 5 are `DELETE FROM walks`. This one deliberately is
not — the blob already holds the value, so back-filling it is the point.

## Call graph store: module `callgraph`, migration 12

Adds `callgraph_edges.kind`: whether an edge is a call, or a REFERENCE to a
function value — the shape of `r.Get("/confirm", h.Confirm)`, where nothing is
invoked and a value is handed to a router. Store `v75` -> `v76`.

Additive: no purge, no pipeline bump, no schema-version bump.

**Back-filled to `''`, which is the truth rather than a default.** Nothing before
this extracted a reference edge, so every stored edge IS a call, and the zero
value of `EdgeKind` is `call`. There is no unrecorded third state.

## Call graph store: module `callgraph`, migration 13

Adds `callgraph_records.analysis_root`: the absolute, symlink-free directory a
worktree analysis ran in. Store `v76` -> `v77`.

Additive: no back-fill, no purge, no pipeline bump, no schema-version bump.
`analysis_root` is `omitempty` on the canonical record, so stored hashes are
unaffected.

The worktree digest identifies the tree's CONTENT, which is the wrong key for
"answer me from the tree I am standing in" — a tree with one uncommitted edit
matches no stored content state. One local coordinate held eighteen generations
across sixteen digests: one working tree at sixteen content states. The root
survives edits.

**No back-fill:** `''` is the true value for every existing row, because no
earlier record states where its tree was.

## Call graph store: module `callgraph`, migration 14

Adds `callgraph_records.worktree_scan_digest`: a digest of the working tree a run
was HANDED, taken by scanning it before the analysis ran. Store `v77` -> `v78`.

Additive: no back-fill, no purge, no pipeline bump, no schema-version bump.

It is a second digest because `worktree_digest` covers the files the loader
resolved and is only knowable after the load — an exact identity of what was
analysed, and useless for deciding whether to analyse at all. This one is a
directory walk (every `.go` file under the root plus `go.mod` and `go.sum`), so a
run can ask "is this the tree my record was taken of?" beforehand. The two carry
different scheme prefixes and nothing compares them; this one is always
`scanned-sha256:`.

It is taken **before** the analysis: stamping the end state would let the next run
reuse a graph of a tree that never existed.

**No back-fill:** `''` is the true value for every existing row.

## Call graph store: module `callgraph`, migration 15

Adds `callgraph_records.analyser`: the `golang.org/x/tools` version that
type-checked the module and built the SSA, with how the store came to state it.
Store `v82` -> `v83`.

Additive: no purge, no pipeline bump, no schema-version bump. The value sits
outside the seal, so every stored `content_hash` is unchanged. Nothing ranks,
caches or reuses on it — it is read, printed and compared, and that is all.

The stored value is `observed:v0.49.0` or `inferred:v0.47.0`, never a bare
version. Empty means the row states none.

**Back-fill: every row, and every value it writes is `inferred:`.** No record ever
captured the analyser, so the pass attributes `extracted_at` against this
repository's `go.mod` pin history (`v0.47.0` from 2026-07-05, `v0.49.0` from
2026-08-15). That is weak evidence and is marked as such. Three rules:

- a row whose `extracted_at` cannot be parsed is left empty, not failed;
- a row extracted before the pin history begins is left empty;
- a row already stating an analyser is never re-attributed.

**Reads that change.** `callgraph-show` names the analyser on every record and on
every generation under `--history`. Where the generations composed for one
coordinate state more than one analyser version, the composed read says so. It
does not change which generation wins.


## Call graph store: module `callgraph`, migration 16

Adds `callgraph_records.foreign_modules_built` — the modules other than the
analysed one whose packages that record built with bodies, each with its resolved
version. Store `v83` -> `v84`.

Additive: no purge, no pipeline bump, no schema-version bump. The field is
`omitzero` in the canonical encoding, so stored `content_hash` values stay
verifiable.

**Back-fill: every row.** The value is already inside each record, so the pass
decompresses and unmarshals each blob to copy it out — one decode per row,
offline, once. A row whose record predates the field back-fills to empty, meaning
the analysis named no foreign module. **A row that cannot be decoded fails the
migration rather than being skipped.**

**Reads that change.** `callgraph-show` prints a `foreign modules built:` line
when the set is non-empty, and `--json` carries the same field. `callers`,
`callees`, their transitive forms and `implementers` qualify their `answer:` line
when part of the answer comes from those modules' nodes.


## Call graph records: the wrapper hop, no migration and no bump

The analyser now records the outgoing edges of the synthetic wrapper a method
value goes through, so an invocation path reaches the method that runs rather
than stopping on the wrapper.

**No migration, no purge, no bump.** The recovered hop is a `CallEdge` like any
other, in columns that already exist.

**What an old record can get wrong.** A method invoked only through a method
value is a node with ZERO in-edges in a record whose `ReferenceScope` is
`Analysed`, so `callers` answers `RESOLVED-ABSENT` — a measured "nothing calls
this" — for a method every request runs. Re-extract to correct it.

## Vulnerability records: canonical collection order, no migration and no bump

A `VulnerabilityRecord` is put into canonical order at the moment it is sealed:
the collections whose order carries no meaning — `findings`, and inside each
finding `affected_symbols`, `aliases`, `references` and `reachable.routes` — are
sorted before the content hash is taken.

The hops inside one route are **not** sorted: a route is a call stack and its
order is the fact it states.

**No migration, no purge, no bump.**

What it fixes: two `vuln-scan --force` runs of one walk against one snapshot
produced different records for the same coordinate. Over a 128-module walk, 6 of
128 differed between passes, every difference a reordering of the same values.
After the change, 0 of 128.

## SBOM: pipeline `0.8.0` → `0.9.0`

**Document bytes change; no store migration.** SBOM records are cached on
`(walk id, scan run id, format, pipeline version)`, so the bump makes stored
`0.8.0` documents unreachable and a request regenerates. Nothing is purged. Six
stored records go dark at once.

Two behaviours forced it:

- **External references were assembled from the module path**, unconditionally —
  a `vcs` URL and a `proxy.golang.org` distribution URL on every component, with
  no branch for a local coordinate, a replace, a vendored tree or a private path.
  Neither was read from anything measured. A component now carries a `vcs`
  reference only where the fetch ledger holds one.
- The subject asserted a proxy download for `@v/local.zip`, which the proxy does
  not serve.

## SBOM: pipeline `0.7.0` → `0.8.0`

**Document bytes change; no store migration.** SBOM records are cached on
`(walk id, scan run id, format, pipeline version)`, so the bump is what stops a
`0.7.0` document being served for a `0.8.0` request. The SBOM record is hashed
over the document bytes, not over a canonical struct, so there is no sealed
shape to migrate and nothing is purged: the stored `0.7.0` documents stay
readable and simply stop being reachable, and a request regenerates.

The behaviour that forced the bump: the standard-library component's
`kanonarion:stdlib:anchor_limitation` property was one fixed sentence — anchored
to the go.dev/dl published checksum and the googlesource tag/commit — emitted
whatever the measurement had reached. An offline run records
`VerifiedLocalToolchain`, whose detail says the published checksum was not
consulted and the commit anchor was skipped, and the fixed sentence asserted both
of them three lines later. The property is now derived from the verification
status and from whether a commit anchor was resolved, so it names the anchors
reached and, separately, those that were not. Every stdlib-bearing document
changes bytes, including the connected-side ones, because the wording changed on
all routes.

**The stored `0.7.0` documents are wrong where they were generated offline.** The
bump makes them unreachable through the cache; it does not correct copies already
shipped. A document already handed to a consumer states an anchor its own
verification detail denies, and re-issuing it is the only fix for that copy.

## FIPS record: pipeline `0.2.0` → `0.3.0`

**Finding-set change; no store migration.** FIPS records are keyed
`(project_module_path, pipeline_fingerprint)`, so the bump is the migration:
`0.2.0` rows stay where they are and are never served for a `0.3.0` request.

The `module` of a finding read from a file under `vendor/` is now the module
`vendor/modules.txt` lists for that directory, resolved by longest-prefix match
so a nested major-version module (`github.com/minio/minio-go/v7` beneath
`github.com/minio/minio-go`) reports itself rather than its parent. `0.2.0` took
the first two segments of the vendored path, which is a module path for almost
no module: a `0.2.0` record on a vendored project names `github.com/IBM`,
`golang.org/x` and `cloud.google.com/go`, none of which is a module anyone can
upgrade, pin or exempt. A vendored path no listed module owns now reports
`(unresolved)` instead of a plausible-looking invention.

Only `module` moves. The finding kinds, packages, source paths and lines are
unchanged, and the content hash covers `module`, so an unchanged tree hashes
differently from its `0.2.0` record.

**The stored `0.2.0` findings misname their module.** The bump makes them
unreachable through the cache; it does not correct a report already pasted
somewhere from one.

## GODEBUG record: pipeline `0.1.0` → `0.2.0`

**Finding-set change; no store migration.** GODEBUG records are keyed
`(project_module_path, pipeline_fingerprint)`, so the bump is the migration:
`0.1.0` rows stay where they are and are never served for a `0.2.0` request.

The same change the FIPS record took, in the context that carried the same
heuristic. The `module` of a `//go:debug` directive found under `vendor/` is now
the module `vendor/modules.txt` lists for that directory, resolved by
longest-prefix match so a nested major-version module
(`github.com/minio/minio-go/v7` beneath `github.com/minio/minio-go`) reports
itself rather than its parent. `0.1.0` took the first two segments of the
vendored path. A vendored path no listed module owns now reports `(unresolved)`.

The `applied` flag is unchanged in meaning and in value: it comes from whether
the path lies under `vendor/` at all, which the old split also answered
correctly, and a directive under a directory nothing claims is still
`applied: false`. Only `module` moves, and the content hash covers it.

Both contexts now read that mapping through one rule
(`vendortree/domain.VendoredModuleIndex`) and one parser of `modules.txt`. Two
implementations of "which listed module owns this path" were free to disagree
about one file, which is how a fixed two-segment split survived in two scanners
at once.

## Native component record: new store module `native`, migration 1

Creates `native_records`, a new table and record type: what a module's artefact
compiles into a binary as native code — the presence answer, the identified
components with the declaration that established each, and every native source
file the build compiles, with size and digest. Store `v81` -> `v82`.

Additive: no existing record shape changes, so no pipeline version moves
anywhere, and nothing is purged or back-filled.

It owns a **new module series** rather than joining `license` or `fetch`, so
adding a recipe never forces a migration in an unrelated context.

The **artefact identity is a key column**, alongside the coordinate and the
pipeline fingerprint: a native record is a claim about specific bytes, and two
records naming different artefacts for one pinned version is a contradiction the
store must be able to see.

## Native record shape change: pipeline version 0.1.0 -> 0.2.0, no migration

`native` records gain a `linked_libraries` collection and a fourth `presence`
value, `linked_not_shipped`. **No migration and no DDL** — the store's migration
count is unchanged. This entry exists because a shape changed without a migration
running.

No DDL is needed: `presence` is an unconstrained `TEXT` column, and the
collection lives inside the serialised blob.

**The pipeline version moves anyway**, because re-measuring an unchanged artefact
now produces a different record. Rows at `0.1.0+recipes.1` are simply never read
at `0.2.0+recipes.1` — not migrated, rewritten or deleted. They stay as the
record of what was measured then.

What it fixes: a module that declares cgo, compiles no native source of its own
and links an external native library used to answer `absent`.

## Native pkg-config operand: pipeline version 0.2.0 -> 0.3.0, no migration

`#cgo pkg-config:` is now read as a fourth operand form alongside `-l<name>`,
`-framework <name>` and `.a` archive paths. **No shape change, no DDL, no
migration** — the record shape, field set and content-hash formula are as `0.2.0`
left them.

**The pipeline version moves because the measurement changed.** Without the bump
an affected row is served as a cache hit and keeps its old answer forever:

| coordinate | held at 0.2.0 | re-measurement |
|---|---|---|
| `github.com/terminalstatic/go-xsd-validate@v0.1.6` | `absent` | `linked_not_shipped`, naming `libxml-2.0` |
| `go.mongodb.org/mongo-driver/v2@v2.6.0` | `present_unidentified` | `present_unidentified`, with `libmongocrypt` |

Rows are not migrated, rewritten or deleted; the fingerprint moves and they stop
being read.

## Purging a table other rows point at

A migration that deletes rows must state what happens to the rows that reference
them. The reference is by convention, not by foreign key, so nothing in SQLite
stops a purge leaving a dangling one.

It has already happened: `walk` migration 5 purged `walks` and `walk_scan_runs`
rows kept naming the deleted walks — 16 of 127 runs. Their findings survived
while the statement of what was scanned did not.

A migration that purges `walks` chooses one, in the migration comment:

- **Purge together** — delete the dependent `walk_scan_runs` and
  `walk_scan_run_modules` rows. Correct when the dependents are regenerable.
- **Orphan with the reason recorded** — keep them and say why they are stranded.
  Correct when the dependents are evidence in their own right, as findings are.

The read side does not depend on the choice: every surface serving a scan run
derives whether its walk is still present and states `inputs unresolvable` when
it is not.

Note that a purge of `walks` also destroys reuse the store has already paid for,
since `walks.identity_hash` is the key scan reuse looks a walk up by.

## Audit log (`audit.jsonl`)

Append-only JSONL; **no schema migration is ever required to add an event type.**
Every line carries an `event_type` discriminator. The fact-record line keeps its
historical flat layout with `event_type: "fact_record_written"` added
additively; all other events use the generic `{event_type, timestamp, payload}`
envelope. Recognised event types are the closed set in `internal/audit`.

Event types added since `callgraph_extracted`, none needing a migration:

| Event type | One per |
|---|---|
| `interface_extracted` | persisted interface generation |
| `examples_extracted` | persisted examples generation |
| `extraction_run_completed` | extraction run over a walk, on every outcome |
| `stdlib_custody_recorded` | persisted standard-library custody measurement |
| `sbom_generated` | persisted SBOM record |
| `sbom_served` | stored SBOM document handed back from the cache |
| `advisory_snapshot_recorded` | persisted advisory database snapshot |
| `vuln_scan_served` | stored walk scan run handed back instead of measured |

Each is emitted only where the write happened, so a cache hit appends nothing.
`sbom_served` and `vuln_scan_served` are the deliberate exceptions: they witness
an asking rather than a write.

**This file and the event-vocabulary docs are updated in the same commit as the
change they describe.** A reader checking whether a write is witnessed cannot
tell an omission from an absence.
