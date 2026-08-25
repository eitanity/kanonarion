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

## Interface record: pipeline `0.4.0` → `0.5.0`

**Record shape change; no store migration. This bump is also a repair** — the
only one available for the coordinates the defect below has already killed.

Extraction parsed every non-test `.go` file in a package directory and handed the
set to `go/doc`, evaluating no build constraints. A package carrying mutually
exclusive build-tag variants therefore presented `go/doc` with several
declarations of one exported symbol, and `go/doc` resolves duplicates in **map
iteration order**. Two extractions of one zip could disagree, and the winner
described no build that exists. In this store's own history,
`github.com/mattn/go-isatty@v0.0.20` — one zip, one linux/amd64 host — is held
twice and the two records disagree: the `0.3.0` generation records `IsTerminal`
at `isatty_windows.go`, the `0.4.0` generation at `isatty_bsd.go`. Neither file
is in a linux build. Two hundred extractions of a six-variant package produced
six distinct `public_api` hashes.

Extraction now evaluates build constraints with `go/build` and reads only the
files one configuration contains. Three things follow into the record:

- **`build_frame`** names that configuration — `goos`, `goarch`, `cgo_enabled`.
  An API measured at linux/amd64 and one measured at windows/386 are different
  facts and must not collide on one coordinate.
- **`out_of_frame`** marks a package directory whose files are all for other
  platforms. It is kept, empty, rather than dropped: a package absent from the
  module and a package this build does not contain are different facts.
- The declarations narrow to one platform. `modernc.org/libc@v1.73.5` at
  linux/amd64 goes from 69,298 exported declarations across 715 position files to
  17,742 across 78, package count unchanged at 32, none left in a file for
  another platform. That is not less than the old record said but a different
  claim — the old one unioned every platform and picked arbitrarily where they
  collided — so the two must not be served for one another.

Both fields are omitted from the canonical bytes when unset, so every `0.3.0` and
`0.4.0` row still verifies its stored content hash. A framed record hashes
differently from the unframed record of the same zip.

The cost is one re-extraction per module on its next `interface` run — 482 stored
records at the bump, 472 already stranded at `0.3.0`. Until re-extracted each
answers as a not-found naming the pipeline versions held and the command that
produces a servable record, exactly as the `0.4.0` bump arranged.

**Why the bump is the repair.** Interface records are append-only and nothing
retires a generation. Two records for one artefact at one pipeline version that
disagree about the exported API are a `public_api` conflict, and a conflicted
coordinate is not served — on the reference store 17 are dead that way at
`0.4.0`, five of them this project's own dependencies. Re-extracting one at
`0.4.0` would append a third generation beside the two poisoned ones and change
nothing, and the framed record would then conflict on `build_frame` too. The bump
puts the poisoned generations behind the pipeline filter, so the first framed
re-extraction at `0.5.0` is the only record in play and the coordinate answers
again. Composition names a `build_frame` disagreement before it compares APIs, so
a pair measured on different platforms reads as the frame difference it is rather
than as non-determinism in the extractor.

## Interface record: pipeline `0.3.0` → `0.4.0`

**Record shape change; no store migration.** Interface records are keyed
`(module_path, module_version, pipeline_version)` and `GetInterfaceRecord`
selects on the current one, so the bump is the migration: `0.3.0` rows stay
where they are and are never served for a `0.4.0` request. The cost is one
re-extraction per module on its next `interface` run — 472 stored records at the
time of the bump, each of which answers `interface-show`, `interface-diff` and
`symbol-find` as a not-found until it is re-extracted, naming the command that
produces it.

Two extraction reads changed, and both change what the record says a module
exports.

A **constant group carries its declared type to every member.** A spec with no
expression list repeats the previous spec's type and expression — that is what
makes an `iota` enumeration work. Reading each spec on its own left every member
but the first with no type at all: on `github.com/golang-jwt/jwt/v4@v4.5.1`, 9 of
11 constants. A constant's type is also the whole of its signature in
`interface-diff`, so a `0.3.0` record cannot see a grouped constant's type change
and a `0.4.0` record can. That is not less than the old record said, it is a
different answer, so the two must not be served for one another.

An **embedded type from another package is recorded as a field.** Exportedness
belongs to the embedded type's own identifier, not to the lower-case package
qualifier in front of it: an embedded `time.Time` publishes `x.Time`. A `0.3.0`
record dropped every such embedding, and with it the promotions it explains.

The content hash covers both, so an unchanged module hashes differently from its
`0.3.0` record.

Because the bump darkens records that are still in the ledger, every reader that
can come up empty tells "never extracted" from "extracted under superseded
logic", names the pipeline versions held against the one this build serves, and
gives `kanonarion interface <coord>` as the remedy: `interface-show`,
`interface-list <module>`, `interface --history`, `interface-diff`,
`symbol-find`, `symbol-context` and the `context` interface section (status
`superseded`). `interface-list` marks each superseded row and counts them. The
wording is the call graph's `supersededPipelineError`, which answers the same
condition on the other side of the binary.

## Vulnerability record: pipeline `v23` → `v24`

**No shape change; not hash-transparent.** One record was built from two advisory
databases and named only one.

A vulnerability record has two producing routes. `govulncheck` was handed the
pinned snapshot; the coordinate-match route (`LookupFindings`, and the cheap
`CheckVulnerable` pre-check beside it) queried `https://vuln.go.dev` live,
because neither carried a snapshot parameter and the OSV adapter reached a
package constant. The record stated the snapshot.

An advisory published after the pinned snapshot therefore entered the record
having never been seen by the analyser — and was then stamped `IsReachable:
false`, `High` confidence, derived by `govulncheck`, on the strength of that
analyser's silence. Silence is only evidence about an advisory the analyser was
given.

Both routes now read the snapshot the record names. `LookupFindings` and
`CheckVulnerable` take the snapshot identity, read `index/modules.json` and each
`ID/<id>.json` out of the stored archive, and have no path to the network: a
snapshot the store cannot produce is a refusal, not a live read.

The third member of the class was the same defect inverted. `prepareDBArg` fell
back to the live database on three failures — the store would not produce the
snapshot, no scratch directory could be created, the archive would not extract —
each announced by a log warning while the record went on naming the snapshot: an
entirely live scan sealed under a pinned generation. All three refuse now, under
`ports.ErrSnapshotUnavailable`, kept distinct from `ErrSnapshotIntegrity` so a
caller preserving evidence of a tamper can still tell an absent snapshot from an
altered one. A pre-extracted database supplied by the walk is checked against the
snapshot's generation rather than trusted.

Migration for existing stores: **none, and no purge.** Reads are keyed on the
pipeline version, so the `v23` rows are already unreachable for a `v24` question,
and the change lives inside the serialised record — which findings it carries,
and the reachability verdict on each — rather than in a column. It cannot be a
migration in any case: which findings in a stored record came from the live
service was never recorded, and the correct reachability verdict for one depends
on an analysis that never ran.

The re-scan cost is the smallest a vuln bump has carried. Measured before the
change: 2,548 records at `v19`, 1 at `v20`, 158 at `v21`, 650 at `v22` and
**0 at `v23`**. Nothing had been re-scanned since the `v23` bump, so this darkens
nothing that was not already awaiting one.

Measured on the divergence itself, 2026-08-14, against the store's only snapshot
`vuln.go.dev@2026-07-27T20:14:16Z` (18 days old, 4,134 advisory records). Live
`vuln.go.dev` listed eight advisories against `stdlib` that the snapshot does
not — GO-2026-5026, 5942, 5972, 6088, 6089, 6090, 6091, 6218 — and all eight
affect the host toolchain go1.26.5. `govulncheck` over this repository against
the extracted snapshot: 168 messages, **0 findings**. The same tree and toolchain
against the live database: 207 messages, 29 finding messages, 10 advisories. Under
`v23` a scan at that snapshot produced a stdlib record carrying eight findings the
analysis could not have seen, each with a high-confidence not-reachable verdict.

Consumer impact: a scan whose snapshot lags the live database reports fewer
findings, and the ones it reports are the ones its stated database can produce. A
scan whose snapshot agrees with live is unchanged. A scan that cannot read its
pinned database now fails instead of quietly answering from another one.

## Licence record: pipeline `1.2.0` → `1.3.0`

**No shape change; not hash-transparent.** The expression was inferred from a
confidence delta; it is now read from the licence file's prose.

`DeriveExpression` concluded a *legal relationship* between two licences from
the confidence gap between two text matches. One branch emitted `OR` for three
materially different files, and its own comment named the module that disproves
the assumption. The detector was never wrong — licensecheck reports what is in
each file — the conclusion was.

A compound file is now read down an ordered ladder:

- **election** — a disjunctive `SPDX-License-Identifier:` line, or wording such
  as "under the terms of either licence";
- **split** — the file names what each grant covers ("the following files…",
  "all the remaining project files"). Checked **before** bundling, because a
  split names several copyright holders and would otherwise look like a bundle;
- **bundled grant** — a later text standing behind its own dated copyright
  notice or a `Files: <glob>` stanza. The module's own grant is the one that
  comes **first** in the file, not the one with the largest span;
- **unstated** — every grant applies, and the record says the reading was
  conservative. Understating an obligation is the harmful direction.

`"may choose"` is deliberately absent from the election phrases: Apache-2.0 §9
contains it, so every Apache-2.0 file in a real corpus does.

A bundled grant leaves the expression and is recorded beside it on
`BundledSPDXs`, with `ExpressionBasis` naming the reading. Both fields are
`omitempty` and additive, so **every 1.2.0 record still verifies**.

Migration for existing stores: **none, and no purge.** Reads key on the pipeline
version, so `1.2.0` rows are already unreachable for a `1.3.0` question and stay
readable as what the earlier generation concluded. The cost that IS owed is a
full re-extraction — the prose lives only in the module zip, so no stored record
can be re-read into the new answer — and because records are keyed
`(module_path, module_version, pipeline_version)`, the re-extraction writes a
**second generation** rather than replacing the first.

Measured on the store at the bump: **864 records at `1.2.0`**, of which 21
expressions change and 717 are re-derived identically. `gopkg.in/yaml.v3` and its
oasdiff fork move to `Apache-2.0 AND MIT`; twelve OpenTelemetry modules to
`Apache-2.0` with `BSD-3-Clause` recorded beside; `sean-/seed` and
`oasdiff/yaml` to `MIT`, and `klauspost/compress` to `BSD-3-Clause` — the last
three correcting a `PrimarySPDX` that named a third party's grant rather than
the module's own.

Consumer impact: `license` and `notice` state the module's own licence where they
previously named a bundled one, and `license --json` gains `BundledSPDXs` and
`ExpressionBasis`. `notice` also gains a `License expression:` line, emitted only
where the expression says something the primary `License:` line does not — so
`gopkg.in/yaml.v3` now reads `MIT` plus `Apache-2.0 AND MIT` rather than `MIT`
alone. The `License:` line is unchanged for every module, including the ones
whose primary was corrected; a consumer parsing it keeps working.

## Vulnerability record: pipeline `v22` → `v23`

**No shape change; not hash-transparent.** Two producers of a finding's fixed
version disagreed, and the coarser one won.

`govulncheck` emits one finding message **per level** for the same advisory:
module, package, and a symbol level when it can trace a call into the vulnerable
code. The parse kept only the symbol level and discarded the other two, so an
advisory govulncheck could not trace to a symbol was ingested as though it had
never been mentioned. That advisory then reached the record by coordinate match
instead, carrying the coordinate route's fixed version — the advisory's single
highest, taken from `index/modules.json`, whose own comment calls it that.

An advisory backported across maintained release branches states one
`introduced`/`fixed` pair per branch. For a Go standard-library advisory the
highest pair is usually the next major's release candidate, so a project on a
supported stable branch was told to move to an unreleased toolchain when a point
release already carried the fix. `fixedForVersion` now selects the fixed bound of
the interval containing the version in hand and overrides the index value. A
version inside an interval with no fixed bound reports no fix rather than
borrowing another branch's, and a range in a vocabulary other than SEMVER selects
nothing.

The selection runs inside the affected block for the module path being asked
about, so a **dual-module advisory** — one listed under both `stdlib` and
`golang.org/x/net` with different ranges and different fixes — answers each
coordinate from its own block. Measured on one project stream, `GO-2026-5942`
arrives twice, `trace[0].module=stdlib` with `fixed_version=v1.26.6` and
`trace[0].module=golang.org/x/net` with `v0.56.0`, and is stored as two records
under two coordinates. They are not merged.

Reading the other levels also turns the negative from an inference into a
statement. A module- or package-level message **is** the analyser reporting that
the build carries the affected code and that its call graph found no route into
the vulnerable symbol; that answer now rests on something it said rather than on
its silence. Package initialisation is still not such a report: a trace of
nothing but init frames stays undetermined at symbol level, because linkage says
the package is in the build and nothing about whether its code runs.

An advisory now has one shape whichever route produced it. Where the analysis
reached no symbols, the advisory's own at-risk list is the only answer there is,
and the OSV message already on the wire carries it — read on decode, one entry
per module path, deduplicated and sorted, the same rule the coordinate route
applies. It never overwrites a reached symbol: the two lists say different things.

Migration for existing stores: **none, and no purge.** Reads are keyed on the
pipeline version, so the `v22` rows are already unreachable for a `v23` question,
and the fixed version, symbol list and reachability verdict all live inside the
serialised record rather than in a column. The cost that IS owed is a re-scan:
**650 stored records at `v22` go dark for a `v23` question until re-scanned**, on
top of 2,548 already dark at `v19`, 1 at `v20` and 158 at `v21`.

Measured across the change on one project walk — same walk, same snapshot, same
coordinate — the stdlib record's seal moved from `sha256:548def0a` to
`sha256:1c23a321`, with exactly one field changed: the advisory carrying no
symbol-level message moved from `v1.27.0-rc.3` to `v1.26.6`. Findings (13),
reachable verdicts (9), routes (45) and symbol lists were identical either side.

Consumer impact: `vuln` / `vuln-show` name the branch-correct fix on the `fix:`
line, and a finding whose advisory was reported at module or package level
carries a negative resting on that report rather than on silence.

## Vulnerability record: pipeline `v19` → `v20`

**Additive in shape, not hash-transparent.** `VulnerabilityFinding.references`
was on the sealed wire shape from the start, entered the content hash, and no
producer ever wrote it: across the 2,548 stored records the count carrying a
reference was 0. It is now populated with the advisory's own links, each an OSV
`{type, url}` pair.

The shape changed with it. The field was `[]string` and is now a list of
objects: `[{"type": "FIX", "url": "https://..."}]`. The type is carried because
it is what separates a `FIX` commit — remediation a reader can apply — from a
`WEB` mention, and a flattened URL list destroys that distinction.

Both producing routes populate it, from an advisory each already had in hand, so
no scan does extra work:

- the OSV database adapter, from the `ID/<ID>.json` document it already fetches
  to enrich a finding;
- the govulncheck parse, from the OSV message the stream already carries (a
  measured `govulncheck -format json` run: 233 of 233 OSV messages carried a
  non-empty `references` array).

The list is sorted at the seal, type then URL, for the reason
`affected_symbols` is: measured on the pinned snapshot, 253 of the 3,748
advisories carrying more than one reference present them in an order sorting
changes, and an arrangement that reaches the seal makes the seal describe the
arrangement.

An **empty** list means no advisory was read for that finding — a failed
advisory fetch, or a stream whose OSV message never arrived — not that the
advisory publishes none. Measured on the pinned snapshot, 4,130 of 4,134
advisories carry at least one reference (15,132 URLs; 3,160 of them `FIX`).

Migration for existing stores: **none, and no purge.** Reads are keyed on the
pipeline version, so the `v19` rows are already unreachable for a `v20` question
and the references live inside the serialised record rather than in a column.
The cost that IS owed is a full re-scan: **all 2,548 stored records go dark for
a `v20` question until re-scanned.**

Consumer impact: `vuln` / `vuln-show` gain a `fix refs:` line carrying the
`FIX` references only, and `--json` emits the whole list under
`findings[].references`. `context` is unchanged — it is a token-budgeted
document and a dozen URLs per finding is bulk without a decision attached.

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

## Staleness ledger: module `staleness`, migration 2

**Additive; four new columns on `staleness_records`, no record shape change and
no pipeline bump — this table carries neither a content hash nor a pipeline
version.** The whole store's migration count goes `v78` -> `v79`.

A `+incompatible` pin's OWN major republished at `/vN` is a different fact from
a newer major line: the major NUMBER is unchanged there and only the path moved.
It shared the `newer_major_*` columns and so was reported as a major upgrade,
and where a pin had both — `github.com/go-chi/chi@v3.3.4+incompatible` has both
`/v3@v3.3.5` and `/v5@v5.3.1` — one set of columns could hold only the higher
and the nearer move was dropped. The new columns are:

| Column | Meaning |
|---|---|
| `republication_asked` | `1` when the probe put the question. It is put only for a `+incompatible` pin on a bare path, so `0` means "does not apply", NOT "asked, no". |
| `republication_path` | The `/vN` path that resolved. Empty with `republication_asked = 1` is a recorded negative. |
| `republication_version` | The newest version at that path. |
| `republication_published_at` | Its publication time; empty when the proxy supplied none. |

Migration for existing stores: the columns are added with defaults, and one
`UPDATE` moves a same-major answer written by the previous shape out of
`newer_major_*` into them. The move is keyed on the walk's start: the walk begins
at `major_probe_from`, so any path it found names that major or above, and only
the same-major question can have written the major immediately BELOW it. Both
suffix conventions are matched (`/vN` and gopkg.in's `.vN`). On the live store
that moved 3 rows of 397 and left every genuine newer major untouched.

Rows the `UPDATE` does not touch keep `republication_asked = 0`. They are not
lost answers: the resolver will not serve a stored probe to a pin that asks the
republication question unless the row asked it too, so such a row is re-probed
the next time it is used — and a pin that never asks the question is still
served from it unchanged.

## Staleness ledger: module `staleness`, migration 3
**Additive; two new columns on `staleness_records`, no record shape change and
no pipeline bump — this table carries neither a content hash nor a pipeline
version.** The whole store's migration count goes `v79` -> `v80`.

A module's own **deprecation notice** — the `// Deprecated:` comment on the
`module` directive in its `go.mod` — is a fourth fact on the row, beside the
same-major latest, the newer major and the republication. It is not a variant of
any of them: the successor a notice names is frequently at a path the `/vN` walk
structurally cannot reach (`google.golang.org/protobuf` succeeds
`github.com/golang/protobuf` on a different host), while a module with a newer
major is usually not deprecated. The new columns are:

| Column | Meaning |
|---|---|
| `deprecation_checked` | `1` when the question was ANSWERED. `0` means "not established", NOT "not deprecated". |
| `deprecation_notice` | The notice verbatim. Empty with `deprecation_checked = 1` is a recorded negative — the module declares none. |

The two are separate for the reason `major_probe_from` is separate from
`newer_major_path`. The notice is visible only to a source that reports it — the
batched `go list -m -u` answer a `--gomod` scope is resolved through — and a
per-path `@latest` lookup cannot see it at all, so an empty notice alone could
not say whether the module declares none or was never asked.

Migration for existing stores: the columns are added with defaults and **nothing
is back-filled.** There is nothing stored to derive the notice from, and a row
written before the question existed genuinely was not asked; it keeps
`deprecation_checked = 0` and acquires the fact the next time its latest is
resolved. No `PipelineVersion` bump is owed: nothing on this table is hashed or
verified, `looked_up_at` is what qualifies a row, and an older binary reads the
table through explicit column lists that the new columns do not disturb.

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

## Call graph record: pipeline `0.4.1` → `0.5.0`

**Behaviour change in what gets analysed; no record shape change, no schema
bump, no store migration.** Call graph records are keyed
`(module, version, pipeline_version)`, so the bump is the migration: `0.4.1`
rows stay where they are, become unreachable, and are never served for a
`0.5.0` request. The cost is one re-extraction per coordinate on its next
`callgraph` run.

The analyser no longer takes its function set from the SSA library's
`AllFunctions`, and builds the class-hierarchy graph over a set it closes
itself. The library derives most of that set by enumerating the program's
runtime types, and that enumeration is not reproducible: it de-duplicates types
by identity while walking them under two spellings, so meeting an alias first
consumes the entry its named twin needed and the pointer type — and with it the
pointer-receiver method wrapper — is never derived. Measured on one unchanged
tree, five consecutive enumerations of one program returned five different sets.

The effect on a record is small and always in one direction: a graph could be
missing a wrapper and the interface call sites the class hierarchy would have
resolved to it. Ten consecutive analyses of one unchanged working tree produced
three different graphs before this change and one after it, and that one graph
is set-identical to the most complete of the three — same nodes, same edges,
same interfaces, same implementations. Nothing is added that the analysis did
not already find on a good run; what changes is that every run is now that run.

Until a coordinate is re-analysed, every query for it refuses rather than
answering empty: `callers`, `callees`, their transitive forms, `implementers`
and `callgraph-show` name the superseded versions the store holds and the
command that re-derives them. An empty answer would otherwise be read as a fact
about the code, and its stated cause would be read off a generation the query
never consulted.

A `0.4.1` record can therefore say that nothing calls a method that was simply
never enumerated, and nothing in the record distinguishes that from a measured
absence. Two `0.4.1` records of one artefact can also disagree with no cause
recorded, which is the conflicting-generations condition composition already
refuses on. Both are why the old rows are re-derived rather than served.

## Call graph record: pipeline `0.3.0` → `0.4.1`

**Behaviour change in what gets loaded; no record shape change, no schema bump,
no store migration.** Call graph records are keyed
`(module, version, pipeline_version)`, so the bump is the migration: `0.3.0`
rows stay where they are, become unreachable, and are never served for a
`0.4.1` request. The cost is one re-extraction per coordinate on its next
`callgraph` run.

Four changes to what the loader is pointed at, each of which can turn an empty
graph into a real one and so must not be served for the other:

- **Package membership follows the module path the analysed tree DECLARES**, not
  the coordinate it was published under. A fork republished at a new path that
  never rewrote its own `module` directive matched none of its own packages, so
  the target set was empty and the record was an empty graph.
- **The load no longer requires the artefact to ship a `go.sum` covering its own
  module graph** (`-mod=mod` on every load, not only synthesised ones). `go.sum`
  is an obligation of whatever is being built; a module analysed alone is a main
  module for the first time, and its published zip was never required to carry
  one.
- **A synthesised `go.mod` pins `go 1.17` rather than `go 1.16`**, so the module
  graph is pruned to what the build reads. Unpruned, minimal version selection
  reads the `go.mod` of every module reachable through every requirement, and
  one absent from the local cache failed the load on a version nothing compiles.
  Records carrying `synthesised_go_mod.go_directive: "1.16"` were built under
  the older selection; the language does not differ between the two versions.
- **A load that resolves nothing records which of those it was.** The old
  records said `no packages successfully loaded`, which named neither what was
  sought, nor what the loader found, nor what it reported.

Nothing in the sealed shape moved, and no field was added or removed, so every
stored record keeps its content hash verifiable. The version skips `0.4.0`,
which was consumed by an intermediate measurement.

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

**Additive; two new columns, no record shape change and no pipeline bump.**
`walks` gains `goos` and `goarch`: the target platform a walk resolved for. The
whole store's migration count goes `v74` -> `v75`.

The value already lived in the sealed blob, as the graph's `BuildEnv`. These
columns are a projection of it, exactly like `identity_hash` is a projection of
the record — the canonical shape the content hash covers is unchanged, so every
stored walk still verifies against the hash it was written with and nothing is
purged.

**Back-filled**, unlike `identity_hash`. The migration decompresses each stored
walk once and copies the frame out of its own record. Leaving the columns empty
would have made every walk already in the store permanently invisible to the
platform-filtered lookups the columns exist for, and the value is already
present, so there is nothing to recompute. A row whose record carries no build
environment back-fills to empty strings; a row this build cannot decode is left
at empty rather than failing the migration, because an unreadable row's frame is
genuinely unknown.

Empty means **the frame was never recorded**, and it never matches an explicit
platform filter. A caller asking for `linux/amd64` must not receive a walk whose
platform is unknown, so `WalkFilter.BuildEnv` matches both axes exactly and "any
platform" is expressible only by leaving the filter nil.

Measured on the real store at migration time: 92 rows, 72 back-filled to
`linux/amd64`, 20 left unrecorded — and those 20 are exactly the module-rooted
walks. Only the project resolver writes a `BuildEnv`, so a walk rooted at a
published coordinate structurally has no frame and can never gain one.

## Walk store: module `walk`, migration 9

**Additive; one new column, no record shape change and no pipeline bump.**
`walks` gains `go_version`: the Go toolchain that resolved the walk, as
`go env GOVERSION` reported it in the project's own directory. The whole store's
migration count goes `v80` -> `v81`.

Like `goos`/`goarch` the value already lived in the sealed blob, as the graph's
`BuildEnv`. The column is a projection of it — the canonical shape the content
hash covers is unchanged, so every stored walk still verifies against the hash it
was written with, `identity_hash` is untouched, and nothing is purged. **Walk
migrations 4 and 5 are `DELETE FROM walks`; this one deliberately is not.** The
blob already holds the value, so back-filling it is the entire point, and a purge
here would destroy the evidence the column exists to make selectable.

**Why the toolchain needs a column when the platform already has one.** Selection
partitioned latest-for-target on `(target, version, scope)` and let recency decide
the rest. Two walks of one project, one scope and one platform can still differ in
the toolchain that resolved them — whichever `go` led `PATH`, or a `toolchain`
directive the project acquired — and the toolchain pins the synthetic stdlib node,
so the two walks name different standard library versions. A read that fell
through to recency therefore answered about whichever Go release happened to be
newest. Because a newer patch release CLEARS toolchain advisories, the error was
not symmetric: it ran towards reporting the toolchain clean, on the one module
every Go project links.

**Back-filled**, on exactly the terms migration 8 established. The migration
decompresses each stored walk once and copies the toolchain out of its own
record; leaving it empty would make every stored walk permanently invisible to
the toolchain-filtered lookups the column exists for. A row whose record carries
no build environment back-fills to the empty string; a row this build cannot
decode is skipped rather than failing the migration, because an unreadable row's
toolchain is genuinely unknown.

Empty means **the toolchain was never recorded**, and it never matches an
explicit filter. `WalkFilter.Toolchain` matches exactly and "any toolchain" is
expressible only by leaving it nil — which is also what a read does when its own
`go env` probe cannot answer, because filtering on the empty string would select
the unrecorded rows rather than widening.

`WalkFilter.Toolchain` is a field of its own rather than a third field on
`BuildEnvFilter`. The two axes are asked independently: a caller pinning the
platform is asking which files the build selects, a caller pinning the toolchain
is asking which standard library it links, and folding them together would force
every platform-filtered read to pin a toolchain with no value meaning "any".

`LatestOnly` now partitions on `(target, version, scope, go_version)`. Two walks
under two toolchains are two builds, not two attempts at one.

Measured on the real store at migration time: 17 rows, all 17 retained, 12
back-filled (7 to `go1.26.5`, 5 to `go1.26.6`) and 5 left unrecorded — and those
5 are exactly the module-rooted walks, which record no build environment at all.
Every row's `content_hash`, `identity_hash` and stored bytes came back
byte-identical.

## Call graph store: module `callgraph`, migration 12

**Additive; one new column, no record-shape purge, no schema-version bump and no
pipeline bump.** `callgraph_edges` gains `kind`: whether an edge is a call, or a
REFERENCE to a function value — the shape of `r.Get("/confirm", h.Confirm)`,
where nothing is invoked and a value is handed to a router. The whole store's
migration count goes `v75` -> `v76`.

**Back-filled `''`, and that is the truth rather than a default.** Nothing before
this migration extracted a reference edge, so every stored edge IS a call, and
the zero value of `EdgeKind` is `call`. There is no unrecorded third state to
ladder against.

**Why no bump, when a new edge kind looks exactly like the sort of change that
owes one.** The rule this repository applies is in
`CallGraphSchemaVersion`'s own doc comment: *bump only when a change makes an OLD
record say something FALSE, not merely something less*. Two facts settle it.

- The record shape is unchanged for stored bytes. `kind` on the canonical edge
  and `reference_scope` on the canonical record are both `omitempty` from birth,
  so every stored record re-marshals to the bytes it was sealed over and still
  verifies. (See the fetch-record precedent for the same exemption.)
- The one thing an old record WOULD have said falsely is now stated by the
  record itself. `CallGraphRecord.ReferenceScope` reads "not measured" on every
  record written before references existed, and the verdict layer downgrades an
  empty `callers` answer over such a record to `UNRESOLVED` naming
  `reference-scope-unmeasured` — instead of the `RESOLVED-ABSENT` that was the
  actual defect.

Bumping either version would have taken every stored call graph out of every
answer until re-extraction — a purge by another name — to replace a fact the
record can simply carry. Re-extraction costs roughly 52 MiB per module and the
largest graphs in the store take minutes; the ledger exists precisely so that
cost is paid when a measurement is wanted, not when a column is added.

## Call graph store: module `callgraph`, migration 13

**Additive; one new column, no back-fill, no purge, no schema-version bump and no
pipeline bump.** `callgraph_records` gains `analysis_root`: the absolute,
symlink-free directory a worktree analysis ran in. The whole store's migration
count goes `v76` -> `v77`.

**Why a record needs it when it already carries a worktree digest.** The digest
is the tree's IDENTITY — a hash of what it contains — and it is the right answer
to "are these two measurements of the same code". It is the wrong key for
"answer me from the tree I am standing in", because a tree with one uncommitted
edit matches no content state the ledger holds. Measured on the maintainer's
store before this landed: one local coordinate held **eighteen generations across
sixteen distinct digests** — one working tree at sixteen content states, not
sixteen checkouts. A read filtering on digest equality would have answered
nothing for the developer it exists for. The root survives edits, and it is what
"the tree the caller is in" actually means.

**No back-fill.** `''` is the true value for every existing row. No record
written before this states where its tree was, and the decoded record carries the
same empty value. Inventing a root — the store's directory, the module path,
anything — would answer "which tree did this come from" with a guess, in the one
table whose job is keeping two checkouts apart.

**No purge, and no bump.** `analysis_root` is `omitempty` on the canonical
record, so every stored record marshals to the bytes it was sealed over and still
verifies against its stored hash. It IS inside the sealed shape, which matters
for a different reason: two checkouts can hold byte-identical trees, and without
the root in the hash they would share a `content_hash` — a primary-key column —
and collapse onto one row.

**What an unlocated generation does now.** It still answers. The tree-scoped read
tries the caller's root first and falls back to the newest generation of any tree
when nothing matches, so no reader loses an answer they had. What changes is that
the fall-back is stated: a `callers` query run inside a module whose only
generations predate this migration prints one notice naming what answered and
what to run to be answered from this tree. The generations are neither superseded
nor silently trusted — they are named as unattributable, which is what they are.

**The worktree digest changed VALUE at the same migration, and did not bump
either.** It is now hashed over the file list the loader resolved rather than a
filesystem walk of the tree, so it follows an out-of-root symlink the walk could
not see and ignores `testdata`, nested modules and build-tag-excluded files the
walk counted. Re-analysing an unchanged tree therefore mints a different digest
than it did before. That makes no stored record say anything false — each still
identifies the tree it read, under the rule in force when it was written — and
the values now carry a scheme prefix (`analysed-sha256:`, `scanned-sha256:`; a
bare `sha256:` is a pre-migration record) so the two can never be compared as
though they were one. Nothing routes on digest equality, so nothing needed the
comparison the change breaks.

**What a reader sees change without re-extracting anything:** `callers` on a
symbol with no edges over a pre-existing record answers `UNRESOLVED` where it
previously answered `RESOLVED-ABSENT`. That is the correction, not a regression.
Re-extract the module to get the measured answer back.


## Call graph store: module `callgraph`, migration 14

**Additive; one new column, no back-fill, no purge, no schema-version bump and no
pipeline bump.** `callgraph_records` gains `worktree_scan_digest`: a digest of
the working tree a run was HANDED, taken by scanning it before the analysis ran.
The whole store's migration count goes `v77` -> `v78`.

**Why a second digest.** `worktree_digest` covers the files the loader resolved,
so it is only knowable once the load has happened. That makes it an exact
identity of what was analysed and useless as a key for deciding whether to
analyse at all. This one is a directory walk — every `.go` file under the root
plus `go.mod` and `go.sum`, following symlinks to source files — so a run can ask
"is this the tree the record I hold was taken of?" before spending the analysis.
The two carry different scheme prefixes and nothing compares them: this one is
`scanned-sha256:` always.

**It is taken before the analysis, not after.** A tree edited while an analysis
is running produces a graph of neither state. A digest of the tree as it was at
the start then differs from what the next run scans, and that run re-derives;
stamping the end state would let the next run reuse a graph of a tree that never
existed.

**No back-fill.** `''` is the true value for every existing row: no record
written before this stated the tree it was handed, and there is nothing to derive
it from — the tree that produced a record two months ago is not on this disk in
that state. An empty digest matches nothing, so every existing generation behaves
exactly as it did: re-derived rather than reused, and composed by sequence
position rather than by ladder.

**No purge, and no bump.** `worktree_scan_digest` is `omitempty` on the canonical
record, so every stored record marshals to the bytes it was sealed over and still
verifies against its stored hash. It is inside the sealed shape because a later
run decides whether to re-derive by reading it: a value outside the seal could be
edited without breaking the record's own integrity check, and the run that
trusted it would serve a graph of another tree.

**What it changes for a read.** Two generations carrying the same scan digest at
the same root were handed the same tree, so they are two measurements of one
thing rather than two observations of a changing one, and the completeness ladder
orders them. A re-analysis that came back with less than an earlier one measured
the analysis environment, not the tree. Generations with different digests are
still a sequence, and the newest still wins — a tree that genuinely changed is a
new question.

**Cost.** `ALTER TABLE ... ADD COLUMN` with a constant default is a metadata-only
operation in SQLite: no row is rewritten, whatever the table holds.

## Call graph records: the wrapper hop, no migration and no bump

**No store migration, no schema-version bump, no pipeline bump.** The analyser
now records the outgoing edges of the synthetic wrapper a method value goes
through, so an invocation path reaches the method that runs rather than stopping
on the wrapper. Nothing about the record's SHAPE changes: the recovered hop is a
`CallEdge` like any other, in columns that already exist.

**The counter-argument, because it is real.** An old record does not merely say
less here — it can say something false. Measured on a fixture: a method invoked
only through a method value is a node in the graph (it calls other things) with
ZERO in-edges, in a record whose `ReferenceScope` is `Analysed`. `callers` over
that record answers `RESOLVED-ABSENT` — a measured "nothing calls this" — for a
method every request runs. That is exactly the condition
`CallGraphSchemaVersion`'s rule names.

**Why it still does not earn a bump.** The population that can make that false
claim is bounded by `ReferenceScope`, and it is small and self-healing. Measured
read-only against the store: 461 stored call-graph records, all schema v13; 456
have no `ReferenceScope`, so the verdict layer already downgrades an empty
`callers` answer over them to `UNRESOLVED` naming `reference-scope-unmeasured`
and they cannot claim an absence at all. The remaining 5 are one module's local
working-tree generations, which the next `kanonarion local .` supersedes. A bump
would darken 461 records to correct 5 — the purge-by-another-name the rule exists
to avoid — and would not even correct them, only hide them.

**What is owed instead, and is not in this change.** The instrument that fits is
the one migration 12 introduced: an axis the record carries about itself, so the
silence describes itself and the verdict downgrades over a record written before
wrapper hops were recorded. Until that lands, the residual is the 5 records
above, and re-extraction closes it.

**What a reader sees change after re-extracting:** a `$bound` wrapper appears as
a caller, paths across a method value are one hop longer, and a method reachable
only through a method value stops answering "no callers".

## Vulnerability records: canonical collection order, no migration and no bump

**No store migration, no schema-version bump, no pipeline bump.** A
`VulnerabilityRecord` is now put into canonical order at the moment it is
sealed: the collections whose order carries no meaning — `findings`, and inside
each finding `affected_symbols`, `aliases`, `references` and
`reachable.routes` — are sorted before the content hash is taken. The hops
inside one route are NOT sorted; a route is a call stack and its order is the
fact it states. `internal/vuln/domain.SealedCollections` carries the
classification, and a reflection test fails when a slice is added to the sealed
shape without being classified either way.

**What it fixes.** Two `vuln-scan --force` runs of one walk against one advisory
snapshot produced two different records for the same coordinate. Measured on the
working store over walk `01KZMJBYXA5RJZZYJW2HQ31KE8` (128 modules), 6 of 128
coordinates differed between the two passes with `content_hash`, `scanned_at`
and `first_scanned_at` excluded, and every difference was a reordering of the
same values — `affected_symbols` inside a finding, and the routes that arrive
beside those symbols. After the change the same loop differs on 0 of 128.

**Where the order is taken, and why that decides the bump.** The seal step, not
the hash recipe. `VerifyContentHash` recomputes the hash from the record as it
was read back, so canonicalising inside the recipe would rearrange a stored
record on the way to checking it: 51 of the 2,006 vulnerability records in the
working store hold an `affected_symbols` list, and 47 findings hold a route
list, in an order sorting would change. Those records would have stopped
verifying and been reported in the wording reserved for altered bytes, which
would have owed a pipeline bump darkening all 2,006 until re-scan. They are not
wrong about what they measured — they are arranged differently — so the bump
would have bought nothing. Taking the order at the seal makes every record
written from here on reproducible and leaves stored bytes verifiable exactly as
they are.

**What a reader sees.** A re-scan of unchanged inputs now yields a record that
differs from the last one only in `scanned_at` and the `content_hash` that
covers it. A record written before this change and one written after may list
the same values in two orders; they are the same measurement, and the older one
is not superseded by the arrangement alone.

## SBOM: pipeline `0.8.0` → `0.9.0`

**Document bytes change; no store migration.** Same mechanism as the bump below:
SBOM records are cached on `(walk id, scan run id, format, pipeline version)` and
hashed over the document bytes, so the bump makes stored `0.8.0` documents
unreachable and a request regenerates. Nothing is purged. Six stored records —
five at `0.7.0`, one at `0.8.0` — go dark at once.

Two behaviours forced it.

**Every component's external references were assembled from the module path.**
Each carried `{vcs: "https://" + path}` and
`{distribution: "https://proxy.golang.org/" + path + "/@v/" + version + ".zip"}`,
unconditionally, with no branch for a local coordinate, a replace directive, a
vendored tree or a private path. Neither was read from anything measured. In the
one artefact shipped from this tool, all 18 components carried both: the subject
asserted a proxy download for `@v/local.zip`, a version the proxy does not serve
for a module it does not hold, and `github.com/oklog/ulid/v2` asserted a
repository URL whose `/v2` is a module-path element GitHub answers `404` for. A
component now carries a `vcs` reference only where the fetch ledger holds a
positively cross-verified record naming the repository, ref and commit, and no
library component carries a `distribution` reference at all — the ledger records
the route bytes arrived by and the blob handle they were filed under, never a
public download address. Components with nothing recorded carry no
`externalReferences` block.

**A stamped subject was described twice at two versions.** `--main-version` and
`--main-license` reached `metadata.component` only. The subject's own entry in
the component list kept the synthetic `local` version and no licence, so one
document asserted two `purl`s for one module, the `dependencies` array carried
two entries for it each repeating the whole dependency set, and the
undetermined-licence count read the copy the stamp never reached — the run
exited `1` naming the operator's own module while `--main-license` sat on the
other copy. The stamp now decides the subject once, and both descriptions read
that decision.

**Stored `0.8.0` and earlier documents carry the constructed references.** The
bump makes them unreachable through the cache; it does not correct copies
already shipped. A document already handed to a consumer points at a download
location that may not exist, and re-issuing it is the only fix for that copy.

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

## Purging a table other rows point at

A migration that deletes rows must state what happens to the rows that reference
them. The reference is by convention, not by foreign key, so nothing in SQLite
stops a purge leaving a dangling one.

The case that already happened: `walk` migration 5 purged `walks` on a record
shape change, and `walk_scan_runs` rows kept naming the deleted walks. Their
findings survived while the statement of *what was scanned* did not, and nothing
in the run row said so - the `walk_id` looked like a valid reference. (Measured
on the real store: 16 of 127 runs, all written between the last `vuln`
migration-8 purge and the `walk` migration-5 purge.)

A migration that purges `walks` therefore chooses one, in the migration comment:

- **Purge together** - delete the dependent `walk_scan_runs` and
  `walk_scan_run_modules` rows in the same migration. Correct when the dependents
  are regenerable and worth nothing on their own.
- **Orphan with the reason recorded** - keep the dependents and say in the
  migration comment that they are being stranded and why. Correct when the
  dependents are evidence in their own right, as findings are.

Either way the read side does not depend on the choice: every surface that serves
a scan run derives whether its walk is still present and states
`inputs unresolvable` when it is not, so a run stranded by any future purge is
reported rather than rendered as ordinary. Nothing is stamped on the rows, so
there is no back-fill and no shape change.

The same rule reaches reuse. `walks.identity_hash` (migration 7) is the key scan
reuse looks a walk up by; rows written before that column carry the empty identity
and are never reuse candidates, so **no back-fill is owed** - but a purge of
`walks` destroys reusability the store has already paid for, which is part of what
the migration comment must weigh.

## Audit log (`audit.jsonl`)

Append-only JSONL; **no schema migration** is ever required to add an event
type. Every line carries an `event_type` discriminator. The
fact-record line keeps its historical flat layout with `event_type:
"fact_record_written"` added additively; all other events use the generic
`{event_type, timestamp, payload}` envelope. Recognised event types are the
closed set in `internal/audit`.

The event types added since `callgraph_extracted` (one per persisted call-graph
generation, on both the fetched-artefact and working-tree routes), in the order
they landed. None needed a migration, as above:

| Event type | One per |
|---|---|
| `interface_extracted` | persisted interface generation |
| `examples_extracted` | persisted examples generation |
| `extraction_run_completed` | extraction run over a walk, on every outcome including a cancelled one |
| `stdlib_custody_recorded` | persisted standard-library custody measurement, on both acquisition routes |
| `sbom_generated` | persisted SBOM record |
| `sbom_served` | stored SBOM document handed back from the cache |
| `advisory_snapshot_recorded` | persisted advisory database snapshot, by whichever route acquired it |
| `vuln_scan_served` | stored walk scan run handed back instead of measured, naming the run, the walk it answered for and the surface that asked |

The rule this table exists to serve: **this file and the event-vocabulary docs
are updated in the same commit as the change they describe.** It went stale by
four event types before this one, and a reader checking whether a write is
witnessed cannot tell an omission from an absence.

Each of these is emitted only where the write happened, so a cache hit or a
reused snapshot appends nothing. There are two deliberate exceptions, and they
share one reason: `sbom_served` and `vuln_scan_served` witness an ASKING rather
than a write, because a document handed to a caller and a stored scan run served
without re-measuring are both observations in their own right. Without them, an
unchanged store answers from existing rows indefinitely and the ledger's
timestamps track only when evidence was DERIVED — so "when did we first learn X"
stays answerable while "when did we last check X" becomes unrecoverable. Every
other event is a write, which is why a stable line count in `audit.jsonl` is
evidence about **writes**, not about runs.

### What the log does NOT witness

Several record kinds are persisted and append no event. `kanonarion store ledger`
states this on every reading, because silence in an append-only stream otherwise
reads as proof that nothing happened:

| Not witnessed | Note |
|---|---|
| individual vulnerability record generations | `vuln_scan_completed` **counts** them and `vuln_finding_observed` names each finding, but no event names a per-module verdict; a Clean generation is only an increment, and a single-module scan names no generation either — it appends only the advisory snapshot it acquired, if it acquired one. Enumerating generations is a store query, not a ledger query |
| attestations | additive provenance recorded beside a fact record, not mirrored into the log |
| latest-version (staleness) ledger entries | the staleness context has no audit sink wired at all |
| blob content writes | `fact_record_written` names the blob identity; the write of the bytes appends nothing |
| directive / GODEBUG / FIPS scans that found nothing | those events are emitted per finding, so a clean scan writes a record and appends no event |

This table is covered by the same rule as the one above: it is updated in the
same commit as any change to what emits.

### Reading the log

`audit.jsonl` is read by `kanonarion store ledger` (see
[`docs/cli/store.md`](../cli/store.md)). Two properties of the on-disk artefact
that the reader is built for, and that any other consumer must also handle:

- **Torn lines exist.** The reference store carries three (lines 4601, 4618,
  4636 of 33,012), all `license_extracted` events written inside one 8-second
  window by the pre-refactor writer, each showing a second event's JSON spliced
  mid-line. The current writer (`sync.Mutex` + `O_APPEND` per append) is safe
  within a process; the mutex does not cross processes. A strict line-by-line
  parse **aborts** at the first of them, so a reader must tolerate and COUNT them
  rather than abort or skip silently, and must state that the event count for the
  affected window is a lower bound.
- **File order is not guaranteed to be time order**, though in practice it is.
  The reader sorts by timestamp.
