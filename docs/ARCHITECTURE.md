# Architecture

## Overview

Kanonarion is a deterministic facts engine for Go module supply chains. It
ingests Go modules, verifies them against the checksum database, walks their
full transitive dependency closures, and extracts structured facts - public
API surface, call graphs, licences, vulnerabilities, directives, and more.
Every result is persisted as a content-addressed record whose integrity hash
is verified on every read, and
every query distinguishes *"not analysed"* from *"analysed, zero result"* so
absence is never reported as a confident negative.

---

## DDD Layering

The codebase is organised into bounded contexts, each following the same
strict layering. Dependencies point **inward only** - a layer may import the
layers listed beneath it, never above:

```
cmd/kanonarion            (binary entry point)
  → internal/cli          (cobra commands; wiring + output formatting)
    → internal/{ctx}/adapters      (concrete I/O implementations)
      → internal/{ctx}/application (use cases; orchestration)
        → internal/{ctx}/ports     (interfaces / dependency-inversion boundary)
          → internal/{ctx}/domain  (pure logic: entities, value objects, rules)
```

- **domain** - pure Go. No I/O, no third-party dependencies beyond
  `golang.org/x/mod`. The business rules live here as functions, fully
  unit-testable without mocks.
- **ports** - Go interfaces describing what the application needs from the
  outside world. Adapters implement them; tests use fakes.
- **application** - use cases that load inputs via ports, delegate rules to
  `domain`, and delegate parsing/serialisation to port-backed adapters.
- **adapters** - one package per backend (a parser, a store, an external tool).
- **cmd/kanonarion** - the cobra CLI, wired through the composition root.

Two rules keep this honest. Both are enforced by the architecture tests under
`test/`, over a bounded-context set derived from the tree rather than listed, so
a context added later is covered without editing a test:

- **No cross-context imports** except through another context's `ports`
  interfaces (or a shared coordinate type). A context never imports another
  context's `application` or `adapters`. Enforced by
  `TestNoCrossContextApplicationImports`. A third guard,
  `TestNoInfraImportsInApplicationOrDomain`, keeps source/format parsing and raw
  SQL out of those layers on the same terms.
- **No wall-clock access** (`time.Now`/`time.Since`) in `application` or
  `domain`. A `Clock` is injected for record timestamps and a `Stopwatch` for
  latency metrics. Enforced by `TestNoWallClockInApplicationOrDomain`.

The tests are what gates this, not only the `forbidigo` lint rule that states
the second one: `make lint` does not run `golangci-lint`, so a lint-only rule
would be advisory.

All JSON and graph output is deterministic: sorted keys, lexicographically
sorted edges, fixed field ordering. *Determinism* below states each of those
properties with the test that enforces it.

---

## Bounded Contexts

Each context owns a slice of the pipeline and persists its own record type in
SQLite (versioned per module - see *Persistence*). Composition of multiple
contexts always lives in an `adapters` package or the composition root, never
in a use case.

| Group | Context | Package | Responsibility |
|-------|---------|---------|----------------|
| Ingest | fetch | `internal/fetch` | Fetch and verify a single module version |
| Ingest | walk | `internal/walk` | Resolve and fetch the full transitive closure |
| Ingest | stdlib | `internal/stdlib` | Establish the Go standard library's chain of custody (go.dev/dl tarball, checksum, VCS anchor, licence) |
| Extract | extract | `internal/extract` | Orchestrate per-module extraction stages |
| Extract | iface | `internal/iface` | Extract the public API surface |
| Extract | callgraph | `internal/callgraph` | Build the intra-module call graph |
| Extract | example | `internal/example` | Harvest `Example*` functions |
| Risk | license | `internal/license` | Detect and classify licences |
| Risk | vuln | `internal/vuln` | Scan for known vulnerabilities |
| Risk | sbom | `internal/sbom` | Generate a CycloneDX SBOM |
| Risk | capability | `internal/capability` | Report which sensitive capabilities a module's reachable code can exercise |
| Risk | staleness | `internal/staleness` | Resolve how far behind upstream a pinned dependency is |
| Governance | directive | `internal/directive` | Classify go.mod/go.work replace & exclude directives |
| Governance | godebug | `internal/godebug` | Classify `//go:debug` settings |
| Governance | vendortree | `internal/vendortree` | Analyse a vendored tree for drift & inconsistency |
| Governance | fips | `internal/fips` | Assess FIPS toolchain eligibility |
| Local | local | `internal/local` | Analyse the local working tree |
| Config | config | `internal/config` | Governance configuration overlay |

### Ingest

**fetch** - responsible for a single module at a pinned version: fetch the zip
from a proxy or VCS, verify it against the Go checksum database, store it as a
content-addressed blob, and persist a `FactRecord` (coordinate, hashes,
verification status, pipeline version). It declares the shared substitution
ports (`BlobStore`, `FactStore`, `Clock`, `Signer`, `ModuleProxy`,
`VCSClient`, `SumDBClient`) and binds them to the shared adapters under
`internal/adapters`; it has no adapters package of its own.

**walk** - resolves a module's full transitive closure and fetches every node.
The build list is **delegated to the Go toolchain**
(`adapters/buildlist/gotoolchain`) rather than reimplementing Go's module-graph
pruning and minimum-version selection - matching `go list -m all` exactly and
tracking toolchain changes automatically. It fetches concurrently under a
worker-pool bound through `walkports.ModuleFetcher` (a thin adapter over the
fetch use case, keeping the dependency at the port boundary), then persists a
`WalkRecord` (graph, per-node results, timing, policy snapshot, content hash).
Partial and cancelled walks are surfaced explicitly and still persisted.
*Adapters:* `gomod/xmod`, `fetcher/local`, `buildlist/gotoolchain`,
`policy/localfile`, `walks/sqlite`.

**stdlib** - establishes the Go standard library's chain of custody, the
toolchain-provided analogue of a module's proxy→sumdb custody. Its `Acquirer`
downloads the canonical `go{VERSION}.src.tar.gz` from `go.dev/dl`, matches its
`SHA-256` against Go's published release manifest, resolves the
`go.googlesource.com/go` tag → commit, computes the `SHA-256`/`SHA-384`/`SHA-512`
digests, and extracts the `BSD-3-Clause` licence from the tarball's `LICENSE`.
The facts are cached per Go version and attached to the synthetic `stdlib` walk
node (via the `walkports.StdlibAcquirer` port and the `walkbridge` adapter, so
the walk context never imports stdlib), where `audit` and `sbom` read them. The
anchor is deliberately weaker than a sumdb transparency-log entry and recorded as
such. *Adapters:* `godev` (manifest + tarball), `gitlsremote` (commit),
`licenseident` (SPDX), `store/sqlite`, `walkbridge`.

### Extract

**extract** - orchestrates the per-module extraction stages over a walk,
persisting an `ExtractionRun` with per-module stage results. It loads inputs
via ports and delegates each stage to a port-backed adapter; the multi-stage
composition lives in `adapters/extractor/local`, never in the use case.
*Adapters:* `stages/local`, `extractor/local`, `store/sqlite`.

**iface** - extracts a module's public API surface (types, functions, methods,
constants) into a structured `InterfaceRecord` an agent can consume directly.
Source parsing is confined to `adapters/extractor/godoc`.

**callgraph** - builds the intra-module call graph (`CallGraphRecord`) for
impact analysis and reachability, using a static class-hierarchy-analysis
algorithm (`adapters/analyser/staticcha`). Powers the `callers`/`callees`
traversals and vulnerability reachability.

The record carries two axes beyond the edges. `_test.go` declarations are nodes
tagged `IsTest`, and `TestScope` records whether that axis was measured at all -
so an empty callers answer over a module whose tests were never analysed is
reported as `UNRESOLVED` rather than as an absence. `Interfaces` and
`Implementations` record which of the module's concrete types satisfy which of
its declared interfaces; that relation is what `implementers` reads, and it is
the type-level counterpart of the edge queries, since an interface method has no
callers.

The whole target module is type-checked in a **single** `go/packages` call.
This is a correctness constraint, not a performance choice: go/packages mints
fresh `*types.Package` objects per call and go/types compares types by pointer
identity, so a concrete type loaded in one call never satisfies
`types.Implements` against an interface loaded in another - and that relation is
how CHA binds every interface dispatch.

**example** - harvests `Example*` functions from module test files into an
`ExampleRecord`, so downstream context offers patterns that actually compile.
*Adapter:* `parser/goast`.

### Risk

**license** - opens a fetched module's zip and classifies its licences with
`google/licensecheck` (`adapters/detector/licensecheck`), deriving a primary
SPDX identifier and an overall status (`Detected` / `Unclassified` / `None` /
…) into a `LicenseRecord`. It reuses the fetch ports (`BlobStore`, `FactStore`,
`Clock`) rather than redeclaring them, and supports operator overrides
(`adapters/overrides/yaml`), transitive-closure compatibility reporting, and
version diffs.

**vuln** - scans a walk's modules against a pinned OSV snapshot
(`adapters/vulndb/osv`) by wrapping govulncheck (`adapters/vuln/govulncheck`),
persisting per-module `VulnerabilityRecord`s and a `WalkScanRun`. Optional
call-graph reachability (`adapters/reachability`, reading the callgraph and
fetch contexts through their ports) triages findings the code cannot actually
reach. Scan runs are append-only, and each record carries an immutable
`first_scanned_at`.

**sbom** - generates a deterministic CycloneDX software bill of materials
(`SBOMRecord`) from any walk. *Adapter:* `generator/cyclonedx`.

**capability** - reports which sensitive capabilities (`NETWORK`, `FILES`,
`EXEC`, `REFLECT`, `UNSAFE_POINTER`, …) a module's reachable code can exercise,
over kanonarion's own call graph rather than a second analyser. The taxonomy is
adopted from `google/capslock` so reports are comparable. Every finding carries
the weakest edge confidence along its witnessing path, so a capability reached
only through interface over-approximation is not conflated with one reached by a
resolved direct call, and a report computed over a `Partial` graph is flagged
`Partial` rather than presented as a clean set. The context is pure domain over
callgraph value objects: no I/O, no toolchain, no clock.

**staleness** - resolves how far behind upstream a pinned dependency is, as two
facts that are never collapsed into one: the newest version of the module's own
path, and whether a newer major line exists at a different path entirely. A
module several majors behind resolves to its own path's newest version and would
otherwise be reported as current. Proxy answers are cached with a TTL and an
absent path is a cacheable negative, distinct from a lookup that could not be
made. *Adapters:* `proxy` (with `retrying`), `golist`, `store/sqlite`.

### Governance

These contexts detect a supply-chain signal, classify it against a versioned
taxonomy, and evaluate it against policy - reporting facts and caveated
inferences, never a verdict.

**directive** - detects and classifies go.mod/go.work `replace` and `exclude`
directives by risk class (`adapters/parser/xmod`), with scan history, show, and
diff.

**godebug** - detects and classifies `//go:debug` settings against a versioned
taxonomy (`adapters/scanner/gosrc`). A directive under `vendor/` names the
module `vendor/modules.txt` lists for that directory, read through godebug's own
`VendoredModuleLister` port (`adapters/vendortree`).

**vendortree** - reconciles a vendored closure and detects `vendor/` drift and
`modules.txt` inconsistency (`adapters/scanner/localfs`). The directory is
named `vendortree`, not `vendor`, because Go reserves `vendor/`.

**fips** - assesses FIPS toolchain eligibility and detects non-FIPS algorithms
and cgo-crypto usage (`adapters/scanner/gosrc`). A finding read from a file
under `vendor/` names the module `vendor/modules.txt` lists for that directory,
read through the vendor context's scanner behind fips's own
`VendoredModuleLister` port (`adapters/vendortree`), the same shape godebug
uses - there is one parser of `modules.txt` in the tree and one rule for which
listed module owns a path (`vendortree/domain.VendoredModuleIndex`), so no
analysis learns how `modules.txt` is read and no two of them can disagree about
one file.

### Local

**local** - ingests the local working tree so `callers`/`callees` resolve
internal symbols and reachability can be probed against uncommitted code. Its
adapters wrap the Go tooling directly (`importer/golist`, `symbols/gopackages`,
`probe/builder`, `snapshot/walkdir`). A working tree mutates, so a stored graph
of it is only an answer while the tree is unchanged: the tree is scanned first
and the held record is served when it matches, and re-analysed otherwise.

### Config

**config** - a supporting context holding the governance configuration overlay
(licence, directive, godebug, vendor, and FIPS policies plus output
preferences), loaded from `<store-root>/config.yaml` as a sparse overlay on
built-in defaults (`adapters/store/yaml`). Other contexts read it through its
ports; it has no application layer of its own.

---

## Shared Adapters

Infrastructure used by more than one context lives under `internal/adapters/`
rather than being re-declared per context:

- `blobstore` - SHA-256 content-addressed blob storage (module zips)
- `factstore` - `FactRecord` persistence in SQLite, wrapped by the
  `AuditingStore` that appends the assurance log
- `proxy` - module proxy client (`proxy.golang.org` or `$GOPROXY`)
- `vcs` - `git`-binary client for source cross-verification
- `sumdb` - Go checksum-database client
- `signer` - `Signer` port; the OSS build wires a no-op default (no attestation)
- `clock` - `System` (production) and `Fixed` (tests)
- `blobcodec`, `ziparchive`, `modcache` - blob (de)serialisation, zip handling,
  and Go module-cache materialisation for `use`

---

## Cross-context Composition

Three layers sit *above* the bounded contexts and are exempt from the
cross-context import ban because their whole job is composition:

- **`internal/composition`** - the neutral composition root shared by the CLI
  and the public façade. It owns `Migrations()` (the schema's migration set),
  `NewQueries(storeRoot)` (wires the read stores and every `Query*` use case),
  and `NewDriver(storeRoot)` (wires the fetch/verify, local walk-extract, and
  validate-and-ingest pipelines).
- **`internal/driver`** - cross-context use cases that sit above the contexts,
  such as `LocalWalkExtractUseCase` (walk a local working tree, then run its
  extraction stages). It depends on narrow runner interfaces so it unit-tests
  without the full pipeline.
- **`internal/cli`** - the cobra command surface; wires adapters through the
  composition root, invokes use cases, and formats output.

The public API is the curated façade **`pkg/kanonarion`** - the only surface
external consumers may import (everything else is `internal/`). It re-exports a
small, hand-curated subset: read-shaped result-type aliases, substitution ports,
the `Query*` use cases, and `Open`/`OpenDriver` entry points. Every exported
identifier carries a doc comment and a `Stability:` line; published ports grow
only by adding a new optional interface, never by widening an existing one.

---

## Determinism

Each invariant below names the test that enforces it. An invariant with no
enforcing test does not belong in this section.

- **`application` and `domain` never read the wall clock.** Every timestamp
  those layers put on a record comes from an injected `Clock`, and every
  latency they report comes from an injected `Stopwatch`. An `adapters` package
  may read the clock to stamp when it observed something, and no such stamp
  survives into a sealed record: the use case restamps it from the injected
  clock before the record is sealed. Enforced by
  `TestNoWallClockInApplicationOrDomain`, which parses every non-test file in
  every bounded context's `application` and `domain` layer and rejects
  `time.Now` and `time.Since`. The context set it walks is derived from the
  tree, so a context added later is covered without editing the test.
- **Canonical serialisation** uses sorted JSON keys, RFC3339 UTC timestamps,
  and fixed field ordering. Maps that must serialise (e.g. per-node results)
  are emitted as sorted arrays of `(key, value)` pairs, since maps have no
  canonical JSON order. Enforced by `TestCanonicalShape_IsPinned`, which every
  record domain runs against a golden file of the exact bytes it seals, so a
  field added, reordered or retyped fails before it can invalidate the records
  already in a store.
- **`ContentHash` is computed over the canonical form with the hash field
  zeroed.** A domain that excludes a further field declares it through
  `SealExcludes`, so a verifier working from stored bytes alone can reproduce
  the seal. Enforced by `TestEveryDomainHasher_IsAcceptedBySelfConsistent` and
  `TestEveryDomainHasher_IsAcceptedByVerifyBlob`, which seal a fully populated
  record from every domain and verify it through the shared verifier.
- **Module zips are stored verbatim.** A zip fetched from a proxy or the module
  cache is stored byte for byte as it arrived and is never recompressed: its
  hash is what the checksum database attests and what every later reader
  recomputes, so re-zipping it would replace the artefact the trust anchor
  covers. A local module has no upstream zip - it is packaged from its working
  tree, and that synthetic zip may be rewritten to carry the local coordinate's
  entry prefix, since `modzip` requires a canonical semver the local version is
  not. Enforced by `TestNoZipRewritingOutsideNamedPackages`, which rejects an
  `archive/zip` writer in any non-test package outside a named list, each entry
  stating why no fetched artefact reaches it.
- **Iteration order never depends on map enumeration.** Graph nodes and edges
  are sorted lexicographically by module path and version, and every collection
  a record seals is ordered by a total order rather than by the walk or map that
  produced it. Enforced by `TestOrderingComparatorsAreTotal`, which rejects a
  comparator in a domain layer keyed on too few fields to break every tie, and
  by `TestEveryHashedTypeHasADeterminismGuard`, which derives from the code that
  every content-hashed type has a per-type guard shuffling its collections and
  asserting one digest.

---

## Audit Log

Every `PutFetchRecord` call appends a JSONL entry to
`{store-root}/audit.jsonl` via `AuditingStore`. Fields: timestamp, module
coordinate, pipeline version, verification status, content hash. This is the
`fact_record_written` event - what was *written*.

A write that would have replaced a stronger verification anchor with a weaker
one is recorded on whichever side it landed:

- `fact_record_write_refused` - the re-measurement was refused and the existing
  record kept, which is the fetch result the caller gets back.
- `fact_record_downgraded` - the operator explicitly permitted the weaker
  measurement to replace the stronger one. This is the only path by which an
  anchor can weaken.

Both carry the same payload - module, version, pipeline version, both
verification statuses, both acquisition modes, both content hashes, and whether
the run was forced - so the pair reads as one series and a demotion attempt is
reconstructable from the log alone.

The read/serve verification path records what was *read*, using the generic
`{event_type, timestamp, payload}` envelope (no new on-disk schema):

- `record_read_verified` - a successful verified read/serve. Emitted by
  `ServeModuleUseCase.Serve` when the resolved module is positively verified,
  and by `ValidateAndIngestUseCase.ReadVerified` when a stored record passes
  re-verification. Payload: module, version, pipeline version, verification
  status.
- `verification_failed` - the read/serve path rejected a record: served without
  a positive trust anchor, or a stored record that failed re-verification
  fail-closed. This is the single highest-value security event - a tampered or
  mismatched blob being refused. Payload adds the rejection `reason`; the exact
  `verification_status` travels alongside it, so a hard mismatch is never
  conflated with an un-analysed/unknown outcome.

Both use cases take the audit sink optionally (`WithAudit`, mirroring
`WithSigner`); the composition root wires the shared `AuditingStore`. An emit
failure fails the read: the assurance log can never silently miss what was
served, and a rejected read never loses the fact that it was rejected.

The vulnerability scan records what was *found*, using the same envelope:

- `vuln_scan_completed` - one per walk-wide scan run. Payload: walk id,
  scan-run id, snapshot source/version, overall status, and the module-count
  breakdown (`affected`/`clean`/`unscannable`/`failed`). It anchors "we scanned
  this dependency set against this database on this date".
- `vuln_finding_observed` - one per finding. Payload: module, version,
  vulnerability id, and the module's overall status. One event per finding
  makes "when did we first learn module X was affected by CVE-Y" answerable
  from the append-only log, not only from the mutable vuln DB.
- `vuln_scan_served` - a stored scan run handed to a caller instead of being
  measured again. Payload: the run served (scan id, walk id, pipeline version),
  the advisory database it was judged against, and the surface that asked
  (`vuln-scan`, `audit`, `inspect`). It is named for the asking, because nothing
  was scanned: without it an unchanged store answers from existing rows
  indefinitely and "when did we last check" becomes unanswerable while "when did
  we first learn" stays answerable from the derivation events. It restates none
  of the run's conclusions - the scan id reaches them.

The governance contexts record what was *classified*, one event per detected
signal so that an add, a removal or a change between two scans is readable off
the log without a bespoke diff schema. Each of those payloads names the project,
where the signal was found, its classification, and the policy outcome it
evaluated to:

- `replace_directive_observed` and `exclude_directive_observed` - one per
  `replace` or `exclude` directive, with the old and new path/version, whether
  the directive applied, and its risk class.
- `godebug_setting_observed` - one per `//go:debug` or `GODEBUG` setting, with
  its name, value, and taxonomy tier.
- `fips_assessment` - one per FIPS finding, with the finding kind and category,
  the package and module it sits in, and whether the toolchain is FIPS-capable.
- `vendor_tree_generated` - one per vendored-closure scan rather than per
  finding, and the one governance event carrying no policy outcome. It records
  the reconciled posture (project, vendor directory, whether the build is
  vendor-only, module and finding counts, overall status, content hash);
  finding-level detail is in the persisted record, and it is the sequence of
  scans that makes a tree's drift history first-class.

Licence extraction records what was *classified* (`license_extracted`: module,
version, resolved primary SPDX, overall status, identity source), and the walk
records what was *resolved* (`walk_completed`: walk id, root, scope
(`code`/`tool`/`complete`), node count, content hash). Both anchor the inputs
that bound every downstream verdict in the append-only assurance log, not only
in a mutable record. Each is emitted only after a successful, freshly computed
result is persisted; cache hits re-serve without re-emitting.

Call graph extraction records what was *analysed* (`callgraph_extracted`:
module, version, pipeline version, completeness level, overall status, analysis
source, node/edge counts, content hash, plus the artefact identity or worktree
digest the analysis read). It covers both write paths - the fetched-artefact
route and the working-tree route `kanonarion local` takes - on the same terms:
one event per persisted generation, nothing on a cache hit. It is what every
reachability and capability answer is derived from, and without it a store write
left no trace at all, so a stable audit line count read as "nothing ran".

Interface and example extraction record what was *read out of the source*
(`interface_extracted`: module, version, pipeline version, overall status,
package count, build frame, content hash, the artefact identity and the fetch
record's content hash; `examples_extracted`: the same fields with example and
parse-failure counts). Both state a `failure_detail` when the record has a
reason. One event per persisted generation, nothing on a cache hit.

The extraction orchestrator records the *campaign* those per-stage events belong
to (`extraction_run_completed`: run id, walk id, requested stages, module count,
per-stage outcome counts, overall status, content hash). It writes a run record
on every outcome - including a cancelled one - so it has no cache branch and
every run appends. Without it, a batch of stage events could not be told apart
from a series of single-module re-extractions.

Standard-library custody records that a *measurement was taken*
(`stdlib_custody_recorded`: toolchain version, acquisition route (`godev` /
`local-toolchain`), the verification anchors that acquisition established, the
artefact identity it was taken over, and the measurement's content hash). Both
acquisition routes emit on the same terms. The payload deliberately omits the
verification status, the published checksum and the licence: the event
*witnesses* that a custody record was written and by which route, and the record
carries the claims - the content hash is what reaches them. A cache hit re-serves
without appending, and a run that could not establish custody at all wrote no
record and so appends nothing, since an absence is not an observation.

SBOM generation records what *left the building*. It is the only artefact
kanonarion hands to someone else, so both halves are logged: `sbom_generated`
(record id, walk, format, pipeline version, the document's content hash, and
whether the creation timestamp was caller-supplied) for a document produced and
persisted, and `sbom_served` (the record served plus the identity that requested
*this* serving) for a stored document handed back from the cache. Two types, not
one, because a produced document and a re-served one are different facts and
"how often has this gone out" needs both. A `--package` run is ephemeral - no
cache lookup, nothing persisted - and appends nothing, since the events state
that a record exists.

The advisory database snapshot records what the findings are *judged against*
(`advisory_snapshot_recorded`: source, that database's own generation of itself,
the retrieval instant, the content identity of the persisted bytes, and the
acquisition route - `walk_scan`, `module_scan`, `advisory_refresh`,
`walk_rescan`). Every persist site emits, so an advisory set is witnessed once
by whichever run fetched it. It states nothing about the advisories themselves,
their count, or any module's standing: those are the snapshot's and the scan
records' claims, reachable through the content identity. A run that reuses a
stored snapshot appends nothing - reuse is not an acquisition, and dating an
earlier arrival to this run would report an event that never happened.

Both composition roots wire the same sinks. The CLI container and the library
composition root behind `pkg/kanonarion` append identical events for the same
operation; a consumer driving the pipeline as a library does not get a quieter
assurance log than one driving it from the command line.

Walk and every extraction record verify their content hash on every read;
mismatches are typed integrity errors that callers distinguish from not-found.

---

## Policy and Configuration

Two distinct mechanisms, deliberately separate:

- **Depth policy** (`DepthPolicy`) - a versioned value object controlling how
  each pipeline stage traverses the graph (`max_depth`, `follow_replace`,
  `follow_test`, `follow_indirect`), plus the fetch stage's
  `allowed_vcs_hosts` - the forge allowlist VCS cross-verification may clone
  from. It is loaded once per invocation from a `.kanonarion/policy.yaml`
  searched upward from the working directory, and snapshotted into every
  `WalkRecord` that applies it (`PolicyVersion`, `PolicyHash`, `StageDepths`),
  making each record self-describing and reproducible. It is kept separate from
  per-invocation parameters (`Force`, `WorkerCount`) because it is
  organisational and version-controlled.
  `allowed_vcs_hosts` is the one field keyed on presence rather than its zero
  value (`*[]string`, nil = absent): zero-value-on-omit is safe for a traversal
  toggle and unsafe for a trust list, where an unrelated edit to the stage must
  never silently weaken verification. Absent resolves to the built-in set; an
  explicitly empty list is a load error, because turning verification off is
  the orthogonal `--skip-vcs-verify`, not a value of the allowlist.
- **Governance configuration** (the config context) - the licence, directive,
  godebug, vendor, and FIPS policies plus output preferences, a sparse overlay
  on built-in defaults in `<store-root>/config.yaml`. Governance outcomes are
  `allow | notify | warn`; unknown licences additionally support `block`, a
  hard compliance failure that makes `audit` exit non-zero for a CI gate.

---

## Persistence and Migrations

All metadata lives in a single SQLite database (`{store-root}/mirror.db`);
module zips are content-addressed blobs under `{store-root}/blobs/`. Schema
migrations are versioned **per module** (`Module` + `Version` as the primary
key), so each context evolves its own tables independently. The composition
root aggregates every context's migration set through `Migrations()`, and
`store info` reports the resolved schema version and migration status.
