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

Two rules keep this honest and are enforced mechanically (by `forbidigo` lint
and the architecture tests under `test/`):

- **No cross-context imports** except through another context's `ports`
  interfaces (or a shared coordinate type). A context never imports another
  context's `application` or `adapters`.
- **No wall-clock access** (`time.Now`/`time.Since`) in `application` or
  `domain`. A `Clock` is injected for record timestamps and a `Stopwatch` for
  latency metrics.

All JSON and graph output is deterministic: sorted keys, lexicographically
sorted edges, fixed field ordering.

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

### Governance

These contexts detect a supply-chain signal, classify it against a versioned
taxonomy, and evaluate it against policy - reporting facts and caveated
inferences, never a verdict.

**directive** - detects and classifies go.mod/go.work `replace` and `exclude`
directives by risk class (`adapters/parser/xmod`), with scan history, show, and
diff.

**godebug** - detects and classifies `//go:debug` settings against a versioned
taxonomy (`adapters/scanner/gosrc`).

**vendortree** - reconciles a vendored closure and detects `vendor/` drift and
`modules.txt` inconsistency (`adapters/scanner/localfs`). The directory is
named `vendortree`, not `vendor`, because Go reserves `vendor/`.

**fips** - assesses FIPS toolchain eligibility and detects non-FIPS algorithms
and cgo-crypto usage (`adapters/scanner/gosrc`).

### Local

**local** - ingests the local working tree so `callers`/`callees` resolve
internal symbols and reachability can be probed against uncommitted code. Its
adapters wrap the Go tooling directly (`importer/golist`, `workspace/goast`,
`symbols/gopackages`, `probe/builder`, `snapshot/walkdir`). Local source
analysis is intentionally **never cached** - the working tree mutates, so each
run recomputes fresh.

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

- All timestamps come from an injected `Clock`, never `time.Now()` directly.
- Canonical serialisation uses sorted JSON keys, RFC3339 UTC timestamps, and
  fixed field ordering. Maps that must serialise (e.g. per-node results) are
  emitted as sorted arrays of `(key, value)` pairs, since maps have no
  canonical JSON order.
- `ContentHash` is computed over the canonical form with the hash field zeroed.
- Module zips are stored verbatim; re-zipping is never performed.
- `PipelineVersion` is a code constant per extraction stage, bumped
  deliberately when logic changes such that cached records would differ from
  re-extraction.
- Graph nodes and edges are sorted lexicographically by module path and
  version. Iteration order never depends on map enumeration.

---

## Audit Log

Every `PutFetchRecord` call appends a JSONL entry to
`{store-root}/audit.jsonl` via `AuditingStore`. Fields: timestamp, module
coordinate, pipeline version, verification status, content hash. This is the
`fact_record_written` event - what was *written*.

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

Licence extraction records what was *classified* (`license_extracted`: module,
version, resolved primary SPDX, overall status, identity source), and the walk
records what was *resolved* (`walk_completed`: walk id, root, scope
(`code`/`tool`/`complete`), node count, content hash). Both anchor the inputs
that bound every downstream verdict in the append-only assurance log, not only
in a mutable record. Each is emitted only after a successful, freshly computed
result is persisted; cache hits re-serve without re-emitting.

Walk and every extraction record verify their content hash on every read;
mismatches are typed integrity errors that callers distinguish from not-found.

---

## Policy and Configuration

Two distinct mechanisms, deliberately separate:

- **Depth policy** (`DepthPolicy`) - a versioned value object controlling how
  each pipeline stage traverses the graph (`max_depth`, `follow_replace`,
  `follow_test`, `follow_indirect`). It is loaded once per invocation from a
  `.kanonarion/policy.yaml` searched upward from the working directory, and
  snapshotted into every `WalkRecord` that applies it (`PolicyVersion`,
  `PolicyHash`, `StageDepths`), making each record self-describing and
  reproducible. It is kept separate from per-invocation parameters (`Force`,
  `WorkerCount`) because it is organisational and version-controlled.
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
