# `kanonarion walk` - Dependency graph resolution

## Synopsis

```
kanonarion walk <module>@<version> [flags]
kanonarion walk --gomod ./go.mod [flags]
kanonarion walk --gomod ./go.mod --tool [flags]
kanonarion walk --gomod ./go.mod --project [flags]
kanonarion walk-list [--scope <scope>] [flags]
kanonarion walk-show <walk-id> [flags]
kanonarion walk-diff <walk-id-a> <walk-id-b> [flags]
```

## Description

The `walk` family resolves and persists a module's dependency graph. A
`WalkRecord` captures every node in the closure, per-node fetch results, the
scope and depth, an overall status, and a content hash.

Each module in the closure is fetched and verified (the same checks as
`kanonarion fetch`); `walk` therefore implicitly fetches what it resolves.

A **depth policy** (`.kanonarion/policy.yaml`, searched upward from the cwd, or
`--policy`) controls how deep the closure is resolved per module.

## Commands

### `walk`

Resolve and persist the dependency graph of a module (or every module
required by a `go.mod`).

```
kanonarion walk <module>@<version> [flags]
kanonarion walk --gomod ./go.mod [flags]
```

`--gomod` and a positional module are mutually exclusive.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--pipeline-version` | _(compiled-in)_ | Override the pipeline version |
| `--goproxy` | `$GOPROXY` or `proxy.golang.org` | Override the module proxy |
| `--force` | `false` | Re-fetch and re-verify every module in the closure, bypassing the fact-store cache. Wall time scales with the closure size; `per_node_results[].from_cache` will be `false` for every node. |
| `--allow-partial` | `false` | Exit 0 even when the walk status is partial |
| `--workers` | `16` | Concurrent fetch workers |
| `--operator` | `$USER` | Operator identifier |
| `--policy` | _(search for `.kanonarion/policy.yaml`)_ | Path to depth policy YAML |
| `--gomod` | _(none)_ | Walk this `go.mod` as a project: one record rooted at the local main module. The dependency **scope** is `code` by default. See [`go.mod` walks](#gomod-walks). Defaults to `./go.mod`. |
| `--tool` | `false` | Scope the project walk to the **tooling** supply chain: the import closure of the `go.mod` `tool` directives (scope `tool`). Mutually exclusive with `--project`. See [Scopes](#scopes-code-tool-complete). |
| `--project` | `false` | Scope the project walk to the **complete** set: the project's code **and** tooling (the full Go build list, `go list -m all`, scope `complete`). Mutually exclusive with `--tool`. See [Scopes](#scopes-code-tool-complete). |
| `--shallow` | `false` | Fetch only the target; list its `go.mod` requires without recursing (positional module walk only) |
| `--skip-vcs-verify` | `false` | Skip git cross-verification (checksum still runs) |
| `--analyse-local` | `false` | Ingest `replace` targets that point to local directories so callgraph/iface/license can analyse them (requires `--gomod`) |
| `--analyse-root` | `false` | Ingest the project's own working tree so all extraction stages analyse the project's own packages. Re-reads the tree fresh on every run. Requires a `go.mod` walk; incompatible with `--tool` (a tool walk does not cover the project's own packages). See [Analysing the project root](#analysing-the-project-root---analyse-root). |
| `--stdlib-from-gomod` | `false` | Version the `stdlib` node from the `go.mod` directive, not the live toolchain. See [Standard-library version](#standard-library-version---stdlib-from-gomod). |
| `--json` | `false` | Emit the walk record as JSON |

### `walk-list`

List stored walk records, most recent first.

```
kanonarion walk-list [--scope code|tool|complete] [--json]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--scope` | _(all)_ | Filter by walk scope (`code`, `tool`, or `complete`) |
| `--json` | `false` | Emit the list as JSON |

### `walk-show`

Print a single stored walk record by ID.

```
kanonarion walk-show <walk-id> [--json]
```

### `walk-diff`

Print the difference between two walk records (added, removed, and
version-changed modules).

```
kanonarion walk-diff <walk-id-a> <walk-id-b> [--json]
```

## `go.mod` walks

`walk --gomod ./go.mod` produces a **single** record whose root is the local
main module. The set of dependencies it captures is governed by the **scope**
(see below); by default this is the project's own **code** - the modules the
project's packages actually import (`go list -deps -test ./...`), the set the
vulnerability-triage question ("is there vulnerable code in my project?") is
asked over.

```
kanonarion walk --gomod ./go.mod
```

| Aspect | Behaviour |
|--------|-----------|
| Root coordinate | The `module` path from `go.mod`, at the synthetic version `local` |
| Root resolution source | `local_main_module` - an unfetched anchor node; the main module is private/local, has no proxy artefact, and carries no `fetch_record` |
| Set | The scope's module set (default `code`); see [Scopes](#scopes-code-tool-complete) |
| `walk-list --latest-success` | Returns the project walk, so downstream `extract` / `vuln-scan` / `sbom` operate on the project |
| SBOM subject | `metadata.component` resolves to the local module (`pkg:golang/<module>@local`); the scoped set becomes `components` |

## Scopes (`code`, `tool`, `complete`)

Every command that walks a `go.mod` - `walk`, `audit`, `inspect`, `context`,
`latest`, `notice`, `sbom`, `vuln-scan`, `fetch` - exposes the **same** three
scopes with the **same** flags and resolves them through the **same** definition,
so the same question returns the same module set regardless of command.

| Scope | Flag | Set | Question it answers |
|-------|------|-----|---------------------|
| **code** | _(default)_ | `go list -deps -test ./...` → modules | "what does *my* code build/run" - the vulnerability / licence / copyright / symbol triage set, including test code |
| **tool** | `--tool` | import closure of the `go.mod` `tool` directives → modules | "what is in my tooling supply chain" (linters, generators, `go tool` binaries) |
| **complete** | `--project` | `go list -m all` (the full Go build list) | "code **and** tooling" - nothing vulnerable anywhere near the project |

`--tool` and `--project` are mutually exclusive; absent both, the scope is
`code`. The walk record is tagged with the scope (`code` / `tool` / `complete`),
so `walk-list --scope` and downstream stages select the right record.

The set is derived by delegating to the Go toolchain in the project directory;
every listed module is still fetched and sumdb/VCS-verified by kanonarion (the
toolchain decides only the *set*, never content trust).

Build tooling executes in developer and CI environments with full access and is
a primary supply-chain attack surface, so it is a first-class, separately
addressable scope (`--tool`) - never folded silently into the code view, never
dropped.

**Toolchain-unavailable fallback.** If `go` is absent or `go list` fails
(incomplete `go.sum`, restricted network), the walk falls back to the internal
resolver and is marked `partial` with reason `build_list_approximate: …`, so an
approximate set is never presented as authoritative.

**Why `local`?** The main module is unpublished, so it has no semver to pin. The
synthetic `local` marker anchors the record and the SBOM subject. (The Go-native
alternatives are `(devel)`; CycloneDX also permits omitting the root purl.)
Because `local` does not pin content the way a published version does - the
working tree's `go.mod` can change between runs - a project walk always
re-resolves rather than reusing a cached successful record. Re-resolution is
cheap: it re-derives the build list and reads the fetch cache, downloading
nothing for an unchanged closure.

## Analysing the project root (`--analyse-root`)

By default the project-walk root is an unfetched anchor: extraction skips it
with a reason, so a walk→extract teaches you nothing about the project's OWN
licence, public API, call graph, or examples. `--analyse-root` closes that gap:

```
kanonarion walk --gomod ./go.mod --analyse-root
```

| Aspect | Behaviour |
|--------|-----------|
| Root resolution source | Promoted from `local_main_module` to `local_analysed`; the root carries a real `fetch_record` built from the working tree (verification status `LocalSource`) |
| Extraction | All four stages (license, interface, callgraph, example) run on the project's own packages |
| Root licence record | Marked `role: root_declaration` - the licence the project itself declares outbound (grant + asserted copyright), not an inbound obligation. A proprietary root resolving to `Unclassified` plus copyright statements is a correct outcome, not a failure |
| `license-compat` | Adopts the analysed root licence as the implicit `--target` when the flag is omitted |
| `notice` / `sbom` | Carry the root's own licence and copyright (SBOM `metadata.component` gains `licenses` and `copyright`) |
| Freshness | The working tree is re-read and re-analysed on every run; no cached record is ever served for the `local` coordinate, so an edit is always reflected in the next run |
| Source locality | The tree is zipped into the local store only; nothing leaves the machine |

Default off, so without the flag the root stays skipped-with-reason and only
dependency facts are produced.

**Expect first-run downloads.** A `--project` walk fetches every module the
toolchain selects - including the full lint/tool dependency tree pinned by `go
mod tidy`, and, for any shared transitive, the version the build actually
selects. Those new coordinates download and verify once; subsequent runs are
fully cached.

## Standard-library version (`--stdlib-from-gomod`)

A project walk injects the Go standard library as a first-class node (`stdlib`),
so vuln-scan, `sbom`, and `audit` cover it. Its version comes from:

| Source | When | Example |
|--------|------|---------|
| Live toolchain (`go env GOVERSION`) | Default | 1.26.5 toolchain → `stdlib@v1.26.5` |
| `go.mod` `toolchain`/`go` directive | `--stdlib-from-gomod` | `go 1.22` → `stdlib@v1.22` |

The default reflects what compiled the code; `--stdlib-from-gomod` makes it
deterministic and source-matched (depends only on the checked-in `go.mod`) - what
release SBOMs and audits want. Shared verbatim by `walk`, `sbom`, `audit`, and
`inspect`. If neither source yields a version the node is omitted.

During a project walk the `stdlib` node also gains a **chain of custody**: the
canonical `go{VERSION}.src.tar.gz` is acquired from `go.dev/dl`, its `SHA-256`
matched against Go's published checksum, its `SHA-256`/`SHA-384`/`SHA-512`
digests and `go.googlesource.com/go` tag → commit recorded, and its
`BSD-3-Clause` licence extracted from the tarball's `LICENSE`. These facts flow
into `audit` and `sbom`. The tarball is cached per Go version; `--force`
re-acquires and re-verifies it, and `--skip-vcs-verify` omits the commit anchor
(the checksum verification still runs). A fully offline run (`--from-modcache`)
leaves the node without the custody chain. See [SBOM standard-library chain of
custody](sbom.md#standard-library-chain-of-custody).

## Scope and depth

| Field | Values | Meaning |
|-------|--------|---------|
| Scope | `code` | The project's own code dependencies - `go list -deps -test ./...` (default) |
| Scope | `tool` | The tooling supply chain - the `go.mod` `tool` directives' closure (`--tool`) |
| Scope | `complete` | Code **and** tooling - the whole build list, `go list -m all` (`--project`) |
| Depth | `full` | Full transitive closure (default) |
| Depth | `shallow` | Target only; its requires are listed, not recursed (`--shallow`, positional walk only) |

## Local-replace targets

A `go.mod` file may redirect a dependency to a local path via a
`replace example.com/foo => ../local/foo` directive. When the **local main
module** carries such a directive (a `--gomod` project walk), the walk records
the redirected node with resolution source `local_replace` and marks it as
unscannable by default - there is no version to fetch from a proxy.

Local-path replaces are honoured only for the local main module, exactly as the
Go toolchain does: it applies the *main* module's replaces and ignores a
dependency's. A **fetched** module target (a positional `module@version` walk)
is analysed as the published artefact a consumer would import, so its own
filesystem replaces - which point at directories absent from the module zip -
are ignored and the required module resolves normally from the proxy. This is
why a multi-module repository member such as `go.opentelemetry.io/otel/trace`,
whose published `go.mod` declares `replace go.opentelemetry.io/otel => ../`,
does not strand its sibling as an unscannable `local_replace` node.

Pass `--analyse-local` (with `--gomod`) to opt in to ingesting those directories
from disk:

```
kanonarion walk --gomod ./go.mod --analyse-local
```

When `--analyse-local` is set, the walker reads each local directory,
creates an in-memory module zip with `golang.org/x/mod/zip.CreateFromDir`,
hashes it, and stores it in the blob store exactly like a remotely-fetched
module. The node is promoted to resolution source `local_analysed` and
proceeds through `extract`, `callgraph`, `iface`, and `license` analysis
as a normal dependency.

If a local path cannot be read (directory missing, no `go.mod`, zip error),
the walker falls back to `local_replace` with a warning log; the overall walk
still succeeds.

The base directory for resolving relative paths is the directory that contains
the `go.mod` file supplied via `--gomod`.

## Per-node fetch results

Every module in the closure is recorded in `per_node_results` with the
outcome of its underlying fetch:

| Field | Meaning |
|-------|---------|
| `from_cache` | `true` if the module was already in the fact store on entry to the walk; `false` if it was downloaded during the walk |
| `duration_ms` | Wall-clock time spent inside the fetcher for this module |
| `status` | `succeeded`, `fetch_failed`, `internal_panic`, or `local_replace` |
| `fetch_record` | The full `FactRecord` for the successful fetch (null on failure) |

`from_cache` and `duration_ms` reflect the *first* call to the underlying
fetcher for each coordinate during the walk. This means the cold-fetch
fraction of a walk is readable from the record: count
`per_node_results[] | select(.from_cache == false)` to see how many modules
were actually downloaded.

The recorder that captures these outcomes also memoises per-coordinate
fetches inside the walk, so a coordinate is downloaded at most once per
walk even when the resolver and walker would otherwise both call the
fetcher.

## Large graphs: authentication, rate limits, and concurrency

For a big transitive closure (hundreds of modules - e.g. a CLI app or a
DFIR tool), the bound on a *cold* walk is rarely the worker count. It is the
**git cross-verification** step: for every module hosted on a public forge,
the walk runs `git ls-remote` plus a shallow fetch against the upstream
repository to confirm the proxy zip reproduces from source. GitHub allows
only **60 unauthenticated requests per hour per IP**, so a github-heavy
closure exhausts that budget partway through and the remaining modules record
`VerifiedBySumDBOnly` (checksum-database verified, source not reproduced)
rather than `Verified`.

Three levers, in order of preference:

- **Set `GITHUB_TOKEN`.** The walk injects it into the git subprocess
  environment, raising the limit to 5,000 requests/hour and letting the whole
  closure cross-verify. This is the right default for large graphs:

  ```bash
  GITHUB_TOKEN=<your-pat> kanonarion walk <module>@<version>
  ```

- **Raise or lower `--workers` (default 16).** The graph is resolved
  breadth-first; within each level the modules are independent, so their
  fetches run concurrently under this bound (level N+1 is gated on level N's
  `go.mod` parses). More workers therefore shortens the cold fetch phase
  against the Go proxy; `--workers 1` forces strictly sequential fetching. It
  does **not** raise the GitHub ceiling - past the rate limit, extra workers
  only exhaust it faster. Tune this for proxy throughput, not for the VCS step.

- **`--skip-vcs-verify`.** Skips git entirely; every module is verified
  against the checksum database only (`VerifiedBySumDBOnly`) and the walk
  completes in minutes regardless of graph size. Use it when you accept
  sumdb-only assurance for a one-off or when no token is available - never as
  a silent default, since it drops the source-reproduction guarantee.

A cold walk prints a throttled **progress heartbeat** to stderr - about one
line every 20 s, e.g. `walk progress: 142 modules fetched (3m20s elapsed)` - so
a long fetch is visibly alive rather than silent. It is written to stderr only,
so stdout (and `--json`) is unaffected. Disable it with `--no-progress` or
`kanonarion config set preferences.progress false`; a warm walk shorter than
the interval prints nothing. For full per-module detail pass `--log-level info`
to stream `fetch_start`/`fetch_end`/`cache_hit` and `vcs_cross_verify` lines
(which suppresses the heartbeat, since the stream already shows liveness). The
walk ID is logged as `walk_started` at the very beginning, so an interrupted
walk still leaves a correlation ID even though the walk **record** is persisted
only on completion.

## Overall status

| Value | Meaning |
|-------|---------|
| `succeeded` | Every module in the closure fetched successfully |
| `partial` | Target fetched but at least one dependency failed |
| `failed` | The target module itself could not be fetched |
| `cancelled` | Context cancelled before the walk completed |

With `--allow-partial`, a `partial` walk still exits `0`; otherwise it exits
non-zero. A failed-target walk is still persisted and is readable via
`walk-show` / `walk-list`.

## Local `go.sum` verification (project walks)

A **project walk** (`walk --gomod`) has the project's `go.sum` on disk. When it
is present, each fetched module's computed `h1` (zip and `/go.mod`) is also
cross-checked against the local `go.sum` - a cheap, offline complement to the
network checksum database that reuses the hashes already computed during
download. A module that **matches** `go.sum` but whose network checksum lookup
was unavailable reports `VerifiedByGoSum` (a positive offline anchor) rather than
`UnverifiedNoSumDB`; a module that **disagrees** with its `go.sum` entry is
tamper-evidence and records a fetch failure with the mismatch detail. A module
**absent** from `go.sum` simply falls through to the network checksum database.
See [`audit` › Local `go.sum` verification](audit.md#local-gosum-verification)
for the full behaviour, which `audit` and `sbom --package` promote to a hard,
non-zero exit.

## Storage

Walk records are stored in `<store-root>/mirror.db` (SQLite). The walk schema
is tracked in the shared `schema_migrations` table under module key `walk`
(current version: 4). Module zips resolved by the walk are written to the
content-addressed blob store, and each fetch is appended to
`<store-root>/audit.jsonl`.

## Assurance log

Each successful walk appends a `walk_completed` event to the append-only audit
log (`<store-root>/audit.jsonl`): the walk id, root `module` and `version`,
`scope` (`code` / `tool` / `complete`), `node_count`, and the record
`content_hash`. The walk defines the dependency set every downstream stage is
scoped from, so this anchors *what was resolved, and when* in the
append-only assurance log - independent of the mutable walk record in SQLite. Only a
`succeeded` walk emits: a `partial` or `cancelled` walk defines no complete
population to anchor, and a cached succeeded walk (no `--force`) re-serves the
stored record without re-walking, so neither appends anything.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success (or `partial` with `--allow-partial`) |
| `1` | Partial walk (without `--allow-partial`) |
| `2` | Failed walk |
| `3` | Cancelled |
| `10` | Walk record integrity check failed |
| `20` | Configuration error / walk ID not found (`walk-diff`) |

## Relation to other stages

- **Requires:** module proxy access; implicitly performs `kanonarion fetch`
  for every node in the closure.
- **Consumed by:** `kanonarion extract`, `vuln-scan`, and `sbom`, which all
  operate over a stored walk.

## See also

- [`kanonarion fetch`](fetch.md) - fetch and verify a single module
- [`kanonarion extract`](extract.md) - run extraction stages over a walk
- [`kanonarion sbom`](sbom.md) - generate an SBOM for a walk
