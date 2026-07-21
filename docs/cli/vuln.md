# `kanonarion vuln-scan` - Vulnerability scanning

## Synopsis

```
kanonarion vuln <module>@<version> [flags]
kanonarion vuln-scan [walk-id] [flags]
kanonarion vuln-scan-list [walk-id] [flags]
kanonarion vuln-scan-show <run-id> [flags]
kanonarion vuln-show <module>@<version> [flags]
kanonarion vuln-by-id <finding-id> [flags]
kanonarion vuln-snapshot-list [flags]
kanonarion vuln-snapshot-show <source> <version> [flags]
```

## Description

The `vuln` family of commands scans Go modules for known vulnerabilities using
the Go vulnerability database (`vuln.go.dev`) and queries the results.

Scanning works at the walk level: given a walk ID, every module in the walk is
scanned against a pinned snapshot of the vulnerability database. Results are
stored in the local SQLite store and can be queried offline.

The vulnerability database is fetched once and stored as a `DatabaseSnapshot`
blob. Subsequent scans reuse the cached snapshot, making them fast and
offline-capable. The snapshot is pinned so repeat scans are reproducible.

The module must have been fetched first (`kanonarion walk` or `kanonarion fetch`).

### Prerequisites

`vuln-scan` invokes `govulncheck` as a subprocess. It must be present in `$PATH`:

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
```

If the binary is not found, `vuln-scan` returns a descriptive error with the
install command rather than a generic failure.

## Commands

### `vuln`

Show the vulnerability record for a module. Shorthand for `vuln-show` that
automatically finds the most recent scan result without requiring a walk ID.

```
kanonarion vuln <module>@<version> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Path to fact store root (or `KANONARION_STORE` env var) |
| `--json` | `false` | Emit record as JSON |

**Example:**

```
$ kanonarion vuln github.com/gin-gonic/gin@v1.6.2
github.com/gin-gonic/gin@v1.6.2 - Affected
  Scanned:  2024-01-15T10:30:00Z
  Snapshot: vuln.go.dev@20240115000000
  GO-2020-0001 (CVE-2020-28483): HTTP request smuggling
      affected: < v1.7.7
      fix:      fixed in v1.7.7
```

---

### `vuln-scan`

Scan all modules in a walk for known vulnerabilities. Modules are scanned
concurrently using a bounded worker pool (default: `min(NumCPU, 4)` workers)
to keep memory pressure from simultaneous `govulncheck` subprocesses bounded.

Before the worker pool starts, kanonarion pre-populates a shared `GOMODCACHE`
from the blob store. Because every module in a walk is already stored locally as
a content-addressed blob, govulncheck workers resolve the selected module zips
against local disk rather than downloading them. When the walk's graph contains
a pre-pruning (go < 1.17) dependency, the toolchain must also read the `go.mod`
of the *superseded* intermediate versions minimal version selection compares
(e.g. a `go-logr/stdr@v1.2.2` requirement on `logr@v1.2.2` when the walk selected
a higher `logr@v1.4.3`). kanonarion fetches those intermediate versions and
writes their `go.mod` (only - a superseded version is never compiled, so its zip
is never needed) into the cache alongside the selected build list, so the module
graph rebuilds entirely offline. This extra work is skipped for a fully pruned
graph, which never reads a superseded `go.mod`.

The scan then runs pinned to that cache (`GOPROXY=off`, see the resolution note
below): the analysis is faithful to the project's verified toolchain rather than
reaching to the network for versions the project never builds.

**On-demand callgraph extraction with `--reachability`**

When `--reachability` is enabled, kanonarion checks the callgraph store before
running reachability analysis for each module that has `StatusAffected` findings
with symbol-level detail (`AffectedSymbols` non-empty). If no callgraph record
exists, it automatically spawns `kanonarion callgraph <module@version>` as a
child process (same binary, 10-minute timeout) to populate the store on demand.
This limits expensive SSA work to the modules that actually need it.

- At most `--callgraph-workers` (default `1`) subprocesses run concurrently.
  SSA builds are memory-heavy; keep this value low.
- If the subprocess fails or times out, the finding's `Reachable` is left as
  `null` and a `reachability_note` is set describing the failure. The overall
  verdict (`StatusAffected`) is not changed - the uncertainty is traceable.
- `--force` re-runs callgraph extraction even when a cached record exists.
- Modules with `StatusClean`, `StatusUnscannable`, or findings without
  `AffectedSymbols` never trigger a subprocess.

**Assurance log**

Each scan run appends events to the append-only audit log
(`{store-root}/audit.jsonl`): one `vuln_scan_completed` for the run (walk id,
scan-run id, snapshot source/version, overall status, and the
`affected`/`clean`/`unscannable`/`failed` module-count breakdown), plus one
`vuln_finding_observed` per finding (module, version, vulnerability id, overall
status). This anchors *when* a module was first observed affected in the
append-only assurance log, independent of the mutable vuln DB's `first_scanned_at`.
`vuln-scan-rescan` emits the same events for its fresh run.

```
kanonarion vuln-scan [walk-id] [flags]
kanonarion vuln-scan --module <module>@<version> [flags]
kanonarion vuln-scan --gomod ./go.mod [flags]
kanonarion vuln-scan --tool [--gomod ./go.mod] [flags]
kanonarion vuln-scan --project [--gomod ./go.mod] [flags]
```

`--gomod`, `--tool`, and `--project` select the project's dependency **scope**
and scan the latest succeeded project walk for that scope (one record produced
by `walk --gomod [--tool|--project]`). The scope is consistent with every other
go.mod command - default `code`, `--tool` the tooling supply chain, `--project`
the complete set; see [`walk` Scopes](walk.md#scopes-code-tool-complete). The
matching walk must exist first (run `walk --gomod` with the same scope). A scope
scan is mutually exclusive with a positional walk-id and with `--module`.

**The project-scoped views are project-rooted.** A `--gomod`/`--tool`/`--project`
scan (and the project walk behind `audit` and `inspect --gomod`) derives its
verdict from **one scan of the project's live working tree** - `govulncheck` over
the project's real import graph, with each finding attributed to the module that
owns the vulnerable symbol and every other in-build module analysed-and-clean.
No dependency is scanned in isolation on this path, so the per-module-isolation
and out-of-toolchain behaviour documented below applies **only to the
coordinate-keyed `--module` / positional-walk-id path**, never to a project scan.
Because the working tree mutates between runs, a project scan is recomputed
fresh each time and is not served from the coordinate cache.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Path to fact store root (or `KANONARION_STORE` env var) |
| `--module` | _(none)_ | Look up the latest walk for `<module@version>` and scan it |
| `--gomod` | _(search upward from cwd)_ | Scan the latest project walk for this `go.mod`'s scope (default scope `code`) |
| `--tool` | `false` | Scan the tooling supply chain (the latest tool-scoped project walk). Mutually exclusive with `--project` |
| `--project` | `false` | Scan the complete set (the latest complete-scope project walk). Mutually exclusive with `--tool` |
| `--force` | `false` | Force re-scan even if results exist; also re-runs on-demand callgraph extraction |
| `--fresh` | `false` | Fetch a fresh vulnerability database snapshot from the network |
| `--reachability` | `false` | Enable call-graph reachability analysis; spawns `kanonarion callgraph` on demand for modules with findings but no cached callgraph |
| `--callgraph-workers` | `1` | Maximum number of concurrent on-demand callgraph subprocesses (SSA builds are memory-heavy; keep low) |
| `--go-binary` | _(from `PATH`)_ | Path to the `go` binary if not on `PATH` (used by on-demand callgraph extraction) |
| `--binary-pre-pass` | `false` | Fast binary-mode pre-pass; source mode only for affected modules |
| `--operator` | `$USER` | Operator name recorded in the scan run |
| `--log-level` | `warn` | Log level: `debug`, `info`, `warn`, `error` |

**Examples:**

```
$ kanonarion vuln-scan 01KQDBVW092ER1HNXZ60X27CMD
Scanning walk 01KQDBVW092ER1HNXZ60X27CMD...
  [1/3] github.com/gin-gonic/gin@v1.6.2 - Affected
      GO-2020-0001 (CVE-2020-28483), fixed in v1.7.7: HTTP request smuggling
  [2/3] github.com/spf13/cobra@v1.8.1 - Clean
  [3/3] golang.org/x/net@v0.0.0-20210405180319-a5a99cb37ef4 - Affected
      GO-2022-0969 (CVE-2022-27664): HTTP/2 server DoS
Scan completed with status: Affected
Run ID: 01KQDBVW092ER1HNXZ60X27CME
```

```
$ kanonarion vuln-scan --module github.com/gin-gonic/gin@v1.6.2
```

---

### `vuln-scan-list`

List walk scan runs. When called without arguments, lists all scan runs across all walks. Pass an optional `[walk-id]` to filter to a specific walk.

```
kanonarion vuln-scan-list [walk-id] [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Path to fact store root |
| `--limit` | `20` | Maximum number of results (0 = unlimited) |

**Examples:**

```
$ kanonarion vuln-scan-list
01KQDBVW092ER1HNXZ60X27CME  walk=01KQDBVW092ER1HNXZ60X27CMD  status=Affected      2024-01-15T10:30:00Z
01KQDBVW092ER1HNXZ60X27CMF  walk=01KQDBVW092ER1HNXZ60X27CMA  status=Clean         2024-01-14T09:00:00Z

$ kanonarion vuln-scan-list 01KQDBVW092ER1HNXZ60X27CMD
01KQDBVW092ER1HNXZ60X27CME  walk=01KQDBVW092ER1HNXZ60X27CMD  status=Affected      2024-01-15T10:30:00Z
```

---

### `vuln-scan-show`

Show details of a specific walk scan run.

```
kanonarion vuln-scan-show <run-id> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Path to fact store root |
| `--json` | `false` | Emit record as JSON |

**Example:**

```
$ kanonarion vuln-scan-show 01KQDBVW092ER1HNXZ60X27CME
ID:          01KQDBVW092ER1HNXZ60X27CME
Walk ID:     01KQDBVW092ER1HNXZ60X27CMD
Status:      Affected
Operator:    alice
Started:     2024-01-15T10:29:55Z
Completed:   2024-01-15T10:30:02Z
Snapshot:    vuln.go.dev@20240115000000
Modules:     3
```

---

### `vuln-show`

Show the vulnerability record for a specific module.

```
kanonarion vuln-show <module>@<version> [flags]
```

When `--walk-id` is omitted, the most recent scan record for the module is
returned automatically. Pass `--walk-id` to pin to a specific walk.

Use `--history` to list every stored scan record across all walks and
snapshots, ordered newest first. This is the primary way to determine
whether a finding was present in an earlier scan or absent because the
vulnerability database snapshot predated it.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Path to fact store root |
| `--walk-id` | _(none)_ | Walk ID the scan was performed under (optional) |
| `--history` | `false` | List all scan records across walks and snapshots |
| `--json` | `false` | Emit record as JSON |

Each finding answers the two questions a finding exists to answer - *will a
version bump fix it?* and *which symbol is at risk?* - directly in the output:

| Line | Meaning |
|---|---|
| `affected:` | The version range the advisory applies to (e.g. `>= v1.7.3`) |
| `fix:` | `fixed in <version>` when a patch exists, or **`no fix available`** when none does - the no-fix state is rendered explicitly, never left blank |
| `symbols:` | The at-risk symbols named by the advisory, surfaced even for metadata-only (Unscannable) modules where reachability could not be computed |

**Examples:**

```
$ kanonarion vuln-show github.com/gorilla/csrf@v1.7.3
github.com/gorilla/csrf@v1.7.3 - Affected
  Walk:            01KWA68CG1PT0R1PTT1X75HFAW
  First validated: 2026-06-29T17:19:15Z
  Last validated:  2026-06-29T17:19:15Z
  Snapshot:        vuln.go.dev@2026-06-16T23:55:18Z
  GO-2025-3884 (CVE-2025-47909): Improper validation of TrustedOrigins allows CSRF attacks in github.com/gorilla/csrf
      affected: >= v1.7.3
      fix:      no fix available
      symbols:  TrustedOrigins

$ kanonarion vuln-show github.com/gin-gonic/gin@v1.6.2
github.com/gin-gonic/gin@v1.6.2 - Affected
  Walk:     01KQDBVW092ER1HNXZ60X27CMD
  Scanned:  2024-01-15T10:30:00Z
  Snapshot: vuln.go.dev@20240115000000
  GO-2020-0001 (CVE-2020-28483): HTTP request smuggling
      affected: < v1.7.7
      fix:      fixed in v1.7.7

$ kanonarion vuln-show www.velocidex.com/golang/velociraptor@v0.76.6
www.velocidex.com/golang/velociraptor@v0.76.6 - Unscannable (generated-assets-missing)
  Walk:     01KV3N2T20MWT7MPJPW4YAQM2F
  Scanned:  2026-06-16T08:51:03Z
  Snapshot: vuln.go.dev@2026-06-02T21:39:47Z
  Reason:   source analysis unavailable: missing generated or embedded assets (module requires a code-generation step not present in the module zip); results are metadata-only with no reachability

$ kanonarion vuln-show github.com/gin-gonic/gin@v1.6.2 --history
github.com/gin-gonic/gin@v1.6.2 - 3 scan record(s)

  2024-03-01T08:00:00Z  walk=01KQDBVW092ER1HNXZ60X27CMD  snap=20240301000000  Affected  GO-2020-0001  GO-2024-0042
  2024-02-01T08:00:00Z  walk=01KQABC123...               snap=20240201000000  Affected  GO-2020-0001
  2024-01-01T08:00:00Z  walk=01KQXYZ789...               snap=20240101000000  Clean     no findings
```

The last row above shows the module was clean on 2024-01-01 because
`GO-2020-0001` was not yet in the `20240101000000` snapshot - not because
the module was unaffected.

When `OverallStatus` is `Unscannable`, the JSON record includes an `unscan_reason`
field with a machine-readable cause code alongside the human-readable `unscannable_reason`:

| `unscan_reason` | Cause |
|---|---|
| `generated-assets-missing` | Module zip is missing source files produced by a code-generation step |
| `go-work-monorepo` | Module references sibling modules via `go.work` not present in the zip |
| `workspace-mode` | The Go toolchain entered workspace mode during an isolated scan (a `go.work` shipped in the module zip or inherited from the environment); the scanner sets `GOWORK=off`, so this indicates a misconfigured scan environment rather than a module that fails to build |
| `relative-replace-directive` | Module uses a `replace` directive pointing to a sibling directory |
| `windows-only` | Module only builds on Windows |
| `c-headers-missing` | Module requires C system headers not available on the scanning host |
| `missing-go-sum` | `go.sum` entry absent; module cannot be resolved without network access |
| `version-not-in-toolchain` | Scanned in isolation the module re-selects a dependency version the project's build list never resolved; the scan is pinned to the verified store (`GOPROXY=off`), so that out-of-toolchain version is deliberately absent rather than fetched from the network |
| `incomplete-scan-cache` | An offline resolution failed on a version the walk graph itself records (a node, or a superseded requirement on one of its edges). Unlike `version-not-in-toolchain` this is a fault: the version was one kanonarion undertook to supply to the hermetic cache. `error_detail` names the version |
| `package-declarations-missing` | A package's declarations are absent because every file that would declare them is excluded by build constraints — most often a host Go toolchain newer than the range the module supports. Nothing is missing from the zip, so there is no code-generation step to run |
| `build-incompatible` | Build fails for an unrecognised reason |
| `oom-killed` | `govulncheck` was killed by the OS (likely OOM); retryable on a host with more memory |
| `no-go-mod` | Module zip does not contain a `go.mod` file |
| `local-replace` | Node is a local filesystem replacement (a `replace` pointing at a working-tree path), not a fetched version, so there is no fetched source to scan; `unscannable_reason` retains the local path |

On the **coordinate-keyed path** (`--module` and a positional walk-id) each
module is scanned in isolation as its own main module. (A project scan -
`--gomod`/`--tool`/`--project`, `audit`, `inspect --gomod` - does not: it is
project-rooted, so none of the isolation, out-of-toolchain, or dropped-replace
behaviour in this section applies to it.) Before invoking
`govulncheck`, kanonarion drops any **filesystem (local-path) replace
directives** from the extracted `go.mod` - a published multi-module member such
as `go.opentelemetry.io/otel/trace` ships development-time replaces (for example
`replace go.opentelemetry.io/otel => ../`) that point outside the module zip.
The Go toolchain ignores a dependency's replaces, so dropping them reproduces a
consumer's view and lets the required sibling resolve from the module cache
instead of failing the build. Module-to-module (versioned) replaces are kept -
they name a resolvable coordinate.

Dropping the replace exposes a second problem for such members: their published
`go.sum` has no entry for the sibling, because a local `replace ... => ../`
needs no checksum. Running read-only, the toolchain would then error with
`missing-go-sum` on the now cache-resolved sibling. When a `GOMODCACHE` is
pre-populated, kanonarion therefore runs the toolchain with `-mod=mod` (compute
and write the absent `go.sum` entries into the disposable extract directory from
the cached zips), `GOSUMDB=off` (skip the checksum database, unreachable offline
and redundant once the fetch-verified cache is trusted), and **`GOPROXY=off`**.

Pinning `GOPROXY=off` is a fidelity choice, not just an optimisation. The cache
is the project's verified toolchain: the exact versions its build list resolved.
A network fallback would let a module scanned in isolation re-run minimal version
selection as its own main module and pull in a dependency version the project
never builds - analysing a graph that does not represent the toolchain. The
intermediate `go.mod` files minimal version selection reads for a pre-pruning
dependency are pre-populated into the cache (above), so an *in-toolchain* scan
resolves fully offline. A module whose isolated build requires an
out-of-toolchain version fails here deliberately, surfaced as an honest
`Unscannable` (`version-not-in-toolchain`) rather than papered over with a
network fetch of a version the project never selected.

At the default log level this reads as the expected metadata-only outcome, not
a failure. The govulncheck adapter records its non-zero exit and stderr at
`debug` and hands the error up; severity is then decided once, by reason, in the
layer that classifies it: an out-of-toolchain module logs at `info` (expected -
its isolated build simply needs a version outside the project toolchain), a
genuine build incompatibility that still falls back to metadata logs at `warn`,
and a hard scanner fault logs at `error`. Nothing is dumped as a warning per
out-of-toolchain module. Run with `--log-level debug` to see the raw
`govulncheck` stderr behind an `Unscannable` verdict.

`Unscannable` records with findings indicate that OSV coordinate matching found
advisories even though source-level analysis was not possible. Such findings are
still enriched from the advisory record - `summary`, `affected_range`,
`fixed_in` and `affected_symbols` are all populated - so remediation can be
assessed without leaving the tool. Only `reachable` is absent: reachability
requires the call-graph that source analysis would have produced. An empty
`fixed_in` on an enriched finding is the actionable "no fix exists yet" state,
not missing data.

Coordinate matching on this path evaluates the advisory's **full multi-range
affected set**, not the single collapsed fixed version from the database's
`index/modules.json`. That coarse index lists one (highest) fixed version per
advisory; for an advisory backported across several release branches it names
only the newest branch's fix. Matching against it alone over-reports a version
that was patched on an *older* branch below that highest fix. kanonarion instead
reads each candidate advisory's own `affected[].ranges` `introduced`/`fixed`
event list and flags a coordinate only when its version falls inside a genuine
affected interval. For example the stdlib advisory whose affected set is
`[0, 1.25.12)`, `[1.26.0-0, 1.26.5)`, `[1.27.0-0, 1.27.0-rc.2)` collapses in the
index to `fixed 1.27.0-rc.2`; `go1.26.5` is **not** flagged (the 1.26 branch is
fixed at 1.26.5), matching the full-range verdict `govulncheck` produces on the
project-rooted path. The coarse index is still used as a cheap pre-filter - it
only ever over-includes, never wrongly excludes - and when a candidate
advisory's record cannot be fetched the finding falls back to the conservative
index verdict rather than being dropped.

---

### `vuln-by-id`

Find all modules in the store affected by a specific vulnerability ID (OSV, CVE, or GHSA).

```
kanonarion vuln-by-id <finding-id> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Path to fact store root |
| `--json` | `false` | Emit records as JSON |

**Example:**

```
$ kanonarion vuln-by-id GO-2020-0001
github.com/gin-gonic/gin@v1.6.2                              Affected
github.com/gin-gonic/gin@v1.7.0                              Affected

$ kanonarion vuln-by-id CVE-2020-28483
github.com/gin-gonic/gin@v1.6.2                              Affected
```

---

### `vuln-snapshot-list`

List all stored vulnerability database snapshots.

```
kanonarion vuln-snapshot-list [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Path to fact store root |
| `--json` | `false` | Emit records as JSON |

**Example:**

```
$ kanonarion vuln-snapshot-list
vuln.go.dev                    20240115000000       2024-01-15T00:00:00Z
vuln.go.dev                    20240101000000       2024-01-01T00:00:00Z
```

---

### `vuln-snapshot-show`

Show metadata for a specific vulnerability database snapshot.

```
kanonarion vuln-snapshot-show <source> <version> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Path to fact store root |
| `--json` | `false` | Emit record as JSON |

**Example:**

```
$ kanonarion vuln-snapshot-show vuln.go.dev 20240115000000
Source:       vuln.go.dev
Version:      20240115000000
Retrieved at: 2024-01-15T00:00:00Z
Content hash: sha256:abc123...
```

---

## Workflow

```bash
# 1. Walk the dependency graph
kanonarion walk github.com/gin-gonic/gin@v1.6.2 --store-root ~/.kanonarion

# 2. Scan for vulnerabilities (fetches and pins the database snapshot)
kanonarion vuln-scan --module github.com/gin-gonic/gin@v1.6.2 --store-root ~/.kanonarion

# 3. Inspect the scan run
kanonarion vuln-scan-list --walk-id <walk-id> --store-root ~/.kanonarion
kanonarion vuln-scan-show <run-id> --store-root ~/.kanonarion

# 4. Drill into a specific module (walk-id optional; defaults to most recent scan)
kanonarion vuln-show github.com/gin-gonic/gin@v1.6.2 --store-root ~/.kanonarion

# 4a. Check whether a finding was detected in earlier scans
kanonarion vuln-show github.com/gin-gonic/gin@v1.6.2 --history --store-root ~/.kanonarion

# 5. Cross-reference a CVE across all scanned modules
kanonarion vuln-by-id CVE-2020-28483 --store-root ~/.kanonarion

# 6. Inspect stored database snapshots
kanonarion vuln-snapshot-list --store-root ~/.kanonarion
```

## Design decisions

- All vulnerabilities are reported, including non-reachable findings.
- Reachability is reported with explicit confidence levels.
- The vulnerability database snapshot is pinned so repeat scans are reproducible.
- `govulncheck` runs as a subprocess with `Cmd.Dir` (goroutine-safe working
  directory; binary requirement) rather than as an in-process library.
- The `GOMODCACHE` is pre-populated from the blob store for walk scans - the
  selected module zips plus, for a graph with a pre-pruning (go < 1.17)
  dependency, the `go.mod` of the superseded intermediate versions minimal
  version selection reads. The scan is then pinned to that cache (`GOPROXY=off`),
  so the analysis is faithful to the project's verified toolchain and never
  fetches a version the project's build list did not resolve.
