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

The snapshot is content-addressed. Its `content_hash` is computed over the blob
when it is fetched, stored beside it, and verified before any scan consumes it —
so the pinning is a checkable claim rather than a version string the blob itself
asserts, and two stores holding the same `version` can be shown to hold the same
advisories. A blob that no longer matches its stored hash is refused as an
integrity failure rather than reported as absent, because absence would trigger
a silent re-fetch that overwrites the evidence.

Snapshots stored before the hash existed carry an empty one, and are deliberately
**left that way**. Hashing a blob the store already holds would attest "these are
the bytes we hold now", not "these are the bytes we fetched" — a seal
indistinguishable from an honest one, reporting an integrity guarantee that was
never established. Such a snapshot therefore reads as *unverifiable*, which is
what it honestly is; it is still returned and still serves a scan. They age out
as fresh snapshots are fetched.

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
| `--no-vendor` | `false` | Analyse the fetched artefacts even when the project is vendored. By default a project carrying `vendor/modules.txt` is analysed from `vendor/`, the source it actually compiles |
| `--operator` | `$USER` | Operator name recorded in the scan run |
| `--no-progress` | `false` | Suppress stderr progress output (the throttled heartbeat and any per-module progress lines); results and warnings are unaffected |
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
Scan completed: Complete, Affected (2)  Run ID: 01KQDBVW092ER1HNXZ60X27CME
```

The completion line reports two independent axes, because a run answers two
different questions: **coverage** — was every module in the build list analysed?
(`Complete`, or `Partial coverage (N of T unanalysed)` / `Failed coverage (…)`) —
and **findings** — did the analysis find vulnerabilities? (`Affected (N)` or
`Clean`). They are independent: a run can be `Partial coverage (…), Clean` or
`Complete, Affected (7)`, and a run that both left modules unanalysed and found
vulnerabilities names both, so neither fact hides the other:

```
Scan completed: Partial coverage (112 of 285 unanalysed), Affected (7)  Run ID: …
```

The stored run also carries a single collapsed `overall_status`
(`AllClean` / `Affected` / `Partial` / `ScanFailed`) for consumers that display
only a summary word; because one word cannot carry both axes, no consumer should
derive a findings fact from it — read `findings_status` instead.

#### The same two axes on a per-module record

Each `VulnerabilityRecord` carries the same split, for the same reason. Its
`overall_status` is one word over five values that answer two different
questions:

| `overall_status` | `coverage_status` | `findings_status` |
|---|---|---|
| `Clean` | `Analysed` | `Clean` |
| `Affected` | `Analysed` | `Affected` |
| `Withdrawn` | `Analysed` | `Withdrawn` |
| `Unscannable` | `Unscannable` | `Clean` |
| `ScanFailed` | `Failed` | `Clean` |

Read the two axes, not the collapsed word. `findings_status: Clean` on a record
whose `coverage_status` is not `Analysed` means "no finding is being reported",
not "there is nothing here" — only `Analysed` + `Clean` is an all-clear. The
diagnostic detail for a coverage failure is unchanged and sits beside the axes:
`unscan_reason` / `unscannable_reason` for `Unscannable`, `error_detail` for
`Failed`.

The axes can also state a pair the collapsed word has no value for: an advisory
matched, but coverage failed, so whether it applies was never established
(`coverage_status: Failed` with `findings_status: Affected`). On a single status
that became `Clean`, which reads as an all-clear. `overall_status` still
collapses it to the coverage word — coverage outranks findings in the summary,
as it does for a whole run — while the findings axis keeps the finding.

This is what lets `vuln-by-id` rank honestly when one coordinate has several
records. A record that reports the finding wins first; among those that report
none, one that was analysed beats one that could not be, however recent the
latter is. Ranking on the collapsed word put "we could not look" and "we looked
and it was clean" in one bucket, where the newer scan won — answering a security
question with a scan that never completed.

Records written before the split carry the axes back-filled by a store
migration, and readers recover them from `overall_status` when absent; the
projection is exact in both directions, so no record loses information.

#### Withdrawn advisories

`Withdrawn` is the third value on the findings axis, and it is not a flavour of
`Clean`. `Clean` says no advisory ever applied; `Withdrawn` says one did and was
retracted upstream, and the retraction date travels on the finding itself as
`withdrawn_at` (the OSV top-level `withdrawn` timestamp).

The rule for a finding set:

- no advisory matched — `Clean`.
- at least one matched advisory is live — `Affected`. One live advisory decides it
  however many retracted ones sit beside it; those stay on the record with their
  own dates.
- every matched advisory is retracted — `Withdrawn`.

A finding whose advisory enrichment failed carries no date and is therefore treated
as live. That is the conservative direction on purpose: a lookup that could not read
the advisory has not established a retraction.

A withdrawn module is reported, never omitted. It is listed apart from the affected
set, so a reader scanning for what to act on sees the affected modules alone, while a
reader asking why a module stopped being listed finds it named with its date rather
than having to notice an absence:

```
Findings (4 affected):
  ...
Withdrawn advisories (1, not counted as findings):
  go.etcd.io/bbolt@v1.4.3
    GO-2026-4923: retracted upstream 2026-04-08T13:33:56Z — WITHDRAWN: out-of-range-index in go.etcd.io/bbolt
```

Note that upstream signals a retraction *twice*: in the top-level `withdrawn`
timestamp, and by prefixing the advisory summary with `WITHDRAWN: `. Only the
timestamp is a fact a consumer can route on; the prefix is prose that kanonarion
passes through. It carries no fix or reachability line, because neither applies to an
advisory that no longer stands — and reachability is not the lever here: a retracted
advisory is excluded on the strength of its retraction, not on nothing calling it.
`reachability` answers such a query with its own `withdrawn` verdict rather than
computing a call graph for it.

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
| `WITHDRAWN:` | The advisory was retracted upstream on the date given, and is **not a finding against this module**. Printed ahead of the range and the fix, because it changes what the rest of the entry means |
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

$ kanonarion vuln-show go.etcd.io/bbolt@v1.4.3
go.etcd.io/bbolt@v1.4.3 — Withdrawn
  Walk:            01KYKDXSM74WQ9FBSN7WX0S97P
  First validated: 2026-07-28T06:06:20Z
  Last validated:  2026-07-28T06:06:20Z
  Snapshot:        vuln.go.dev@2026-07-27T16:28:49Z
  GO-2026-4923 (CVE-2026-33817, GHSA-6jwv-w5xf-7j27) [not reachable]: WITHDRAWN: out-of-range-index in go.etcd.io/bbolt
      WITHDRAWN: advisory retracted upstream 2026-04-08T13:33:56Z — not a finding against this module
      fix:      no fix available

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
| `no-go-mod` | Fetched module zip does not contain a `go.mod` file and none could be synthesised — a property of the published artefact |
| `project-no-go-mod` | The project directory supplied for a project-rooted scan contains no `go.mod`, so there is no main module to root the analysis at — an operator-side input fault, not a property of any artefact |
| `project-dir-unavailable` | The project directory supplied for a project-rooted scan could not be stat'ed (missing or unreadable) — an operator-side input fault; the scan never got far enough to check for a `go.mod` |
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

### Which bytes were analysed

A module version has more than one copy on disk: the zip kanonarion fetched and
holds in its blob store, and — for a vendored project — the tree under `vendor/`
that the project actually compiles. They can differ, and detecting exactly that
divergence is what the tool is for, so every vulnerability record names the
surface its verdict was reached from:

| `analysis_surface` | Meaning |
|------|---------|
| `vendored` | The build was analysed from the project's `vendor/` tree under `-mod=vendor`. The bytes measured are the bytes the project compiles |
| `fetched` | The build was resolved from artefacts kanonarion fetched — the blob-store-populated module cache, or the host cache under `--from-modcache` |

A vendored project is detected automatically: `vendor/modules.txt` alongside the
target `go.mod` is the signal, and no flag is needed to opt in. The whole build
is then analysed in one pass from `vendor/`, which means no dependency is
resolved on its own — so a dependency shipping no `go.mod` (every dependency
published before Go modules) needs no synthesised one, and MVS is not re-run, so
no version can be out of the toolchain. Both of those coverage gaps are
artefacts of isolated resolution and cannot arise on this path.

`--no-vendor` forces the fetched surface for comparison. It is a real override
rather than an absence of preference: the Go toolchain defaults to `-mod=vendor`
whenever `vendor/modules.txt` is present, so the fetch path has to be requested
explicitly, and the run then records `fetched`. Running both surfaces over one
project is how a divergence between the vendored tree and the published
artefacts becomes visible.

A module reached through a `replace` directive is vendored under its **original**
module path, with the replacement named only on the `modules.txt` comment line
(`# original v1.2.1 => replacement v1.2.4`), while the walk's resolved build list
keys on the replacement coordinate. The coordinate is resolved through that
mapping before its presence in the tree is judged, so a replaced dependency is
analysed like any other.

A module in the walk's build list that `vendor/` holds no files for is recorded
`Unscannable` with reason `absent-from-vendor`, never quietly fetched and
scanned in its place. Substituting a fetched artefact for an absent vendored one
would report findings about bytes the project does not build, under a verdict a
reader would take for the build's — which is the divergence choosing the
vendored surface exists to close. The reason's prose distinguishes the two ways
a module can be absent: listed in `modules.txt` with no files under `vendor/`
(an incomplete vendor tree, the same inconsistency `kanonarion vendor` reports),
or not listed at all (`go mod vendor` pruned it as contributing no imported
package).

Records written before this field existed read as `fetched`: nothing consumed a
vendored tree then, so that is what those bytes mean.

`kanonarion vuln-scan <walk-id>` reaches the vendored surface too. A project walk
records the directory it was taken from, and a scan by walk id - which is given
no directory of its own - reads it back, so the same walk does not answer one way
under `--gomod` and another way under its id. A directory the caller supplies
always wins over the recorded one.

The recorded directory is provenance, never an oracle. If it no longer exists, or
no longer holds `vendor/modules.txt`, the scan does not fail: it proceeds on the
fetched surface, every record says `fetched`, and the run log names the directory
and the reason. A moved or deleted checkout must not make a stored walk
unscannable. `--no-vendor` is honoured before the directory is reached for at
all, since it is only ever adopted to reach the vendored surface.

---

### How an `Unscannable` module is displayed

Every reason code has an explicit display treatment; none falls through to a
bare `Unscannable`. The per-module progress line carries a label naming the
cause, and the end-of-run summary prints one section per reason with its count
and its coordinates, so a reason's population is readable without scrolling the
progress stream. `vuln-scan-show` prints the same categories as one line each.

Two families of label appear, and the difference is what the run actually
learned about the module:

- **`Metadata-only (…)`** - the isolated scan could not analyse the source, but
  the module's advisory set was still matched by coordinate. The verdict is
  real; only reachability is absent.
- **`Not scanned (…)`** - no advisory match was performed at all. A local
  filesystem replace has no fetched source, and a project-rooted scan that could
  not start never reached any module. The two project-directory reasons are a
  *single* fault stamped onto every coordinate in the walk, so their headings say
  so rather than reading as N independent module problems.

Only `version-not-in-toolchain` carries a next-step direction (`kanonarion
reachability --local`), because it is the only reason where the module is
analysable and an operator action changes the outcome. A toolchain or host
limitation gets no direction: none would help. This is why sections are printed
per reason rather than merged.

A reason with no entry in the display table is a test failure
(`TestUnscanDisplays_CoversEveryReason`), not a silent bare status; the runtime
fallback still names the unmapped reason rather than hiding it.

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
| `--walk-id` | *(none)* | Restrict results to the modules scanned under this walk |
| `--store-root` | `~/.kanonarion` | Path to fact store root |
| `--json` | `false` | Emit records as JSON |

Without `--walk-id` the answer spans the whole store: every module version,
every pipeline version and every database snapshot generation ever scanned.
That includes a module version a later build patched out, which will still be
listed as `Affected`. Pass `--walk-id` when the question is "which of the
modules in *this* build is hit by this advisory"; text output then prints a
`notice:` line naming the walk it filtered against, so a shorter list is never
mistaken for an unrestricted one.

A `--walk-id` with no stored vulnerability scan run is an error, not an empty
result — an all-clear for a walk that was never scanned would be a claim the
store cannot support. The walk constraint resolves through scan-run membership,
not the `walk_id` provenance column on the record, so a scan two walks share is
reported for both.

**One row per module version.** A module accumulates a scan record for every
(pipeline version, database snapshot) it has been scanned under, and those
records disagree. `vuln-by-id` reports one row per module version, choosing the
record that reports the advisory as affecting the module; only among records
that agree does the most recent scan win. A later all-clear does not retire an
earlier finding: `Clean` is the right label for a module where the advisory was
never found, not a state a finding may decay into without a stated reason. Each
row carries the snapshot and scan time it came from, so a stale answer is
visible as one. Use `vuln-show --history` to see every generation.

**Example:**

```
$ kanonarion vuln-by-id GO-2020-0001
github.com/gin-gonic/gin@v1.6.2       Affected     vuln-db=2026-07-24T18:35:55Z   scanned=2026-07-26T06:37:10Z
github.com/gin-gonic/gin@v1.7.0       Affected     vuln-db=2026-07-23T18:46:07Z   scanned=2026-07-24T11:07:36Z

$ kanonarion vuln-by-id CVE-2020-28483
github.com/gin-gonic/gin@v1.6.2       Affected     vuln-db=2026-07-24T18:35:55Z   scanned=2026-07-26T06:37:10Z

$ kanonarion vuln-by-id GO-2020-0001 --walk-id 01KQDBVW092ER1HNXZ60X27CMD
notice: results restricted to the modules scanned under walk "01KQDBVW092ER1HNXZ60X27CMD"
github.com/gin-gonic/gin@v1.7.0       Affected     vuln-db=2026-07-23T18:46:07Z   scanned=2026-07-24T11:07:36Z
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
