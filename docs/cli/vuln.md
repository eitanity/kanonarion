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

The snapshot is also counted. When a scan extracts the pinned database it counts
the advisories the extracted tree holds, and a database holding none fails the
scan naming the snapshot and the count. `govulncheck` reports
`No vulnerabilities found.` and exits 0 against an empty database, so scanning
against one would seal a `Clean` verdict for every module while consulting
nothing — a confident negative derived from no analysis, indistinguishable from
a measured clean. This is a precondition failure, not a per-module outcome: the
operator asked for a measurement the supplied database cannot produce, and
recording 128 `Unscannable` modules would bury the one fact that matters.

A populated database records its count onto the snapshot every record in the run
names, shown as the `Advisories` line of `vuln` and `vuln-scan-show`. A run
normally extracts the database once and shares it; when it cannot, each module
scan extracts one of its own and records the count it measured there, so those
records name the count too. A scan handed an already-extracted database, or
answered by the live service, records no count — that reading was taken
elsewhere or not at all. That is
what lets a reader tell a clean scan against six thousand advisories from a clean
scan against three. Records written before the count existed report it as *not
recorded* rather than as zero — a measured zero cannot exist, because such a scan
is refused. Note the limit: the count detects an **empty** database, not a
truncated one. A database that lost most of itself still parses and still counts,
and nothing readable from it says how many entries it ought to have had, so the
count is carried to the reader rather than judged.

The module must have been fetched first (`kanonarion walk` or `kanonarion fetch`).

### Coverage decides the exit code

`vuln-scan` exits on what it *established*, not on what it found. A run whose
coverage is `Complete` exits 0 whether or not it found advisories: it did the
work it was asked to do, and whether findings should fail a build is a policy
question this command does not answer. A run that could not analyse part of the
walk exits `1` (partial coverage), and one that analysed nothing exits `2`.

That distinction matters most for the walk's own target. When a coordinate-keyed
walk's target-rooted analysis cannot load the module's packages, the run falls
back to scanning each module in isolation — a weaker question, since an isolated
scan describes the module built alone rather than the build that consumes it.
The target's refusal is recorded in the run's own frame under the
`target-load-failed` reason, carrying the toolchain's own load error, and the
run counts *that* rather than a verdict derived in another frame. A record from
the other frame is not destroyed and still answers its own question; the run
simply declines to present it as coverage of the question that was asked, and
names the frame it declined in its log.

Without this, a walk whose target never loaded reported `Complete, Clean` at
exit 0 — an un-run scan indistinguishable from a passing one on the line an
operator reads.

Note that partial coverage on a **project-scoped** scan (`--gomod`, `--tool`,
`--project`) means something has genuinely gone unanalysed: the project path is
rooted at the resolved graph, so modules are not re-resolved in isolation and
`version not in project build` cannot arise there. Seeing that reason means the
scan was not project-rooted — for example a walk-id scan whose recorded project
directory no longer exists, which degrades to per-module isolation by design and
names the missing directory in its log.

### Prerequisites

`vuln-scan` invokes `govulncheck` as a subprocess. It must be present in `$PATH`:

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
```

If the binary is not found, `vuln-scan` returns a descriptive error with the
install command rather than a generic failure.

### Air-gapped scanning

Under `GOPROXY=off` - read as the go command reads it, so `go env -w
GOPROXY=off` counts - the advisory snapshot is **not downloaded**. What that
means in practice:

- A store that already holds a snapshot **scans normally**. Snapshot resolution
  prefers the stored generation, so nothing changes: the run is judged against
  the snapshot the store carries, and the scan-run record names it as always.
  Both routes into a record read that stored snapshot — the `govulncheck`
  analysis and the advisory match by coordinate — so neither needs the network.
- `--fresh` refuses. Refreshing means reading the published generation from
  `vuln.go.dev`, which is the network.
- A store with **no** snapshot refuses, naming the remedy: drop `--fresh`, pin
  one with `--snapshot-source`/`--snapshot-version`, or carry in a store that
  holds one. `vuln-snapshot-list` shows what the store has.

The scan itself is already offline - `govulncheck` is run with `GOPROXY=off`
against the verified module cache, which is unchanged. See
[`fetch`: what else `GOPROXY=off` withdraws](fetch.md#what-else-goproxyoff-withdraws).

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
      fix refs: https://github.com/gin-gonic/gin/pull/2237, https://github.com/gin-gonic/gin/commit/a71af9c144f9579f6dbe945341c1df37aaf09c0d
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

**The toolchain axis**

Beside the result, on **stderr**, every scan states what the advisory database
says about the Go toolchain the walk was built by:

```
toolchain:
  go1.26.5: none of the 30 toolchain advisories in vuln.go.dev@2026-07-27T20:14:16Z covers it
```

```
toolchain:
  go1.26.2 is covered by 3 advisories in vuln.go.dev@2026-07-27T20:14:16Z: GO-2026-4978 (fixed in 1.26.3), GO-2026-4979 (fixed in 1.26.3), GO-2026-4984 (fixed in 1.26.3)
  this is the build toolchain, not a dependency of the artefact: it is reported as its own axis and is counted in no module roll-up
```

The database keys the toolchain (`cmd/go`, the compiler, the linker) separately
from `stdlib`, and the two sets are disjoint; this line is the only place a
toolchain advisory appears. The fix named is the one on **this toolchain's own release branch** — an
advisory backported to two release lines has two fixes, and only one of them is
a move forward.

The judgment is derived at report time from the stored snapshot and the walk's
recorded build toolchain (`go env GOVERSION`): nothing is fetched, nothing is
recorded, and it is derived identically on a reused run and a fresh one.
`--stdlib-from-gomod` pins the stdlib node to the `go.mod` directive but does not
change this line, which always reports the toolchain that ran.

When no judgment can be made the line says so rather than being omitted — a
missing line reads as a clear:

```
toolchain:
  go1.26.5 was not judged against the advisory database's toolchain key: the snapshot's module index carries no toolchain key
```

The other reasons are `the walk recorded no build toolchain version`, `the
recorded toolchain version is not comparable to the database's version ranges`
(a release-candidate or development toolchain), and `no advisory database
snapshot is stored`.

The axis never changes the exit code, never appears under `--json`, and is
counted in no roll-up. The SBOM is untouched by it.

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

**Reuse of an existing run**

When a scan run of the same walk against the same advisory snapshot already
exists, its result is served and `govulncheck` does not run:

```
vulnerability scan: reused run vscan-01KZ0DJEV5XKAV1PSN1JM47D37-1785646889 of 2026-08-02T05:01:35Z against snapshot vuln.go.dev@2026-07-27T20:14:16Z; nothing was re-scanned, and its 4 reachability verdicts came from the source that run read, which this run did not re-read (--force to re-measure)
```

The line names the run whose verdicts you are reading and when it was made. The
findings, roll-ups, exit code and `--json` document are the ones **that run**
produced, rebuilt from the records it wrote, and `audit` states the same line.

Which advisories apply is fixed by the resolved module versions, so reuse is
sound there. Reachability is computed from source, which is not a condition
below, so the line states what those verdicts rest on and does not claim the
source is unchanged — nothing re-read it. Absent when none were answered. Under
`--json` the same fact is `reachability_basis`: the verdict count, and
`source_read_by_this_run`.

A stored run is served only when the walk, the advisory snapshot (source,
version and seal) and the scan pipeline version all match, **and** the stored
run's coverage is complete — a partial or failed run is never served. The
snapshot's retrieval time is not compared: two downloads of one generation with
one seal are one advisory database. `--force` re-measures. `--fresh` refreshes the advisory database and re-measures
only when the refresh changes an advisory listed for a module in this walk.

For a walk of a project, one further condition applies: the project directory
must still require the module versions the walk resolved. A stored run of a
project walk is an analysis of that directory, so once the directory has moved it
is not served, and the command re-derives — reaching the metadata-only
degradation described under "no longer builds the walk" below.  The
comparison is one `go.mod` read, and an agreeing directory still reuses.

Two `--force` runs of one walk against one advisory snapshot write two records
per module and both say the same thing. The lists inside a record — the findings,
and a finding's affected symbols, aliases, references and reachability routes —
are written in one fixed order, so the only fields that move between the two are
`scanned_at` and the `content_hash` that covers it. The hops WITHIN one reachability route
are never reordered — a route is a call stack, printed entry point first.

**Refreshing the advisory database (`--fresh`)**

Two cheap checks stand between the flag and the multi-megabyte database body:
the generation `vuln.go.dev` publishes (standalone `index/db.json`, one small
request), and — when that has moved on — the standalone `index/modules.json`
(~60 KB compressed), compared against the stored snapshot's own copy and
restricted to the modules this walk holds, `stdlib` among them. It states what it
found on stderr before the scan decision:

```
advisory database: checked vuln.go.dev and found it unchanged at 2026-07-27T20:14:16Z; nothing was downloaded and the stored snapshot was kept
advisory database: vuln.go.dev advanced 2026-07-27T20:14:16Z -> 2026-08-01T09:00:00Z; the advisories listed for all 322 modules in this walk are identical between the two, so the run judged against 2026-07-27T20:14:16Z remains current for this walk; nothing was downloaded
advisory database: vuln.go.dev advanced 2026-07-27T20:14:16Z -> 2026-08-01T09:00:00Z and the advisories changed for a module in this walk; downloaded the new database
advisory database: vuln.go.dev advanced 2026-07-27T20:14:16Z -> 2026-08-01T09:00:00Z, but the advisories could not be compared (<error>); downloaded the new database
advisory database: vuln.go.dev published generation unreadable (<error>); downloaded the database, now at 2026-07-27T20:14:16Z
```

The last two are the fail-closed cases: when a cheap check cannot be made the
body is downloaded anyway, so a refresh never turns into a cache hit on a network
error. A reused run always names the snapshot it was actually judged against; the
claim that it remains current is a separate statement carrying the number of
modules the comparison covered.

**Assurance log**

Each scan run appends events to the append-only audit log
(`{store-root}/audit.jsonl`): one `vuln_scan_completed` for the run (walk id,
scan-run id, snapshot source/version, overall status, and the
`affected`/`clean`/`unscannable`/`failed` module-count breakdown), plus one
`vuln_finding_observed` per finding (module, version, vulnerability id, overall
status). This anchors *when* a module was first observed affected in the
append-only assurance log, independent of the mutable vuln DB's `first_scanned_at`.
`vuln-scan-rescan` emits the same events for its fresh run.

A run that **downloads and stores an advisory database snapshot** appends one
`advisory_snapshot_recorded` event for it: the database it came from, that
database's own generation of itself, when this store retrieved it, the content
hash of the persisted bytes, and the route that acquired it — `walk_scan`,
`module_scan` (a single-module scan resolving its own snapshot),
`advisory_refresh` (`--fresh`) or `walk_rescan`. "What did we know and when"
turns on when an advisory set arrived, and the arrival is the fact this states.

It witnesses the persist and its route only. The advisories the snapshot holds,
how many there are and any module's standing against them are not in the
payload: those are the snapshot's and the scan records' claims, and the content
hash is what reaches them. A run that reuses a stored snapshot appends nothing —
reuse is not an acquisition, and dating an earlier arrival to this run would
report something that never happened. That includes a `--fresh` refresh that
found the stored generation still current: nothing was transferred, so nothing
is appended.

```
kanonarion vuln-scan [flags]
kanonarion vuln-scan [walk-id] [flags]
kanonarion vuln-scan --module <module>@<version> [flags]
kanonarion vuln-scan --gomod ./go.mod [flags]
kanonarion vuln-scan --tool [--gomod ./go.mod] [flags]
kanonarion vuln-scan --project [--gomod ./go.mod] [flags]
```

`--gomod`, `--tool`, and `--project` select the project's dependency **scope** and
scan the latest succeeded project walk for that scope (one record produced by
`walk --gomod [--tool|--project]`). The scope is consistent with every other
go.mod command - default `code`, `--tool` the tooling supply chain, `--project`
the complete set; see [`walk` Scopes](walk.md#scopes-code-tool-complete). With no
walk-id and no `--module`, `--gomod` defaults to `./go.mod`. A scope scan is
mutually exclusive with a positional walk-id and with `--module`.

**The walk must match this platform.** Selection filters on the current
environment's `go env GOOS`/`GOARCH`, because build constraints select which
files compile and reachability follows those files. A store holding walks for
several platforms therefore never answers a scan from another platform's walk;
when this platform has no matching walk the scan refuses and names the remedy:

```
no succeeded code project walk for example.com/myapp on darwin/arm64 — run: kanonarion walk --gomod ./go.mod
```

To scan another platform's walk deliberately, name it by ID:
`kanonarion vuln-scan <walk-id>`. The progress line states the frame the
selected walk was resolved in.

**The walk must still describe this manifest.** The lookup above finds a walk by
the project's module path, which does not change when the `go.mod` does, so
before anything is served the scan re-resolves the scope and compares the module
set against the selected walk's own nodes. Two outcomes, both stated on stderr:

```
manifest re-resolved: 126 module versions, identical to walk 01KZ3VA296P8KTP265M6CDBCHB
```

The build is the one that walk recorded, so the run proceeds exactly as before —
including serving a stored scan run for it.

```
the manifest no longer resolves to walk 01KZ3VA296P8KTP265M6CDBCHB: 1 changed (github.com/golang-jwt/jwt/v4 v4.5.1 -> v4.5.2); it now resolves 126 module versions, that walk recorded 126
re-walking ./go.mod before scanning: no stored run describes this build
```

Drift is never served. The scan walks the manifest as it stands, then scans that
walk. An edit that is later reverted converges back onto the original walk — the
walk machinery reuses an identical analysis by identity — and with it onto that
walk's stored run, so a revert is cheap rather than a re-measurement.
`--force` on a drifted manifest re-walks too, rather than re-measuring a walk
that describes a build you no longer have.

The re-resolution is a `go list` over the scope, so it costs about a second on a
320-module project against the fraction of one a stored answer takes to serve.
The read-only surfaces do not pay it: `vuln-show`/`vuln-list --gomod`, the
build-scoped call-graph and interface queries, and `context --gomod` state in
their notice that the manifest was not re-resolved for the read.

`--module` is **not** filtered this way. A walk rooted at a published
coordinate records no target platform at all — only project walks (`--gomod`)
do — so there is nothing to filter on, and the scan states the frame as
`not-platform-scoped` instead:

```
scanning walk 01KQDBVW092ER1HNXZ60X27CMD rooted at github.com/spf13/cobra@v1.8.1 (frame not-platform-scoped)
```

**The project-scoped views are project-rooted.** A `--gomod`/`--tool`/`--project`
scan (and the project walk behind `audit` and `inspect --gomod`) derives its
verdict from **one scan of the project's live working tree** - `govulncheck` over
the project's real import graph, with each finding attributed to the module that
owns the vulnerable symbol and every other in-build module analysed-and-clean.
No dependency is scanned in isolation on this path, so the per-module-isolation
and out-of-toolchain behaviour documented below applies **only to a scan with no
project build in hand**, never to a project scan. Because the working tree
mutates between runs, a project scan is recomputed fresh each time and is not
served from the coordinate cache.

**A positional walk id is project-rooted when the walk is.** A project walk
records the directory it was taken from, so `kanonarion vuln-scan <walk-id>`
reads that back and scans exactly as `--gomod` does over the same walk — one
pass over the project's build, the standard library analysed from it, no
dependency re-resolved alone. One walk gets one coverage answer however the
command was spelled, and either command's run is reusable by the other. A walk
rooted at a published coordinate (`--module`, or its id) has no project build to
be rooted at and keeps the per-module route.

If the recorded directory has moved or is no longer readable, the run does not
fail and does not scan some other tree: it degrades to the per-module route and
says so, naming the directory and the stat error. Such a run reports the
coverage that route leaves — the standard library metadata-only, plus any module
whose isolated build re-resolves a version the project never selected — so its
coverage is `Partial` and it exits non-zero. Re-run it from the checkout
(`--gomod`) or re-walk to record the current directory.

**If the directory is still there but no longer builds the walk, the run records
no reachability.** Before attributing an analysis of the directory to the walk's
coordinates — and before serving a stored run of it — the scan compares the
directory's `go.mod` requirements against the versions the walk resolved. If any module both name is required at a different
version, that directory is a different build and its analysis is not evidence
about this walk, so the run does not analyse it. It still matches every
coordinate against the advisory database — you keep the "this walk is pinned to a
vulnerable version" answer, at the versions the walk pinned — and records **no
reachability verdict at all**: those findings carry no reachable/not-reachable
answer, the module's coverage is `Unscannable` with reason
`project-build-diverged`, and the reason names the directory and every module
version the two disagree on (`path walked -> required`). The run's coverage is
therefore `Partial` and it exits non-zero.

A module the directory requires and the walk does not carry is not a divergence
(that is a narrower walk of the same tree). A module the walk carries that the
`go.mod` does not require is not compared; in a pruned module (`go >= 1.17`)
those are the modules contributing no imported package.

The remedy is one command: `kanonarion walk --gomod <project-dir>/go.mod` records
the current resolution, and scanning that walk gives a reachability answer again.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Path to fact store root (or `KANONARION_STORE` env var) |
| `--module` | _(none)_ | Look up the latest walk for `<module@version>` and scan it (not platform-filtered; such walks record no platform) |
| `--gomod` | `./go.mod` | Scan the latest project walk for this `go.mod`'s scope (default scope `code`) on this platform |
| `--tool` | `false` | Scan the tooling supply chain (the latest tool-scoped project walk). Mutually exclusive with `--project` |
| `--project` | `false` | Scan the complete set (the latest complete-scope project walk). Mutually exclusive with `--tool` |
| `--force` | `false` | Force re-scan even if results exist; also re-runs on-demand callgraph extraction |
| `--fresh` | `false` | Refresh the vulnerability advisory database: read the published generation and module index, and download a new snapshot only if an advisory listed for a module in this walk has changed |
| `--reachability` | `false` | Enable call-graph reachability analysis; spawns `kanonarion callgraph` on demand for modules with findings but no cached callgraph |
| `--callgraph-workers` | `1` | Maximum number of concurrent on-demand callgraph subprocesses (SSA builds are memory-heavy; keep low) |
| `--go-binary` | _(from `PATH`)_ | Path to the `go` binary if not on `PATH` (used by on-demand callgraph extraction) |
| `--binary-pre-pass` | `false` | Fast binary-mode pre-pass; source mode only for affected modules. Applies to a walk-id scan; refused by name with `--module` and with a `--gomod`/`--tool`/`--project` scope scan, neither of which carries it into the scan |
| `--no-vendor` | `false` | Analyse the fetched artefacts even when the project is vendored. By default a project carrying `vendor/modules.txt` is analysed from `vendor/`, the source it actually compiles. Refused by name with `--module`, which scans a walk rooted at a published coordinate and has no project tree to vendor |
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
| `--offset` | `0` | Skip this many results before listing |

When the limit bites, the listing says so on both output paths and names the
invocation that lifts it, per [Truncated listings](conventions.md#truncated-listings).

A zero result distinguishes "that walk has no scan run" from "nothing has been
scanned", per [Zero-result listings](conventions.md#zero-result-listings).

**Examples:**

```
$ kanonarion vuln-scan-list
01KQDBVW092ER1HNXZ60X27CME  walk=01KQDBVW092ER1HNXZ60X27CMD  status=Affected      2024-01-15T10:30:00Z
01KQDBVW092ER1HNXZ60X27CMF  walk=01KQDBVW092ER1HNXZ60X27CMA  status=Clean         2024-01-14T09:00:00Z

$ kanonarion vuln-scan-list 01KQDBVW092ER1HNXZ60X27CMD
01KQDBVW092ER1HNXZ60X27CME  walk=01KQDBVW092ER1HNXZ60X27CMD  status=Affected      2024-01-15T10:30:00Z
```

**Runs whose inputs no longer resolve.** A scan run names the walk it analysed,
and the two are separate rows: a walk can be removed while the run and its
per-module findings stay. Such a run is still listed - it is the only record
those scans happened - but the walk reference is stated as unresolvable rather
than printed as though it resolves:

```
$ kanonarion vuln-scan-list --limit 0
vscan-01KYBTWG8TW0KY1ME26KXZTH6X-1784956207  walk=01KYBTWG8TW0KY1ME26KXZTH6X  status=Affected      2026-07-25T05:12:12Z  inputs unresolvable: walk absent from this store
```

The findings stand; what cannot be recovered is *what was scanned* - which
modules, at which versions, from which project root. Under `--json` the entry
gains an `inputs_unresolvable` field naming the missing walk; the field is absent
on a run whose walk resolves, so an existing consumer sees no change. The same
statement appears on `vuln-scan-show` (on the `Walk ID:` line),
`vuln-scan-history` (once, above the table, and also for a walk with no runs
left) and `vuln-scan-diff` (on the `Walk:` line).

The check is a live lookup against the walks table on every read, so it
classifies any run stranded in future as well as the ones already in the store,
and it is one indexed read per listing.

A stranded run is never served by scan reuse: `vuln-scan` reuses a stored run
only when the walk it analysed is still readable, so a re-scan is performed
instead.

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
Advisories:  6027 in the snapshot scanned against
Modules:     3
build:
  linux/amd64 under go1.26.6
Reachability of 61 finding(s):
  reachable        28
  not reachable     0 — a search ran at a fidelity that can support a negative and found no route
  undecided        33 — a recorded negative no search stands behind; none of these is a clean negative
    inferred       31 — no search ran; the negative reads a source-fidelity analysis's silence
    unsearchable    2 — the advisory names no symbol for this module path, so no search was ever possible
```

#### The build the run's verdicts are about

`build:` names the platform and Go toolchain the walk this run scanned was
resolved under — the toolchain that pins the `stdlib` node the run reported on.
A walk that recorded none says so and never reports the reader's own. Where the
project the walk was taken from is still present and `go env GOVERSION` there no
longer resolves the recorded toolchain, a second line names both versions.
`--json` carries the same fact as a `build` object of `goos`, `goarch` and
`go_version`.

#### The reachability split

`Reachability of N finding(s)` is the run's findings in the three buckets a
release decision turns on. It covers the findings in the affected modules;
withdrawn advisories are excluded wherever they sit, matching the
"not counted as findings" heading below.

| Bucket | Meaning |
|---|---|
| `reachable` | A route exists. The route itself is in `--json` and in `vuln-show`. |
| `not reachable` | A negative on the `confirmed` rung, and nothing else. This is the only clean negative. |
| `undecided` | Every remaining negative, broken down by the rung it earned. |

The undecided breakdown lists each rung the run holds, with what that rung means
— see [soundness](reachability.md). `disputed` always gets its own line: it is a
*contradicted* negative, where a search found the path the record denies, and it
is never tallied beside `inferred`.

The split is not derivable from `is_reachable` alone. A negative may be recorded
with no search behind it, and counting negatives would report those as clean.
A run with no findings prints no block at all. A complete scan whose findings are
all undecided is not a pass: coverage and reachability are separate axes.

Deriving the split costs the text path nothing — every field it reads is already
on the findings — and it does not trigger the route-root classification the text
path deliberately skips. Per-finding routes and roots stay in `--json` and in
`vuln-show`.

When the walk this run analysed is no longer in the store, the reference says so
on the line it is rendered on, and `--json` gains an `inputs_unresolvable` field:

```
Walk ID:     01KQDBVW092ER1HNXZ60X27CMD (inputs unresolvable: walk absent from this store)
```

#### A run this build cannot read in full

A scan run stores the identities of the records it was built from, so a run
recorded under an older scan pipeline names records this build does not serve.
Those modules are listed under their own heading, with what the store still
holds behind each, and a notice under the report names both generations:

```
Modules:     283
Superseded scan records (279): the store holds these modules at pipeline v19 and this build reads pipeline v24, so none of them is served
  cel.dev/expr@v0.25.1 (1 record(s), 0 finding(s) at pipeline v19)
  ...

notice: 279 of 283 module(s) this run names are recorded at pipeline v19, holding 366
        record(s) and 57 finding(s) this build does not serve: it reads pipeline v24 and
        the store holds them at pipeline v19. A superseded record is not served, so this
        answer is empty for want of a scan at this generation — they have been
        vuln-scanned, and this is a stale cache, not a coverage gap. Re-scanning does
        not repair this run: a run names the records it was built from, so a new scan
        writes new records beside these and leaves this run reading as it does.
        Scan the walk again for a current answer:
          kanonarion vuln-scan 01KZ6TG0NS1B8TYTV5YXCC6T3W --reachability
```

Re-scanning the walk does not change how this run renders. It produces a **new**
run, at the current generation; the old one keeps naming the records it named.

The exit code is `4` whenever any module the run counted produced no record this
build serves — including the plain coverage gap below, whose modules the store
does not hold at the run's generation either:

```
No scan record (1): the run reports a verdict for these modules but no record backs it
```

The report is printed in full before the refusal; the header, the module count,
the `Withdrawn advisories` section and every other section are unaffected.

Every module line is the record the run itself named, looked up by the content
hash the run pinned. A later scan of the same module — under a newer pipeline,
against a newer snapshot, or rooted at another project — is a different record
and is never shown in this run's body, so a run recorded under an older pipeline
reports all of its modules as superseded and exits `4` even where the coordinate
has since been scanned again.

`--json` carries the same facts as fields:

| Field | Meaning |
|---|---|
| `pipeline_version` | the generation the run was recorded under |
| `reads_pipeline_version` | the generation this build serves |
| `superseded` | whether the two differ; emitted on every run, `false` included |
| `superseded_records` | per module: `coordinate`, `pipeline_version`, and the `records` and `findings` the store holds there. Absent when there are none |
| `missing_records` | modules the store holds at no generation at all |

A module is in `superseded_records` or in `missing_records`, never both: the
first is held and declined, the second is not there.

The text form lists finding ids per module and publishes no reachability
verdict. `--json` does: each finding carries `reachable`, and beside it the
derived `soundness` and `soundness_reason` that say how thorough the search
behind a negative was, and `route_root` — null where the finding records no
route — saying where the route begins and how far below an entry point that is.
See
[reachability](reachability.md#a-negative-states-how-sound-the-search-behind-it-was)
for the rungs.

A run id that is not there exits `4` and the message says how many runs were
searched, so a mistyped id over a stocked store cannot be read as an unscanned
one. The corpus is every run in the store: a run id is not keyed on a walk, so
the walk you were looking at is not what excluded it.

```
no scan run matched run id "vscan-NOPE" — the value is compared for exact equality against the run id of
all 15 scan run(s) in the store (e.g. vscan-01KQDBVW092ER1HNXZ60X27CMD-1786116020); to list every scan
run: kanonarion vuln-scan-list --limit 0
```

---

### `vuln-show`

Show the vulnerability record for a specific module.

```
kanonarion vuln-show <module>@<version> [flags]
```

A stored record answers "what did this advisory do in **this** build", so the
answer depends on which build you mean:

- `--walk-id <id>` answers in the frame of that walk's scans, restricted to the
  records that walk covered. A `notice:` line names the walk and its frame.
- `--gomod <path>` does the same for the newest succeeded project walk of that
  `go.mod`. The path is required and may be written either way round
  (`--gomod ./go.mod` or `--gomod=./go.mod`). Mutually exclusive with
  `--walk-id`.
- With neither, the record that answers a **consumer's** question about the
  module is returned: one produced by an analysis rooted at a project that
  consumes it, if the store holds one.

If the store holds the coordinate in more than one consumer's build — two
projects scanned into one store — the unanchored form **refuses** (exit 20),
names every frame it found, and names the flags that select one. It does not
serve the newest: the newest scan of a shared dependency belongs to whichever
project was scanned last.

```
$ kanonarion vuln-show github.com/golang-jwt/jwt/v4@v4.5.1
error: the store holds github.com/golang-jwt/jwt/v4@v4.5.1 in 2 consumer frames, and this question names none:
  target-rooted:github.com/cortezaproject/corteza/server@local
  target-rooted:github.com/tmc/langchaingo@v0.1.14
name the build you mean: kanonarion vuln-show github.com/golang-jwt/jwt/v4@v4.5.1 --walk-id <walk of that build>, or ... --gomod <path/to/go.mod>
```

A pinned walk that covered the module but holds no record in its own frame is
refused too (exit 4), naming the frames its records were measured in. It never
answers from a neighbouring frame, and the walk named in the answer is always
the walk you pinned.

A coordinate the store holds **only at a superseded pipeline version** is
refused with its own message (exit 4), naming each generation held and how many
records and findings sit in it:

```
$ kanonarion vuln-show golang.org/x/crypto@v0.31.0
error: no vulnerability record for golang.org/x/crypto@v0.31.0 that this build serves: it reads pipeline v20 and the store holds this coordinate at pipeline v19 (16 record(s), 252 finding(s)). A superseded record is not served, so this answer is empty for want of a scan at this generation — the module has been vuln-scanned, and this is a stale cache, not a coverage gap. Re-scan it:
  kanonarion vuln-scan --module golang.org/x/crypto@v0.31.0 --reachability
```

This is a different statement from `no vulnerability record for <coord> — run:
kanonarion vuln-scan <walk-id>`, which means the store holds the coordinate at
no pipeline version at all. A pipeline bump darkens every record written before
it until a re-scan, so after one the first message is the ordinary answer and
the second is the exception.

`--history` does not refuse here. It reads across generations by design and
lists the darkened records, marking each `[superseded]` and stating under the
listing how many of the rows a current scan would not produce. The point-in-time
reads and the history listing ask different questions: one is *what holds now*,
which a superseded record may not answer, and the other is *what has ever been
recorded*, which the bump does not change.

That selection is not "newest wins", and the difference is load-bearing. An
isolated scan builds the module as its own main module, so it records call-graph
completeness `BUILT_WITH_BODIES`; an analysis rooted at a consuming project
searched a call graph kanonarion did not build, so it records none. Ranking the
two against each other on completeness let an older isolated *not reachable*
outrank a newer consumer-rooted record carrying the route to the vulnerable
symbol — so `vuln-show` and `reachability` printed opposite headlines from one
store. The frame is picked first; the ladder decides only within it.

The isolated answer is not discarded. When the store holds one, it is printed
below the record, labelled, under `Isolated frame` — the two frames disagreeing
is itself information:

```
  Isolated frame (a different question — the module built alone, not the build that consumes it), scanned 2026-07-31T17:49:28Z:
    GO-2025-3553: not_reachable [confidence: High, soundness: inferred, by: govulncheck]
```

Every negative carries the rung behind it on both surfaces. In text it is
appended to the finding's label — `[not reachable — inferred]`. In `--json` each
finding carries `soundness` and `soundness_reason` beside `reachable`; the same
two keys appear on `--history`, on `vuln-by-id --json` and on
`vuln-scan-show --json`, so an answer can be compared across surfaces. Both are
derived at read time from the analyser the stored answer names and that
analyser's own fidelity — nothing is stored, and no record's content hash
changes.

A routed finding also carries `route_root` in `--json`, beside `soundness`: the
same object, with the same field names, that
[`reachability --json`](reachability.md#root-classification) publishes — `kind`,
`reason`, `node_id`, `remedy`, `closure_rooted` where it applies, and the
`entry_point_ancestry` block that says how far below the nearest entry point the
route begins, how weak the weakest edge on that path is, and whether a hop was a
registration rather than a call. The text form has printed all of it under
`root:` since the classification existed; `--json` states it under one key so a
consumer need not parse prose.

`route_root` is **null**, never absent, on a finding that records no route:
there is no root to classify, and an advisory that names no symbols for the
module path explains that absence already. The key missing entirely is a
different statement — that the producer does not derive the root at all — and it
is what `vuln-scan-diff --json` emits, because a diff delta carries a coordinate
and no analysis frame, and the frame is what decides whether a route is
closure-rooted. The classification is derived at read time from the call-graph
ledger, so it improves as the graph does and no re-scan is owed for it.

`Analysis frame:` on the record itself always names the frame the served answer
was reached in. The same selection backs the `vulnerabilities` section of
`context` and `inspect`, which report it as `frame`.

`Toolchain:` names the Go toolchain that compiled the module for the scan, as
`go env GOVERSION` of the process govulncheck was driven in. Which files build
constraints selected, which stdlib was linked and which symbols the analysis
could reach are all the toolchain's, so a verdict is a verdict about that build.
Records written before it was recorded read `Toolchain: not recorded`. Two
records for one coordinate naming different toolchains are reported as a conflict
**when they reached different verdicts** — the verdict difference is the
disagreement and the toolchain is what explains it; two toolchains that reached
the same status, the same findings and the same reachability produced the same
answer and compose. A record naming no toolchain never conflicts with one that
does. Under `--json` the field is `toolchain`, emitted on every record, empty when
not recorded.

Use `--history` to list every stored scan record across all walks, snapshots
and pipeline generations, ordered newest first. This is the primary way to
determine whether a finding was present in an earlier scan or absent because
the vulnerability database snapshot predated it.

Each row names the generation that wrote it. A row from a pipeline version this
build no longer serves is marked `[superseded]`, and a notice under the listing
counts them: those rows are history, not the answer a scan would give today. In
`--json` the same state is the `superseded` boolean on each record, beside the
`pipeline_version` it was written under. The same field appears on
`vuln-by-id --json`, the other read that spans generations.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Path to fact store root |
| `--walk-id` | _(none)_ | Answer in the frame of this walk's scans |
| `--gomod <path>` | _(none)_ | Answer in the frame of the latest project walk for this go.mod. Takes a path, e.g. `--gomod ./go.mod`. The notice states that the go.mod was not re-resolved for the read, so an edit made since that walk is not reflected |
| `--history` | `false` | List all scan records across walks, snapshots and pipeline generations, marking superseded rows |
| `--json` | `false` | Emit record as JSON |

Each finding answers the two questions a finding exists to answer - *will a
version bump fix it?* and *which symbol is at risk?* - directly in the output:

| Line | Meaning |
|---|---|
| `WITHDRAWN:` | The advisory was retracted upstream on the date given, and is **not a finding against this module**. Printed ahead of the range and the fix, because it changes what the rest of the entry means |
| `affected:` | The version range the advisory applies to (e.g. `>= v1.7.3`) |
| `fix:` | `fixed in <version>` when a patch exists, or **`no fix available`** when none does - the no-fix state is rendered explicitly, never left blank. An advisory backported across several release branches states one fix per branch; the version named is the fix for the branch the module's own version is on, not the newest of them, so a module on a supported older branch is not pointed at a release candidate |
| `symbols:` | The at-risk symbols named by the advisory, surfaced even for metadata-only (Unscannable) modules where reachability could not be computed |
| `fix refs:` | The advisory's own `FIX` links - the commit or CL that remediates the vulnerability. Printed only when the advisory publishes one |

**Advisory references**

A finding carries every reference the advisory publishes, as a `{type, url}`
pair: `ADVISORY`, `WEB`, `FIX`, `REPORT`, `ARTICLE` and any other type the
upstream document uses. The type is kept because it is what separates a `FIX`
commit - remediation you can apply - from a page that merely discusses the
vulnerability.

The text output prints only the `FIX` links, on the `fix refs:` line. `--json`
emits the whole list under `references` on each finding.

An **empty** `references` list means no advisory was read for that finding, not
that the advisory publishes none. Two circumstances produce it:

- the advisory fetch failed and the finding degraded to its bare ID and fixed
  version (the run logs `advisory enrichment failed`);
- the scan stream carried findings for an advisory whose own advisory message
  never arrived.

Records written before references were recorded also carry none; they answer at
an older pipeline version and are replaced by a re-scan.

**Examples:**

```
$ kanonarion vuln-show github.com/gorilla/csrf@v1.7.3
github.com/gorilla/csrf@v1.7.3 - Affected
  Walk:            01KWA68CG1PT0R1PTT1X75HFAW
  First validated: 2026-06-29T17:19:15Z
  Last validated:  2026-06-29T17:19:15Z
  Snapshot:        vuln.go.dev@2026-06-16T23:55:18Z
  Advisories:      6027 in the snapshot scanned against
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
  Advisories:      6027 in the snapshot scanned against
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

  2024-03-01T08:00:00Z  walk=01KQDBVW092ER1HNXZ60X27CMD  snap=20240301000000  frame=target-rooted  pipeline=v23                 Affected  GO-2020-0001  GO-2024-0042
  2024-02-01T08:00:00Z  walk=01KQABC123...               snap=20240201000000  frame=target-rooted  pipeline=v22 [superseded]    Affected  GO-2020-0001
  2024-01-01T08:00:00Z  walk=01KQXYZ789...               snap=20240101000000  frame=target-rooted  pipeline=v22 [superseded]    Clean     no findings

notice: 2 of 3 record(s) were produced by superseded scan logic (this build reads pipeline v23).
        They are the history this coordinate has, and they are not what a current scan would
        answer — the point-in-time reads serve none of them. Re-scan to add a current record:
          kanonarion vuln-scan --module github.com/gin-gonic/gin@v1.6.2 --reachability
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
| `project-build-diverged` | The project directory the walk was taken from is still readable but requires different versions of modules the walk resolved, so no analysis of it was attributed to this walk. Advisories were matched by coordinate against the versions the walk pinned; reachability was not established. `unscannable_reason` names the directory and each disagreement as `path walked -> required` |
| `local-replace` | Node is a local filesystem replacement (a `replace` pointing at a working-tree path), not a fetched version, so there is no fetched source to scan; `unscannable_reason` retains the local path |

On the **coordinate-keyed path** (`--module`, and a positional walk-id whose walk
is not a project walk or whose recorded directory is gone) each module is
scanned in isolation as its own main module. (A project scan -
`--gomod`/`--tool`/`--project`, `audit`, `inspect --gomod`, and a positional
walk-id naming a project walk whose directory is still there - does not: it is
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

Whether that directory holds `vendor/modules.txt` decides which **source** the
run reads, not whether the project's build is the frame. A project walk with no
vendor tree is still scanned rooted at its own build, on the fetched surface,
and every record says `fetched`. `--no-vendor` likewise selects a surface and
not a frame: the vendored closure is never read, the toolchain is forced onto
`-mod=mod`, and the run is still one pass over the project's build.

The recorded directory is provenance, never an oracle. If it no longer exists or
cannot be stat'ed, the scan does not fail and does not substitute another tree:
it falls back to scanning each module in isolation, on the fetched surface, and
the run log names the directory and the stat error. A moved or deleted checkout
must not make a stored walk unscannable - but the fallback measures less, so
such a run reports `Partial` coverage.

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

An analysed record shows the same advisory fields. Where source analysis and
coordinate matching both report one advisory, the finding carries the
`affected_symbols` the analysis saw and its `reachable` answer, plus the
advisory's `affected_range` and `references` — one shape, whichever route
reached it. Records scanned by an earlier build may show `affected_range` empty
on an analysed finding; `fixed_in` on those records still states the remedy, and
a re-scan fills the range.

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

**Every row names the pipeline version that produced it**, marked
`[superseded]` when it is not the version this build serves. Those rows are
served — they are the newest evidence the store holds for those coordinates —
but `vuln-show` and `reachability` will not answer from them, so a row marked
this way is not what a current scan would say. A `notice:` under the listing
counts them. `--json` needs no marking: it emits the record, `pipeline_version`
and all.

**Example:**

```
$ kanonarion vuln-by-id GO-2020-0001
github.com/gin-gonic/gin@v1.6.2       Affected     vuln-db=2026-07-24T18:35:55Z   scanned=2026-07-26T06:37:10Z   pipeline=v20
github.com/gin-gonic/gin@v1.7.0       Affected     vuln-db=2026-07-23T18:46:07Z   scanned=2026-07-24T11:07:36Z   pipeline=v19 [superseded]

notice: 1 of 2 row(s) were produced by superseded scan logic (this build reads pipeline v20).
        They are the newest evidence the store holds for those coordinates, and they are not
        what a current scan would answer. Re-scan a coordinate to replace one.

$ kanonarion vuln-by-id CVE-2020-28483
github.com/gin-gonic/gin@v1.6.2       Affected     vuln-db=2026-07-24T18:35:55Z   scanned=2026-07-26T06:37:10Z

$ kanonarion vuln-by-id GO-2020-0001 --walk-id 01KQDBVW092ER1HNXZ60X27CMD
notice: results restricted to the modules scanned under walk "01KQDBVW092ER1HNXZ60X27CMD"
github.com/gin-gonic/gin@v1.7.0       Affected     vuln-db=2026-07-23T18:46:07Z   scanned=2026-07-24T11:07:36Z
```

The text rows carry a status, not a reachability verdict. `--json` emits the
whole record for each row, so it does carry one — and with it the derived
`soundness` and `soundness_reason` on every finding, which is the only place
this command's answer states how thorough the search behind a negative was. A
routed finding carries `route_root` here too, on the same terms as
[`vuln-show --json`](#vuln-show): each row is classified in its own record's
frame, so two projects' scans of one module are never read against each other's
rooting.

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

This command takes no filter and no `--limit`, so an empty answer has exactly one
cause and says it:

```
$ kanonarion vuln-snapshot-list
the store holds no vulnerability database snapshot at all
  to produce one: kanonarion vuln-scan <walk-id>
```

A snapshot is pinned by the scan that judged a walk against it; there is no
command whose job is to fetch one on its own.

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

A snapshot that is not there exits `4` and the message says how many snapshots
were searched, so an unrecognised version over a stocked store cannot be read as
an empty one:

```
no vulnerability database snapshot matched source and version "vuln.go.dev@20991231000000" — the value is
compared for exact equality against the source and version of all 2 vulnerability database snapshot(s) in
the store (e.g. vuln.go.dev@20240115000000); to list every vulnerability database snapshot: kanonarion
vuln-snapshot-list
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

## Modules resolved under pre-modules semantics

A `+incompatible` coordinate resolves no requirement edges at all, so what this command can show is bounded: reachability under such a coordinate is measured over a call graph built from a module whose own requirements the toolchain never resolved, so a not-reached verdict rests on less than the completeness axis alone states. The answer states that and names the coordinates responsible; see [pre-modules modules](conventions.md#modules-resolved-under-pre-modules-semantics).
