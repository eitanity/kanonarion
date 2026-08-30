# `kanonarion inspect` - Full pipeline for a module

## Synopsis

```
kanonarion inspect <module>@<version> [flags]
kanonarion inspect [--gomod <path>] [flags]
```

With no positional module, `inspect` defaults to `--gomod ./go.mod` and runs the
pipeline over a single project-rooted walk (see
[`inspect --gomod <path>`](#inspect---gomod-path)).

## Description

`inspect` runs the full kanonarion pipeline for a module in a single command:

1. **Walk** - resolve the transitive dependency graph
2. **Extract** - run license, interface, call-graph, and example extraction for every module in the walk
3. **Vuln-scan** - scan all modules against the Go vulnerability database
4. **Context** - aggregate and print all stored records as AI-ready context

This is the primary entry point when you want a complete picture of a module
before using it in a project or passing it to an LLM.

## Prerequisites

The vuln-scan step invokes `govulncheck` as a subprocess. It must be present
in `$PATH`:

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
```

If the binary is missing, the scan fails with a descriptive error naming the
install command, and the summary reports `Partial` with a scan-failure count
instead of a clean verdict.

## Commands

The two modes scan from **different roots**, and their vuln legs differ to match:

- **Single-module** (`inspect <module>@<version>`) roots the walk at that module,
  which becomes the main module and is scanned in isolation (the coordinate-keyed
  path). This is the intended "scan it on its own to see what it looks like" view.
- **Project** (`inspect`, `--gomod`, `--tool`, `--project`) roots the walk at the
  local main module and derives its vuln verdict from a single **project-rooted**
  scan of the live working tree - the project's real build - not from re-scanning
  each dependency in isolation. In-build modules read `Clean`/`Affected`/`Withdrawn`; only a
  genuine fault reads `Unscannable`/`ScanFailed`.

### `inspect <module>@<version>`

Run the full pipeline for a single module and print its context.

```
kanonarion inspect github.com/spf13/cobra@v1.8.1
kanonarion inspect modernc.org/sqlite@latest --reachability
kanonarion inspect github.com/spf13/cobra@v1.8.1 --json
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Path to fact store root (or `KANONARION_STORE` env var) |
| `--force` | `false` | Re-fetch and re-extract even if cached records exist |
| `--fresh` | `false` | Refresh the vulnerability advisory database: read the published generation and module index, and download a new snapshot only if an advisory listed for a module in this walk has changed |
| `--reachability` | `false` | Enable call-graph reachability analysis during vuln-scan. For `--gomod`, reachability roots at the dependency closure, not the project's own code (see the note under [`inspect --gomod`](#inspect---gomod-path)) |
| `--skip-vcs-verify` | `false` | Skip git cross-verification; sumdb verification still runs |
| `--policy` | _(auto-discover `.kanonarion/policy.yaml`)_ | Depth policy file; its fetch stage governs traversal and the `allowed_vcs_hosts` forge allowlist |
| `--goproxy` | `$GOPROXY` | Override the Go module proxy. `off` and `direct` are honoured, not rewritten: resolving `@latest` refuses before any network I/O and exits `20`. See [`fetch`: `GOPROXY=off` and `direct`](fetch.md#goproxyoff-and-direct) |
| `--go-binary` | | Path to `go` binary if not in `$PATH` |
| `--json` | `false` | Emit final context as JSON |
| `--full` | `false` | Include full doc comments and complete example bodies in context. Refused with `--gomod`, which prints a summary rather than context |
| `--size-only` | `false` | Print estimated token count and byte size of the context, then exit. With `--gomod`, prints a total plus a per-module breakdown in place of the summary |
| `--gomod` | _(none; `./go.mod` when no positional module)_ | Run the pipeline over a project-rooted walk and print a summary |
| `--tool` | `false` | Scope the `go.mod` run to the tooling supply chain. Mutually exclusive with `--project` |
| `--project` | `false` | Scope the `go.mod` run to the complete set: code **and** tooling. Mutually exclusive with `--tool` |
| `--stdlib-from-gomod` | `false` | Version the `stdlib` node from the `go.mod` directive, not the live toolchain (project-mode `--gomod` run; refused on a positional module run). See [Standard-library version](walk.md#standard-library-version---stdlib-from-gomod). |
| `--log-level` | `warn` | Log level: `debug`, `info`, `warn`, `error` |

**Example output:**

```
github.com/spf13/cobra@v1.8.1
  Verification:    Verified (git: https://github.com/spf13/cobra)
  Dependencies:    4 direct (succeeded)
  License:         Apache-2.0
  Interface:       2 package(s), 66 symbol(s) (Extracted)
  Call Graph:      1192 nodes, 3463 edges (Extracted)
  Examples:        2 (Found)
  Vulnerabilities: Clean

Context size: ~3562 tokens (14249 bytes) of JSON for this module  (use --full for complete docs, --json for machine-readable)
```

#### The `run` section

`inspect` runs a walk, an extraction and a vulnerability scan before it prints
anything, and states what each did on **stderr**. Under `--json` those facts are
also a section of the document, `run`, beside the per-module content:

```json
{
  "run": {
    "walk_id": "01KQDBVW092ER1HNXZ60X27CMD",
    "walk": "reused",
    "scan_run_id": "vscan-01KQDBVW092ER1HNXZ60X27CMD-1788082354",
    "scan": "reused",
    "snapshot": { "source": "vuln.go.dev", "version": "2026-08-28T14:47:45Z" },
    "toolchain": { "judged": false, "status": "unjudged", "reason": "the walk recorded no build toolchain version", "…": "…" }
  },
  "module": { "…": "…" }
}
```

`walk` and `scan` say what this run did with each stage - `measured by this
run`, `reused`, `not run`, or `attempted and failed` - so a reused answer cannot
be read as a fresh measurement. `toolchain` is the scan's judgment, in the shape
[`vuln-scan --json`](vuln.md) carries, including the case where nothing could be
judged and why: a stage that did not run is a value this section states, never a
key it leaves out.

Everything else in the document is exactly what [`context`](context.md) renders,
key for key and byte for byte. The same section is a field of the `--gomod`
summary.

---

### `inspect --gomod <path>`

Run the full pipeline for the local project using a **single project-rooted
walk**, then print a summary. The project walk resolves Go's pruned module
graph - the same validated build inputs every other go.mod command uses - so
the walk record is directly composable with `sbom`, `vuln-scan-show`, and
`walk-show`.

The scope is consistent with every other go.mod command: the default is the
project's own **code** dependencies (`go list -deps -test ./...`); `--tool`
selects the tooling supply chain; `--project` the complete set (code +
tooling). `--tool` and `--project` are mutually exclusive. See
[`walk` Scopes](walk.md#scopes-code-tool-complete). A bare `kanonarion inspect`
(no positional module) is shorthand for `inspect --gomod ./go.mod`.

The summary states the test axis the scope resolved over on its own line
(`Scope:    code — test-scope dependencies included`), and the `--json` summary
carries it as `dependency_scope`, always present, beside `walk_frame`.
`--exclude-tests` is **refused by name**: `inspect` records a project walk, and a
walk record names its scope but not its test axis. See [Test scope](walk.md#test-scope---exclude-tests).

```
kanonarion inspect
kanonarion inspect --gomod ./go.mod
kanonarion inspect --gomod ./go.mod --json
kanonarion inspect --gomod ./go.mod --force --fresh
kanonarion inspect --gomod ./go.mod --tool
kanonarion inspect --gomod ./go.mod --project
```

The `--gomod` form does not emit per-module context - it emits a single
summary covering the project walk. To get per-module context afterwards, run
`kanonarion context --gomod <path>` (or bare `kanonarion context` for
`./go.mod`): it enumerates the same module set this command populates, so
the pair composes with no `not_fetched`/`not_run` gaps.

The `Walk ID` in the output is the project walk record. It can be passed
directly to `sbom`, `extract`, `vuln-scan`, and `walk-show`.

> **Reachability roots at the dependency closure, not the project's own code.**
> With `--reachability`, the project walk analyses the consumer module in
> consumer-mode, so its call graph is not loaded into the store. A `reachable`
> verdict therefore means "reachable from the closure roots", one hop short of
> "reachable from a project entrypoint" - the final application-to-dependency
> edge is absent. `inspect --gomod --reachability` prints an explicit banner to
> stderr stating this. To root reachability at the application, run
> [`kanonarion local <dir>`](local.md), which ingests the target graph.

**Example output:**

```
Status:   AllClean
Modules:  21 (0 failed)
Affected: 0
Snapshot: 2026-05-07T19:21:40Z
Walk ID:  01KQDBVW092ER1HNXZ60X27CMD
Frame:    linux/amd64

To get module context: kanonarion context --gomod ./go.mod
```

`Frame` is the `GOOS/GOARCH` the answering walk resolved for, or
`not-platform-scoped` for a module-rooted walk. `inspect` answers from the most
recent walk of the target regardless of platform, so this line says which one
answered. JSON carries `walk_frame` and `walk_frame_basis`.

`Status` is the coverage word (`AllClean` / `Affected` / `Partial` /
`ScanFailed`) and `Affected` is the findings count; the two are independent
axes. A run left `Partial` by an unscannable module still reports its real
`Affected` count on its own line rather than collapsing it to zero — the
coverage gap does not hide the findings, and neither hides the other.

A module whose advisories were all retracted upstream is **not** in the `Affected`
count; the scan output above the summary names it under `Withdrawn advisories (N,
not counted as findings)` with its retraction date. See
[`vuln.md`](vuln.md#withdrawn-advisories).

**Example JSON output:**

```json
{
  "module_count": 21,
  "node_fails": 0,
  "extract_fails": 0,
  "extract_failures": [],
  "scan_fails": 0,
  "overall_status": "AllClean",
  "affected_count": 0,
  "snapshot_version": "2026-05-07T19:21:40Z",
  "walk_ids": ["01KQDBVW092ER1HNXZ60X27CMD"],
  "run": {
    "walk_id": "01KQDBVW092ER1HNXZ60X27CMD",
    "walk": "measured by this run",
    "scan_run_id": "vscan-01KQDBVW092ER1HNXZ60X27CMD-1788082354",
    "scan": "measured by this run",
    "snapshot": { "source": "vuln.go.dev", "version": "2026-05-07T19:21:40Z" },
    "toolchain": { "judged": true, "status": "clear", "version": "go1.26.5", "…": "…" }
  }
}
```

`run` is the same section the coordinate form carries - see [The `run`
section](#the-run-section). A scope that resolved no dependencies still carries
it, stating that nothing ran.

## When a stage does not measure a module

`inspect` runs [`extract`](extract.md) over the walk it just made. A stage that
fails leaves that module's licence, public API, call graph or examples
unmeasured, and the summary says so on both paths rather than presenting the
gap as a clean result:

- `extract_fails` is the **count of failed stages** on the run this invocation
  recorded — the same number `extract` prints as `Failed stages (N)`, not a 0/1
  flag. It is emitted at zero like the tallies beside it.
- `extract_failures` names them: one `{module, stage, error}` object per failed
  stage, an empty list when none failed.
- The breakdown is also printed to **stderr** as the extraction step runs, so a
  text reader sees the coordinates without `--json`.
- Any non-zero tally moves `Status` off `AllClean` to `Partial`; the text
  summary adds an `Extract fails: N` line, and the run exits
  [`1`](conventions.md#exit-codes) — the work completed and is
  known-incomplete. The other roll-up words keep exit `0`.

An extraction that could not run at all — rather than one that ran and lost
stages — reports `extract_fails: 1` with an empty `extract_failures` and the
reason on stderr: there is no breakdown to count, and zero is the one answer
that would be wrong.

## Vendored builds

A project carrying `vendor/modules.txt` beside its `go.mod` compiles the bytes
under `vendor/`, which need not be the bytes the proxy would serve for the same
coordinates. This command resolves the manifest, so its answer describes the
modules `go.mod` **resolves**, not what ships. Where the two can differ, the run
says so on its basis channel (stderr, with the other basis lines, on both the
text and `--json` paths):

```
vendored build:
  …/vendor/modules.txt is present beside go.mod, so this project compiles the bytes under vendor/
  this answer describes the modules the manifest resolves, not those bytes; `kanonarion vendor` is what measures the vendored tree
```

It states a fact and changes no verdict: a vendored project answers exactly as
before, with one more line of basis. `kanonarion vendor` is the command that
compares the shipped bytes against the published module zips.

An unvendored project states nothing - its answer was never ambiguous.

`inspect --json` also carries the answer in the document, under `build`
(`vendoring_known`, `vendored`, `vendor_modules_txt`), so a consumer can see
which of two things the rest of the document describes. `build` is absent only
when there was no project directory to look in - an unanswered question, which
must not decode the same as a negative answer.

## Workflow

`inspect` is equivalent to running these commands in sequence:

```bash
kanonarion walk github.com/spf13/cobra@v1.8.1
WALK_ID=$(kanonarion walk-list --json | jq -r '.records[0].id')
kanonarion extract "$WALK_ID"
kanonarion vuln-scan "$WALK_ID"
kanonarion context github.com/spf13/cobra@v1.8.1
```

For the `--gomod` form, the equivalent is:

```bash
kanonarion walk --gomod ./go.mod
WALK_ID=$(kanonarion walk-list --latest-success --json | jq -r '.id')
kanonarion extract "$WALK_ID"
kanonarion vuln-scan "$WALK_ID"
```

Use the individual commands when you need finer control - for example, to run
only specific extraction stages or to re-scan with a different snapshot.

## Caching

Each stage is independently cached by its pipeline version and, for
vuln-scan, the database snapshot version. Running `inspect` a second time on
the same module is fast: only changed or absent records are recomputed. Use
`--force` to bypass the cache for all stages.

## Memory

The vuln-scan stage runs a bounded pool of `govulncheck` processes. A single
source-mode scan of a cloud-SDK-heavy module can hold several GB, so the pool is
sized against the host's available memory as well as its CPU count:

```
workers = max(1, min(NumCPU, 4, floor(available memory / 4 GiB)))
```

Available memory is read once, when the pool is built (on Linux, `MemAvailable`
from `/proc/meminfo`). When the memory term lowers the count, `inspect` logs it
at info with the available bytes, the per-worker budget and the resulting cap —
so a slow scan is explained rather than mysterious. When the reading cannot be
taken at all, which is the normal case off Linux, the pool falls back to
`min(NumCPU, 4)` and says so at debug; a missing reading never fails a scan.

**The budget is per-process.** Two `inspect` runs on one host each measure the
same free memory and each admit a full pool against it, so they share no budget
with each other and can still exhaust the host. When that happens the scanners
are OOM-killed and the affected modules are reported as **unanalysed** — a
coverage gap, correctly, not a clean result. On a host that is tight on memory,
run them one at a time.

## See also

- `extract` - run extraction stages independently
- `vuln-scan` - run vulnerability scanning independently
- `context` - query and display stored context without re-running the pipeline
- `walk` - walk the dependency graph independently
- `sbom` - generate a Software Bill of Materials for the project walk
