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
  each dependency in isolation. In-build modules read `Clean`/`Affected`; only a
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
| `--fresh` | `false` | Fetch a fresh vulnerability database snapshot from the network |
| `--reachability` | `false` | Enable call-graph reachability analysis during vuln-scan |
| `--skip-vcs-verify` | `false` | Skip git cross-verification; sumdb verification still runs |
| `--goproxy` | `$GOPROXY` | Override the Go module proxy |
| `--go-binary` | | Path to `go` binary if not in `$PATH` |
| `--json` | `false` | Emit final context as JSON |
| `--full` | `false` | Include full doc comments and complete example bodies in context |
| `--size-only` | `false` | Print estimated token count and byte size, then exit |
| `--gomod` | _(none; `./go.mod` when no positional module)_ | Run the pipeline over a project-rooted walk and print a summary |
| `--tool` | `false` | Scope the `go.mod` run to the tooling supply chain. Mutually exclusive with `--project` |
| `--project` | `false` | Scope the `go.mod` run to the complete set: code **and** tooling. Mutually exclusive with `--tool` |
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
  Vulnerabilities: Clean [walk: AllClean]

Context size: ~90 tokens  (use --full for complete docs, --json for machine-readable)
```

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

**Example output:**

```
Status:   AllClean
Modules:  21 (0 failed)
Affected: 0
Snapshot: 2026-05-07T19:21:40Z
Walk ID:  01KQDBVW092ER1HNXZ60X27CMD

To get module context: kanonarion context --gomod ./go.mod
```

**Example JSON output:**

```json
{
  "module_count": 21,
  "overall_status": "AllClean",
  "affected_count": 0,
  "snapshot_version": "2026-05-07T19:21:40Z",
  "walk_ids": ["01KQDBVW092ER1HNXZ60X27CMD"]
}
```

## Workflow

`inspect` is equivalent to running these commands in sequence:

```bash
kanonarion walk github.com/spf13/cobra@v1.8.1
WALK_ID=$(kanonarion walk-list --json | jq -r '.[0].id')
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

## See also

- `extract` - run extraction stages independently
- `vuln-scan` - run vulnerability scanning independently
- `context` - query and display stored context without re-running the pipeline
- `walk` - walk the dependency graph independently
- `sbom` - generate a Software Bill of Materials for the project walk
