# `kanonarion extract` - Multi-stage Extraction

Runs a multi-stage extraction pipeline over all modules in a completed walk. This
orchestrates the individual extraction stages (licence, interface, callgraph,
example) in a deterministic order.

## Prerequisites

A walk must have been completed successfully:

```bash
kanonarion walk --policy policy.yaml
```

## Commands

### `kanonarion extract <walk-id>`

Executes the requested extraction stages for all modules in the specified walk.

```bash
kanonarion extract 01J1Z... --stages license,interface
kanonarion extract 01J1Z... --force
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--stages` | `license,interface,example` | Comma-separated list of stages to run |
| `--force` | false | Re-extract even if cached records exist for current pipeline versions |
| `--workers` | `runtime.NumCPU()` | Number of modules to process concurrently |
| `--json` | false | Output extraction run record as JSON |
| `--go-binary` | | Path to `go` binary (used for callgraph stage) |

> **Note:** `callgraph` is not run by default. It loads each module's full
> transitive dependency closure into SSA and will exhaust available RAM on
> large walks. Pass it explicitly when needed:
> ```bash
> kanonarion extract 01J1Z... --stages callgraph --workers 2
> ```

### `kanonarion extract list`

Lists historical extraction runs.

```bash
kanonarion extract list
kanonarion extract list --limit 50
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for storage |
| `--limit` | `20` | Maximum number of runs to list (0 = unlimited) |

### `kanonarion extract show <run-id>`

Displays the results of a specific extraction run, including per-module stage outcomes.

```bash
kanonarion extract show 01J1Z...
kanonarion extract show 01J1Z... --json
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for storage |
| `--json` | false | Output as JSON |

## Orchestration Logic

1.  **Walk Loading**: The orchestrator loads the module graph from the specified `walk-id`.
2.  **Parallel Execution**: Modules are processed concurrently using a bounded worker
    pool (`--workers`, default `runtime.NumCPU()`). Stages within each module execute
    sequentially.
3.  **Stage Dispatch**: For each module, requested stages are executed in canonical
    order. The `callgraph` stage is special (see below).
4.  **Result Aggregation**: A single `ExtractionRun` record is persisted, linking
    all module-level results.

## Callgraph Subprocess Isolation

The `callgraph` stage spawns a child process (`kanonarion callgraph <coord>
[--force]`) for each module with a 10-minute per-module timeout. This bounds
the blast radius of OOM conditions: if a module's SSA closure exhausts RAM the
kernel kills only the child process; the parent captures the exit code and
stderr, records `StageFailed` with `error_detail`, and continues to the next
module.

The `--workers` flag controls how many callgraph subprocesses run concurrently.
On memory-constrained hosts, lower this to 1 or 2:

```bash
kanonarion extract 01J1Z... --stages callgraph --workers 1
```

A timed-out subprocess produces a `StageFailed` record with
`error_detail: subprocess timed out after 10m0s`. A module can be retried via
`extract <walk-id> --stages callgraph --force`.

## Caching

If a stage has already been successfully extracted for a module with the current
`pipeline-version`, the orchestrator will skip it unless `--force` is used.
This allows resuming interrupted extraction runs efficiently.

The database schema is versioned via the shared `schema_migrations` table
(migration version 7).

## Fetch pipeline version dependency

Each extraction stage looks up the module's fact record (the stored zip blob
and metadata) using the fetch pipeline version constant from
`internal/fetch/application`. If `extract` is built from a different version of
kanonarion than the one that ran `fetch`, the fact records may not be found and
every stage will be silently skipped - producing `(not run)` in the context
output.

This is not a normal user-facing concern: the binary you run is always a
consistent build. It is relevant when building or testing kanonarion itself
across commits that bump the fetch pipeline version.

## See also

- `inspect` - run walk + extract + vuln-scan + context in one command
- `walk` - prerequisite: produces the walk record that extract operates on
