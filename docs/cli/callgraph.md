# `kanonarion callgraph` - Call graph extraction

## Synopsis

```
kanonarion callgraph <module>@<version> [flags]
kanonarion callgraph-show <module>@<version> [flags]
kanonarion callgraph-list [<module>] [flags]
kanonarion callers <symbolID> [flags]
kanonarion callees <symbolID> [flags]
```

## Description

The `callgraph` family of commands extracts and queries the static call graph
of Go modules. For each module it produces a `CallGraphRecord` containing every
call node (function or method) and every call edge (caller → callee) found by
Class Hierarchy Analysis (CHA).

Extraction uses `golang.org/x/tools/go/callgraph/cha` on an SSA representation
built from `go/packages`. The target module's source is loaded via the Go type
checker; no code from the module is executed.

The module must have been fetched first (`kanonarion fetch`).

## Commands

### `callgraph`

Extract and print a summary of a module's call graph.

```
kanonarion callgraph <module>@<version> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--pipeline-version` | _(compiled-in)_ | Override the pipeline version |
| `--force` | `false` | Re-extract even if a cached record exists |
| `--json` | `false` | Emit the full record as JSON to stdout |
| `--log-level` | `warn` | Log level: `debug`, `info`, `warn`, `error` |

**Example:**

```
$ kanonarion callgraph github.com/spf13/cobra@v1.8.1
github.com/spf13/cobra@v1.8.1  Extracted  nodes=142 edges=387  pipeline=0.1.0
```

```
$ kanonarion callgraph github.com/spf13/cobra@v1.8.1 --json
{
  "SchemaVersion": "1",
  "Coordinate": { "Path": "github.com/spf13/cobra", "Version": "v1.8.1" },
  "Algorithm": "CHA",
  "OverallStatus": "Extracted",
  ...
}
```

### `callgraph-show`

Show the full call graph record for a module, optionally filtered.

```
kanonarion callgraph-show <module>@<version> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--pipeline-version` | _(current)_ | Pipeline version to query |
| `--node` | _(all)_ | Filter to nodes/edges containing this symbol substring |
| `--limit-nodes` | `0` | Maximum nodes to show (`0` = unlimited) |
| `--limit-edges` | `0` | Maximum edges to show (`0` = unlimited) |

**Example:**

```
$ kanonarion callgraph-show github.com/spf13/cobra@v1.8.1 --node Execute
Nodes (2):
  github.com/spf13/cobra.(*Command).Execute  exported  cobra.go:906
  github.com/spf13/cobra.(*Command).ExecuteC exported  cobra.go:940

Edges (5):
  github.com/spf13/cobra.(*Command).Execute  →  github.com/spf13/cobra.(*Command).ExecuteC  direct
  ...
```

### `callgraph-list`

List all modules with extracted call graph records, ordered by extraction time.

```
kanonarion callgraph-list [<module>] [flags]
```

The optional `<module>` argument filters results to a specific module path.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--limit` | `50` | Maximum records to show (`0` = unlimited) |

**Example:**

```
$ kanonarion callgraph-list
github.com/spf13/cobra@v1.8.1     Extracted  nodes=142 edges=387
github.com/spf13/pflag@v1.0.5     Extracted  nodes= 98 edges=201

$ kanonarion callgraph-list github.com/spf13/cobra
github.com/spf13/cobra@v1.8.1     Extracted  nodes=142 edges=387
github.com/spf13/cobra@v1.7.0     Extracted  nodes=138 edges=371
```

### `callers`

Find all recorded call sites where a given symbol is the callee.

```
kanonarion callers <symbolID> [flags]
```

`<symbolID>` is the full node ID in the form `pkg/path.FuncName` or
`pkg/path.(*RecvType).MethodName`, as shown by `callgraph-show`.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--pipeline-version` | _(current)_ | Pipeline version to query |

**Example:**

```
$ kanonarion callers 'github.com/spf13/cobra.(*Command).Execute'
github.com/spf13/cobra@v1.8.1  github.com/spf13/cobra.(*Command).ExecuteC  →  github.com/spf13/cobra.(*Command).Execute  direct
```

### `callees`

Find all recorded call sites where a given symbol is the caller.

```
kanonarion callees <symbolID> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--pipeline-version` | _(current)_ | Pipeline version to query |

**Example:**

```
$ kanonarion callees 'github.com/spf13/cobra.(*Command).Execute'
github.com/spf13/cobra@v1.8.1  github.com/spf13/cobra.(*Command).Execute  →  github.com/spf13/cobra.(*Command).ExecuteC  direct
```

## Symbol IDs

Node IDs follow the SSA function naming convention:

| Kind | Format |
|------|--------|
| Free function | `import/path.FuncName` |
| Method (pointer receiver) | `import/path.(*TypeName).MethodName` |
| Method (value receiver) | `import/path.(TypeName).MethodName` |

## Edge confidence

| Value | Meaning |
|-------|---------|
| `direct` | Static call; callee known at compile time |
| `dynamic_dispatch` | Interface method call; callee determined by CHA (over-approximated) |
| `reflection` | Static callee in the `reflect` package |
| `unknown` | No call site information available (e.g. synthetic init edges) |

## Overall status

| Value | Meaning |
|-------|---------|
| `Extracted` | All packages loaded and graph built successfully |
| `Partial` | Some packages loaded with errors; graph may be incomplete |
| `LoadFailed` | `go/packages` failed; no graph produced |
| `ExtractionFailed` | Infrastructure error (zip extraction, temp dir) |
| `Cancelled` | Context cancelled before or during extraction |

## Storage

Call graph records are stored in `<store-root>/mirror.db` (SQLite) under two
tables:

- `callgraph_records` - one serialised blob per `(module_path, module_version, pipeline_version)`.
- `callgraph_edges` - denormalised edge rows with two covering indices:
  - `callgraph_edges_to_idx ON (to_id, pipeline_version)` - used by `callers`
  - `callgraph_edges_from_idx ON (from_id, pipeline_version)` - used by `callees`

The callgraph schema is tracked in the shared `schema_migrations` table under
module key `callgraph` (current version: 2).

## Relation to other stages

- **Requires:** `kanonarion fetch` - the module zip must exist in the blob store.

## See also

- [`kanonarion fetch`](reference.md) - fetch a module zip
- [`kanonarion interface`](interface.md) - extract the public interface
- [`kanonarion examples`](examples.md) - harvest example functions
