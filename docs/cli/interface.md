# `kanonarion interface` - Public interface extraction

## Synopsis

```
kanonarion interface <module>@<version> [flags]
kanonarion interface-show <module>@<version> [flags]
kanonarion interface-list [flags]
kanonarion symbol-find <name> [flags]
```

## Description

The `interface` family of commands extracts and queries the public API surface
of Go modules. For each module, it produces an `InterfaceRecord` containing
every exported type, function, constant, variable, and method along with
signatures, doc comments, and source positions.

Extraction uses `go/parser` and `go/doc` (AST-only, no full type-checking).
No code from the target module is executed.

The module must have been fetched first (`kanonarion fetch`).

## Commands

### `interface`

Extract and print a summary of a module's public API.

```
kanonarion interface <module>@<version> [flags]
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
$ kanonarion interface github.com/spf13/cobra@v1.8.1
github.com/spf13/cobra@v1.8.1: Extracted - 1 package(s)
  github.com/spf13/cobra                          23T 12F 0C 0V
```

The per-package line shows counts of types (T), functions (F), constants (C),
and variables (V).

```
$ kanonarion interface github.com/spf13/cobra@v1.8.1 --json
{
  "SchemaVersion": "1",
  "Coordinate": { ... },
  ...
}
```

### `interface-show`

Show the full interface record for a module, optionally filtered.

```
kanonarion interface-show <module>@<version> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--pipeline-version` | _(current)_ | Pipeline version to query |
| `--package` | _(all)_ | Filter to a specific import path |
| `--symbol` | _(all)_ | Filter to a specific symbol name (case-insensitive) |
| `--json` | `false` | Emit record as JSON |

**Example:**

```
$ kanonarion interface-show github.com/spf13/cobra@v1.8.1 --package github.com/spf13/cobra

package cobra // github.com/spf13/cobra
  type Command (struct)
    func (c *Command) AddCommand(cmds ...*Command)
    func (c *Command) Execute() error
    ...
  func New() *Command
  ...
```

### `interface-list`

List all modules with extracted interface records, ordered by extraction time.

```
kanonarion interface-list [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--limit` | `50` | Maximum records to show (`0` = unlimited) |

**Example:**

```
$ kanonarion interface-list
github.com/spf13/cobra@v1.8.1               Extracted    1 package(s)
github.com/spf13/pflag@v1.0.5               Extracted    1 package(s)
```

### `symbol-find`

Search all extracted interface records for a symbol by name.

```
kanonarion symbol-find <name> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--pipeline-version` | _(current)_ | Pipeline version to query |

**Example:**

```
$ kanonarion symbol-find Marshal
github.com/spf13/cobra@v1.8.1          func       Marshal
encoding/json@v1.0.0                   func       Marshal
```

## Storage

Interface records are stored in `<store-root>/mirror.db` (SQLite) under two
tables:

- `interface_records` - one serialised blob per `(module, version, pipeline_version)`.
- `interface_symbols` - a denormalised index of every exported symbol, enabling
  fast `symbol-find` queries without deserialising the full record blob.

The database schema is versioned via the shared `schema_migrations` table
(migration version 4).

## Relation to other stages

- **Requires:** `kanonarion fetch` - the module zip must exist in the blob store.
- **Consumed by:** M2.3 (call graph extraction) uses the symbol index to anchor
  call sites; M2.4 (example harvesting) may cross-reference `OrphanSymbol`
  against the interface record.

## See also

- [`kanonarion fetch`](reference.md) - fetch a module zip
- [`kanonarion examples`](examples.md) - harvest example functions
