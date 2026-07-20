# `kanonarion examples` - Example-function harvesting

## Synopsis

```
kanonarion examples <module>@<version> [flags]
kanonarion examples-show <module>@<version> <example-name> [flags]
kanonarion examples-find <symbol> [flags]
kanonarion examples-list [flags]
```

## Prerequisites

The target module must be fetched before examples can be extracted:

```
kanonarion fetch github.com/spf13/cobra@v1.8.1
kanonarion examples github.com/spf13/cobra@v1.8.1
```

## Commands

### `examples` - harvest and list examples for a module

Reads the module's zip from the blob store, parses every `_test.go` file for
`Example*` functions, and persists an `ExampleRecord`. On subsequent calls the
cached record is returned unless `--force` is given.

```
kanonarion examples github.com/spf13/cobra@v1.8.1
kanonarion examples github.com/spf13/cobra@v1.8.1 --json
kanonarion examples github.com/spf13/cobra@v1.8.1 --force
```

**Output (default):**

```
github.com/spf13/cobra@v1.8.1: Found - 42 example(s)
  ExampleCommand_Execute (cobra_test) → Command.Execute [validated]
  ExampleCommand_GenMarkdown (cobra_test) → Command.GenMarkdown
  ...
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--force` | false | Re-extract even if a cached record exists |
| `--json` | false | Emit full `ExampleRecord` as JSON |
| `--log-level` | `warn` | Log level: `debug\|info\|warn\|error` |

### `examples-show` - print a specific example

```
kanonarion examples-show github.com/spf13/cobra@v1.8.1 ExampleCommand_Execute
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory |
| `--json` | false | Emit entry as JSON |

### `examples-find` - find all examples for a symbol

Searches the `example_index` table for every example whose `AssociatedSymbol`
matches the given value, across all stored modules.

```
kanonarion examples-find Client.Do
kanonarion examples-find Marshal
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory |

### `examples-list` - list modules with harvested example records

```
kanonarion examples-list
kanonarion examples-list --limit 100
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory |
| `--limit` | `50` | Maximum records to show (0 = unlimited) |

## What gets extracted

For each `Example*` function found in a `_test.go` file:

- **Associated symbol**: derived from the function name per Go convention
  (`ExampleClient_Do` → `Client.Do`, `ExampleFoo_bar` → `Foo` with sub-example
  `bar`).
- **Body**: the canonical function body (reformatted via `go/format`).
- **Output**: the text captured from `// Output:` or `// Unordered output:`
  comments at the end of the function body.
- **Validates**: `true` when an `Output:` comment is present and `go test`
  would have validated it at publish time - higher-trust examples.
- **Imports**: the import paths actually used in the function body (not the full
  file import list).
- **Doc**: the doc comment on the `Example*` function.

The database schema is versioned via the shared `schema_migrations` table
(migration version 3).

## Limitations

- No fetched code is executed. Extraction is purely lexical/syntactic.
- The `OrphanSymbol` flag (whether the associated symbol exists in the module's
  exported interface) is not yet populated - it requires M2.2 (interface
  extraction) to be integrated at the M2.5 orchestration stage.
- Files that fail to parse produce a `ParseFailure` entry in the record rather
  than halting extraction.
