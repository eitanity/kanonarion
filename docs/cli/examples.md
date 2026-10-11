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

A `local` coordinate is never served from cache at all: the working tree
mutates, so it is re-read and re-extracted on every run. The run appends a
generation only when the extraction says something the ledger does not already
say; a re-extraction that comes back identical appends nothing and says so on
stderr. `--force` records the measurement either way.

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

**Code newer than this kanonarion.** kanonarion parses `_test.go` files with
the `go/parser` compiled into the binary. When the module's `go` directive is
newer than the Go it was built with, a file it cannot parse is **not
analysed** rather than a parse failure, and the examples in it are not in the
record:

```
example.com/mod@v1.0.0: Found — 1 example(s)
  not analysed: 1 file (example_test.go): the kanonarion that ran was built with go1.26.6 and the code requires go1.27.2.
  Use a kanonarion built with go1.27.2 or newer: a newer release, or `go install github.com/eitanity/kanonarion@latest` run with go1.27.2 or newer.
  ExamplePlain (plain:plain_test) → Plain [validated]
```

The record is stored and the command exits `20`. Under `--json` the record
carries `AnalyserLimit` (`Limit.Required`, `Limit.Built`, `Files`); it is absent
when every file was read. Such a record is never served as a cache hit. Nor is a
record with parse failures in a module whose `go` directive is newer than
go1.26.4, the oldest Go a kanonarion writing these records can be built with:
it may hold that build's limit filed as the module's failure, so it is measured
again. The `context` examples section states the limit; `examples-list
<module>` states it on stderr, and `examples-show` names it when the example
asked for is not in the record.

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

Also takes the build-scope flags `--gomod`, `--walk-id`, `--toolchain` and
`--target GOOS/GOARCH` — see [Declaring the build
target](walk.md#declaring-the-build-target---target).

### `examples-list` - list modules with harvested example records

```
kanonarion examples-list
kanonarion examples-list --limit 100
kanonarion examples-list --all-generations --limit 0
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory |
| `--all-generations` | `false` | Also list records extracted at a superseded pipeline version, marking each one |
| `--limit` | `50` | Maximum records to show (0 = unlimited) |
| `--offset` | `0` | Skip this many records before listing |

By default the listing shows only records at the pipeline version this build
serves, one row per coordinate, and says so on its last line.
`--all-generations` includes records from earlier pipeline versions and marks
each one. Every JSON row carries `pipeline_version` and `superseded`, and the
document carries a `generation` object. See [The generation a listing
serves](conventions.md#the-generation-a-listing-serves).

When the limit bites, the listing says so on both output paths and names the
invocation that lifts it, per [Truncated listings](conventions.md#truncated-listings).

Under `--json` the command answers with one object carrying `records` and the
paging state, not a bare array, and writes nothing to stderr — see [Listing
documents](conventions.md#listing-documents).

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

## Assurance log

Each persisted generation appends one `examples_extracted` event to the
append-only audit log (`{store-root}/audit.jsonl`): module, version, pipeline
version, overall status, example count, parse-failure count, the record's content
hash, the identity of the artefact the extraction read and the content hash of
the fetch record that supplied it. A failed extraction carries its recorded
reason as `failure_detail`. A cache hit re-serves the stored record without
re-extracting, so it appends nothing; `--force` re-extracts and appends. A re-extraction that appends no generation appends no event either: the log
records generations, not runs.

## A stored record this build cannot verify

A record written by a build with a different canonical shape may not be
reproducible by this binary, though its bytes still hash to the seal it carries.
Such a generation is **set aside**: left out of the answer and named by its
`content_hash`. Read it with the build that wrote it, or upgrade. The statement
goes to stderr:

```
set aside example record example.com/mod@v1.0.0 (pipeline 0.3.0) content_hash sha256:6863…: written in a canonical shape this build cannot reproduce; its bytes hash to their own seal, so nothing was altered — read it with the build that wrote it, or upgrade
```

Under `--json`, `examples` and `examples-list` carry it in the document as
`set_aside` (`kind: "example record"`), and `context` in its `examples` section. `examples-show`,
`examples-find` and `examples-list <module>` print a bare object or array, so
they state it on stderr. For a module holding one generation, `examples-list`
and `examples-find` answer from the stored columns and index rows without
reading the record.

When **every** generation of a module was set aside, `examples-show` and
`examples-list <module>` exit `4` and name the generations; `examples` extracts
it again; `examples-list` and `examples-find` leave the module out and name it.

A record whose stored bytes do **not** hash to its seal has been altered, and
every command that meets one refuses at exit `10`, as before.

## Limitations

- No fetched code is executed. Extraction is purely lexical/syntactic.
- The `OrphanSymbol` flag (whether the associated symbol exists in the module's
  exported interface) is not yet populated - it requires M2.2 (interface
  extraction) to be integrated at the M2.5 orchestration stage.
- Files that fail to parse produce a `ParseFailure` entry in the record rather
  than halting extraction. A file this kanonarion is too old to parse is listed
  under `AnalyserLimit` instead.
- `examples-list` without a module reads stored columns, so its rows do not
  carry the limit; `examples <module>@<version>` does.
