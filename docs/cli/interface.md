# `kanonarion interface` - Public interface extraction

## Synopsis

```
kanonarion interface <module>@<version> [flags]
kanonarion interface-show <module>@<version> [flags]
kanonarion interface-list [flags]
kanonarion symbol-find <name> [flags]
```

## Description

The `interface` family extracts and queries the public API surface of Go
modules. Each module yields an `InterfaceRecord` of every exported type,
function, constant, variable and method, with signatures, doc comments and
source positions.

Extraction uses `go/parser` and `go/doc` (AST-only, no full type-checking).
No code from the target module is executed.

The module must have been fetched first (`kanonarion fetch`).

## Build frame

A record holds the public API of **one buildable configuration** — its build
frame: `goos/goarch` plus cgo state, printed on every answer. `go/build`
evaluates the constraints (`//go:build` lines and `_goos_goarch.go` filename
suffixes); only the files that configuration contains are read. The frame is the
extracting host's.

It matters for any module with per-platform variants. `golang.org/x/sys`,
`modernc.org/libc` and `github.com/mattn/go-isatty` declare one exported symbol
once per platform; a record at `linux/amd64` reports the linux declaration only.

A package whose files are all for other platforms is kept, empty, and marked
`out_of_frame` (text: `not in this build frame`) — absent from the module and
not built here are different facts.

Records written before frames read as `build frame: unrecorded`. Two records
naming different frames, or one naming a frame and one not, are reported as a
`build_frame` conflict rather than composed; re-extract to replace them.

The `toolchain:` line under it names the Go toolchain whose release tags
(`go1.1 … go1.N`) selected the files. A `//go:build go1.27` file enters or leaves
the recorded API with the toolchain, and the frame does not say which tags were
in force, so the two lines are read together. Records written before the
toolchain was recorded read `toolchain: not recorded`. Two records naming
different toolchains are reported as a `toolchain` conflict **when their APIs also
differ** — the API difference is the disagreement and the toolchain is what
explains it; two toolchains that produced the identical API produced the same
answer and compose. A record naming no toolchain never conflicts with one that
does. Under `--json` the field is `toolchain`, emitted on every record, empty when
not recorded.

`interface-diff --toolchain` restricts the consumer call graph `--used-by`
resolves, on the same terms as the other query commands: see
[callgraph.md](callgraph.md).

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
| `--force` | `false` | Re-extract even if a cached record exists |
| `--json` | `false` | Emit the full record as JSON to stdout |
| `--log-level` | `warn` | Log level: `debug`, `info`, `warn`, `error` |

**Example:**

```
$ kanonarion interface github.com/spf13/cobra@v1.8.1
github.com/spf13/cobra@v1.8.1: Extracted - 1 package(s), build frame linux/amd64 (cgo on)
  github.com/spf13/cobra                          23T 12F 0C 0V
```

The per-package line counts types (T), functions (F), constants (C) and
variables (V).

```
$ kanonarion interface github.com/spf13/cobra@v1.8.1 --json
{
  "schema_version": "...",
  "coordinate": { "path": "github.com/spf13/cobra", "version": "v1.8.1" },
  "overall_status": "Extracted",
  "packages": [ ... ],
  "pipeline_version": "...",
  "content_hash": "sha256:...",
  "extracted_at": "...",
  "build_frame": { "goos": "linux", "goarch": "amd64", "cgo_enabled": true },
  "artefact_identity": "zip:h1:...",
  "source_content_hash": "sha256:..."
}
```

`build_frame` names the configuration measured. `artefact_identity` names the
bytes read and `source_content_hash` the fetch record that supplied them; both
are absent together on a record that names no artefact, which reads as "not
recorded", never as "derived from nothing".

### `interface-show`

Show the full interface record for a module, optionally filtered.

```
kanonarion interface-show <module>@<version> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--package` | _(all)_ | Filter to a specific import path |
| `--symbol` | _(all)_ | Filter to a specific symbol name (case-insensitive) |
| `--json` | `false` | Emit record as JSON |

**Example:**

```
$ kanonarion interface-show github.com/spf13/cobra@v1.8.1 --package github.com/spf13/cobra
build frame: linux/amd64 (cgo on)
toolchain:   go1.26.6

package cobra // github.com/spf13/cobra
  type Command (struct)
    embeds *ParentCommand
    field Use string
    field Args PositionalArgs
    func (c *Command) AddCommand(cmds ...*Command)
    func (c *Command) Execute() error
    promoted func (p *ParentCommand) Name() string  // via *ParentCommand
    ...
  func New() *Command
  const MaxDepth uint32
  var Default (no declared type)
  ...
```

A type prints everything the record holds about it:

- `field` - an exported struct field, with its type and its struct tag.
- `embeds` - an embedded type, struct or interface.
- an unprefixed `func` line - a method **declared on this type**.
- `promoted` - a method or field **callable on this type** only because of an
  embedding, with the chain it arrives through. Declared and promoted are never
  merged. Go's own rules apply - a name the type redeclares shadows the promoted
  one, and a name two embeddings offer at the same depth promotes neither.
- `[promotions from X not shown]` - the type embeds `X` and this record describes
  no such type. Common for a type embedded from the standard library or a
  dependency; an interface record covers one module.
- `(no declared type)` on a `const` or `var` - the source declared no type for
  it. It is a statement about the declaration, not a gap in the reading.

`--package` and `--symbol` narrow what is printed, not what a printed type
offers: promotion is resolved against the whole record.

`symbol-find` and `symbol-context` index types, funcs, methods, consts and vars.
Struct fields are in the record and in `interface-show`, but not searchable.

### A record this build does not serve

A record is served only at the pipeline version this build produces. After a
bump the store's earlier records answer nothing, which reads at a query as an
absent record. The two are told apart wherever a record can go missing:

```
$ kanonarion interface-show github.com/golang-jwt/jwt/v4@v4.5.1
error: the interface record for github.com/golang-jwt/jwt/v4@v4.5.1 was produced by
superseded extraction logic: this build serves pipeline 0.6.0 and the store holds this
coordinate at pipeline 0.3.0. A superseded record is not served, so this answer is empty
for want of a measurement of this module, not because the coordinate is wrong.
Re-extract it:
  kanonarion interface github.com/golang-jwt/jwt/v4@v4.5.1
```

A coordinate the store has never held keeps the other statement, which points at
`interface-list`. `interface-show`, `interface-list <module>`,
`interface --history`, `interface-diff`, `symbol-find`, `symbol-context` and the
`context` interface section all draw the same distinction. Exit code is `4` in
either case: no record was served.

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
| `--offset` | `0` | Skip this many records before listing |

When the limit bites, the listing says so and names the invocation that lifts
it, per [Truncated listings](conventions.md#truncated-listings).

Under `--json` the command answers with one object carrying `records` and the
paging state, not a bare array, and writes nothing to stderr — see [Listing
documents](conventions.md#listing-documents).

**Example:**

```
$ kanonarion interface-list
github.com/spf13/cobra@v1.8.1               Extracted    1 package(s)
github.com/spf13/pflag@v1.0.5               Extracted    1 package(s)  [superseded pipeline 0.3.0]
1 of 2 listed record(s) were produced by superseded extraction logic; this build serves
pipeline 0.6.0 and answers no query from them. Re-extract one:
  kanonarion interface <module>@<version>
```

The listing shows every stored record whatever produced it: a marked row says
the record is there and that no query will be answered from it. `--json` carries
the same as `pipeline_version` and `superseded` on every row — `superseded:
false` is what says a record IS servable.

### `symbol-find`

Search all extracted interface records for a symbol by name.

```
kanonarion symbol-find <name> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |

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
- `interface_symbols` - a symbol index, so `symbol-find` need not deserialise
  the record blob.

## Assurance log

Each persisted generation appends one `interface_extracted` event to the
append-only audit log (`{store-root}/audit.jsonl`): module, version, pipeline
version, overall status, package count, build frame, the record's content hash,
the identity of the artefact read and the content hash of the fetch record that
supplied it. A failed or partial extraction carries its reason as
`failure_detail`. A cache hit appends nothing; `--force` re-extracts and appends.

## Relation to other stages

- **Requires:** `kanonarion fetch` - the module zip must exist in the blob store.

## See also

- [`kanonarion fetch`](reference.md) - fetch a module zip
- [`kanonarion examples`](examples.md) - harvest example functions
