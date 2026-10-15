# `kanonarion symbol-context` - Per-module symbol record for AI context

## Synopsis

```
kanonarion symbol-context <name> [--module <module@version>] [--json]
```

`<name>` is a bare name (`NewString`) or a qualified one: the import path
(`github.com/google/uuid.NewString`), the package name a Go caller writes
(`uuid.NewString`, `errors.Wrap` for `github.com/pkg/errors/v2`), the receiver
type alone (`UUID.String`), or package and receiver together
(`uuid.UUID.String`). A qualified name keeps only the declarations it names, and
lists every package a short qualifier answers to. When the qualifier names none
of the packages that export the name, stdout is the usual miss and a `notice:`
line on stderr names one or two of the packages that do.

## Description

`symbol-context` assembles everything the store knows about an exported symbol
into one AI-ready record: its **signature**, its **godoc**, and any harvested
**examples** - grouped per module, since the same name (`Marshal`, `New`,
`Client`) is exported by many modules.

It draws on the interface and example extraction stages: run
[`interface`](interface.md) (and optionally [`examples`](examples.md)) for the
relevant modules first. Without `--module` it returns every module in the store
that exports the name; with `--module` it narrows to one coordinate.

Only **importable** packages are included - symbols under `internal/` or
`testdata/` segments are dropped, because an external consumer cannot call them
and listing them as call targets would mislead.

## Output

### Text

```
github.com/BurntSushi/toml@v1.6.0  github.com/BurntSushi/toml.Marshal  (func)
  func Marshal(v any) ([]byte, error)

  Marshal returns a TOML representation of the Go value.
  ...

~120 tokens (480 bytes)
```

Each entry shows `module  qualified-name  (kind)`, the normalised signature,
the doc comment, and an `Examples:` list (with `(validates)` when the example
is known to compile/run). A trailing approximate token count (JSON bytes ÷ 4)
helps budget context windows.

### JSON (`--json`)

A deterministic array of entries (stable order; `[]` when nothing matches):

| Field | Type | Description |
|---|---|---|
| `module` | string | `module@version` that exports the symbol |
| `package` | string | Defining package import path |
| `name` | string | Symbol name |
| `qualified_name` | string | Fully-qualified name (`pkg.Type.Method` for methods) |
| `kind` | string | `func` / `type` / `method` / `const` / `var` |
| `signature` | string | Normalised signature (omitted when empty) |
| `doc` | string | Godoc comment (omitted when empty) |
| `examples[]` | array | `{name, package, validates}` for each harvested example |

## Flags

| Flag | Default | Description |
|---|---|---|
| `<name>` | _(required)_ | Symbol name to assemble context for |
| `--module <module@version>` | _(all)_ | Narrow to a single module's record |
| `--json` | false | Emit the deterministic JSON array |
| `--store-root <path>` | `~/.kanonarion` | Root directory for blobs and SQLite |

## Behaviour when nothing is found

- No served record exports the name, and every module that could hold it was
  read → text `no exports found for symbol "<name>"`, or `[]` in JSON; exit 0.
- The interface store holds **no record at all** → exit `4`, stdout empty; the
  message names `kanonarion interface <module>@<version>` and
  `kanonarion local .`.
- A module that could hold the name is held **only at a superseded pipeline
  version** → exit `4`, stdout empty. Any such module could hold a bare name or
  one qualified without a slash (`errors.Wrap`); an import-path qualifier counts
  only the modules it falls inside. The message counts those modules, names
  them when there are 10 or fewer, and names the coordinate to re-extract when
  the module is known: from a qualified name, or because only one module went
  unread. Of several versions it names the newest and says the others are held.
  Otherwise it names `kanonarion interface <module>@<version>` and
  `kanonarion interface-list --all-generations`.
- `--module` names a module the store serves **no interface record** for →
  exit `4`, stdout empty. The message says whether the module was never
  extracted or is held only at a superseded pipeline, and names
  `kanonarion interface <module>@<version>`.

Under `--json` the message is on stderr; stdout stays empty.

When an answer is found but some modules that could hold the name are held only
at a superseded pipeline, the answer is printed and a `notice:` line on stderr
counts and names them. Under `--module` the answer is about that module alone,
and no such notice is printed.

See [A record this build does not serve](interface.md#a-record-this-build-does-not-serve).

## Relationship to other commands

- **Requires:** interface records (`interface`); examples are optional
  (`examples`).
- **Complementary:** [`symbol-find`](interface.md) locates which modules export
  a name; `symbol-context` then assembles the full record. [`context`](context.md)
  aggregates at module granularity rather than per symbol.

See also: [`interface`](interface.md), [`examples`](examples.md),
[`context`](context.md).
