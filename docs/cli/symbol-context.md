# `kanonarion symbol-context` - Per-module symbol record for AI context

## Synopsis

```
kanonarion symbol-context <name> [--module <module@version>] [--json]
```

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

- No exports for the name → text `no exports found for symbol "<name>"`, or
  `[]` in JSON; exit 0.
- `--module` names a module with **no interface record** → a stderr pointer to
  run `kanonarion interface <module>` first, distinguishing "module not
  indexed" from "symbol genuinely absent".

## Relationship to other commands

- **Requires:** interface records (`interface`); examples are optional
  (`examples`).
- **Complementary:** [`symbol-find`](interface.md) locates which modules export
  a name; `symbol-context` then assembles the full record. [`context`](context.md)
  aggregates at module granularity rather than per symbol.

See also: [`interface`](interface.md), [`examples`](examples.md),
[`context`](context.md).
