# `kanonarion config` - Read and write configuration values

`config` reads and writes the operator configuration file
(`<store-root>/config.yaml`) using a git-config style interface: dotted key
paths, `get` reads a single value, `set` writes it. Writes are non-destructive
- only the targeted key is modified, comments and unrelated keys are preserved.

## Commands

### `kanonarion config init`

Write a commented config template to `<store-root>/config.yaml` so the
available settings are easy to discover and edit.

```
kanonarion config init [--store-root <dir>]
```

Every key in the template is commented out, so the file changes nothing until
you uncomment a value. Keys left commented keep their live built-in default and
continue to track default changes across upgrades (nothing is frozen to disk).
An existing file is preserved - only sections this binary knows about but that
are missing are appended.

This is the only way to *materialise* the file proactively; no other command
creates `config.yaml` as a side effect.

---

### `kanonarion config show`

Print the full effective configuration (after defaults and flag overrides).

```
kanonarion config show [--store-root <dir>] [--json]
```

When `--json` is not given, the raw `config.yaml` file is printed (including
comments). When `--json` is given, the resolved config is emitted as JSON.

---

### `kanonarion config get <key>`

Print the value for a single dotted key path.

```
kanonarion config get <key>
```

Scalar values (booleans, strings) are printed as plain text. Sequences and maps
are printed as YAML. Exits with code 20 on unknown key.

---

### `kanonarion config set <key> <value>`

Write a value to the configuration file. Creates the file from the commented
template if it does not yet exist, then writes the targeted key. Only that key
is changed - existing content and comments are preserved, and keys you have not
set stay absent so they continue to resolve to the live built-in default.

```
kanonarion config set <key> <value>
```

Exits with code 20 if the key is unknown, read-only, or the value has the
wrong type.

## Defaults and precedence

A value is resolved with the precedence **flag > `config.yaml` > built-in
default**. The config file holds only the keys you explicitly write with
`config set` (or by hand); every other key stays absent and resolves to the
*live* built-in default at runtime.

This matters when kanonarion is upgraded: because unset keys are never frozen
to disk, a changed built-in default (for example a new default `log_level`)
takes effect automatically for any key you never set. A value you did set
keeps winning until you change it.

The template (`config init` writes it, `config set` creates it on demand)
leaves every key commented out for exactly this reason - uncomment a line only
when you want to pin a value and stop tracking the built-in default.

Read-only commands (`config get`, `config show`, `walk-list`, and every other
query) never create or modify `config.yaml`. The file is materialised only by
`config init` or `config set`. An empty store with no `config.yaml` resolves
entirely to built-in defaults.

### License policy is a sparse overlay

`license_policy` is treated as a sparse overlay on the built-in defaults so a
mostly-commented file never silently drops the rest of the policy:

- **Categories merge by name.** Setting `license_policy.categories.<name>`
  adds or overrides that one category; the built-in categories you don't
  mention are kept. (You can override or add a category, but not delete a
  built-in one - set it to an empty list to neutralise it.)
- **Rules replace when present.** If you define `license_policy.rules`, your
  list fully replaces the built-in rules (they are a scope-keyed whole). If
  you omit `rules`, the built-in rules apply.

## Key paths

Keys follow the dotted-path structure of `config.yaml`.

| Key | Type | Example value |
|-----|------|---------------|
| `version` | string (read-only) | `"1"` |
| `preferences.json` | bool | `true` |
| `preferences.log_level` | string | `debug` / `info` / `warn` / `error` |
| `preferences.progress` | bool | `false` (default `true`) - throttled stderr fetch heartbeat on long `walk`/`inspect` runs; never affects stdout/`--json`. Equivalent to `--no-progress` when `false`. |
| `license_policy.categories.<name>` | sequence | `[MIT, Apache-2.0]` |
| `license_policy.rules` | sequence (read-only) | - |
| `license_overrides.<module>` | string | `MIT` |
| `callgraph.exclude` | sequence | `[github.com/foo/bar]` |

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--json` | `false` | Emit output as JSON (`show` only) |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `20` | Unknown key, read-only key, wrong value type, or I/O error |

## Examples

```
# Write a commented template to discover the available settings
kanonarion config init

# Inspect the full config
kanonarion config show

# Read a single value
kanonarion config get preferences.json
kanonarion config get license_policy.categories.permissive

# Write values
kanonarion config set preferences.json true
kanonarion config set preferences.log_level debug
kanonarion config set license_policy.categories.permissive '[MIT, Apache-2.0, ISC]'
kanonarion config set license_overrides.golang.org/x/mod MIT
kanonarion config set callgraph.exclude '[]'
```

## See also

- [`kanonarion store config show`](store.md) - alias for `config show`
- [`kanonarion policy`](policy.md) - inspect and validate depth policy files
