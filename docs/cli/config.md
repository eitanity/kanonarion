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
comments), followed by an **effective configuration** block: every enforced key,
the value actually in force, and `(default)` when that value comes from the
built-in default rather than from the file.

```
# effective configuration (resolved; (default) = not set in this file)
preferences.log_level                             warn  (default)
license_policy.rules[production].unknown_license  block  (default)
license_policy.rules[tool].unknown_license        warn  (default)
fetch_policy.allowed_vcs_hosts                    (unset: built-in host set, advisory)  (default)
...
```

The file alone does not answer "what is in force" - a key you never wrote is
absent from it and still resolves to a built-in default at runtime. The block
below the file is the answer.

**No `config.yaml` in the store is a normal state, not an error.** The command
exits `0` and prints the effective configuration, with a line in place of the
file saying which path was looked for:

```
# no config file at /home/you/.kanonarion/config.yaml - nothing is set in this store, so every value below is a built-in default
#   to write a commented template: kanonarion config init

# effective configuration (resolved; (default) = not set in this file)
...
```

Every key in that case carries `(default)`. A file that *exists* but cannot be
read (permissions) or cannot be parsed is still a refusal, exit `20`, and the
message names the file rather than reporting an all-defaults posture.

When `--json` is given, the resolved config is emitted as JSON. Each licence
rule carries `unknown_license` (the value in force) and
`unknown_license_is_default` (whether it came from the built-in default). The
document opens with `config_file`, giving the `path` looked for and whether it
is `present`; `"present": false` means every value below it is a built-in
default.

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
| `preferences.progress` | bool | `false` (default `true`) - throttled stderr fetch heartbeat on long `walk`/`inspect`/`audit`/`sbom` runs; never affects stdout/`--json`. Equivalent to `--no-progress` when `false`. |
| `license_policy.categories.<name>` | sequence | `[MIT, Apache-2.0]` |
| `license_policy.rules` | sequence (read-only) | - |
| `license_policy.rules[].unknown_license` | string (read-only, edit the file) | `allow` / `notify` / `warn` / `block` - see below |
| `license_overrides.<module>` | string | `MIT` |
| `callgraph.exclude` | sequence | `[github.com/foo/bar]` |
| `staleness.ttl` | duration | `1h` |
| `fetch_policy.allowed_vcs_hosts` | sequence | `[github.com, git.example.org]` - absent leaves the built-in host set advisory; naming it switches to enforcing |

The unified governance blocks (`directive_policy`, `godebug_policy`,
`vendor_policy`, `fips_policy`) are edited in the file rather than through
`config set`; each is documented on its own page
([`directives`](directives.md), [`godebug`](godebug.md),
[`vendor`](vendor.md), [`fips`](fips.md)). All of them appear in the effective
configuration block of `config show`.

### `license_policy.rules[].unknown_license` - the unknown-licence gate

A dependency whose licence could not be resolved to any SPDX identifier is
**undetermined** - no licence record, or an extraction that produced
`None` / `Multiple` / `ExtractionFailed` / `Cancelled`, with no
`license_overrides` entry. Undetermined is not the same as "uncategorised": a
named-but-unlisted licence like `Totally-Unknown-1.0` still resolves through the
rule's `default`.

`unknown_license` is the per-scope control for undetermined licences, and it is
the only setting that can fail a build:

| Value | Effect |
|-------|--------|
| `allow` | accepted silently |
| `notify` | surfaced for awareness |
| `warn` | flagged as needing attention |
| `block` | hard compliance failure - `audit` exits non-zero (code `5`) and names the blocked modules |

**Defaults, when the key is not set:** `block` for `scope: production`, `warn`
for every other scope. Uncertainty fails closed in production rather than being
rendered as a clean allow.

```yaml
license_policy:
  rules:
    - scope: production
      allow: [permissive]
      default: allow
      unknown_license: block
    - scope: tool
      allow: [permissive, weak_copyleft, strong_copyleft]
      default: allow
      unknown_license: warn
```

Run `kanonarion config show` to see the value in force for each scope, including
whether it is the default.

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
kanonarion config set staleness.ttl 6h
```

## See also

- [`kanonarion store config show`](store.md) - alias for `config show`
- [`kanonarion policy`](policy.md) - inspect and validate depth policy files
